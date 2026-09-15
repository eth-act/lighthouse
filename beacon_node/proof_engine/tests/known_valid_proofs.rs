//! End-to-end verification of known-valid execution proofs.
//!
//! The fixtures are the reth stateless-validator guest v0.1.0-rc.3 artifacts published by
//! `eth-act/ere-guests` at tag `v0.17.0`, the tag this crate's verifier is built from. They are
//! checked in so that the built-in program verification keys cannot drift away from the guest
//! they are meant to verify without a test failing.
#![cfg(feature = "ere-verifier")]

use proof_engine::ere::EreProofEngine;
use proof_engine::{ProofEngineConfig, ProofEngineT, ProofVerificationOutcome};
use ssz::Encode;
use tree_hash::TreeHash;
use types::Hash256;
use types::execution::{ExecutionProof, ProofData, ProofType, PublicInput};

/// The proof fixture for each proof type, alongside the guest that produced it.
const PROOFS: [(ProofType, &str); 3] = [
    (
        ProofType::RethOpenvm,
        "stateless-validator-reth-openvm-v2.1.0-preview.proof",
    ),
    (
        ProofType::RethSp1,
        "stateless-validator-reth-sp1-v6.4.0.proof",
    ),
    (
        ProofType::RethZisk,
        "stateless-validator-reth-zisk-v1.1.0-alpha.proof",
    ),
];

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("missing fixture {path:?}: {error}"))
}

/// The public input the fixture proofs were generated over.
fn public_input() -> PublicInput {
    PublicInput {
        new_payload_request_root: Hash256::from_slice(
            &hex::decode("68e2250786a622ab175a8149c63d220704e7ed9610a12b7864047510235e7bb7")
                .expect("fixture root is valid hex"),
        ),
        successful_validation: true,
        chain_id: 1,
        schema_id: 0x1501,
    }
}

fn execution_proof(proof_type: ProofType, public_input: PublicInput) -> ExecutionProof {
    let name = PROOFS
        .iter()
        .find_map(|(candidate, name)| (*candidate == proof_type).then_some(*name))
        .expect("proof type has a fixture");
    ExecutionProof {
        proof_data: ProofData::new(fixture(name)).expect("fixture is within the proof size bound"),
        proof_type,
        public_input,
    }
}

/// The guest commits the SSZ encoding of its validation result, which is the encoding
/// `PublicInput` produces. Comparing against a tree hash root would compare 32 bytes of hash with
/// 43 bytes of encoding.
#[test]
fn public_input_reproduces_the_guest_commitment() {
    let serialized = public_input().as_ssz_bytes();
    assert_eq!(serialized, fixture("public_values.bin"));
    assert_ne!(
        serialized.as_slice(),
        public_input().tree_hash_root().as_slice()
    );
}

#[test]
fn known_valid_proofs_verify_against_the_built_in_keys() {
    let engine = EreProofEngine::new(ProofEngineConfig::default()).expect("engine initializes");

    for (proof_type, _) in PROOFS {
        let proof = execution_proof(proof_type, public_input());
        assert_eq!(
            engine
                .verify_execution_proof(&proof)
                .expect("verifier runs"),
            ProofVerificationOutcome::Valid,
            "{proof_type:?} proof did not verify against the built-in program verification key"
        );
    }
}

/// A proof proves one public input. Changing any field of the reconstructed input must reject it,
/// which is what stops a valid proof being replayed against a different payload.
#[test]
fn known_valid_proofs_reject_a_different_public_input() {
    let engine = EreProofEngine::new(ProofEngineConfig::default()).expect("engine initializes");

    let mut altered_root = public_input();
    altered_root.new_payload_request_root = Hash256::repeat_byte(0xab);
    let mut altered_chain = public_input();
    altered_chain.chain_id = 2;
    let mut altered_validation = public_input();
    altered_validation.successful_validation = false;

    for (proof_type, _) in PROOFS {
        for altered in [&altered_root, &altered_chain, &altered_validation] {
            let proof = execution_proof(proof_type, altered.clone());
            assert_eq!(
                engine
                    .verify_execution_proof(&proof)
                    .expect("verifier runs"),
                ProofVerificationOutcome::Invalid,
                "{proof_type:?} accepted a public input it does not prove"
            );
        }
    }
}

/// A proof is bound to the proof system that produced it, so a fixture must not verify under
/// another proof type's verifier and program key.
///
/// The OpenVM proof is not offered to the SP1 verifier. That combination aborts the process
/// inside the ERE verifier library rather than returning an error: the SP1 decoder reads a length
/// from OpenVM-shaped bytes and attempts an allocation of several hundred petabytes. Every other
/// combination, and arbitrary or truncated bytes, is rejected cleanly. Restore the excluded pair
/// once the upstream decoder bounds that length.
#[test]
fn known_valid_proofs_reject_a_foreign_proof_type() {
    let engine = EreProofEngine::new(ProofEngineConfig::default()).expect("engine initializes");

    for (proof_type, name) in PROOFS {
        for (foreign, _) in PROOFS {
            if foreign == proof_type
                || (proof_type == ProofType::RethOpenvm && foreign == ProofType::RethSp1)
            {
                continue;
            }
            let proof = ExecutionProof {
                proof_data: ProofData::new(fixture(name)).expect("fixture is within the bound"),
                proof_type: foreign,
                public_input: public_input(),
            };
            assert_eq!(
                engine
                    .verify_execution_proof(&proof)
                    .expect("verifier runs"),
                ProofVerificationOutcome::Invalid,
                "a {proof_type:?} proof verified as {foreign:?}"
            );
        }
    }
}

/// Arbitrary and truncated proof data is rejected rather than crashing the verifier.
#[test]
fn malformed_proof_data_is_rejected() {
    let engine = EreProofEngine::new(ProofEngineConfig::default()).expect("engine initializes");

    for (proof_type, name) in PROOFS {
        let valid = fixture(name);
        for data in [
            vec![0u8; 1],
            vec![0xAA; 4096],
            valid[..valid.len() / 3].to_vec(),
        ] {
            let proof = ExecutionProof {
                proof_data: ProofData::new(data).expect("within the bound"),
                proof_type,
                public_input: public_input(),
            };
            assert_eq!(
                engine
                    .verify_execution_proof(&proof)
                    .expect("verifier runs"),
                ProofVerificationOutcome::Invalid,
                "{proof_type:?} accepted malformed proof data"
            );
        }
    }
}

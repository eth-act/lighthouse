//! End-to-end verification of known-valid execution proofs.
//!
//! The fixtures are proofs of the ethrex v32.0.0-rc.1, reth v0.1.0-rc.9, zesu-zkvm
//! tests@v21.0.7, nimbus-zkvm-guests v0.4.0-alpha, nethermind zkvm-guests-2.3.0-preview+6, and
//! zilkworm v0.1.0-alpha.8 guests, copied from `eth-act/zkboost` at commit
//! `dfa7c04a7429d255d95d1a06aea2520f3a69f2be`. Their program verification keys are registered by
//! `eth-act/ere-guests` v0.20.0 and verified here with ERE v0.20.2, the verifier release pinned by
//! this crate.
#![cfg(feature = "ere-verifier")]

use proof_engine::ere::EreProofEngine;
use proof_engine::{ProofEngineConfig, ProofEngineT, ProofVerificationOutcome};
use ssz::Encode;
use tree_hash::TreeHash;
use types::Hash256;
use types::execution::{ExecutionProof, ProofData, ProofType, PublicInput};

/// The proof fixture for each proof type, alongside the guest that produced it.
const PROOFS: [(ProofType, &str); 15] = [
    (
        ProofType::EthrexOpenVM,
        "stateless-validator-ethrex-openvm-v2.1.0-preview.proof",
    ),
    (
        ProofType::EthrexSP1,
        "stateless-validator-ethrex-sp1-v6.9.0.proof",
    ),
    (
        ProofType::EthrexZisk,
        "stateless-validator-ethrex-zisk-v1.4.0-alpha.proof",
    ),
    (
        ProofType::RethOpenVM,
        "stateless-validator-reth-openvm-v2.1.0-preview.proof",
    ),
    (
        ProofType::RethSP1,
        "stateless-validator-reth-sp1-v6.9.0.proof",
    ),
    (
        ProofType::RethZisk,
        "stateless-validator-reth-zisk-v1.4.0-alpha.proof",
    ),
    (
        ProofType::ZesuZisk,
        "stateless-validator-zesu-zisk-v1.4.0-alpha.proof",
    ),
    (
        ProofType::NimbusSP1,
        "stateless-validator-nimbus-sp1-v6.9.0.proof",
    ),
    (
        ProofType::NimbusZisk,
        "stateless-validator-nimbus-zisk-v1.4.0-alpha.proof",
    ),
    (
        ProofType::NethermindSP1,
        "stateless-validator-nethermind-sp1-v6.9.0.proof",
    ),
    (
        ProofType::NethermindZisk,
        "stateless-validator-nethermind-zisk-v1.4.0-alpha.proof",
    ),
    (
        ProofType::ZilkwormSP1,
        "stateless-validator-zilkworm-sp1-v6.9.0.proof",
    ),
    (
        ProofType::ZesuOpenVM,
        "stateless-validator-zesu-openvm-v2.1.0-preview.proof",
    ),
    (
        ProofType::ZesuSP1,
        "stateless-validator-zesu-sp1-v6.9.0.proof",
    ),
    (
        ProofType::RethPico,
        "stateless-validator-reth-pico-v3.1.5.proof",
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
            &hex::decode("52c1bb9fa385915dd4710fd10bf25e2cea436aa42f498e9e8619a34ba4721b03")
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
/// another proof type's verifier and program key. Every pairing is offered, including an OpenVM
/// proof to the SP1 verifier, which the bounded decoder rejects rather than aborting on.
#[test]
fn known_valid_proofs_reject_a_foreign_proof_type() {
    let engine = EreProofEngine::new(ProofEngineConfig::default()).expect("engine initializes");

    for (proof_type, name) in PROOFS {
        for (foreign, _) in PROOFS {
            if foreign == proof_type {
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

/// A real SP1 proof with corrupted nested length data is rejected, not aborted.
///
/// The SP1 fixture is a `Compressed` proof, the one shape the verifier accepts, so it passes the
/// engine's outer proof-shape check and reaches the decoder. Inflating length prefixes inside it
/// is the selector-1 case an outer discriminant check cannot screen: the bytes are handed to the
/// decoder, and the decoder must reject them without an allocation that would end the process.
#[test]
fn corrupted_sp1_nested_lengths_are_rejected() {
    let engine = EreProofEngine::new(ProofEngineConfig::default()).expect("engine initializes");
    let valid = fixture("stateless-validator-reth-sp1-v6.9.0.proof");

    // Offsets inside the decoded structure, past the outer enum selector, set to lengths far
    // larger than the input. A bounded decoder answers `Invalid`; an unbounded one aborts.
    for offset in [8usize, 64, 256, 1024, 4096] {
        let mut data = valid.clone();
        if offset + 8 <= data.len() {
            data[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        }
        let proof = ExecutionProof {
            proof_data: ProofData::new(data).expect("within the bound"),
            proof_type: ProofType::RethSP1,
            public_input: public_input(),
        };
        assert_eq!(
            engine
                .verify_execution_proof(&proof)
                .expect("verifier runs"),
            ProofVerificationOutcome::Invalid,
            "corrupted SP1 proof at offset {offset} was not rejected cleanly"
        );
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

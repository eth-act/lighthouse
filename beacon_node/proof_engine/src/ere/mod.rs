//! ERE-backed production proof-engine implementation.

mod bindings;

use crate::{ProofEngineConfig, ProofEngineError, ProofEngineT, ProofVerificationOutcome};
use bindings::{EreVerifierError, Verifier};
use ssz::Encode;
use std::collections::HashMap;
use types::execution::{ExecutionProof, ProofType, ZkvmKind};

/// In-process proof engine backed by ERE's native verifier library.
pub struct EreProofEngine {
    verifiers: HashMap<ProofType, Verifier>,
}

impl EreProofEngine {
    /// Construct the configured ERE verifiers and validate their program verification keys.
    pub fn new(config: ProofEngineConfig) -> Result<Self, ProofEngineError> {
        let mut verifiers = HashMap::with_capacity(config.execution_proofs().len());

        for config in config.execution_proofs() {
            let verifier =
                Verifier::new(config.proof_type.zkvm(), &config.program_vk).map_err(|error| {
                    ProofEngineError::ProofVerifierError(format!(
                        "failed to initialize ERE verifier for proof type {:?}: {error:?}",
                        config.proof_type
                    ))
                })?;
            verifiers.insert(config.proof_type, verifier);
        }

        Ok(Self { verifiers })
    }
}

impl ProofEngineT for EreProofEngine {
    fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        let verifier = self
            .verifiers
            .get(&proof.proof_type)
            .ok_or(ProofEngineError::UnconfiguredProofType(proof.proof_type))?;
        // The guest commits the canonical SSZ serialization of its validation result, whose layout
        // is the one `PublicInput` encodes, so the proven public values are compared with those
        // bytes.
        let expected_public_values = proof.public_input.as_ssz_bytes();
        if !accepted_proof_shape(proof.proof_type.zkvm(), proof.proof_data.as_ref()) {
            return Ok(ProofVerificationOutcome::Invalid);
        }
        let public_values = match verifier.verify(proof.proof_data.as_ref()) {
            Ok(public_values) => public_values,
            Err(EreVerifierError::DecodeProof | EreVerifierError::Verify) => {
                return Ok(ProofVerificationOutcome::Invalid);
            }
            Err(error) => {
                return Err(ProofEngineError::ProofVerifierError(format!(
                    "ERE verifier failed for proof type {:?}: {error:?}",
                    proof.proof_type
                )));
            }
        };

        Ok(verify_public_values(
            &public_values,
            &expected_public_values,
            proof.proof_type.zkvm(),
        ))
    }
}

/// The only `SP1Proof` variant an ERE verifier accepts, as a bincode-legacy enum selector.
///
/// `sp1_verifier::SP1Proof` orders its variants `Core`, `Compressed`, `Plonk`, `Groth16`.
const SP1_COMPRESSED_SELECTOR: u32 = 1;

/// Whether `proof_data` is shaped like a proof the verifier for `zkvm_kind` accepts.
///
/// The verifier decodes a proof before deciding whether its kind is one it handles, and the
/// decoder allocates on a length it reads out of the input. Proof data arrives from gossip, so a
/// sender chooses both the proof type that selects the verifier and the bytes handed to it. Bytes
/// carrying another proof system's shape can therefore reach a decoder that reads a length from
/// them, and an allocation refused by the allocator ends the process rather than the request.
///
/// Checking the selector first admits exactly what the verifier admits: SP1 accepts the compressed
/// proof alone and answers every other kind with an error, so rejecting the others here loses
/// nothing and keeps those bytes away from the decoder. OpenVM and Zisk expose no such selector,
/// and no input has been found that makes either of them allocate on a length it has not read.
fn accepted_proof_shape(zkvm_kind: ZkvmKind, proof_data: &[u8]) -> bool {
    match zkvm_kind {
        ZkvmKind::Sp1 => proof_data
            .get(..size_of::<u32>())
            .and_then(|selector| selector.try_into().ok())
            .is_some_and(|selector| u32::from_le_bytes(selector) == SP1_COMPRESSED_SELECTOR),
        ZkvmKind::Openvm | ZkvmKind::Zisk => true,
    }
}

/// Verify that `public_values` proves exactly `expected`, allowing only the trailing zero
/// padding that the zkVM's ERE output contract adds.
///
/// OpenVM reveals a fixed-size public-value buffer and Zisk a fixed public-word count, so both
/// zero-pad a shorter guest commitment. SP1 returns the committed bytes verbatim, so `expected` is
/// the whole of its output.
fn verify_public_values(
    public_values: &[u8],
    expected: &[u8],
    zkvm_kind: ZkvmKind,
) -> ProofVerificationOutcome {
    let proven = match zkvm_kind {
        ZkvmKind::Openvm | ZkvmKind::Zisk => public_values
            .split_at_checked(expected.len())
            .is_some_and(|(value, padding)| {
                value == expected && padding.iter().all(|byte| *byte == 0)
            }),
        ZkvmKind::Sp1 => public_values == expected,
    };

    if proven {
        ProofVerificationOutcome::Valid
    } else {
        ProofVerificationOutcome::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;
    use types::{
        Hash256,
        execution::{ProofData, PublicInput},
    };

    /// Every zkVM the comparison distinguishes, derived from the assigned proof types.
    fn zkvm_kinds() -> impl Iterator<Item = ZkvmKind> {
        ProofType::all().iter().map(|proof_type| proof_type.zkvm())
    }

    fn public_input() -> PublicInput {
        ExecutionProof::new(
            ProofData::new(vec![1]).expect("proof data within bound"),
            ProofType::RethSp1,
            Hash256::repeat_byte(0x33),
            1,
        )
        .public_input
    }

    #[test]
    fn default_config_initializes_ere_verifier() {
        EreProofEngine::new(ProofEngineConfig::default())
            .expect("ERE accepts the embedded program verification keys");
    }

    #[test]
    fn sp1_admits_only_the_compressed_proof_shape() {
        for selector in [0u32, 2, 3, u32::MAX] {
            assert!(!accepted_proof_shape(
                ZkvmKind::Sp1,
                &selector.to_le_bytes()
            ));
        }
        assert!(accepted_proof_shape(
            ZkvmKind::Sp1,
            &SP1_COMPRESSED_SELECTOR.to_le_bytes()
        ));

        // Too short to carry a selector.
        for truncated in [&[][..], &[1][..], &[1, 0, 0][..]] {
            assert!(!accepted_proof_shape(ZkvmKind::Sp1, truncated));
        }

        // The other verifiers expose no selector to check.
        for zkvm_kind in [ZkvmKind::Openvm, ZkvmKind::Zisk] {
            assert!(accepted_proof_shape(zkvm_kind, &[]));
        }
    }

    #[test]
    fn malformed_ere_proof_is_invalid() {
        let proof_engine = EreProofEngine::new(ProofEngineConfig::default())
            .expect("default verifiers initialize");
        let proof = ExecutionProof::new(
            ProofData::new(vec![0xff]).expect("proof data within bound"),
            ProofType::RethSp1,
            Hash256::default(),
            1,
        );

        assert_eq!(
            proof_engine
                .verify_execution_proof(&proof)
                .expect("ERE reports a verification outcome"),
            ProofVerificationOutcome::Invalid
        );
    }

    #[test]
    fn serialized_public_input_matches_the_guest_output_layout() {
        let public_input = public_input();
        let serialized = public_input.as_ssz_bytes();

        // The reth stateless-validator guest commits this fixed 43-byte encoding.
        assert_eq!(serialized.len(), 43);
        assert_eq!(
            &serialized[..32],
            public_input.new_payload_request_root.as_slice()
        );
        assert_eq!(serialized[32], u8::from(public_input.successful_validation));
        assert_eq!(&serialized[33..41], &public_input.chain_id.to_le_bytes());
        assert_eq!(&serialized[41..], &public_input.schema_id.to_le_bytes());
    }

    #[test]
    fn serialized_public_input_and_its_tree_hash_root_are_not_interchangeable() {
        let public_input = public_input();
        let serialized = public_input.as_ssz_bytes();
        let tree_hash_root = public_input.tree_hash_root();

        assert_ne!(serialized.as_slice(), tree_hash_root.as_slice());
        for zkvm_kind in zkvm_kinds() {
            assert_eq!(
                verify_public_values(tree_hash_root.as_slice(), &serialized, zkvm_kind),
                ProofVerificationOutcome::Invalid
            );
        }
    }

    #[test]
    fn accepts_the_serialized_public_input_with_permitted_zero_padding() {
        let expected = public_input().as_ssz_bytes();

        for zkvm_kind in zkvm_kinds() {
            assert_eq!(
                verify_public_values(&expected, &expected, zkvm_kind),
                ProofVerificationOutcome::Valid
            );
        }

        // Only OpenVM and Zisk reveal a padded buffer.
        let mut padded = expected.clone();
        padded.resize(256, 0);
        for (zkvm_kind, expected_outcome) in [
            (ZkvmKind::Openvm, ProofVerificationOutcome::Valid),
            (ZkvmKind::Zisk, ProofVerificationOutcome::Valid),
            (ZkvmKind::Sp1, ProofVerificationOutcome::Invalid),
        ] {
            assert_eq!(
                verify_public_values(&padded, &expected, zkvm_kind),
                expected_outcome
            );
        }
    }

    #[test]
    fn rejects_changed_truncated_and_non_zero_padded_public_values() {
        let expected = public_input().as_ssz_bytes();

        let mut changed_field = expected.clone();
        changed_field[33] ^= 1;
        let truncated = expected[..expected.len() - 1].to_vec();
        let mut non_zero_padding = expected.clone();
        non_zero_padding.extend_from_slice(&[0, 0, 1]);

        for zkvm_kind in zkvm_kinds() {
            for public_values in [&changed_field, &truncated, &non_zero_padding, &Vec::new()] {
                assert_eq!(
                    verify_public_values(public_values, &expected, zkvm_kind),
                    ProofVerificationOutcome::Invalid,
                    "accepted {public_values:?} for {zkvm_kind:?}"
                );
            }
        }
    }
}

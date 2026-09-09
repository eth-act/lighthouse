//! ERE-backed production proof-engine implementation.

mod bindings;

use crate::{ProofEngineConfig, ProofEngineError, ProofEngineT, ProofVerificationOutcome};
use bindings::{EreVerifierError, Verifier};
use std::collections::HashMap;
use tree_hash::TreeHash;
use types::execution::{ExecutionProof, ProofType};

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
                Verifier::new(config.zkvm_kind, &config.program_vk).map_err(|error| {
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
        let expected_public_values = proof.public_input.tree_hash_root();
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

        // OpenVM and Zisk may zero-pad the guest's public-value buffer.
        let outcome = if public_values
            .split_at_checked(expected_public_values.len())
            .is_some_and(|(value, padding)| {
                value == expected_public_values.as_slice() && padding.iter().all(|byte| *byte == 0)
            }) {
            ProofVerificationOutcome::Valid
        } else {
            ProofVerificationOutcome::Invalid
        };

        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Hash256, execution::ProofData};

    #[test]
    fn default_config_initializes_ere_verifier() {
        EreProofEngine::new(ProofEngineConfig::default())
            .expect("ERE accepts the embedded program verification keys");
    }

    #[test]
    fn malformed_ere_proof_is_invalid() {
        let proof_engine = EreProofEngine::new(ProofEngineConfig::default())
            .expect("default verifiers initialize");
        let proof = ExecutionProof::new(
            ProofData::new(vec![0xff]).expect("proof data within bound"),
            2,
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
}

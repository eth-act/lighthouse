//! Test utilities for proof-engine consumers.

use crate::{ProofEngineError, ProofEngineT, ProofVerificationOutcome};
use std::collections::HashSet;
use types::execution::ExecutionProof;

/// Deterministic proof engine used by beacon-chain tests.
#[derive(Debug, Default)]
pub struct MockProofEngine {
    valid_proof_data: HashSet<Vec<u8>>,
}

impl MockProofEngine {
    /// Construct a mock that accepts exactly the supplied proof-data byte strings.
    pub fn new(valid_proof_data: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            valid_proof_data: valid_proof_data.into_iter().collect(),
        }
    }
}

impl ProofEngineT for MockProofEngine {
    fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        Ok(
            if self.valid_proof_data.contains(proof.proof_data.as_ref()) {
                ProofVerificationOutcome::Valid
            } else {
                ProofVerificationOutcome::Invalid
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProofEngine;
    use types::{Hash256, execution::ProofData};

    #[test]
    fn matches_configured_proof_data() {
        let valid_data = vec![1, 2, 3];
        let proof_engine = ProofEngine::new(MockProofEngine::new([valid_data.clone()]));
        let proof = |proof_data| {
            ExecutionProof::new(
                ProofData::new(proof_data).expect("proof data within bound"),
                2,
                Hash256::default(),
                1,
            )
        };

        assert_eq!(
            proof_engine
                .verify_execution_proof(&proof(valid_data))
                .expect("mock verification succeeds"),
            ProofVerificationOutcome::Valid
        );
        assert_eq!(
            proof_engine
                .verify_execution_proof(&proof(vec![9]))
                .expect("mock verification succeeds"),
            ProofVerificationOutcome::Invalid
        );
    }
}

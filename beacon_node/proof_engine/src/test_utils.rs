//! Mock proof engines, for tests and for devnets without a prover.

use crate::{ProofEngineError, ProofEngineT, ProofVerificationOutcome};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::HashSet;
use types::execution::{ExecutionProof, ProofType};

/// Deterministic proof engine used by beacon-chain tests, and by devnets through
/// `--proof-engine-mock-proofs`.
#[derive(Debug, Default)]
pub struct MockProofEngine {
    valid_proof_data: HashSet<Vec<u8>>,
    /// Proof types whose zkboost mock proofs are accepted. `None` accepts no mock proof.
    mock_proof_types: Option<HashSet<ProofType>>,
}

impl MockProofEngine {
    /// Construct a mock that accepts exactly the supplied proof-data byte strings.
    pub fn new(valid_proof_data: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            valid_proof_data: valid_proof_data.into_iter().collect(),
            mock_proof_types: None,
        }
    }

    /// Construct a mock that accepts the mock proofs of zkboost's mock zkVMs for `proof_types`.
    ///
    /// A zkboost mock proof is the SSZ container
    /// `MockProof { public_values: List[byte], proof: List[byte] }` whose `proof` is random bytes.
    /// It is valid when its public values are the serialized public input of the proof, the bytes
    /// a real guest commits; `proof` is not checked.
    pub fn zkboost(proof_types: impl IntoIterator<Item = ProofType>) -> Self {
        Self {
            valid_proof_data: HashSet::new(),
            mock_proof_types: Some(proof_types.into_iter().collect()),
        }
    }
}

/// The `proof_data` of a zkboost mock proof, as `MockProof` in eth-act/zkboost
/// (`crates/types/src/execution_proof.rs`). The `proof_data` list bounds both lists.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct MockProof {
    /// The public values that the guest commits, as a verifier of a real proof returns them.
    pub public_values: Vec<u8>,
    /// Random bytes in place of a real proof.
    pub proof: Vec<u8>,
}

impl ProofEngineT for MockProofEngine {
    fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        if let Some(mock_proof_types) = &self.mock_proof_types {
            if !mock_proof_types.contains(&proof.proof_type) {
                return Err(ProofEngineError::UnconfiguredProofType(proof.proof_type));
            }
            if MockProof::from_ssz_bytes(proof.proof_data.as_ref()).is_ok_and(|mock_proof| {
                mock_proof.public_values == proof.public_input.as_ssz_bytes()
            }) {
                return Ok(ProofVerificationOutcome::Valid);
            }
        }

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
    use types::{
        Hash256,
        execution::{ProofData, ProofType},
    };

    #[test]
    fn matches_configured_proof_data() {
        let valid_data = vec![1, 2, 3];
        let proof_engine = ProofEngine::new(MockProofEngine::new([valid_data.clone()]));
        let proof = |proof_data| {
            ExecutionProof::new(
                ProofData::new(proof_data).expect("proof data within bound"),
                ProofType::RethSP1,
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

    fn zkboost_mock_proof(public_values: &[u8], proof: &[u8]) -> Vec<u8> {
        MockProof {
            public_values: public_values.to_vec(),
            proof: proof.to_vec(),
        }
        .as_ssz_bytes()
    }

    /// The encoding matches the layout zkboost tests: the offsets of both lists, then the public
    /// values and the proof.
    #[test]
    fn mock_proof_layout_matches_zkboost() {
        let mock_proof = MockProof {
            public_values: vec![0xaa; 3],
            proof: vec![0xbb; 2],
        };
        let encoded = mock_proof.as_ssz_bytes();
        assert_eq!(
            encoded,
            [8, 0, 0, 0, 11, 0, 0, 0, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb]
        );
        assert_eq!(
            MockProof::from_ssz_bytes(&encoded).expect("valid mock proof"),
            mock_proof
        );
    }

    #[test]
    fn zkboost_mock_proofs_verify_their_public_values() {
        let proof_engine = ProofEngine::new(MockProofEngine::zkboost([ProofType::EthrexSP1]));
        let proof = |proof_type, proof_data| {
            ExecutionProof::new(
                ProofData::new(proof_data).expect("proof data within bound"),
                proof_type,
                Hash256::repeat_byte(0x33),
                1,
            )
        };
        let public_values = proof(ProofType::EthrexSP1, vec![1])
            .public_input
            .as_ssz_bytes();
        let verify = |proof_type, proof_data| {
            proof_engine.verify_execution_proof(&proof(proof_type, proof_data))
        };

        assert_eq!(
            verify(
                ProofType::EthrexSP1,
                zkboost_mock_proof(&public_values, &[0xbb; 64])
            )
            .expect("mock verification succeeds"),
            ProofVerificationOutcome::Valid
        );

        let mut other_public_values = public_values.clone();
        other_public_values[0] ^= 1;
        for proof_data in [
            zkboost_mock_proof(&other_public_values, &[0xbb; 64]),
            zkboost_mock_proof(&public_values[..public_values.len() - 1], &[0xbb; 64]),
            vec![0xff; 64],
        ] {
            assert_eq!(
                verify(ProofType::EthrexSP1, proof_data).expect("mock verification succeeds"),
                ProofVerificationOutcome::Invalid
            );
        }

        assert!(matches!(
            verify(
                ProofType::RethSP1,
                zkboost_mock_proof(&public_values, &[0xbb; 64])
            ),
            Err(ProofEngineError::UnconfiguredProofType(ProofType::RethSP1))
        ));
    }

    #[test]
    fn exact_proof_data_mock_rejects_zkboost_mock_proofs() {
        let proof = ExecutionProof::new(
            ProofData::new(vec![1]).expect("proof data within bound"),
            ProofType::RethSP1,
            Hash256::default(),
            1,
        );
        let mock_proof = ExecutionProof::new(
            ProofData::new(zkboost_mock_proof(
                &proof.public_input.as_ssz_bytes(),
                &[0xbb; 64],
            ))
            .expect("proof data within bound"),
            ProofType::RethSP1,
            Hash256::default(),
            1,
        );

        assert_eq!(
            ProofEngine::new(MockProofEngine::default())
                .verify_execution_proof(&mock_proof)
                .expect("mock verification succeeds"),
            ProofVerificationOutcome::Invalid
        );
    }
}

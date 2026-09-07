//! In-process EIP-8025 proof verification using ERE.

use ere_catalog::zkVMKind;
use ere_verifier::Verifier;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf, str::FromStr, sync::Arc};
use tree_hash::TreeHash;
use types::execution::{ExecutionProof, ProofType, is_supported_proof_type};

#[derive(Debug)]
pub enum ProofEngineError {
    DuplicateProofType(ProofType),
    UnsupportedProofType(ProofType),
    ReadProgramVk {
        path: PathBuf,
        error: String,
    },
    InvalidProgramVk {
        proof_type: ProofType,
        error: String,
    },
    UnconfiguredProofType(ProofType),
    VerifierTask(String),
}

/// Outcome of `verify_execution_proof`. `Invalid` means the artifact does not verify; it says
/// nothing about the validity of the payload it claims to prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerificationOutcome {
    Valid,
    Invalid,
}

/// Configuration for the verifier assigned to an EIP-8025 proof type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierConfig {
    pub proof_type: ProofType,
    pub zkvm_kind: zkVMKind,
    pub program_vk_path: PathBuf,
}

impl FromStr for VerifierConfig {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut fields = value.splitn(3, ':');
        let proof_type = fields
            .next()
            .ok_or_else(|| verifier_config_format_error(value))?
            .parse()
            .map_err(|e| format!("invalid proof type in `{value}`: {e}"))?;
        let zkvm_kind = fields
            .next()
            .ok_or_else(|| verifier_config_format_error(value))?
            .parse()
            .map_err(|e| format!("invalid zkVM kind in `{value}`: {e}"))?;
        let program_vk_path = fields
            .next()
            .filter(|path| !path.is_empty())
            .ok_or_else(|| verifier_config_format_error(value))?
            .into();

        Ok(Self {
            proof_type,
            zkvm_kind,
            program_vk_path,
        })
    }
}

fn verifier_config_format_error(value: &str) -> String {
    format!("invalid verifier configuration `{value}`; expected PROOF-TYPE:ZKVM:PROGRAM-VK-PATH")
}

pub struct ProofEngine {
    verifiers: HashMap<ProofType, Arc<Verifier>>,
}

impl ProofEngine {
    pub fn new(configs: Vec<VerifierConfig>) -> Result<Self, ProofEngineError> {
        let mut verifiers = HashMap::with_capacity(configs.len());

        for config in configs {
            if !is_supported_proof_type(config.proof_type) {
                return Err(ProofEngineError::UnsupportedProofType(config.proof_type));
            }
            if verifiers.contains_key(&config.proof_type) {
                return Err(ProofEngineError::DuplicateProofType(config.proof_type));
            }

            let program_vk =
                fs::read(&config.program_vk_path).map_err(|e| ProofEngineError::ReadProgramVk {
                    path: config.program_vk_path.clone(),
                    error: e.to_string(),
                })?;
            let verifier = Verifier::new(config.zkvm_kind, &program_vk).map_err(|e| {
                ProofEngineError::InvalidProgramVk {
                    proof_type: config.proof_type,
                    error: e.to_string(),
                }
            })?;

            verifiers.insert(config.proof_type, Arc::new(verifier));
        }

        Ok(Self { verifiers })
    }

    /// EIP-8025 `ProofEngine.verify_execution_proof`.
    pub async fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        let verifier = self
            .verifiers
            .get(&proof.proof_type)
            .cloned()
            .ok_or(ProofEngineError::UnconfiguredProofType(proof.proof_type))?;
        let encoded_proof = proof.proof_data.to_vec();
        let expected_public_values = proof.public_input.tree_hash_root();

        tokio::task::spawn_blocking(move || {
            verify_with_ere(&verifier, &encoded_proof, expected_public_values.as_slice())
        })
        .await
        .map_err(|e| ProofEngineError::VerifierTask(e.to_string()))
    }
}

fn verify_with_ere(
    verifier: &Verifier,
    encoded_proof: &[u8],
    expected_public_values: &[u8],
) -> ProofVerificationOutcome {
    let public_values = match verifier.verify(encoded_proof) {
        Ok(public_values) => public_values,
        Err(_) => return ProofVerificationOutcome::Invalid,
    };

    if matches_public_values(public_values.as_ref(), expected_public_values) {
        ProofVerificationOutcome::Valid
    } else {
        ProofVerificationOutcome::Invalid
    }
}

// OpenVM and Zisk may zero-pad the guest's public-value buffer.
fn matches_public_values(actual: &[u8], expected: &[u8]) -> bool {
    actual
        .split_at_checked(expected.len())
        .is_some_and(|(value, padding)| value == expected && padding.iter().all(|byte| *byte == 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use types::{Hash256, execution::ProofData};

    // Encoded SP1 program VK from ERE's verifier fixture at the pinned revision.
    const SP1_PROGRAM_VK: [u8; 32] = [
        0x00, 0x2d, 0x67, 0x59, 0x7a, 0x7a, 0xfd, 0xbb, 0x45, 0xa2, 0x4a, 0x31, 0x1e, 0xa7, 0x7a,
        0x6b, 0x07, 0xcc, 0xde, 0xba, 0xb8, 0xb9, 0x2d, 0xb5, 0xa9, 0x5f, 0xe8, 0x37, 0x1b, 0xee,
        0xd3, 0x80,
    ];

    #[test]
    fn parses_verifier_config() {
        let config: VerifierConfig = "2:sp1:/tmp/program.vk"
            .parse()
            .expect("valid verifier configuration");

        assert_eq!(config.proof_type, 2);
        assert_eq!(config.zkvm_kind, zkVMKind::SP1);
        assert_eq!(config.program_vk_path, PathBuf::from("/tmp/program.vk"));
    }

    #[test]
    fn rejects_invalid_verifier_configs() {
        assert!("2:sp1".parse::<VerifierConfig>().is_err());
        assert!(
            "proof:sp1:/tmp/program.vk"
                .parse::<VerifierConfig>()
                .is_err()
        );
        assert!(
            "2:unknown:/tmp/program.vk"
                .parse::<VerifierConfig>()
                .is_err()
        );
        assert!("2:sp1:".parse::<VerifierConfig>().is_err());
    }

    #[test]
    fn rejects_unsupported_proof_type_before_reading_vk() {
        let result = ProofEngine::new(vec![VerifierConfig {
            proof_type: 0,
            zkvm_kind: zkVMKind::SP1,
            program_vk_path: PathBuf::from("missing.vk"),
        }]);

        assert!(matches!(
            result,
            Err(ProofEngineError::UnsupportedProofType(0))
        ));
    }

    #[test]
    fn public_values_must_match_with_only_zero_padding() {
        assert!(matches_public_values(&[1, 2, 3], &[1, 2, 3]));
        assert!(matches_public_values(&[1, 2, 3, 0, 0], &[1, 2, 3]));
        assert!(!matches_public_values(&[1, 2], &[1, 2, 3]));
        assert!(!matches_public_values(&[1, 2, 4], &[1, 2, 3]));
        assert!(!matches_public_values(&[1, 2, 3, 0, 1], &[1, 2, 3]));
    }

    #[tokio::test]
    async fn malformed_ere_proof_is_invalid() {
        let program_vk = NamedTempFile::new().expect("create program VK file");
        fs::write(program_vk.path(), SP1_PROGRAM_VK).expect("write program VK");
        let proof_engine = ProofEngine::new(vec![VerifierConfig {
            proof_type: 2,
            zkvm_kind: zkVMKind::SP1,
            program_vk_path: program_vk.path().into(),
        }])
        .expect("create proof engine");
        let proof = ExecutionProof::new(
            ProofData::new(vec![0xff]).expect("proof data within bound"),
            2,
            Hash256::default(),
            1,
        );

        assert_eq!(
            proof_engine
                .verify_execution_proof(&proof)
                .await
                .expect("verifier task completes"),
            ProofVerificationOutcome::Invalid
        );
    }
}

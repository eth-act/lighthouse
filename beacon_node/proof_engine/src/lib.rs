//! Minimal EIP-8025 proof-engine client.
//!
//! Implements only `verify_execution_proof` from the proof-engine API
//! (consensus-specs `_features/eip8025/proof-engine.md`). The proof engine is a trusted,
//! locally-operated service; its verdict is authoritative for proof validity but never for
//! payload validity.

use sensitive_url::SensitiveUrl;
use serde::Deserialize;
use std::time::Duration;
use types::execution::ExecutionProof;

pub const DEFAULT_VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

const PATH_PROOF_VERIFICATIONS: &str = "/v1/execution_proof_verifications";

#[derive(Debug)]
pub enum ProofEngineError {
    HttpClient(String),
    InvalidUrl(String),
    InvalidResponse(String),
}

/// Outcome of `verify_execution_proof`. `Invalid` means the artifact does not verify; it says
/// nothing about the validity of the payload it claims to prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerificationOutcome {
    Valid,
    Invalid,
}

#[derive(Deserialize)]
struct VerifyResponse {
    status: VerifyStatus,
}

#[derive(Deserialize, Clone, Copy)]
enum VerifyStatus {
    #[serde(rename = "VALID")]
    Valid,
    #[serde(rename = "INVALID")]
    Invalid,
}

fn verification_query(proof: &ExecutionProof) -> [(&'static str, String); 5] {
    [
        (
            "new_payload_request_root",
            format!("{:?}", proof.public_input.new_payload_request_root),
        ),
        (
            "successful_validation",
            proof.public_input.successful_validation.to_string(),
        ),
        ("chain_id", proof.public_input.chain_id.to_string()),
        ("schema_id", proof.public_input.schema_id.to_string()),
        ("proof_type", proof.proof_type.to_string()),
    ]
}

pub struct ProofEngine {
    client: reqwest::Client,
    url: SensitiveUrl,
}

impl ProofEngine {
    pub fn new(url: SensitiveUrl) -> Result<Self, ProofEngineError> {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_VERIFY_TIMEOUT)
            .build()
            .map_err(|e| ProofEngineError::HttpClient(e.to_string()))?;
        Ok(Self { client, url })
    }

    /// EIP-8025 `ProofEngine.verify_execution_proof`.
    pub async fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        let mut url = self.url.expose_full().clone();
        url.set_path(PATH_PROOF_VERIFICATIONS);
        let response: VerifyResponse = self
            .client
            .post(url)
            .query(&verification_query(proof))
            .header("content-type", "application/octet-stream")
            .body(proof.proof_data.to_vec())
            .send()
            .await
            .map_err(|e| ProofEngineError::HttpClient(e.to_string()))?
            .error_for_status()
            .map_err(|e| ProofEngineError::HttpClient(e.to_string()))?
            .json()
            .await
            .map_err(|e| ProofEngineError::InvalidResponse(e.to_string()))?;

        Ok(match response.status {
            VerifyStatus::Valid => ProofVerificationOutcome::Valid,
            VerifyStatus::Invalid => ProofVerificationOutcome::Invalid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{
        Hash256,
        execution::{ProofData, PublicInput, STATELESS_INPUT_SCHEMA_ID},
    };

    #[test]
    fn verification_query_contains_complete_public_input() {
        let proof = ExecutionProof {
            proof_data: ProofData::new(vec![1, 2, 3]).expect("valid progressive list"),
            proof_type: 2,
            public_input: PublicInput {
                new_payload_request_root: Hash256::repeat_byte(0x42),
                successful_validation: true,
                chain_id: 1,
                schema_id: STATELESS_INPUT_SCHEMA_ID,
            },
        };

        assert_eq!(
            verification_query(&proof),
            [
                (
                    "new_payload_request_root",
                    format!("{:?}", proof.public_input.new_payload_request_root),
                ),
                ("successful_validation", "true".into()),
                ("chain_id", "1".into()),
                ("schema_id", STATELESS_INPUT_SCHEMA_ID.to_string()),
                ("proof_type", "2".into()),
            ]
        );
    }
}

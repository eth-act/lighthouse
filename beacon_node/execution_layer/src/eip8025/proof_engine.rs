use super::errors::ProofEngineError;
use super::proof_node_client::{HttpProofNodeClient, ProofNodeClient};
use super::types::ProofEvent;
use bytes::Bytes;
use futures::stream::Stream;
use sensitive_url::SensitiveUrl;
use ssz::Encode;
use std::pin::Pin;
use std::time::Duration;
use types::execution::eip8025::{ProofAttributes, ProofStatus, SignedExecutionProof};
use types::{EthSpec, Hash256};

pub struct HttpProofEngine {
    proof_node: Box<dyn ProofNodeClient>,
}

impl HttpProofEngine {
    pub fn new(url: SensitiveUrl, timeout: Option<Duration>) -> Self {
        Self::with_proof_node(HttpProofNodeClient::new(url, timeout))
    }

    pub fn with_proof_node(proof_node: impl ProofNodeClient + 'static) -> Self {
        Self {
            proof_node: Box::new(proof_node),
        }
    }

    pub async fn verify_execution_proof(
        &self,
        proof: &SignedExecutionProof,
    ) -> Result<ProofStatus, ProofEngineError> {
        self.proof_node
            .verify_proof(proof.request_root(), proof.proof_type(), proof.proof_data())
            .await
    }

    pub async fn get_proof(
        &self,
        new_payload_request_root: Hash256,
        proof_type: u8,
    ) -> Result<Bytes, ProofEngineError> {
        self.proof_node
            .get_proof(new_payload_request_root, proof_type)
            .await
    }

    pub async fn request_proofs<E: EthSpec>(
        &self,
        new_payload_request: crate::NewPayloadRequest<'_, E>,
        proof_attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError> {
        self.request_proofs_ssz(new_payload_request.as_ssz_bytes(), proof_attributes)
            .await
    }

    pub async fn request_proofs_ssz(
        &self,
        ssz_body: Vec<u8>,
        proof_attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError> {
        self.proof_node
            .request_proofs(ssz_body, proof_attributes)
            .await
    }

    pub fn subscribe_proof_events(
        &self,
        filter_root: Option<Hash256>,
    ) -> Pin<Box<dyn Stream<Item = Result<ProofEvent, ProofEngineError>> + Send + '_>> {
        self.proof_node.subscribe_proof_events(filter_root)
    }
}

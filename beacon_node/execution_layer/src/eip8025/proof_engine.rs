//! ProofEngine trait and HTTP implementation for EIP-8025.
//!
//! This module defines the interface for interacting with proof engines
//! and provides an HTTP implementation with an internal proof cache.
//!
//! HTTP transport is delegated to [`super::proof_node_client::ProofNodeClient`].

use super::errors::ProofEngineError;
use super::persisted_state::PersistedProofEngineState;
use super::proof_node_client::ProofNodeClient;
use crate::{
    eip8025::state::{RequestMetadata, State},
    ForkchoiceState, ForkchoiceUpdatedResponse, MissingProofInfo, NewPayloadRequest,
    PayloadStatusV1, PayloadStatusV1Status,
};
use bytes::Bytes;
use futures::stream::Stream;
use parking_lot::RwLock;
use sensitive_url::SensitiveUrl;
use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

use types::execution::eip8025::{ProofAttributes, ProofStatus, SignedExecutionProof};
use types::{EthSpec, Hash256};

// ─── SSE Event Types ─────────────────────────────────────────────────────────

/// SSE event types broadcast by the proof engine.
#[derive(Debug, Clone, PartialEq)]
pub enum ProofEvent {
    /// A proof completed successfully.
    ProofComplete(ProofComplete),
    /// A proof failed.
    ProofFailure(ProofFailure),
    /// Witness fetch timed out.
    WitnessTimeout(ProofEventInfo),
    /// Proof generation timed out.
    ProofTimeout(ProofEventInfo),
}

/// Payload for a successful proof event.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct ProofComplete {
    pub new_payload_request_root: Hash256,
    pub proof_type: u8,
}

/// Payload for a failed proof event.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct ProofFailure {
    pub new_payload_request_root: Hash256,
    pub proof_type: u8,
    pub error: String,
}

/// Common info for timeout events.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct ProofEventInfo {
    pub new_payload_request_root: Hash256,
    pub proof_type: u8,
}

impl ProofEvent {
    /// Reconstruct a [`ProofEvent`] from an SSE event name and JSON data.
    pub fn try_from_parts(name: &str, data: &str) -> Result<Self, ProofEngineError> {
        match name {
            "proof_complete" => Ok(Self::ProofComplete(
                serde_json::from_str(data).map_err(ProofEngineError::SerdeError)?,
            )),
            "proof_failure" => Ok(Self::ProofFailure(
                serde_json::from_str(data).map_err(ProofEngineError::SerdeError)?,
            )),
            "witness_timeout" => Ok(Self::WitnessTimeout(
                serde_json::from_str(data).map_err(ProofEngineError::SerdeError)?,
            )),
            "proof_timeout" => Ok(Self::ProofTimeout(
                serde_json::from_str(data).map_err(ProofEngineError::SerdeError)?,
            )),
            other => Err(ProofEngineError::SseError(format!(
                "unknown SSE event type: {other}"
            ))),
        }
    }

    /// Returns the `new_payload_request_root` from the event.
    pub fn new_payload_request_root(&self) -> Hash256 {
        match self {
            Self::ProofComplete(inner) => inner.new_payload_request_root,
            Self::ProofFailure(inner) => inner.new_payload_request_root,
            Self::WitnessTimeout(inner) => inner.new_payload_request_root,
            Self::ProofTimeout(inner) => inner.new_payload_request_root,
        }
    }

    /// Returns the proof type from the event.
    pub fn proof_type(&self) -> u8 {
        match self {
            Self::ProofComplete(inner) => inner.proof_type,
            Self::ProofFailure(inner) => inner.proof_type,
            Self::WitnessTimeout(inner) => inner.proof_type,
            Self::ProofTimeout(inner) => inner.proof_type,
        }
    }
}

// ─── ProofEngine Trait ───────────────────────────────────────────────────────

/// Trait defining the interface for a proof engine.
#[async_trait::async_trait]
pub trait ProofEngine: Send + Sync {
    /// Get all proofs for a given new_payload_request_root.
    fn get_proofs_by_root(&self, root: &Hash256) -> Vec<SignedExecutionProof>;

    /// Return all buffer entries that do not yet have sufficient proofs for promotion.
    ///
    /// `MissingProofInfo.root` is populated with the new-payload request root.
    /// The beacon chain layer replaces it with the beacon block root before the
    /// sync manager issues `ExecutionProofsByRoot` RPC requests.
    fn missing_proofs(&self) -> Vec<MissingProofInfo>;

    /// Verify an individual execution proof via the proof engine.
    async fn verify_execution_proof(
        &self,
        proof: &SignedExecutionProof,
    ) -> Result<ProofStatus, ProofEngineError>;

    /// Buffer a new payload request for proof association.
    async fn new_payload<E: EthSpec>(
        &self,
        header: &NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatusV1, ProofEngineError>;

    /// Notify the proof engine of a forkchoice update.
    async fn forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdatedResponse, ProofEngineError>;

    /// Request proof generation from the proof engine.
    ///
    /// Sends the `NewPayloadRequest` as SSZ to `POST /v1/execution_proof_requests`.
    /// Returns the `new_payload_request_root` identifying this request.
    async fn request_proofs<E: EthSpec>(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
        attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError>;
}

// ─── HttpProofEngine ─────────────────────────────────────────────────────────

/// HTTP implementation of the ProofEngine trait with internal proof storage.
///
/// This implementation:
/// - Stores ALL unfinalized proofs indexed by new_payload_request_root (unbounded)
/// - Delegates HTTP transport to [`ProofNodeClient`]
/// - Prunes proofs when finalization events occur
pub struct HttpProofEngine {
    /// Low-level HTTP client for proof engine REST+SSZ+SSE API.
    proof_node: ProofNodeClient,
    /// The internal state storing execution proofs in a tree structure and buffer.
    state: RwLock<State>,
    /// Buffered proofs for request roots not yet seen.
    buffered_proofs: RwLock<HashMap<Hash256, Vec<SignedExecutionProof>>>,
}

impl HttpProofEngine {
    /// Create a new HTTP proof engine with internal proof storage.
    pub fn new(url: SensitiveUrl, timeout: Option<Duration>) -> Self {
        Self {
            proof_node: ProofNodeClient::new(url, timeout),
            state: RwLock::new(State::new()),
            buffered_proofs: RwLock::new(HashMap::new()),
        }
    }

    /// Subscribe to SSE proof events from the proof engine.
    ///
    /// Delegates to [`ProofNodeClient::subscribe_proof_events`].
    pub fn subscribe_proof_events(
        &self,
        filter_root: Option<Hash256>,
    ) -> Pin<Box<dyn Stream<Item = Result<ProofEvent, ProofEngineError>> + Send + '_>> {
        self.proof_node.subscribe_proof_events(filter_root)
    }

    /// Download a completed execution proof by proof type.
    ///
    /// Delegates to [`ProofNodeClient::get_proof`].
    pub async fn get_proof(
        &self,
        new_payload_request_root: Hash256,
        proof_type: u8,
    ) -> Result<Bytes, ProofEngineError> {
        self.proof_node
            .get_proof(new_payload_request_root, proof_type)
            .await
    }

    /// Snapshot the current state into a persisted form for serialization.
    pub fn to_persisted(&self) -> PersistedProofEngineState {
        let state = self.state.read();
        PersistedProofEngineState::from_state(&state)
    }

    /// Restore in-memory state from a previously persisted snapshot.
    pub fn restore_from_persisted(&self, persisted: PersistedProofEngineState) {
        let restored = persisted.to_state();
        *self.state.write() = restored;
    }
}

#[async_trait::async_trait]
impl ProofEngine for HttpProofEngine {
    fn get_proofs_by_root(&self, root: &Hash256) -> Vec<SignedExecutionProof> {
        self.state
            .read()
            .get_proofs(root)
            .map(<[SignedExecutionProof]>::to_vec)
            .unwrap_or_default()
    }

    fn missing_proofs(&self) -> Vec<MissingProofInfo> {
        self.state.read().missing_proofs()
    }

    async fn verify_execution_proof(
        &self,
        proof: &SignedExecutionProof,
    ) -> Result<ProofStatus, ProofEngineError> {
        if !self
            .state
            .read()
            .contains_request_root(&proof.request_root())
        {
            tracing::info!(target: "execution_layer", "Received proof for unknown request root {}, buffering", proof.request_root());
            self.buffered_proofs
                .write()
                .entry(proof.request_root())
                .or_default()
                .push(proof.clone());
            return Ok(ProofStatus::Syncing);
        }

        let status = self
            .proof_node
            .verify_proof(
                proof.request_root(),
                proof.proof_type(),
                &proof.message.proof_data,
            )
            .await?;

        if status.is_valid() {
            return Ok(self.state.write().insert_proof(proof.clone())?);
        }

        Ok(status)
    }

    async fn new_payload<E: EthSpec>(
        &self,
        request: &NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatusV1, ProofEngineError> {
        let request: RequestMetadata = request.into();
        let buffered_proofs = self
            .buffered_proofs
            .write()
            .remove(&request.request_root)
            .unwrap_or_default();
        self.state.write().buffer_request(request);

        let mut status = PayloadStatusV1Status::Syncing;
        for proof in buffered_proofs {
            let proof_status = self.verify_execution_proof(&proof).await?;
            if proof_status.is_valid() {
                status = PayloadStatusV1Status::Valid;
            }
        }

        Ok(PayloadStatusV1 {
            status,
            latest_valid_hash: None,
            validation_error: None,
        })
    }

    async fn forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdatedResponse, ProofEngineError> {
        tracing::info!(target: "execution_layer", "Received forkchoice update: head {}, safe {}, finalized {}", forkchoice_state.head_block_hash, forkchoice_state.safe_block_hash, forkchoice_state.finalized_block_hash);
        Ok(self.state.write().forkchoice_updated(forkchoice_state)?)
    }

    async fn request_proofs<E: EthSpec>(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
        proof_attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError> {
        match new_payload_request {
            NewPayloadRequest::Bellatrix(_) => {
                Err(ProofEngineError::ForkNotSupported("Bellatrix".to_string()))
            }
            NewPayloadRequest::Capella(_) => {
                Err(ProofEngineError::ForkNotSupported("Capella".to_string()))
            }
            NewPayloadRequest::Deneb(_) => {
                Err(ProofEngineError::ForkNotSupported("Deneb".to_string()))
            }
            NewPayloadRequest::Electra(_) => {
                Err(ProofEngineError::ForkNotSupported("Electra".to_string()))
            }
            NewPayloadRequest::Fulu(new_payload_request_fulu) => {
                self.proof_node
                    .request_proofs(new_payload_request_fulu, proof_attributes)
                    .await
            }
            NewPayloadRequest::Gloas(_) => {
                Err(ProofEngineError::ForkNotSupported("Gloas".to_string()))
            }
        }
    }
}

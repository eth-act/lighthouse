//! HTTP proof engine implementation for EIP-8025.
//!
//! Provides an HTTP implementation with an internal proof cache.
//! HTTP transport is delegated to a [`ProofNodeClient`] implementation.

use super::chain_config::{ChainConfig, ChainConfigSchedule};
use super::errors::ProofEngineError;
use super::metrics;
use super::persisted_state::PersistedProofEngineState;
use super::proof_node_client::{HttpProofNodeClient, ProofNodeClient};
use super::types::{ProofEvent, ProofRequestBody, ProofVerificationBody};
use crate::{
    ForkchoiceState, ForkchoiceUpdatedResponse, MissingProofInfo, NewPayloadRequest,
    PayloadStatusV1, PayloadStatusV1Status,
    eip8025::state::{RequestMetadata, State},
};
use bytes::Bytes;
use futures::stream::Stream;
use parking_lot::RwLock;
use sensitive_url::SensitiveUrl;
use ssz::Encode;
use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

use types::execution::eip8025::{ProofAttributes, ProofStatus, SignedExecutionProof};
use types::{ChainSpec, EthSpec, Hash256};

// ─── HttpProofEngine ─────────────────────────────────────────────────────────

/// Proof engine with internal proof storage.
///
/// - Stores ALL unfinalized proofs indexed by new_payload_request_root (unbounded)
/// - Delegates transport to a [`ProofNodeClient`] implementation
/// - Prunes proofs when finalization events occur
pub struct HttpProofEngine {
    /// Transport client for proof engine REST+SSZ+SSE API.
    proof_node: Box<dyn ProofNodeClient>,
    /// The internal state storing execution proofs in a tree structure and buffer.
    state: RwLock<State>,
    /// Buffered proofs for request roots not yet seen.
    buffered_proofs: RwLock<HashMap<Hash256, Vec<SignedExecutionProof>>>,
    /// Chain config schedule used to resolve chain config for each request and
    /// verification by block timestamp.
    chain_config_schedule: ChainConfigSchedule,
}

impl HttpProofEngine {
    /// Create a new proof engine backed by the HTTP proof node client.
    pub fn new(
        url: SensitiveUrl,
        timeout: Option<Duration>,
        spec: &ChainSpec,
        genesis_time: u64,
        slots_per_epoch: u64,
    ) -> Self {
        Self::with_proof_node(
            HttpProofNodeClient::new(url, timeout),
            spec,
            genesis_time,
            slots_per_epoch,
        )
    }

    /// Create a proof engine backed by a custom [`ProofNodeClient`] implementation.
    ///
    /// Useful for injecting a [`MockProofNodeClient`] in tests.
    ///
    /// [`MockProofNodeClient`]: super::super::test_utils::MockProofNodeClient
    pub fn with_proof_node(
        proof_node: impl ProofNodeClient + 'static,
        spec: &ChainSpec,
        genesis_time: u64,
        slots_per_epoch: u64,
    ) -> Self {
        Self {
            proof_node: Box::new(proof_node),
            state: RwLock::new(State::new()),
            buffered_proofs: RwLock::new(HashMap::new()),
            chain_config_schedule: ChainConfigSchedule::new(spec, genesis_time, slots_per_epoch),
        }
    }

    /// Resolves the chain config activated at a block `timestamp`.
    ///
    /// Returns `ProofEngineError::NoActiveFork` if no active fork at the `timestamp`.
    fn resolve_chain_config(&self, timestamp: u64) -> Result<ChainConfig, ProofEngineError> {
        self.chain_config_schedule
            .resolve(timestamp)
            .ok_or(ProofEngineError::NoActiveFork(timestamp))
    }

    /// Subscribe to method-invocation events emitted by a mock proof node client.
    ///
    /// Returns `None` for production (HTTP) clients.
    pub fn subscribe_client_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<crate::test_utils::MockClientEvent>> {
        self.proof_node.subscribe_client_events()
    }

    /// Subscribe to SSE proof events from the proof engine.
    pub fn subscribe_proof_events(
        &self,
        filter_root: Option<Hash256>,
    ) -> Pin<Box<dyn Stream<Item = Result<ProofEvent, ProofEngineError>> + Send + '_>> {
        self.proof_node.subscribe_proof_events(filter_root)
    }

    /// Download a completed execution proof by proof type.
    pub async fn get_proof(
        &self,
        new_payload_request_root: Hash256,
        proof_type: u8,
    ) -> Result<Bytes, ProofEngineError> {
        self.proof_node
            .get_proof(new_payload_request_root, proof_type)
            .await
    }

    /// Get all proofs for a given new_payload_request_root.
    pub fn get_proofs_by_root(&self, root: &Hash256) -> Vec<SignedExecutionProof> {
        self.state
            .read()
            .get_proofs(root)
            .map(<[SignedExecutionProof]>::to_vec)
            .unwrap_or_default()
    }

    /// Return all buffer entries that do not yet have sufficient proofs for promotion.
    ///
    /// `MissingProofInfo.root` is populated with the new-payload request root.
    /// The beacon chain layer replaces it with the beacon block root before the
    /// sync manager issues `ExecutionProofsByRoot` RPC requests.
    pub fn missing_proofs(&self) -> Vec<MissingProofInfo> {
        self.state.read().missing_proofs()
    }

    /// Verify an individual execution proof via the proof engine.
    pub async fn verify_execution_proof(
        &self,
        proof: &SignedExecutionProof,
    ) -> Result<ProofStatus, ProofEngineError> {
        let proof_type_str = crate::eip8025::ProofType::from_u8(proof.proof_type())
            .map(|pt| pt.as_str())
            .unwrap_or("unknown");

        let Some(block_timestamp) = self.state.read().get_timestamp(&proof.request_root()) else {
            tracing::info!(target: "execution_layer", "Received proof for unknown request root {}, buffering", proof.request_root());
            let mut buf = self.buffered_proofs.write();
            buf.entry(proof.request_root())
                .or_default()
                .push(proof.clone());
            let total: usize = buf.values().map(|v| v.len()).sum();
            metrics::set_gauge(&metrics::PROOF_ENGINE_BUFFERED_PROOF_COUNT, total as i64);
            metrics::inc_counter_vec(
                &metrics::PROOF_ENGINE_VERIFICATIONS_TOTAL,
                &[proof_type_str, metrics::BUFFERED],
            );
            return Ok(ProofStatus::Syncing);
        };

        let chain_config = self.resolve_chain_config(block_timestamp)?;
        let timer = metrics::start_timer_vec(
            &metrics::PROOF_ENGINE_VERIFICATION_DURATION,
            &[proof_type_str],
        );
        let body = ProofVerificationBody {
            new_payload_request_root: proof.request_root(),
            chain_config,
            proof_type: proof.proof_type(),
            proof: proof.proof_data(),
        };
        let verify_result = self.proof_node.verify_proof(body.as_ssz_bytes()).await;
        drop(timer);

        let status = verify_result.inspect_err(|_e| {
            metrics::inc_counter_vec(
                &metrics::PROOF_ENGINE_VERIFICATIONS_TOTAL,
                &[proof_type_str, metrics::ERROR],
            );
        })?;

        if status.is_valid() {
            metrics::inc_counter_vec(
                &metrics::PROOF_ENGINE_VERIFICATIONS_TOTAL,
                &[proof_type_str, metrics::VALID],
            );
            return Ok(self.state.write().insert_proof(proof.clone())?);
        }

        metrics::inc_counter_vec(
            &metrics::PROOF_ENGINE_VERIFICATIONS_TOTAL,
            &[proof_type_str, metrics::INVALID],
        );
        Ok(status)
    }

    /// Buffer a new payload request for proof association.
    pub async fn new_payload<E: EthSpec>(
        &self,
        request: &NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatusV1, ProofEngineError> {
        metrics::inc_counter(&metrics::PROOF_ENGINE_NEW_PAYLOADS_TOTAL);
        let request: RequestMetadata = request.into();
        let buffered_proofs = self
            .buffered_proofs
            .write()
            .remove(&request.request_root)
            .unwrap_or_default();
        {
            let mut state = self.state.write();
            state.buffer_request(request);
            metrics::set_gauge(
                &metrics::PROOF_ENGINE_BUFFER_SIZE,
                state.buffer_len() as i64,
            );
        } // guard dropped before the await loop below

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

    /// Notify the proof engine of a forkchoice update.
    pub fn forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdatedResponse, ProofEngineError> {
        tracing::info!(target: "execution_layer", "Received forkchoice update: head {}, safe {}, finalized {}", forkchoice_state.head_block_hash, forkchoice_state.safe_block_hash, forkchoice_state.finalized_block_hash);
        let result = self.state.write().forkchoice_updated(forkchoice_state);
        match &result {
            Ok(response) => {
                let status = if response.payload_status.status == PayloadStatusV1Status::Syncing {
                    "syncing"
                } else {
                    metrics::SUCCESS
                };
                metrics::inc_counter_vec(
                    &metrics::PROOF_ENGINE_FORKCHOICE_UPDATES_TOTAL,
                    &[status],
                );
                let state = self.state.read();
                metrics::set_gauge(&metrics::PROOF_ENGINE_TREE_SIZE, state.tree_len() as i64);
                metrics::set_gauge(
                    &metrics::PROOF_ENGINE_MISSING_PROOF_COUNT,
                    state.missing_proofs().len() as i64,
                );
            }
            Err(_) => {
                metrics::inc_counter_vec(
                    &metrics::PROOF_ENGINE_FORKCHOICE_UPDATES_TOTAL,
                    &[metrics::ERROR],
                );
            }
        }
        Ok(result?)
    }

    /// Request proof generation from the proof engine.
    ///
    /// SSZ-encodes `ProofRequestBody` then sends it to `POST /v1/execution_proof_requests`.
    /// Returns the `new_payload_request_root` identifying this request.
    pub async fn request_proofs<E: EthSpec>(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
        proof_attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError> {
        for &proof_type in &proof_attributes.proof_types {
            if let Ok(pt) = crate::eip8025::ProofType::from_u8(proof_type) {
                metrics::inc_counter_vec(&metrics::PROOF_ENGINE_REQUESTS_TOTAL, &[pt.as_str()]);
            }
        }
        let chain_config =
            self.resolve_chain_config(new_payload_request.execution_payload_ref().timestamp())?;
        let body = ProofRequestBody {
            new_payload_request,
            chain_config,
            proof_types: proof_attributes.proof_types,
        };
        self.proof_node.request_proofs(body.as_ssz_bytes()).await
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

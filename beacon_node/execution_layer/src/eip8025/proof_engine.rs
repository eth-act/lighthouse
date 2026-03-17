//! ProofEngine trait and HTTP implementation for EIP-8025.
//!
//! This module defines the interface for interacting with proof engines
//! and provides an HTTP JSON-RPC implementation with an internal proof cache.

use super::persisted_state::PersistedProofEngineState;
use super::{errors::ProofEngineError, json_structures::*};
use crate::{
    ForkchoiceState, ForkchoiceUpdatedResponse, MissingProofInfo, NewPayloadRequest,
    NewPayloadRequestFulu, PayloadStatusV1, PayloadStatusV1Status,
    eip8025::state::{RequestMetadata, State},
    json_structures::{JsonExecutionPayload, JsonRequestBody, JsonResponseBody},
};
use parking_lot::RwLock;
use reqwest::Client;
use reqwest::header::CONTENT_TYPE;
use sensitive_url::SensitiveUrl;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;

use types::execution::eip8025::{ProofAttributes, ProofGenId, ProofStatus, SignedExecutionProof};
use types::{EthSpec, Hash256};

/// Static ID for JSON-RPC requests.
const STATIC_ID: u32 = 1;

/// JSON-RPC version string.
pub const JSONRPC_VERSION: &str = "2.0";

/// This error is returned during a `chainId` call by Geth.
pub const EIP155_ERROR_STR: &str = "chain not synced beyond EIP-155 replay-protection fork block";

/// Engine API method for verifying execution proofs.
pub const ENGINE_VERIFY_EXECUTION_PROOF_V1: &str = "engine_verifyExecutionProofV1";

/// Engine API method for verifying new payload request headers.
///
/// This is currently unused but defined for completeness. We may use it in the future
pub const ENGINE_VERIFY_NEW_PAYLOAD_REQUEST_HEADER_V1: &str =
    "engine_verifyNewPayloadRequestHeaderV1";

/// Engine API method for requesting proof generation.
pub const ENGINE_REQUEST_PROOFS_V1: &str = "engine_requestProofsV1";

/// Default timeout for proof engine requests (1 second per spec).
pub const PROOF_ENGINE_TIMEOUT: Duration = Duration::from_secs(1);

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

    /// Verify an individual execution proof via RPC.
    ///
    /// Maps to `engine_verifyExecutionProofV1`.
    async fn verify_execution_proof(
        &self,
        proof: &SignedExecutionProof,
    ) -> Result<ProofStatus, ProofEngineError>;

    /// Verify that sufficient proofs exist for a new payload request via RPC.
    ///
    /// Maps to `engine_verifyNewPayloadRequestHeaderV*`.
    async fn new_payload<E: EthSpec>(
        &self,
        header: &NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatusV1, ProofEngineError>;

    /// Notify the proof engine of a forkchoice update.
    async fn forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdatedResponse, ProofEngineError>;

    /// Request asynchronous proof generation via RPC.
    ///
    /// Maps to `engine_requestProofsV1`.
    /// Returns a ProofGenId to track the generation request.
    /// Generated proofs are delivered asynchronously via the beacon API endpoint
    /// POST /eth/v1/prover/execution_proofs.
    async fn request_proofs<E: EthSpec>(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
        attributes: ProofAttributes,
    ) -> Result<ProofGenId, ProofEngineError>;
}

/// HTTP JSON-RPC implementation of the ProofEngine trait with internal proof storage.
///
/// This implementation:
/// - Stores ALL unfinalized proofs indexed by new_payload_request_root (unbounded)
/// - Calls out to the execution engine RPC for proof verification
/// - Prunes proofs when finalization events occur
pub struct HttpProofEngine {
    /// HTTP client for making requests.
    client: Client,
    /// URL of the proof engine endpoint.
    url: SensitiveUrl,
    /// The internal state storing execution proofs in a tree structure and buffer.
    state: RwLock<State>,
    /// Buffered proofs for request roots not yet seen.
    buffered_proofs: RwLock<HashMap<Hash256, Vec<SignedExecutionProof>>>,
}

impl HttpProofEngine {
    /// Create a new HTTP proof engine client with internal proof storage.
    pub fn new(url: SensitiveUrl, timeout: Option<Duration>) -> Self {
        let client = Client::builder()
            .timeout(timeout.unwrap_or(PROOF_ENGINE_TIMEOUT))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            url,
            state: RwLock::new(State::new()),
            buffered_proofs: RwLock::new(HashMap::new()),
        }
    }

    /// Make a generic JSON-RPC request to the proof engine.
    pub async fn rpc_request<D: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout: Duration,
    ) -> Result<D, ProofEngineError> {
        let body = JsonRequestBody {
            jsonrpc: JSONRPC_VERSION,
            method,
            params,
            id: json!(STATIC_ID),
        };

        let request = self
            .client
            .post(self.url.expose_full().clone())
            .timeout(timeout)
            .header(CONTENT_TYPE, "application/json")
            .json(&body);

        // TODO: do we want to support authentication?
        // Generate and add a jwt token to the header if auth is defined.
        // if let Some(auth) = &self.auth {
        //     request = request.bearer_auth(auth.generate_token()?);
        // };

        let body: JsonResponseBody = request.send().await?.error_for_status()?.json().await?;

        match (body.result, body.error) {
            (result, None) => Ok(serde_json::from_value(result)?),
            (_, Some(error)) => Err(ProofEngineError::JsonRpcError {
                code: error.code,
                message: error.message,
            }),
        }
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

        let json_proof: JsonExecutionProofV1 = proof.message.clone().into();
        let params = json!([json_proof]);

        let result = self
            .rpc_request(
                ENGINE_VERIFY_EXECUTION_PROOF_V1,
                params,
                PROOF_ENGINE_TIMEOUT,
            )
            .await?;

        let status: JsonProofStatusV1 = serde_json::from_value(result)?;
        let status: ProofStatus = status.into();
        if status.is_valid() {
            // Insert the valid proof into state.
            return Ok(self.state.write().insert_proof(proof.clone())?);
        }

        Ok(status)
    }

    async fn new_payload<E: EthSpec>(
        &self,
        request: &NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatusV1, ProofEngineError> {
        // We buffer the request in state for future proof association and return Syncing.
        // TODO: Currently we don't support proof verification before payload processing to prevent DOS so its not possible that proofs are verified yet. Is this reasonable?
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
    ) -> Result<ProofGenId, ProofEngineError> {
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
                self.request_proofs_v4_fulu(new_payload_request_fulu, proof_attributes)
                    .await
            }
            NewPayloadRequest::Gloas(_) => {
                Err(ProofEngineError::ForkNotSupported("Gloas".to_string()))
            }
        }
    }
}

impl HttpProofEngine {
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

    pub async fn request_proofs_v4_fulu<E: EthSpec>(
        &self,
        new_payload_request_fulu: NewPayloadRequestFulu<'_, E>,
        proof_attributes: ProofAttributes,
    ) -> Result<ProofGenId, ProofEngineError> {
        let params = json!([
            JsonExecutionPayload::Fulu(
                new_payload_request_fulu
                    .execution_payload
                    .clone()
                    .try_into()?
            ),
            new_payload_request_fulu.versioned_hashes,
            new_payload_request_fulu.parent_beacon_block_root,
            new_payload_request_fulu
                .execution_requests
                .get_execution_requests_list(),
            proof_attributes
        ]);

        let response: TransparentJsonProofGenId = self
            .rpc_request(ENGINE_REQUEST_PROOFS_V1, params, PROOF_ENGINE_TIMEOUT)
            .await?;

        Ok(response.into())
    }
}

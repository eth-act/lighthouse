//! Mock proof engine server for testing EIP-8025 execution proofs.
//!
//! Provides an HTTP JSON-RPC server that simulates an external proof engine backend
//! for integration testing. Uses mockito to mock the HTTP endpoints.

// TODO: Move this module into the execution_layer crate

use super::ValidatorClientHttpClient;
use eth2::lighthouse_vc::types::SignExecutionProofRequest;
use execution_layer::NewPayloadRequestFulu;
use execution_layer::json_structures::JsonExecutionPayloadFulu;
use mockito::{Matcher, Mock, Server, ServerGuard};
use parking_lot::{Mutex, RwLock};
use sensitive_url::SensitiveUrl;
use serde_json::json;
use ssz_types::VariableList;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tree_hash::TreeHash;
use types::execution::eip8025::{
    ExecutionProof, ProofAttributes, ProofGenId, ProofType, PublicInput,
};
use types::{EthSpec, ExecutionPayloadFulu, ExecutionRequests, Hash256, VersionedHash};

/// Configuration for a mock proof engine.
#[derive(Clone)]
pub struct MockProofEngineConfig {
    pub server_config: ProofEngineServerConfig,
    pub callback_delay_ms: u64,
    pub callback_url: Arc<RwLock<Option<Arc<ValidatorClientHttpClient>>>>,
}

impl Default for MockProofEngineConfig {
    fn default() -> Self {
        Self {
            server_config: ProofEngineServerConfig::default(),
            callback_delay_ms: 200,
            callback_url: Arc::new(RwLock::new(None)),
        }
    }
}

/// Configuration for proof engine server.
#[derive(Clone)]
pub struct ProofEngineServerConfig {
    pub listen_port: u16,
    pub listen_addr: std::net::Ipv4Addr,
}

impl Default for ProofEngineServerConfig {
    fn default() -> Self {
        Self {
            listen_port: 0,
            listen_addr: std::net::Ipv4Addr::LOCALHOST,
        }
    }
}

/// Record of a proof request received by the mock server.
#[derive(Clone, Debug)]
pub struct ProofRequestRecord {
    pub proof_gen_id: ProofGenId,
    pub new_payload_request_root: Hash256,
    pub proof_types: Vec<ProofType>,
    pub timestamp: std::time::Instant,
}

/// Mock proof engine HTTP server.
///
/// Implements the JSON-RPC endpoints for:
/// - engine_requestProofsV1: Accept proof requests and return ProofGenId
/// - engine_verifyExecutionProofV1: Verify proof validity
pub struct MockProofEngineServer<E: EthSpec> {
    server: ServerGuard,
    config: MockProofEngineConfig,
    proof_requests: Arc<Mutex<Vec<ProofRequestRecord>>>,
    executor: TaskExecutor,
    _mocks: Vec<Mock>, // Keep mocks alive
    _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec> MockProofEngineServer<E> {
    /// Create a new mock proof engine server.
    pub async fn new(config: MockProofEngineConfig, executor: TaskExecutor) -> Self {
        // Use Server::new_async() to avoid starting a runtime within a runtime
        let server = Server::new_async().await;
        let proof_requests = Arc::new(Mutex::new(Vec::new()));

        let mut mock_server = Self {
            server,
            config,
            proof_requests,
            executor,
            _mocks: Vec::new(),
            _phantom: std::marker::PhantomData,
        };

        mock_server.setup_endpoints();
        mock_server
    }

    pub fn set_validator_callback(&mut self, client: Arc<ValidatorClientHttpClient>) {
        *self.config.callback_url.write() = Some(client);
    }

    /// Setup all HTTP endpoints.
    fn setup_endpoints(&mut self) {
        self.setup_request_proofs_endpoint();
        self.setup_verify_proof_endpoint();
    }

    /// Setup the engine_requestProofsV1 endpoint.
    fn setup_request_proofs_endpoint(&mut self) {
        let proof_requests = self.proof_requests.clone();
        let callback_delay = self.config.callback_delay_ms;
        let validator_client_ref = self.config.callback_url.clone();
        let task_executor = self.executor.clone();

        let mock = self
            .server
            .mock("POST", "/")
            .match_body(Matcher::Regex(
                r#".*"method"\s*:\s*"engine_requestProofsV1".*"#.to_string(),
            ))
            .with_status(200)
            .with_body_from_request(move |request| {
                // Helper function to return JSON-RPC error response
                let error_response = |error_msg: &str| -> Vec<u8> {
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32602,
                            "message": format!("Invalid params: {}", error_msg)
                        },
                        "id": 1
                    }))
                    .unwrap_or_else(|_| b"{\"error\":\"internal error\"}".to_vec())
                };

                // Parse JSON-RPC request with error handling
                let body_bytes = match request.body() {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return error_response(&format!("failed to read request body: {}", e));
                    }
                };

                let body: serde_json::Value = match serde_json::from_slice(body_bytes) {
                    Ok(v) => v,
                    Err(e) => return error_response(&format!("invalid JSON: {}", e)),
                };

                // Parse params array
                let Some(params) = body["params"].as_array() else {
                    return error_response("params is not an array");
                };

                if params.len() < 5 {
                    return error_response(&format!("expected 5 params, got {}", params.len()));
                }

                // Parse execution payload
                let execution_payload_json: JsonExecutionPayloadFulu<E> =
                    match serde_json::from_value(params[0].clone()) {
                        Ok(v) => v,
                        Err(e) => {
                            return error_response(&format!("invalid execution payload: {}", e));
                        }
                    };

                let execution_payload: ExecutionPayloadFulu<E> = match execution_payload_json
                    .try_into()
                {
                    Ok(v) => v,
                    Err(e) => return error_response(&format!("failed to convert payload: {}", e)),
                };

                // Parse versioned hashes
                let versioned_hashes: VariableList<VersionedHash, E::MaxBlobCommitmentsPerBlock> =
                    match serde_json::from_value(params[1].clone()) {
                        Ok(v) => v,
                        Err(e) => {
                            return error_response(&format!("invalid versioned hashes: {}", e));
                        }
                    };

                // Parse parent beacon block root
                let parent_beacon_block_root: Hash256 =
                    match serde_json::from_value(params[2].clone()) {
                        Ok(v) => v,
                        Err(e) => return error_response(&format!("invalid parent root: {}", e)),
                    };

                // Deserialize execution requests from JSON with fork context
                let execution_requests_bytes = match serde_json::from_value(params[3].clone()) {
                    Ok(v) => v,
                    Err(e) => {
                        return error_response(&format!("invalid execution requests: {}", e));
                    }
                };
                let execution_requests = match ExecutionRequests::<E>::from_execution_requests_list(
                    execution_requests_bytes,
                ) {
                    Ok(r) => r,
                    Err(e) => return error_response(&e),
                };

                // Parse proof attributes
                let proof_attributes: ProofAttributes =
                    match serde_json::from_value(params[4].clone()) {
                        Ok(v) => v,
                        Err(e) => {
                            return error_response(&format!("invalid proof attributes: {}", e));
                        }
                    };

                // Compute request root with properly decoded execution_requests
                let new_payload_request = NewPayloadRequestFulu {
                    execution_payload: &execution_payload,
                    versioned_hashes,
                    parent_beacon_block_root,
                    execution_requests: &execution_requests,
                };
                let request_root = new_payload_request.tree_hash_root();

                // Trigger callback if validator client is configured
                if let Some(validator) = validator_client_ref.read().as_ref() {
                    tracing::info!(
                        target: "simulator",
                        ?request_root,
                        proof_types = ?proof_attributes.proof_types,
                        "Triggering proof callback"
                    );
                    let _ = Self::proof_callback(
                        validator.clone(),
                        callback_delay,
                        task_executor.clone(),
                        request_root,
                        proof_attributes.proof_types.clone(),
                    );
                }

                // Generate deterministic ProofGenId from request root
                let mut proof_gen_id = [0u8; 8];
                proof_gen_id.copy_from_slice(&request_root.0[0..8]);

                // Store request
                proof_requests.lock().push(ProofRequestRecord {
                    proof_gen_id,
                    new_payload_request_root: request_root,
                    proof_types: proof_attributes.proof_types.clone(),
                    timestamp: std::time::Instant::now(),
                });

                tracing::info!(
                    target: "simulator",
                    proof_gen_id = hex::encode(proof_gen_id),
                    ?request_root,
                    num_proof_types = proof_attributes.proof_types.len(),
                    "Proof request recorded"
                );

                // Return success response
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "result": format!("0x{}", hex::encode(proof_gen_id)),
                    "id": 1
                }))
                .unwrap_or_else(|_| b"{\"error\":\"internal error\"}".to_vec())
            })
            .create();

        self._mocks.push(mock);
    }

    /// Setup the engine_verifyExecutionProofV1 endpoint.
    fn setup_verify_proof_endpoint(&mut self) {
        let mock = self.server
            .mock("POST", "/")
            .match_body(Matcher::Regex(
                r#".*"method"\s*:\s*"engine_verifyExecutionProofV1".*"#.to_string(),
            ))
            .with_status(200)
            .with_body_from_request(move |request| {
                // Validate the request has a body
                let _body_bytes = match request.body() {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return serde_json::to_vec(&json!({
                            "jsonrpc": "2.0",
                            "error": {"code": -32602, "message": format!("failed to read request body: {}", e)},
                            "id": 1
                        }))
                        .unwrap_or_else(|_| b"{\"error\":\"internal error\"}".to_vec());
                    }
                };

                // For the verify endpoint, we just return VALID for all properly formatted requests
                serde_json::to_vec(&json!({
                    "jsonrpc": "2.0",
                    "result": {"status": "VALID"},
                    "id": 1
                }))
                .unwrap_or_else(|_| b"{\"error\":\"internal error\"}".to_vec())
            })
            .create();

        self._mocks.push(mock);
    }

    /// Get the URL of the mock server.
    pub fn url(&self) -> SensitiveUrl {
        SensitiveUrl::parse(&self.server.url()).unwrap()
    }

    /// Get all proof requests received by the server.
    pub fn get_proof_requests(&self) -> Vec<ProofRequestRecord> {
        self.proof_requests.lock().clone()
    }

    /// Manually trigger a callback to the validator client with a generated proof.
    ///
    /// This simulates the proof engine calling back to the validator client
    /// after generating a proof asynchronously.
    pub fn proof_callback(
        client: Arc<ValidatorClientHttpClient>,
        callback_delay: u64,
        task_executor: TaskExecutor,
        new_payload_request_root: Hash256,
        proof_types: Vec<ProofType>,
    ) -> Result<(), String> {
        task_executor.spawn(
            async move {
                tracing::info!(
                    target: "simulator",
                    delay_ms = callback_delay,
                    "Proof callback task started, sleeping"
                );

                tokio::time::sleep(Duration::from_millis(callback_delay)).await;

                tracing::info!(target: "simulator", "Fetching validators for callback");

                let validators = match client.get_lighthouse_validators().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(target: "simulator", error = ?e, "Failed to get validators");
                        return;
                    }
                };

                let pubkey = match validators.data.first() {
                    Some(v) => v.voting_pubkey,
                    None => {
                        tracing::error!(target: "simulator", "No validators found");
                        return;
                    }
                };

                tracing::info!(
                    target: "simulator",
                    ?pubkey,
                    num_proof_types = proof_types.len(),
                    "Generating and sending proofs"
                );

                let execution_proofs =
                    Self::generate_dummy_proofs(new_payload_request_root, proof_types);

                for execution_proof in execution_proofs {
                    tracing::info!(
                        target: "simulator",
                        proof_type = ?execution_proof.proof_type,
                        "Sending proof to validator client"
                    );

                    let request_body = SignExecutionProofRequest {
                        execution_proof,
                        epoch: None,
                    };

                    match client.post_execution_proof(&pubkey, request_body).await {
                        Ok(_) => {
                            tracing::info!(target: "simulator", "Proof sent successfully");
                        }
                        Err(e) => {
                            tracing::error!(target: "simulator", error = ?e, "Failed to send proof");
                        }
                    }
                }
            },
            "proof_callback",
        );

        Ok(())
    }

    /// Generate a dummy execution proof for testing.
    fn generate_dummy_proofs(root: Hash256, proof_types: Vec<ProofType>) -> Vec<ExecutionProof> {
        let mut proofs = vec![];

        for proof_type in proof_types {
            let mut proof_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
            proof_bytes.extend_from_slice(&root.0[0..16]);

            let proof = ExecutionProof {
                proof_data: VariableList::new(proof_bytes).unwrap(),
                proof_type,
                public_input: PublicInput {
                    new_payload_request_root: root,
                },
            };

            proofs.push(proof);
        }

        proofs
    }
}

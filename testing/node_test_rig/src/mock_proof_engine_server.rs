//! Mock proof engine server for testing EIP-8025 execution proofs.
//!
//! Provides an HTTP REST server that simulates a zkboost-compatible proof engine
//! backend for integration testing. Uses axum with SSE support.
//!
//! Endpoints:
//! - POST /v1/execution_proof_requests — Accept SSZ proof request, return root
//! - GET  /v1/execution_proof_requests — SSE stream of proof events
//! - GET  /v1/execution_proofs/:root/:proof_type — Download proof bytes
//! - POST /v1/execution_proof_verifications — Verify proof (always VALID)

use axum::{
    Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json,
    },
    routing::{get, post},
};
use execution_layer::NewPayloadRequestFulu;
use parking_lot::{Mutex, RwLock};
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use ssz_types::VariableList;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tree_hash::TreeHash;
use types::execution::eip8025::ProofType;
use types::{EthSpec, ExecutionPayloadFulu, ExecutionRequests, Hash256, VersionedHash};

/// Configuration for a mock proof engine.
#[derive(Clone)]
pub struct MockProofEngineConfig {
    pub server_config: ProofEngineServerConfig,
    pub callback_delay_ms: u64,
}

impl Default for MockProofEngineConfig {
    fn default() -> Self {
        Self {
            server_config: ProofEngineServerConfig::default(),
            callback_delay_ms: 200,
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
    pub new_payload_request_root: Hash256,
    pub proof_types: Vec<ProofType>,
    pub timestamp: std::time::Instant,
}

// ─── SSE Event Payload ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct ProofCompleteEvent {
    new_payload_request_root: Hash256,
    proof_type: ProofType,
}

// ─── Query Parameters ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ProofRequestQuery {
    proof_types: String,
}

#[derive(Deserialize)]
struct ProofEventQuery {
    new_payload_request_root: Option<Hash256>,
}

#[derive(Deserialize)]
struct ProofVerificationQuery {
    #[allow(dead_code)]
    new_payload_request_root: Hash256,
    #[allow(dead_code)]
    proof_type: ProofType,
}

// ─── Shared State ────────────────────────────────────────────────────────────

struct AppState {
    proof_requests: Mutex<Vec<ProofRequestRecord>>,
    /// Generated proof data: (root, proof_type) -> proof bytes
    proof_store: RwLock<HashMap<(Hash256, ProofType), Vec<u8>>>,
    /// Broadcast channel for SSE events
    event_tx: broadcast::Sender<(String, String)>,
    callback_delay_ms: u64,
}

// ─── Response Types ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ProofRequestResponse {
    new_payload_request_root: Hash256,
}

#[derive(Serialize)]
struct ProofVerificationResponse {
    status: &'static str,
}

// ─── Mock Proof Engine Server ────────────────────────────────────────────────

/// Mock proof engine HTTP server using axum.
///
/// Implements the zkboost-compatible REST API endpoints for:
/// - Proof request submission (POST, SSZ body)
/// - Proof event streaming (GET, SSE)
/// - Proof download (GET, binary)
/// - Proof verification (POST, always VALID)
pub struct MockProofEngineServer<E: EthSpec> {
    url: SensitiveUrl,
    state: Arc<AppState>,
    _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec> MockProofEngineServer<E> {
    /// Create a new mock proof engine server.
    pub async fn new(config: MockProofEngineConfig, executor: task_executor::TaskExecutor) -> Self {
        let (event_tx, _) = broadcast::channel(256);

        let state = Arc::new(AppState {
            proof_requests: Mutex::new(Vec::new()),
            proof_store: RwLock::new(HashMap::new()),
            event_tx,
            callback_delay_ms: config.callback_delay_ms,
        });

        let app = Router::new()
            .route(
                "/v1/execution_proof_requests",
                post(handle_request_proofs::<E>).get(handle_sse_events),
            )
            .route(
                "/v1/execution_proofs/{root}/{proof_type}",
                get(handle_get_proof),
            )
            .route(
                "/v1/execution_proof_verifications",
                post(handle_verify_proof),
            )
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind(std::net::SocketAddr::from((
            config.server_config.listen_addr,
            config.server_config.listen_port,
        )))
        .await
        .expect("should bind mock proof engine listener");

        let local_addr = listener.local_addr().expect("should get local addr");
        let url = SensitiveUrl::parse(&format!("http://{}", local_addr)).unwrap();

        executor.spawn(
            async move {
                axum::serve(listener, app)
                    .await
                    .expect("mock proof engine server failed");
            },
            "mock_proof_engine_server",
        );

        Self {
            url,
            state,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get the URL of the mock server.
    pub fn url(&self) -> SensitiveUrl {
        self.url.clone()
    }

    /// Get all proof requests received by the server.
    pub fn get_proof_requests(&self) -> Vec<ProofRequestRecord> {
        self.state.proof_requests.lock().clone()
    }
}

// ─── Handler: POST /v1/execution_proof_requests ──────────────────────────────

async fn handle_request_proofs<E: EthSpec>(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ProofRequestQuery>,
    body: Bytes,
) -> impl IntoResponse {
    // Parse proof types from query
    let proof_types: Vec<ProofType> = query
        .proof_types
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    // Decode SSZ body and compute tree hash root
    let request_root = match decode_and_hash_request::<E>(&body) {
        Ok(root) => root,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
                .into_response();
        }
    };

    // Store the request
    state.proof_requests.lock().push(ProofRequestRecord {
        new_payload_request_root: request_root,
        proof_types: proof_types.clone(),
        timestamp: std::time::Instant::now(),
    });

    tracing::info!(
        target: "simulator",
        ?request_root,
        num_proof_types = proof_types.len(),
        "Proof request recorded"
    );

    // Generate dummy proofs and schedule SSE events after delay
    let delay = state.callback_delay_ms;
    let state_for_task = state.clone();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(delay)).await;

        for proof_type in &proof_types {
            // Generate dummy proof data
            let mut proof_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
            proof_bytes.extend_from_slice(&request_root.0[0..16]);

            // Store the proof for later download
            state_for_task
                .proof_store
                .write()
                .insert((request_root, *proof_type), proof_bytes);

            // Broadcast SSE event
            let event_data = serde_json::to_string(&ProofCompleteEvent {
                new_payload_request_root: request_root,
                proof_type: *proof_type,
            })
            .unwrap();

            let _ = state_for_task
                .event_tx
                .send(("proof_complete".to_string(), event_data));

            tracing::info!(
                target: "simulator",
                ?request_root,
                proof_type,
                "Proof complete event sent via SSE"
            );
        }
    });

    Json(ProofRequestResponse {
        new_payload_request_root: request_root,
    })
    .into_response()
}

// ─── Handler: GET /v1/execution_proof_requests (SSE) ─────────────────────────

async fn handle_sse_events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ProofEventQuery>,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_tx.subscribe();
    let filter_root = query.new_payload_request_root;

    let stream = BroadcastStream::new(rx).filter_map(move |result| {
        match result {
            Ok((event_name, event_data)) => {
                // Apply root filter if specified
                if let Some(filter) = filter_root {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&event_data) {
                        if let Some(root_str) = parsed
                            .get("new_payload_request_root")
                            .and_then(|v| v.as_str())
                        {
                            let filter_str = format!("{filter:#}");
                            if root_str != filter_str {
                                return None;
                            }
                        }
                    }
                }

                Some(Ok(Event::default().event(event_name).data(event_data)))
            }
            Err(_) => None,
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

// ─── Handler: GET /v1/execution_proofs/:root/:proof_type ─────────────────────

async fn handle_get_proof(
    State(state): State<Arc<AppState>>,
    Path((root_str, proof_type_str)): Path<(String, String)>,
) -> impl IntoResponse {
    let root = match root_str.parse::<Hash256>() {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid root").into_response(),
    };

    let proof_type: ProofType = match proof_type_str.parse() {
        Ok(t) => t,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid proof_type").into_response(),
    };

    match state.proof_store.read().get(&(root, proof_type)) {
        Some(proof_bytes) => (StatusCode::OK, proof_bytes.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "proof not found").into_response(),
    }
}

// ─── Handler: POST /v1/execution_proof_verifications ─────────────────────────

async fn handle_verify_proof(
    State(_state): State<Arc<AppState>>,
    Query(_query): Query<ProofVerificationQuery>,
    _body: Bytes,
) -> Json<ProofVerificationResponse> {
    // Always return VALID for testing
    Json(ProofVerificationResponse { status: "VALID" })
}

// ─── SSZ Decoding Helper ─────────────────────────────────────────────────────

/// Decode SSZ-encoded NewPayloadRequest and compute its tree hash root.
fn decode_and_hash_request<E: EthSpec>(body: &[u8]) -> Result<Hash256, String> {
    use ssz::Decode;

    // Decode the SSZ body as a Fulu NewPayloadRequest.
    // This struct mirrors SszNewPayloadRequestFulu from proof_engine.rs.
    #[derive(ssz_derive::Decode)]
    struct SszNewPayloadRequestFulu<E: EthSpec> {
        execution_payload: ExecutionPayloadFulu<E>,
        versioned_hashes: VariableList<VersionedHash, E::MaxBlobCommitmentsPerBlock>,
        parent_beacon_block_root: Hash256,
        execution_requests: ExecutionRequests<E>,
    }

    let decoded = SszNewPayloadRequestFulu::<E>::from_ssz_bytes(body)
        .map_err(|e| format!("SSZ decode error: {e:?}"))?;

    // Compute tree hash root using the same structure as the real NewPayloadRequestFulu
    let request = NewPayloadRequestFulu {
        execution_payload: &decoded.execution_payload,
        versioned_hashes: decoded.versioned_hashes,
        parent_beacon_block_root: decoded.parent_beacon_block_root,
        execution_requests: &decoded.execution_requests,
    };

    Ok(request.tree_hash_root())
}

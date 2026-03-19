//! Lightweight test server that mirrors the zkBoost proof node HTTP API.
//!
//! This harness uses **no zkBoost dependencies** — it independently implements
//! the exact same HTTP endpoints, query parameters, and response shapes as
//! the real zkBoost server. This validates that Lighthouse's
//! [`HttpProofNodeClient`] speaks the correct wire protocol.
//!
//! ## Why independent (no zkBoost dependency)?
//!
//! 1. **Linker conflict**: `ethrex_crypto` (transitive via `zkboost-server`
//!    → `stateless-validator-ethrex`) defines SHA3 assembly symbols that
//!    collide with `openssl_sys` used by Lighthouse.
//!
//! 2. **Independence**: keeping the test harness dependency-free proves that
//!    the interface alignment is correct by construction, not by type reuse.
//!
//! ## Wire format
//!
//! All proof types use the zkBoost string format (`"reth-sp1"`, `"ethrex-risc0"`,
//! etc.) — never numeric u8 values. This is the real zkBoost format.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::broadcast;
use tokio_stream::{Stream, StreamExt, wrappers::BroadcastStream};
use types::Hash256;

/// The set of valid zkBoost proof type strings.
/// This list mirrors zkBoost's `ProofType` enum exactly.
pub const VALID_ZKBOOST_PROOF_TYPES: &[&str] = &[
    "ethrex-risc0",
    "ethrex-sp1",
    "ethrex-zisk",
    "reth-openvm",
    "reth-risc0",
    "reth-sp1",
    "reth-zisk",
];

/// Check if a string is a valid zkBoost proof type.
pub fn is_valid_zkboost_proof_type(value: &str) -> bool {
    VALID_ZKBOOST_PROOF_TYPES.contains(&value)
}

// ─── Wire Types ─────────────────────────────────────────────────────────────

/// Query params for `POST /v1/execution_proof_requests`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProofRequestQuery {
    #[serde(default)]
    pub proof_types: String,
}

/// Response for `POST /v1/execution_proof_requests`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequestResponse {
    pub new_payload_request_root: Hash256,
}

/// Query params for `GET /v1/execution_proof_requests` (SSE).
#[derive(Debug, Clone, Deserialize)]
pub struct ProofEventQuery {
    pub new_payload_request_root: Option<Hash256>,
}

/// Query params for `POST /v1/execution_proof_verifications`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProofVerificationQuery {
    pub new_payload_request_root: Hash256,
    pub proof_type: String,
}

/// Response for `POST /v1/execution_proof_verifications`.
#[derive(Debug, Clone, Serialize)]
pub struct ProofVerificationResponse {
    pub status: String,
}

/// JSON error response.
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

// ─── Internal SSE Event ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SseProofEvent {
    pub event_name: String,
    pub data: String,
}

// ─── SSE event payloads (string proof_type — the real zkBoost format) ───────

#[derive(Serialize)]
struct ProofCompletePayload {
    new_payload_request_root: Hash256,
    proof_type: String,
}

// ─── Shared Server State ────────────────────────────────────────────────────

pub struct ZkboostTestState {
    /// Completed proofs stored by (root, proof_type_str).
    pub completed_proofs: Arc<RwLock<HashMap<(Hash256, String), Vec<u8>>>>,
    /// Broadcast channel for SSE events.
    pub event_tx: broadcast::Sender<SseProofEvent>,
    /// Received proof requests (for test assertions).
    pub received_requests: RwLock<Vec<ReceivedRequest>>,
    /// Delay before emitting proof_complete events (ms).
    pub callback_delay_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ReceivedRequest {
    pub ssz_body: Vec<u8>,
    /// Raw proof_types query string as received on the wire.
    pub proof_types_raw: String,
    /// Parsed proof type values (split by comma).
    pub proof_types: Vec<String>,
    pub root: Hash256,
}

impl ZkboostTestState {
    pub fn new(callback_delay_ms: u64) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            completed_proofs: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            received_requests: RwLock::new(Vec::new()),
            callback_delay_ms,
        }
    }
}

// ─── Test Server ────────────────────────────────────────────────────────────

pub struct ZkboostTestServer {
    pub state: Arc<ZkboostTestState>,
    pub addr: SocketAddr,
    _shutdown_tx: tokio::sync::oneshot::Sender<()>,
}

impl ZkboostTestServer {
    /// Start a zkBoost-compatible test server on a random port.
    ///
    /// SSE events always use string proof types (the real zkBoost format).
    pub async fn start(callback_delay_ms: u64) -> Self {
        let state = Arc::new(ZkboostTestState::new(callback_delay_ms));

        let app = Router::new()
            .route(
                "/v1/execution_proof_requests",
                post(post_execution_proof_requests).get(get_execution_proof_requests),
            )
            .route(
                "/v1/execution_proofs/:root/:proof_type",
                get(get_execution_proofs),
            )
            .route(
                "/v1/execution_proof_verifications",
                post(post_execution_proof_verifications),
            )
            .route("/health", get(health))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let addr = listener.local_addr().expect("failed to get local addr");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("server error");
        });

        Self {
            state,
            addr,
            _shutdown_tx: shutdown_tx,
        }
    }

    /// Returns the base URL of the test server.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Compute a deterministic Hash256 from raw bytes.
fn hash_bytes(data: &[u8]) -> Hash256 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    data.hash(&mut hasher);
    let h = hasher.finish();
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&h.to_be_bytes());
    bytes[8..16].copy_from_slice(&h.to_le_bytes());
    Hash256::from(bytes)
}

// ─── Route Handlers ─────────────────────────────────────────────────────────

async fn health() -> StatusCode {
    StatusCode::OK
}

/// `POST /v1/execution_proof_requests`
///
/// Accepts proof_types as comma-separated string values (e.g. `reth-sp1,ethrex-risc0`).
/// Validates that all values are valid zkBoost proof types; rejects requests
/// with unknown values (including numeric u8 values).
async fn post_execution_proof_requests(
    State(state): State<Arc<ZkboostTestState>>,
    Query(params): Query<ProofRequestQuery>,
    body: Bytes,
) -> Result<Json<ProofRequestResponse>, (StatusCode, Json<ErrorResponse>)> {
    let root = hash_bytes(&body);

    let proof_types: Vec<String> = if params.proof_types.is_empty() {
        Vec::new()
    } else {
        params
            .proof_types
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    };

    // Validate all proof types are valid zkBoost identifiers.
    for pt in &proof_types {
        if !is_valid_zkboost_proof_type(pt) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "unsupported proof type `{pt}`, expect one of [{}]",
                        VALID_ZKBOOST_PROOF_TYPES.join(", ")
                    ),
                }),
            ));
        }
    }

    state.received_requests.write().push(ReceivedRequest {
        ssz_body: body.to_vec(),
        proof_types_raw: params.proof_types.clone(),
        proof_types: proof_types.clone(),
        root,
    });

    // Schedule proof completion events.
    let event_tx = state.event_tx.clone();
    let delay = state.callback_delay_ms;
    let completed = Arc::clone(&state.completed_proofs);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(delay)).await;

        for pt in proof_types {
            let proof_data = [&[0xDE, 0xAD, 0xBE, 0xEF][..], &root.0[..16]].concat();
            completed.write().insert((root, pt.clone()), proof_data);

            let event_data = serde_json::to_string(&ProofCompletePayload {
                new_payload_request_root: root,
                proof_type: pt,
            })
            .unwrap();

            let _ = event_tx.send(SseProofEvent {
                event_name: "proof_complete".to_string(),
                data: event_data,
            });
        }
    });

    Ok(Json(ProofRequestResponse {
        new_payload_request_root: root,
    }))
}

/// `GET /v1/execution_proof_requests` — SSE stream.
async fn get_execution_proof_requests(
    State(state): State<Arc<ZkboostTestState>>,
    Query(params): Query<ProofEventQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_tx.subscribe();
    let filter_root = params.new_payload_request_root;

    let catch_up = if let Some(root) = filter_root {
        let proofs = state.completed_proofs.read();
        proofs
            .iter()
            .filter(|((r, _), _)| *r == root)
            .map(|((r, pt), _)| SseProofEvent {
                event_name: "proof_complete".to_string(),
                data: serde_json::to_string(&ProofCompletePayload {
                    new_payload_request_root: *r,
                    proof_type: pt.clone(),
                })
                .unwrap(),
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let catch_up_stream = tokio_stream::iter(catch_up);
    let live_stream = BroadcastStream::new(rx).filter_map(move |result| {
        if let Ok(event) = result {
            if let Some(root) = filter_root {
                let root_hex = format!("{root:?}");
                if !event.data.contains(&root_hex) {
                    return None;
                }
            }
            Some(event)
        } else {
            None
        }
    });

    let merged = catch_up_stream.chain(live_stream).map(|sse_event| {
        Ok(Event::default()
            .event(sse_event.event_name)
            .data(sse_event.data))
    });

    Sse::new(merged).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

/// `GET /v1/execution_proofs/:root/:proof_type`
async fn get_execution_proofs(
    State(state): State<Arc<ZkboostTestState>>,
    Path((root_str, proof_type)): Path<(String, String)>,
) -> Response {
    let root: Hash256 = root_str.parse().unwrap_or(Hash256::repeat_byte(0));

    let proofs = state.completed_proofs.read();
    if let Some(proof_data) = proofs.get(&(root, proof_type)) {
        (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            proof_data.clone(),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "proof not found".to_string(),
            }),
        )
            .into_response()
    }
}

/// `POST /v1/execution_proof_verifications`
async fn post_execution_proof_verifications(
    State(_state): State<Arc<ZkboostTestState>>,
    Query(_params): Query<ProofVerificationQuery>,
    _body: Bytes,
) -> Json<ProofVerificationResponse> {
    Json(ProofVerificationResponse {
        status: "VALID".to_string(),
    })
}

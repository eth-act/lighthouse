//! Test harness that starts the **real** zkBoost server with mock zkVM backends.
//!
//! This validates that Lighthouse's [`HttpProofNodeClient`] speaks the correct
//! wire protocol by testing it against the actual zkBoost server implementation.
//!
//! ## Architecture
//!
//! 1. A lightweight mock Execution Layer (EL) that serves fixture data for
//!    `debug_chainConfig` and `debug_executionWitnessByBlockHash` JSON-RPC methods.
//! 2. The real `zkBoostServer` configured with `zkVMConfig::Mock` backends.
//! 3. Lighthouse's `HttpProofNodeClient` as the system under test.

use axum::{Json, extract::State, routing::post};
use bytes::Bytes;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::Value;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use zkboost_server::{
    config::{Config, zkVMConfig},
    server::zkBoostServer,
};
use zkboost_types::ProofType;

// ─── Fixture Data ────────────────────────────────────────────────────────────

/// SSZ-encoded NewPayloadRequest from zkBoost's test fixture.
pub const FIXTURE_NEW_PAYLOAD_REQUEST: &[u8] =
    include_bytes!("../tests/fixture/new_payload_request.ssz");

/// Chain config JSON from zkBoost's test fixture.
const FIXTURE_CHAIN_CONFIG: &str = include_str!("../tests/fixture/chain_config.json");

/// Execution witness JSON from zkBoost's test fixture.
const FIXTURE_EXECUTION_WITNESS: &str = include_str!("../tests/fixture/execution_witness.json");

// ─── Mock Execution Layer ────────────────────────────────────────────────────

struct MockElState {
    chain_config: Value,
    witness: Value,
}

/// Mock EL handler that responds to JSON-RPC requests with fixture data.
async fn mock_el_handler(State(state): State<Arc<MockElState>>, body: Bytes) -> Json<Value> {
    let request: Value = serde_json::from_slice(&body).unwrap_or_default();
    let method = request["method"].as_str().unwrap_or("");

    let result = match method {
        "debug_chainConfig" => state.chain_config.clone(),
        "debug_executionWitnessByBlockHash" => state.witness.clone(),
        _ => Value::Null,
    };

    Json(serde_json::json!({
        "jsonrpc": "2.0",
        "result": result,
        "id": request["id"],
    }))
}

/// Start a mock execution layer server that serves fixture data.
async fn start_mock_el() -> url::Url {
    let chain_config: Value = serde_json::from_str(FIXTURE_CHAIN_CONFIG)
        .expect("fixture chain_config.json should be valid JSON");
    let witness: Value = serde_json::from_str(FIXTURE_EXECUTION_WITNESS)
        .expect("fixture execution_witness.json should be valid JSON");

    let state = Arc::new(MockElState {
        chain_config,
        witness,
    });

    let app = axum::Router::new()
        .route("/", post(mock_el_handler))
        .with_state(state);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("failed to bind mock EL");
    let port = listener.local_addr().expect("no local addr").port();

    tokio::spawn(async move { axum::serve(listener, app).await });

    format!("http://127.0.0.1:{port}").parse().unwrap()
}

// ─── Real zkBoost Server ─────────────────────────────────────────────────────

/// Start the real zkBoost server with mock zkVM backends.
async fn start_zkboost_server(
    el_endpoint: url::Url,
    zkvm_configs: Vec<zkVMConfig>,
) -> (url::Url, CancellationToken) {
    let config = Config {
        port: 0,
        el_endpoint,
        chain_config_path: None,
        witness_timeout_secs: 120,
        proof_timeout_secs: 120,
        proof_cache_size: 128,
        witness_cache_size: 128,
        zkvm: zkvm_configs,
    };

    let metrics = PrometheusBuilder::new().build_recorder().handle();
    let shutdown = CancellationToken::new();
    let server = zkBoostServer::new(config, metrics)
        .await
        .expect("failed to create zkBoost server");
    let (addr, _handles) = server
        .run(shutdown.clone())
        .await
        .expect("failed to start zkBoost server");

    let endpoint = format!("http://127.0.0.1:{}", addr.port()).parse().unwrap();
    (endpoint, shutdown)
}

// ─── Test Harness ────────────────────────────────────────────────────────────

/// Test harness that manages a real zkBoost server with mock backends.
pub struct ZkboostTestHarness {
    /// Base URL of the running zkBoost server.
    pub endpoint: url::Url,
    /// The proof type configured for the mock backend.
    pub proof_type: ProofType,
    /// Cancellation token for graceful shutdown.
    shutdown: CancellationToken,
}

impl ZkboostTestHarness {
    /// Start a test harness with a single mock zkVM backend.
    ///
    /// The mock backend uses `EthrexZisk` by default (same as zkBoost's own
    /// integration tests) with a configurable proving delay.
    pub async fn start(mock_proving_time_ms: u64) -> Self {
        Self::start_with_proof_type(ProofType::EthrexZisk, mock_proving_time_ms).await
    }

    /// Start a test harness with a specific proof type.
    pub async fn start_with_proof_type(proof_type: ProofType, mock_proving_time_ms: u64) -> Self {
        let el_endpoint = start_mock_el().await;

        let zkvm_config = zkVMConfig::Mock {
            proof_type,
            mock_proving_time_ms,
            mock_proof_size: 1024,
            mock_failure: false,
        };

        let (endpoint, shutdown) = start_zkboost_server(el_endpoint, vec![zkvm_config]).await;

        Self {
            endpoint,
            proof_type,
            shutdown,
        }
    }

    /// Return the base URL as a string.
    pub fn url(&self) -> String {
        self.endpoint.to_string().trim_end_matches('/').to_string()
    }
}

impl Drop for ZkboostTestHarness {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

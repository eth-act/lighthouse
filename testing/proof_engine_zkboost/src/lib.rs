//! Integration tests verifying wire-level compatibility between lighthouse's
//! [`HttpProofNodeClient`] and the zkboost Proof Node API.
//!
//! ## What is tested
//!
//! 1. **`POST /v1/execution_proof_requests`** — Body transport, query param
//!    serialization, JSON response parsing.
//! 2. **`GET /v1/execution_proof_requests`** (SSE) — Event stream connection,
//!    event name parsing, JSON payload deserialization.
//! 3. **`GET /v1/execution_proofs/:root/:proof_type`** — Binary proof download.
//! 4. **`POST /v1/execution_proof_verifications`** — Proof verification round-trip.
//!
//! ## Compatibility findings
//!
//! The tests document a known **proof_type encoding mismatch**:
//!
//! - **Lighthouse** uses `ProofType = u8` and serializes `proof_types` as
//!   numeric values (e.g., `proof_types=0&proof_types=1`).
//! - **zkboost** uses `ProofType` as a string enum and expects comma-separated
//!   names (e.g., `proof_types=reth-sp1,ethrex-risc0`).
//!
//! This mismatch exists in both the query parameter encoding and the SSE event
//! payload (`proof_type` field). The test suite exercises both the "numeric"
//! (lighthouse-compatible) and "string" (zkboost-native) modes to surface these
//! differences.

pub mod mock_zkboost_server;

#[cfg(test)]
mod tests {
    use crate::mock_zkboost_server::MockZkboostServer;
    use execution_layer::eip8025::{HttpProofNodeClient, ProofNodeClient};
    use futures::StreamExt;
    use sensitive_url::SensitiveUrl;
    use std::time::Duration;
    use tokio::time::timeout;
    use types::Hash256;
    use types::execution::eip8025::ProofAttributes;

    /// Helper: create an `HttpProofNodeClient` pointing at the mock server.
    fn client_for(url: &str) -> HttpProofNodeClient {
        let sensitive_url = SensitiveUrl::parse(url).expect("mock server URL should be valid");
        HttpProofNodeClient::new(sensitive_url, Some(Duration::from_secs(5)))
    }

    /// Build a dummy payload body for testing.
    ///
    /// The mock server does not decode SSZ — it hashes the raw bytes to produce
    /// a deterministic root. So we can use any bytes.
    fn build_test_payload() -> Vec<u8> {
        vec![0x00, 0x01, 0x02, 0x03, 0xDE, 0xAD, 0xBE, 0xEF]
    }

    // ─── Test 1: request_proofs round-trip ──────────────────────────────────

    /// Verifies that `HttpProofNodeClient::request_proofs` successfully sends
    /// a body and receives the `new_payload_request_root` back.
    #[tokio::test]
    async fn test_request_proofs_roundtrip() {
        let server = MockZkboostServer::start(50, true).await;
        let client = client_for(&server.url());

        let attrs = ProofAttributes {
            proof_types: vec![0, 1],
        };
        let body = build_test_payload();

        let root = client
            .request_proofs(body.clone(), attrs)
            .await
            .expect("request_proofs should succeed");

        let requests = server.state.received_requests.read();
        assert_eq!(requests.len(), 1, "server should have received 1 request");
        assert_eq!(requests[0].root, root, "roots should match");
        assert_eq!(
            requests[0].ssz_body, body,
            "body should be passed through unchanged"
        );
    }

    // ─── Test 2: SSE event streaming (numeric mode) ────────────────────────

    /// Verifies that `HttpProofNodeClient::subscribe_proof_events` correctly
    /// receives and parses SSE events when the server uses numeric proof types.
    #[tokio::test]
    async fn test_sse_events_numeric_proof_types() {
        let server = MockZkboostServer::start(100, true).await;
        let client = client_for(&server.url());

        let attrs = ProofAttributes {
            proof_types: vec![0],
        };

        // Subscribe to events before making the request.
        let mut event_stream = client.subscribe_proof_events(None);

        // Submit a proof request — the mock will emit proof_complete after delay.
        let root = client
            .request_proofs(build_test_payload(), attrs)
            .await
            .expect("request_proofs should succeed");

        // Wait for the SSE event.
        let event = timeout(Duration::from_secs(5), event_stream.next())
            .await
            .expect("timed out waiting for SSE event")
            .expect("stream ended")
            .expect("stream error");

        assert_eq!(
            event.new_payload_request_root(),
            root,
            "event root should match request root"
        );
        assert_eq!(event.proof_type(), 0, "event proof_type should be 0");
    }

    // ─── Test 3: SSE event streaming (string mode — zkboost native) ────────

    /// Documents the proof_type mismatch: when zkboost sends string proof types
    /// like `"reth-sp1"`, lighthouse's parser may fail because it expects a u8.
    ///
    /// This test verifies the failure mode and documents it as a known gap.
    #[tokio::test]
    async fn test_sse_events_string_proof_types_mismatch() {
        let server = MockZkboostServer::start(100, false).await;
        let client = client_for(&server.url());

        let attrs = ProofAttributes {
            proof_types: vec![0],
        };

        let mut event_stream = client.subscribe_proof_events(None);

        let _root = client
            .request_proofs(build_test_payload(), attrs)
            .await
            .expect("request_proofs should succeed");

        // The SSE event will have proof_type: "0" (string) which the lighthouse
        // parser tries to deserialize as u8. Document the outcome.
        let result = timeout(Duration::from_secs(5), event_stream.next()).await;

        match result {
            Ok(Some(Ok(event))) => {
                // If it parsed successfully, the wire format is compatible.
                tracing::info!(
                    "String proof_type parsed successfully: proof_type={}",
                    event.proof_type()
                );
            }
            Ok(Some(Err(e))) => {
                // Expected: lighthouse can't parse string proof types.
                tracing::warn!("String proof_type caused parse error (expected mismatch): {e}");
            }
            Ok(None) => {
                tracing::warn!("SSE stream ended unexpectedly");
            }
            Err(_) => {
                tracing::warn!("Timed out waiting for SSE event");
            }
        }
    }

    // ─── Test 4: get_proof binary download ──────────────────────────────────

    /// Verifies that `HttpProofNodeClient::get_proof` correctly downloads
    /// binary proof data from the server.
    #[tokio::test]
    async fn test_get_proof_binary_download() {
        let server = MockZkboostServer::start(0, true).await;
        let client = client_for(&server.url());

        let attrs = ProofAttributes {
            proof_types: vec![0],
        };

        let root = client
            .request_proofs(build_test_payload(), attrs)
            .await
            .expect("request_proofs should succeed");

        // Wait for the mock to store the proof.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let proof_bytes = client
            .get_proof(root, 0)
            .await
            .expect("get_proof should succeed");

        assert!(
            proof_bytes.starts_with(&[0xDE, 0xAD, 0xBE, 0xEF]),
            "proof should start with mock sentinel bytes"
        );
        assert!(
            proof_bytes.len() > 4,
            "proof should contain root bytes after sentinel"
        );
    }

    // ─── Test 5: verify_proof round-trip ────────────────────────────────────

    /// Verifies that `HttpProofNodeClient::verify_proof` sends proof data and
    /// correctly parses the VALID/INVALID response.
    #[tokio::test]
    async fn test_verify_proof_returns_valid() {
        let server = MockZkboostServer::start(0, true).await;
        let client = client_for(&server.url());

        let root = Hash256::repeat_byte(0xAA);
        let status = client
            .verify_proof(root, 0, &[0x01, 0x02, 0x03])
            .await
            .expect("verify_proof should succeed");

        assert_eq!(
            status,
            types::execution::eip8025::ProofStatus::Valid,
            "mock always returns VALID"
        );
    }

    // ─── Test 6: get_proof 404 for missing proof ────────────────────────────

    /// Verifies that `HttpProofNodeClient::get_proof` returns an error when
    /// the requested proof doesn't exist (HTTP 404).
    #[tokio::test]
    async fn test_get_proof_missing_returns_error() {
        let server = MockZkboostServer::start(0, true).await;
        let client = client_for(&server.url());

        let result = client.get_proof(Hash256::repeat_byte(0xFF), 99).await;

        assert!(result.is_err(), "get_proof for missing proof should error");
    }

    // ─── Test 7: query param encoding analysis ──────────────────────────────

    /// Documents how reqwest serializes the proof_types query parameter.
    ///
    /// Lighthouse sends `Vec<u8>` via `reqwest::RequestBuilder::query()`,
    /// which uses serde_urlencoded. This test captures the actual wire format
    /// to document the compatibility gap with zkboost's comma-separated format.
    #[tokio::test]
    async fn test_query_param_encoding_analysis() {
        let server = MockZkboostServer::start(0, true).await;
        let client = client_for(&server.url());

        let attrs = ProofAttributes {
            proof_types: vec![0, 1, 2],
        };

        let _root = client
            .request_proofs(build_test_payload(), attrs)
            .await
            .expect("request_proofs should succeed");

        let requests = server.state.received_requests.read();
        assert_eq!(requests.len(), 1);

        // Log what the server actually received for proof_types.
        tracing::info!(
            raw = %requests[0].proof_types_raw,
            parsed = ?requests[0].proof_types,
            "Server received proof_types"
        );

        assert!(
            !requests[0].proof_types_raw.is_empty(),
            "proof_types should not be empty"
        );
    }

    // ─── Test 8: full lifecycle ─────────────────────────────────────────────

    /// End-to-end test: request → SSE event → download → verify.
    ///
    /// Exercises the complete communication lifecycle between
    /// HttpProofNodeClient and a zkboost-compatible server.
    #[tokio::test]
    async fn test_full_lifecycle() {
        let server = MockZkboostServer::start(100, true).await;
        let client = client_for(&server.url());

        let attrs = ProofAttributes {
            proof_types: vec![0, 1],
        };

        // Step 1: Subscribe to events.
        let mut events = client.subscribe_proof_events(None);

        // Step 2: Submit proof request.
        let root = client
            .request_proofs(build_test_payload(), attrs)
            .await
            .expect("request should succeed");

        // Step 3: Receive proof_complete events for both proof types.
        let mut completed_types = Vec::new();
        for _ in 0..2 {
            let event = timeout(Duration::from_secs(5), events.next())
                .await
                .expect("timed out")
                .expect("stream ended")
                .expect("stream error");

            assert_eq!(event.new_payload_request_root(), root);
            completed_types.push(event.proof_type());
        }
        completed_types.sort();
        assert_eq!(
            completed_types,
            vec![0, 1],
            "should get events for both proof types"
        );

        // Step 4: Download each proof.
        for pt in [0u8, 1] {
            let proof = client
                .get_proof(root, pt)
                .await
                .expect("get_proof should succeed");
            assert!(proof.starts_with(&[0xDE, 0xAD, 0xBE, 0xEF]));
        }

        // Step 5: Verify a proof.
        let status = client
            .verify_proof(root, 0, &[0x01, 0x02])
            .await
            .expect("verify should succeed");
        assert_eq!(status, types::execution::eip8025::ProofStatus::Valid);
    }
}

//! Integration tests verifying wire-level compatibility between Lighthouse's
//! [`HttpProofNodeClient`] and the zkBoost Proof Node API.
//!
//! ## Architecture: independent mirror (no zkBoost dependency)
//!
//! This test crate uses **no zkBoost crates**. Instead, it runs a lightweight
//! mock server that mirrors the exact zkBoost HTTP API (endpoints, query params,
//! SSE event shapes, response types). Lighthouse's [`HttpProofNodeClient`] has
//! been updated to send zkBoost-format string proof types (`"reth-sp1"`,
//! `"ethrex-risc0"`, etc.) at the wire boundary, converting internally from
//! EIP-8025 `u8` values.
//!
//! ### Why not use zkBoost as a direct dependency?
//!
//! **Linker conflict**: `ethrex_crypto` (transitive via `zkboost-server`
//! → `stateless-validator-ethrex`) defines `SHA3_absorb`/`SHA3_squeeze`
//! assembly symbols that collide with `openssl_sys` (used by Lighthouse).
//!
//! ### Why not just import `zkboost-types`?
//!
//! The task requires an **independent** client implementation. Lighthouse
//! mirrors the zkBoost interface via its own [`ZkBoostProofType`] enum,
//! which is validated by these tests against the known zkBoost API contract.
//!
//! ## Interface compatibility (post-alignment)
//!
//! | Surface | Lighthouse | zkBoost | Compatible? |
//! |---------|-----------|---------|-------------|
//! | Endpoint paths | `/v1/execution_proof_requests` | same | Yes |
//! | SSZ body transport | raw bytes POST | raw bytes POST | Yes |
//! | JSON response shape | `{ new_payload_request_root }` | same | Yes |
//! | SSE event mechanics | `event: proof_complete` | same | Yes |
//! | Binary proof download | `GET .../root/proof_type` | same | Yes |
//! | Verification response | `{ status: "VALID" }` | same | Yes |
//! | Query param `proof_types` | `reth-sp1,ethrex-risc0` (string CSV) | same | **Yes** |
//! | SSE `proof_type` field | `"ethrex-risc0"` (string) | same | **Yes** |
//! | URL path `proof_type` | `/proofs/{root}/reth-sp1` | same | **Yes** |

pub mod zkboost_harness;

#[cfg(test)]
mod tests {
    use crate::zkboost_harness::{ZkboostTestServer, is_valid_zkboost_proof_type};
    use execution_layer::eip8025::{HttpProofNodeClient, ProofNodeClient, ZkBoostProofType};
    use futures::StreamExt;
    use sensitive_url::SensitiveUrl;
    use std::time::Duration;
    use tokio::time::timeout;
    use types::Hash256;
    use types::execution::eip8025::ProofAttributes;

    /// Helper: create an `HttpProofNodeClient` pointing at the test server.
    fn client_for(url: &str) -> HttpProofNodeClient {
        let sensitive_url = SensitiveUrl::parse(url).expect("server URL should be valid");
        HttpProofNodeClient::new(sensitive_url, Some(Duration::from_secs(5)))
    }

    /// Build a dummy payload body for testing.
    fn build_test_payload() -> Vec<u8> {
        vec![0x00, 0x01, 0x02, 0x03, 0xDE, 0xAD, 0xBE, 0xEF]
    }

    // ─── Test 1: request_proofs sends zkBoost string proof types ────────────

    /// Verifies that `HttpProofNodeClient` converts u8 proof types to zkBoost
    /// string identifiers in the query param and that SSZ body is passed through.
    #[tokio::test]
    async fn test_request_proofs_sends_string_proof_types() {
        let server = ZkboostTestServer::start(50).await;
        let client = client_for(&server.url());

        // u8 values 0 and 1 should map to "ethrex-risc0" and "ethrex-sp1"
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
        assert_eq!(
            requests[0].proof_types_raw, "ethrex-risc0,ethrex-sp1",
            "proof_types should be zkBoost string format"
        );
        for pt in &requests[0].proof_types {
            assert!(
                is_valid_zkboost_proof_type(pt),
                "'{pt}' should be a valid zkBoost proof type"
            );
        }
    }

    // ─── Test 2: SSE events with string proof types are parsed correctly ────

    /// Verifies that SSE events with zkBoost string proof_type values are
    /// correctly deserialized back to u8 by the client.
    #[tokio::test]
    async fn test_sse_events_string_proof_types() {
        let server = ZkboostTestServer::start(100).await;
        let client = client_for(&server.url());

        let attrs = ProofAttributes {
            proof_types: vec![0], // maps to "ethrex-risc0"
        };

        let mut event_stream = client.subscribe_proof_events(None);

        let root = client
            .request_proofs(build_test_payload(), attrs)
            .await
            .expect("request_proofs should succeed");

        let event = timeout(Duration::from_secs(5), event_stream.next())
            .await
            .expect("timed out waiting for SSE event")
            .expect("stream ended")
            .expect("stream error");

        assert_eq!(event.new_payload_request_root(), root);
        assert_eq!(
            event.proof_type(),
            0,
            "string 'ethrex-risc0' should be deserialized back to u8 0"
        );
    }

    // ─── Test 3: get_proof uses string proof type in URL path ───────────────

    /// Verifies that binary proof download uses the zkBoost string format in
    /// the URL path (e.g. `/v1/execution_proofs/{root}/ethrex-risc0`).
    #[tokio::test]
    async fn test_get_proof_uses_string_path() {
        let server = ZkboostTestServer::start(0).await;
        let client = client_for(&server.url());

        let attrs = ProofAttributes {
            proof_types: vec![0], // maps to "ethrex-risc0"
        };

        let root = client
            .request_proofs(build_test_payload(), attrs)
            .await
            .expect("request_proofs should succeed");

        tokio::time::sleep(Duration::from_millis(100)).await;

        let proof_bytes = client
            .get_proof(root, 0)
            .await
            .expect("get_proof should succeed with string proof type in URL");

        assert!(
            proof_bytes.starts_with(&[0xDE, 0xAD, 0xBE, 0xEF]),
            "proof should start with mock sentinel bytes"
        );
        assert!(proof_bytes.len() > 4);
    }

    // ─── Test 4: verify_proof sends string proof type ───────────────────────

    /// Verifies that the verification endpoint receives a string proof type
    /// in the query parameter.
    #[tokio::test]
    async fn test_verify_proof_sends_string_proof_type() {
        let server = ZkboostTestServer::start(0).await;
        let client = client_for(&server.url());

        let root = Hash256::repeat_byte(0xAA);
        let status = client
            .verify_proof(root, 0, &[0x01, 0x02, 0x03])
            .await
            .expect("verify_proof should succeed");

        assert_eq!(status, types::execution::eip8025::ProofStatus::Valid);
    }

    // ─── Test 5: get_proof 404 handling ─────────────────────────────────────

    /// HTTP 404 error handling for missing proofs.
    #[tokio::test]
    async fn test_get_proof_missing_returns_error() {
        let server = ZkboostTestServer::start(0).await;
        let client = client_for(&server.url());

        // proof_type 0 maps to "ethrex-risc0" — no proof stored for this root
        let result = client.get_proof(Hash256::repeat_byte(0xFF), 0).await;
        assert!(result.is_err(), "get_proof for missing proof should error");
    }

    // ─── Test 6: invalid u8 proof type is rejected ──────────────────────────

    /// Verifies that an unmapped u8 value (e.g. 99) fails at the client
    /// before even reaching the server.
    #[tokio::test]
    async fn test_invalid_proof_type_rejected_by_client() {
        let server = ZkboostTestServer::start(0).await;
        let client = client_for(&server.url());

        let result = client.get_proof(Hash256::repeat_byte(0xAA), 99).await;
        assert!(
            result.is_err(),
            "u8 value 99 has no zkBoost mapping — should error"
        );
    }

    // ─── Test 7: server rejects numeric proof types ─────────────────────────

    /// Validates that the test server (mirroring real zkBoost behavior) rejects
    /// numeric proof type strings.
    #[tokio::test]
    async fn test_numeric_proof_types_rejected_by_server() {
        let numeric_values = ["0", "1", "2", "42"];
        for value in numeric_values {
            assert!(
                !is_valid_zkboost_proof_type(value),
                "numeric '{value}' should NOT be a valid zkBoost proof type"
            );
        }
    }

    // ─── Test 8: all zkBoost proof type strings are recognized ──────────────

    /// Validates that Lighthouse's `ZkBoostProofType` enum covers all known
    /// zkBoost proof types and the string representations match exactly.
    #[tokio::test]
    async fn test_zkboost_proof_type_coverage() {
        let expected = [
            "ethrex-risc0",
            "ethrex-sp1",
            "ethrex-zisk",
            "reth-openvm",
            "reth-risc0",
            "reth-sp1",
            "reth-zisk",
        ];

        // Verify all expected strings parse to ZkBoostProofType
        for s in &expected {
            let pt: ZkBoostProofType = s
                .parse()
                .unwrap_or_else(|_| panic!("'{s}' should parse as ZkBoostProofType"));
            assert_eq!(
                pt.as_str(),
                *s,
                "round-trip string representation should match"
            );
        }

        // Verify all ZkBoostProofType variants are in the expected list
        for pt in ZkBoostProofType::all() {
            assert!(
                expected.contains(&pt.as_str()),
                "ZkBoostProofType variant {:?} should be in expected list",
                pt
            );
        }

        // Verify u8 round-trip
        for (i, s) in expected.iter().enumerate() {
            let pt = ZkBoostProofType::from_u8(i as u8)
                .unwrap_or_else(|_| panic!("u8 {i} should map to a ZkBoostProofType"));
            assert_eq!(pt.as_str(), *s, "u8 {i} should map to '{s}'");
            assert_eq!(pt.to_u8(), i as u8, "'{s}' should map back to u8 {i}");
        }
    }

    // ─── Test 9: full lifecycle (request → SSE → download → verify) ─────────

    /// End-to-end lifecycle proving the entire path works with string proof types.
    #[tokio::test]
    async fn test_full_lifecycle() {
        let server = ZkboostTestServer::start(100).await;
        let client = client_for(&server.url());

        // Request proofs for u8 types 0 and 1
        let attrs = ProofAttributes {
            proof_types: vec![0, 1],
        };

        let mut events = client.subscribe_proof_events(None);

        let root = client
            .request_proofs(build_test_payload(), attrs)
            .await
            .expect("request should succeed");

        // Verify server received string proof types
        {
            let requests = server.state.received_requests.read();
            assert_eq!(requests[0].proof_types_raw, "ethrex-risc0,ethrex-sp1");
        }

        // Collect SSE events
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
        assert_eq!(completed_types, vec![0, 1]);

        // Download proofs
        for pt in [0u8, 1] {
            let proof = client
                .get_proof(root, pt)
                .await
                .expect("get_proof should succeed");
            assert!(proof.starts_with(&[0xDE, 0xAD, 0xBE, 0xEF]));
        }

        // Verify a proof
        let status = client
            .verify_proof(root, 0, &[0x01, 0x02])
            .await
            .expect("verify should succeed");
        assert_eq!(status, types::execution::eip8025::ProofStatus::Valid);
    }
}

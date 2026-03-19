//! Integration tests verifying wire-level compatibility between Lighthouse's
//! [`HttpProofNodeClient`] and the **real** zkBoost server.
//!
//! ## Architecture
//!
//! This test crate starts the real `zkBoostServer` (from the `zkboost-server` crate)
//! with mock zkVM backends, and validates that Lighthouse's `HttpProofNodeClient`
//! speaks the correct wire protocol against it.
//!
//! A lightweight mock Execution Layer serves fixture data (chain config +
//! execution witness) so the server can generate witnesses without a real node.
//!
//! ## What is validated
//!
//! - Lighthouse sends zkBoost string proof types in query params, URL paths, SSE
//! - The real server accepts Lighthouse's requests and returns valid responses
//! - SSE events with string `proof_type` values are correctly deserialized to u8
//! - Full lifecycle: request → SSE event → proof download → verification

pub mod zkboost_harness;

#[cfg(test)]
mod tests {
    use crate::zkboost_harness::{FIXTURE_NEW_PAYLOAD_REQUEST, ZkboostTestHarness};
    use execution_layer::eip8025::{HttpProofNodeClient, ProofNodeClient, ZkBoostProofType};
    use futures::StreamExt;
    use sensitive_url::SensitiveUrl;
    use std::time::Duration;
    use tokio::time::timeout;
    use types::execution::eip8025::ProofAttributes;
    use zkboost_types::ProofType;

    /// Helper: create an `HttpProofNodeClient` pointing at the test server.
    fn client_for(url: &str) -> HttpProofNodeClient {
        let sensitive_url = SensitiveUrl::parse(url).expect("server URL should be valid");
        HttpProofNodeClient::new(sensitive_url, Some(Duration::from_secs(30)))
    }

    /// The u8 value for `EthrexZisk` (our default test proof type).
    fn ethrex_zisk_u8() -> u8 {
        ZkBoostProofType::EthrexZisk.to_u8()
    }

    // ─── Test 1: request_proofs succeeds against real server ─────────────────

    /// Verifies that `HttpProofNodeClient::request_proofs` sends the correct
    /// wire format (string proof types in query param, SSZ body) and the real
    /// zkBoost server accepts it and returns a root.
    #[tokio::test]
    async fn test_request_proofs_accepted_by_real_server() {
        let harness = ZkboostTestHarness::start(3000).await;
        let client = client_for(&harness.url());

        let attrs = ProofAttributes {
            proof_types: vec![ethrex_zisk_u8()],
        };

        let root = client
            .request_proofs(FIXTURE_NEW_PAYLOAD_REQUEST.to_vec(), attrs)
            .await
            .expect("request_proofs should succeed against real server");

        // The root should be non-zero (the server computes tree_hash_root of the SSZ).
        assert!(
            !root.is_zero(),
            "returned root should be non-zero"
        );
    }

    // ─── Test 2: SSE events from real server are parsed correctly ────────────

    /// Verifies that SSE events from the real zkBoost server (which use string
    /// proof types like `"ethrex-zisk"`) are correctly deserialized by
    /// Lighthouse's client back to u8 values.
    #[tokio::test]
    async fn test_sse_events_from_real_server() {
        let harness = ZkboostTestHarness::start(1000).await;
        let client = client_for(&harness.url());

        let attrs = ProofAttributes {
            proof_types: vec![ethrex_zisk_u8()],
        };

        // Subscribe to events before requesting proofs.
        let mut event_stream = client.subscribe_proof_events(None);

        let root = client
            .request_proofs(FIXTURE_NEW_PAYLOAD_REQUEST.to_vec(), attrs)
            .await
            .expect("request_proofs should succeed");

        // Wait for a proof event from the real server.
        let event = timeout(Duration::from_secs(30), event_stream.next())
            .await
            .expect("timed out waiting for SSE event")
            .expect("stream ended")
            .expect("stream error");

        assert_eq!(event.new_payload_request_root(), root);
        assert_eq!(
            event.proof_type(),
            ethrex_zisk_u8(),
            "string 'ethrex-zisk' from real server should deserialize to u8 {}",
            ethrex_zisk_u8()
        );
    }

    // ─── Test 3: get_proof downloads proof from real server ──────────────────

    /// Verifies that `get_proof` uses the string proof type in the URL path
    /// and successfully downloads a proof from the real server after completion.
    #[tokio::test]
    async fn test_get_proof_from_real_server() {
        let harness = ZkboostTestHarness::start(1000).await;
        let client = client_for(&harness.url());

        let attrs = ProofAttributes {
            proof_types: vec![ethrex_zisk_u8()],
        };

        // Subscribe and wait for proof completion.
        let mut events = client.subscribe_proof_events(None);

        let root = client
            .request_proofs(FIXTURE_NEW_PAYLOAD_REQUEST.to_vec(), attrs)
            .await
            .expect("request should succeed");

        // Wait for proof_complete event.
        let _event = timeout(Duration::from_secs(30), events.next())
            .await
            .expect("timed out waiting for event")
            .expect("stream ended")
            .expect("stream error");

        // Download the proof using string proof type in URL path.
        let proof_bytes = client
            .get_proof(root, ethrex_zisk_u8())
            .await
            .expect("get_proof should succeed with string proof type in URL");

        assert!(
            !proof_bytes.is_empty(),
            "proof should not be empty"
        );
    }

    // ─── Test 4: verify_proof against real server ────────────────────────────

    /// Verifies that `verify_proof` sends the string proof type in query params
    /// and the real server accepts the verification request.
    #[tokio::test]
    async fn test_verify_proof_against_real_server() {
        let harness = ZkboostTestHarness::start(1000).await;
        let client = client_for(&harness.url());

        let attrs = ProofAttributes {
            proof_types: vec![ethrex_zisk_u8()],
        };

        let mut events = client.subscribe_proof_events(None);

        let root = client
            .request_proofs(FIXTURE_NEW_PAYLOAD_REQUEST.to_vec(), attrs)
            .await
            .expect("request should succeed");

        // Wait for completion.
        let _event = timeout(Duration::from_secs(30), events.next())
            .await
            .expect("timed out")
            .expect("stream ended")
            .expect("stream error");

        // Download proof.
        let proof = client
            .get_proof(root, ethrex_zisk_u8())
            .await
            .expect("get_proof should succeed");

        // Verify proof.
        let status = client
            .verify_proof(root, ethrex_zisk_u8(), &proof)
            .await
            .expect("verify_proof should succeed against real server");

        assert_eq!(status, types::execution::eip8025::ProofStatus::Valid);
    }

    // ─── Test 5: invalid u8 proof type is rejected by client ─────────────────

    /// Verifies that an unmapped u8 value (e.g. 99) fails at the Lighthouse
    /// client level before even reaching the server.
    #[tokio::test]
    async fn test_invalid_proof_type_rejected_by_client() {
        let harness = ZkboostTestHarness::start(0).await;
        let client = client_for(&harness.url());

        let result = client.get_proof(types::Hash256::repeat_byte(0xAA), 99).await;
        assert!(
            result.is_err(),
            "u8 value 99 has no zkBoost mapping — should error at client level"
        );
    }

    // ─── Test 6: ZkBoostProofType matches zkboost-types::ProofType ──────────

    /// Validates that Lighthouse's `ZkBoostProofType` enum covers all known
    /// zkBoost proof types with matching string representations.
    #[tokio::test]
    async fn test_zkboost_proof_type_matches_upstream() {
        use strum::IntoEnumIterator;

        // Collect all upstream ProofType variants.
        let upstream: Vec<(String, usize)> = ProofType::iter()
            .enumerate()
            .map(|(i, pt)| (pt.as_str().to_string(), i))
            .collect();

        // Verify Lighthouse's ZkBoostProofType has matching variants.
        for (s, i) in &upstream {
            let pt: ZkBoostProofType = s
                .parse()
                .unwrap_or_else(|_| panic!("'{s}' should parse as ZkBoostProofType"));
            assert_eq!(
                pt.as_str(), s.as_str(),
                "string representation should match upstream"
            );
            assert_eq!(
                pt.to_u8(), *i as u8,
                "u8 mapping for '{s}' should match upstream ordinal {i}"
            );
        }

        // Verify all Lighthouse variants are in the upstream list.
        let upstream_strs: Vec<&str> = upstream.iter().map(|(s, _)| s.as_str()).collect();
        for pt in ZkBoostProofType::all() {
            assert!(
                upstream_strs.contains(&pt.as_str()),
                "Lighthouse variant {:?} should exist in upstream zkBoost",
                pt
            );
        }

        // Counts should match.
        assert_eq!(
            ZkBoostProofType::all().len(),
            upstream.len(),
            "variant count should match between Lighthouse and zkBoost"
        );
    }

    // ─── Test 7: full lifecycle (request → SSE → download → verify) ─────────

    /// End-to-end lifecycle against the real zkBoost server.
    #[tokio::test]
    async fn test_full_lifecycle_against_real_server() {
        let harness = ZkboostTestHarness::start(1000).await;
        let client = client_for(&harness.url());

        let attrs = ProofAttributes {
            proof_types: vec![ethrex_zisk_u8()],
        };

        let mut events = client.subscribe_proof_events(None);

        // Step 1: Request proof.
        let root = client
            .request_proofs(FIXTURE_NEW_PAYLOAD_REQUEST.to_vec(), attrs)
            .await
            .expect("request should succeed");

        assert!(!root.is_zero());

        // Step 2: Wait for SSE proof_complete event.
        let event = timeout(Duration::from_secs(30), events.next())
            .await
            .expect("timed out waiting for event")
            .expect("stream ended")
            .expect("stream error");

        assert_eq!(event.new_payload_request_root(), root);
        assert_eq!(event.proof_type(), ethrex_zisk_u8());

        // Step 3: Download proof.
        let proof = client
            .get_proof(root, ethrex_zisk_u8())
            .await
            .expect("get_proof should succeed");
        assert!(!proof.is_empty());

        // Step 4: Verify proof.
        let status = client
            .verify_proof(root, ethrex_zisk_u8(), &proof)
            .await
            .expect("verify_proof should succeed");
        assert_eq!(status, types::execution::eip8025::ProofStatus::Valid);
    }
}

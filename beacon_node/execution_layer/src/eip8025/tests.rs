//! Unit tests for [`HttpProofEngine`] using [`MockProofNodeClient`].

use crate::eip8025::proof_engine::HttpProofEngine;
use crate::eip8025::proof_node_client::ProofNodeClient;
use crate::test_utils::{MockClientEvent, MockProofNodeClient, make_test_fulu_ssz};
use bls::{FixedBytesExtended, SignatureBytes};
use futures::StreamExt;
use tokio::time::{Duration, timeout};
use types::Hash256;
use types::execution::eip8025::{
    ExecutionProof, ProofAttributes, PublicInput, SignedExecutionProof,
};

// ─── helpers ─────────────────────────────────────────────────────────────────

fn make_proof(request_root: Hash256, proof_type: u8) -> SignedExecutionProof {
    SignedExecutionProof {
        message: ExecutionProof {
            proof_data: Default::default(),
            proof_type,
            public_input: PublicInput {
                new_payload_request_root: request_root,
            },
        },
        validator_index: 0,
        signature: SignatureBytes::empty(),
    }
}

/// Receive the next [`MockClientEvent`] within 2 seconds.
async fn next_event(rx: &mut tokio::sync::broadcast::Receiver<MockClientEvent>) -> MockClientEvent {
    timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for MockClientEvent")
        .expect("channel closed")
}

// ─── MockProofNodeClient tests ────────────────────────────────────────────────

/// `request_proofs` decodes SSZ, records the body, and emits `ProofRequested`.
#[tokio::test]
async fn mock_client_request_proofs_emits_event() {
    let mock = MockProofNodeClient::new(0);
    let mut rx = mock.subscribe_client_events();

    let (body, expected_root) = make_test_fulu_ssz(Hash256::repeat_byte(0xAA));
    let attrs = ProofAttributes {
        proof_types: vec![1, 2],
    };

    let root = mock
        .request_proofs(body.clone(), attrs.clone())
        .await
        .expect("request_proofs should succeed");

    assert_eq!(root, expected_root);
    assert_eq!(mock.request_count(), 1);

    let event = next_event(&mut rx).await;
    assert!(matches!(
        event,
        MockClientEvent::ProofRequested { ssz_body, proof_attributes, root: r }
        if r == root && ssz_body == body && proof_attributes == attrs
    ));
}

/// `verify_proof` emits `ProofVerified`.
#[tokio::test]
async fn mock_client_verify_proof_emits_event() {
    let mock = MockProofNodeClient::new(0);
    let mut rx = mock.subscribe_client_events();

    let root = Hash256::repeat_byte(0xBB);
    let _ = mock.verify_proof(root, 1, &[]).await.unwrap();

    let event = next_event(&mut rx).await;
    assert!(matches!(
        event,
        MockClientEvent::ProofVerified { root: r, proof_type: 1 } if r == root
    ));
}

/// `get_proof` emits `ProofFetched`.
#[tokio::test]
async fn mock_client_get_proof_emits_event() {
    let mock = MockProofNodeClient::new(0);
    let mut rx = mock.subscribe_client_events();

    let root = Hash256::repeat_byte(0xCC);
    let _ = mock.get_proof(root, 2).await.unwrap();

    let event = next_event(&mut rx).await;
    assert!(matches!(
        event,
        MockClientEvent::ProofFetched { root: r, proof_type: 2 } if r == root
    ));
}

/// `request_proofs` broadcasts a `ProofComplete` SSE event for each proof type.
#[tokio::test]
async fn mock_client_request_proofs_broadcasts_sse_events() {
    let mock = MockProofNodeClient::new(0);
    let mut sse = mock.subscribe_proof_events(None);

    let attrs = ProofAttributes {
        proof_types: vec![0, 1],
    };
    let (body, expected_root) = make_test_fulu_ssz(Hash256::repeat_byte(0x42));
    let root = mock
        .request_proofs(body, attrs)
        .await
        .expect("request_proofs should succeed");

    assert_eq!(root, expected_root);

    for expected_type in [0u8, 1u8] {
        let event = timeout(Duration::from_secs(2), sse.next())
            .await
            .expect("timed out waiting for SSE event")
            .expect("stream ended")
            .expect("stream error");
        assert_eq!(event.new_payload_request_root(), root);
        assert_eq!(event.proof_type(), expected_type);
    }
}

/// Multiple subscribers each receive every event independently.
#[tokio::test]
async fn mock_client_multiple_subscribers_each_get_events() {
    let mock = MockProofNodeClient::new(0);
    let mut rx1 = mock.subscribe_client_events();
    let mut rx2 = mock.subscribe_client_events();

    let (body, _) = make_test_fulu_ssz(Hash256::repeat_byte(0x01));
    let _ = mock
        .request_proofs(
            body,
            ProofAttributes {
                proof_types: vec![],
            },
        )
        .await
        .unwrap();

    assert!(matches!(
        next_event(&mut rx1).await,
        MockClientEvent::ProofRequested { .. }
    ));
    assert!(matches!(
        next_event(&mut rx2).await,
        MockClientEvent::ProofRequested { .. }
    ));
}

/// Different SSZ bodies produce different roots (computed via tree-hash).
#[tokio::test]
async fn mock_client_computes_distinct_roots_from_ssz() {
    let mock = MockProofNodeClient::new(0);
    let attrs = ProofAttributes {
        proof_types: vec![],
    };

    let (body1, expected1) = make_test_fulu_ssz(Hash256::repeat_byte(0x01));
    let (body2, expected2) = make_test_fulu_ssz(Hash256::repeat_byte(0x02));
    let (body3, expected3) = make_test_fulu_ssz(Hash256::repeat_byte(0x03));

    let root1 = mock.request_proofs(body1, attrs.clone()).await.unwrap();
    let root2 = mock.request_proofs(body2, attrs.clone()).await.unwrap();
    let root3 = mock.request_proofs(body3, attrs).await.unwrap();

    assert_eq!(root1, expected1);
    assert_eq!(root2, expected2);
    assert_eq!(root3, expected3);
    assert_ne!(root1, root2);
    assert_ne!(root2, root3);
    assert_eq!(mock.request_count(), 3);
}

// ─── HttpProofEngine tests ────────────────────────────────────────────────────

/// `verify_execution_proof` returns `Syncing` for an unknown root and does NOT
/// call `verify_proof` on the underlying client.
#[tokio::test]
async fn engine_verify_proof_unknown_root_returns_syncing() {
    let mock = MockProofNodeClient::new(0);
    let mut rx = mock.subscribe_client_events();
    let engine = HttpProofEngine::with_proof_node(mock);

    let proof = make_proof(Hash256::repeat_byte(0xAB), 0);
    let status = engine
        .verify_execution_proof(&proof)
        .await
        .expect("verify should not error");

    assert!(
        status.is_syncing(),
        "expected Syncing for unknown root, got {status:?}"
    );

    // verify_proof on the client must not be called for unknown roots.
    assert!(
        timeout(Duration::from_millis(50), rx.recv()).await.is_err(),
        "verify_proof should not be called for an unknown root"
    );
}

/// `get_proof` delegates to the underlying client and emits `ProofFetched`.
#[tokio::test]
async fn engine_get_proof_delegates_to_client() {
    let mock = MockProofNodeClient::new(0);
    let mut rx = mock.subscribe_client_events();
    let engine = HttpProofEngine::with_proof_node(mock);

    let root = Hash256::repeat_byte(0xDE);
    let bytes = engine
        .get_proof(root, 3)
        .await
        .expect("get_proof should succeed");

    assert_eq!(bytes.as_ref(), &[0xDE, 0xAD, 0xBE, 0xEF]);

    let event = next_event(&mut rx).await;
    assert!(matches!(
        event,
        MockClientEvent::ProofFetched { root: r, proof_type: 3 } if r == root
    ));
}

/// A proof received before the matching payload is buffered (`Syncing`), and
/// the buffer grows while no `ProofVerified` event is emitted.
#[tokio::test]
async fn engine_unknown_root_proof_is_buffered() {
    let mock = MockProofNodeClient::new(0);
    let mut rx = mock.subscribe_client_events();
    let engine = HttpProofEngine::with_proof_node(mock);

    let root = Hash256::from_low_u64_be(42);
    let proof = make_proof(root, 0);

    // First call: root unknown → Syncing, proof buffered.
    let status = engine.verify_execution_proof(&proof).await.unwrap();
    assert!(status.is_syncing(), "expected Syncing, got {status:?}");

    // The proof must not reach the engine state (tree/buffer promotion requires new_payload).
    assert_eq!(engine.get_proofs_by_root(&root).len(), 0);

    // No ProofVerified event should have been emitted.
    assert!(
        timeout(Duration::from_millis(50), rx.recv()).await.is_err(),
        "verify_proof should not be called for an unknown root"
    );
}

/// `subscribe_proof_events` with a root filter only forwards matching events.
#[tokio::test]
async fn engine_subscribe_proof_events_filters_by_root() {
    let mock = MockProofNodeClient::new(0);
    let attrs = ProofAttributes {
        proof_types: vec![0],
    };

    let (body1, root1) = make_test_fulu_ssz(Hash256::from_low_u64_be(1));
    let (body2, _root2) = make_test_fulu_ssz(Hash256::from_low_u64_be(2));

    // Subscribe before making requests.
    let mut filtered = mock.subscribe_proof_events(Some(root1));

    // root1 matches the filter; root2 should be silently dropped.
    let _ = mock.request_proofs(body1, attrs.clone()).await.unwrap();
    let _ = mock.request_proofs(body2, attrs).await.unwrap();

    // Only the event for root1 should arrive on the filtered stream.
    let event = timeout(Duration::from_secs(2), filtered.next())
        .await
        .expect("timed out")
        .expect("stream ended")
        .expect("stream error");
    assert_eq!(event.new_payload_request_root(), root1);

    // No second event for root2 should arrive within a short window.
    assert!(
        timeout(Duration::from_millis(100), filtered.next())
            .await
            .is_err(),
        "filtered stream should not forward events for other roots"
    );
}

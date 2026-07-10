//! Unit tests for [`HttpProofEngine`] using [`MockProofNodeClient`].

use crate::eip8025::proof_engine::HttpProofEngine;
use crate::eip8025::proof_node_client::ProofNodeClient;
use crate::test_utils::{
    MockClientEvent, MockProofNodeClient, make_test_fulu_ssz, make_test_verification_ssz,
};
use crate::{NewPayloadRequest, NewPayloadRequestFulu};
use bls::{FixedBytesExtended, SignatureBytes};
use futures::StreamExt;
use ssz_types::VariableList;
use tokio::time::{Duration, timeout};
use tree_hash::TreeHash;
use types::execution::eip8025::{ExecutionProof, PublicInput, SignedExecutionProof};
use types::{ChainSpec, Epoch, ExecutionPayloadFulu, ExecutionRequests, Hash256, MainnetEthSpec};

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
    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
    let mut rx = mock.subscribe_client_events();

    let proof_types = vec![1, 2];
    let (body, expected_root) =
        make_test_fulu_ssz::<MainnetEthSpec>(Hash256::repeat_byte(0xAA), proof_types.clone());

    let root = mock
        .request_proofs(body)
        .await
        .expect("request_proofs should succeed");

    assert_eq!(root, expected_root);
    assert_eq!(mock.request_count(), 1);

    let event = next_event(&mut rx).await;
    assert!(matches!(
        event,
        MockClientEvent::ProofRequested { root: r, proof_types: t }
        if r == root && t == proof_types
    ));
}

/// `verify_proof` emits `ProofVerified`.
#[tokio::test]
async fn mock_client_verify_proof_emits_event() {
    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
    let mut rx = mock.subscribe_client_events();

    let root = Hash256::repeat_byte(0xBB);
    let _ = mock
        .verify_proof(make_test_verification_ssz(root, 1))
        .await
        .unwrap();

    let event = next_event(&mut rx).await;
    assert!(matches!(
        event,
        MockClientEvent::ProofVerified { root: r, proof_type: 1 } if r == root
    ));
}

/// `get_proof` emits `ProofFetched`.
#[tokio::test]
async fn mock_client_get_proof_emits_event() {
    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
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
    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
    let mut sse = mock.subscribe_proof_events(None);

    let (body, expected_root) =
        make_test_fulu_ssz::<MainnetEthSpec>(Hash256::repeat_byte(0x42), vec![0, 1]);
    let root = mock
        .request_proofs(body)
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
    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
    let mut rx1 = mock.subscribe_client_events();
    let mut rx2 = mock.subscribe_client_events();

    let (body, _) = make_test_fulu_ssz::<MainnetEthSpec>(Hash256::repeat_byte(0x01), vec![]);
    let _ = mock.request_proofs(body).await.unwrap();

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
    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
    let (body1, expected1) =
        make_test_fulu_ssz::<MainnetEthSpec>(Hash256::repeat_byte(0x01), vec![]);
    let (body2, expected2) =
        make_test_fulu_ssz::<MainnetEthSpec>(Hash256::repeat_byte(0x02), vec![]);
    let (body3, expected3) =
        make_test_fulu_ssz::<MainnetEthSpec>(Hash256::repeat_byte(0x03), vec![]);

    let root1 = mock.request_proofs(body1).await.unwrap();
    let root2 = mock.request_proofs(body2).await.unwrap();
    let root3 = mock.request_proofs(body3).await.unwrap();

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
    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
    let mut rx = mock.subscribe_client_events();
    let engine = HttpProofEngine::with_proof_node(mock, &ChainSpec::mainnet(), 0, 32);

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
    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
    let mut rx = mock.subscribe_client_events();
    let engine = HttpProofEngine::with_proof_node(mock, &ChainSpec::mainnet(), 0, 32);

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
    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
    let mut rx = mock.subscribe_client_events();
    let engine = HttpProofEngine::with_proof_node(mock, &ChainSpec::mainnet(), 0, 32);

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
    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
    let (body1, root1) = make_test_fulu_ssz::<MainnetEthSpec>(Hash256::from_low_u64_be(1), vec![0]);
    let (body2, _root2) =
        make_test_fulu_ssz::<MainnetEthSpec>(Hash256::from_low_u64_be(2), vec![0]);

    // Subscribe before making requests.
    let mut filtered = mock.subscribe_proof_events(Some(root1));

    // root1 matches the filter; root2 should be silently dropped.
    let _ = mock.request_proofs(body1).await.unwrap();
    let _ = mock.request_proofs(body2).await.unwrap();

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

/// The chain config schedule built at init lets `verify_execution_proof` resolve a config and send
/// a verification body instead of buffering as `Syncing`.
#[tokio::test]
async fn engine_resolves_chain_config_and_verifies() {
    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
    let mut rx = mock.subscribe_client_events();

    let mut spec = ChainSpec::mainnet();
    // Capella activates at epoch 1, i.e. execution timestamp 384 (0 + 1 * 12 * 32). A payload
    // stamped before 384 resolves to no fork, so a successful verification below proves the engine
    // reads the fork from the timestamp it recorded for this request.
    spec.capella_fork_epoch = Some(Epoch::new(1));
    let engine = HttpProofEngine::with_proof_node(mock, &spec, 0, 32);

    // Notify the engine of a payload so it buffers the request together with its execution timestamp.
    let payload = ExecutionPayloadFulu::<MainnetEthSpec> {
        timestamp: 384,
        ..Default::default()
    };
    let requests = ExecutionRequests::<MainnetEthSpec>::default();
    let request = NewPayloadRequest::Fulu(NewPayloadRequestFulu {
        execution_payload: &payload,
        versioned_hashes: VariableList::default(),
        parent_beacon_block_root: Hash256::zero(),
        execution_requests: &requests,
    });
    let root = request.clone().tree_hash_root();
    engine.new_payload(&request).await.unwrap();

    // A proof for that root verifies against the resolved config rather than returning Syncing.
    let proof = make_proof(root, 0);
    let status = engine.verify_execution_proof(&proof).await.unwrap();
    assert!(
        !status.is_syncing(),
        "expected verification, got {status:?}"
    );

    let event = next_event(&mut rx).await;
    assert!(matches!(
        event,
        MockClientEvent::ProofVerified { root: r, proof_type: 0 } if r == root
    ));
}

/// `request_proofs` resolves the chain config from the payload timestamp and attaches it to the SSZ
/// body sent to the proof node.
#[tokio::test]
async fn engine_request_proofs_attaches_resolved_chain_config() {
    use crate::eip8025::chain_config::{ChainConfigSchedule, ProtocolFork};
    use crate::test_utils::OwnedProofRequestBody;
    use ssz::Decode;
    use types::execution::eip8025::ProofAttributes;

    let mock = MockProofNodeClient::<MainnetEthSpec>::new(0);
    let recorder = mock.clone();

    let mut spec = ChainSpec::mainnet();
    spec.capella_fork_epoch = Some(Epoch::new(1));
    let engine = HttpProofEngine::with_proof_node(mock, &spec, 0, 32);

    // Capella activates at execution timestamp 384; the payload is stamped there.
    let payload = ExecutionPayloadFulu::<MainnetEthSpec> {
        timestamp: 384,
        ..Default::default()
    };
    let requests = ExecutionRequests::<MainnetEthSpec>::default();
    let request = NewPayloadRequest::Fulu(NewPayloadRequestFulu {
        execution_payload: &payload,
        versioned_hashes: VariableList::default(),
        parent_beacon_block_root: Hash256::zero(),
        execution_requests: &requests,
    });
    engine
        .request_proofs(
            request,
            ProofAttributes {
                proof_types: vec![0],
            },
        )
        .await
        .unwrap();

    // The body carries exactly the config the schedule resolves for the payload timestamp.
    let body = recorder
        .received_requests()
        .pop()
        .expect("request recorded");
    let decoded = OwnedProofRequestBody::<MainnetEthSpec>::from_ssz_bytes(&body).unwrap();
    let expected = ChainConfigSchedule::new(&spec, 0, 32).resolve(384).unwrap();
    assert_eq!(decoded.chain_config, expected);
    assert_eq!(
        decoded.chain_config.active_fork.fork,
        ProtocolFork::Shanghai
    );
}

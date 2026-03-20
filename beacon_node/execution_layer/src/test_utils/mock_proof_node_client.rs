//! Mock [`ProofNodeClient`] for unit testing [`HttpProofEngine`].
//!
//! [`MockProofNodeClient`] implements [`ProofNodeClient`] entirely in memory —
//! no HTTP server required. It records received requests, broadcasts proof
//! events after a configurable delay, and always returns `Valid` for verification.
//!
//! [`ProofNodeClient`]: crate::eip8025::ProofNodeClient
//! [`HttpProofEngine`]: crate::eip8025::HttpProofEngine

use crate::eip8025::errors::ProofEngineError;
use crate::eip8025::proof_node_client::ProofNodeClient;
use crate::eip8025::types::{ProofComplete, ProofEvent};
use crate::engine_api::NewPayloadRequestFulu;
use bytes::Bytes;
use futures::stream::Stream;
use parking_lot::Mutex;
use ssz::{Encode, SszDecoderBuilder};
use ssz_types::VariableList;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tree_hash::TreeHash;
use types::execution::eip8025::{ProofAttributes, ProofStatus};
use types::{
    EthSpec, ExecutionPayloadFulu, ExecutionRequests, Hash256, MainnetEthSpec, VersionedHash,
};

/// Events emitted by [`MockProofNodeClient`] for each method invocation.
///
/// Subscribe via [`MockProofNodeClient::subscribe_client_events`] to observe
/// calls in tests without polling shared state.
#[derive(Debug, Clone)]
pub enum MockClientEvent {
    /// Emitted when [`ProofNodeClient::request_proofs`] is called.
    ProofRequested {
        ssz_body: Vec<u8>,
        proof_attributes: ProofAttributes,
        root: Hash256,
    },
    /// Emitted when [`ProofNodeClient::verify_proof`] is called.
    ProofVerified { root: Hash256, proof_type: u8 },
    /// Emitted when [`ProofNodeClient::get_proof`] is called.
    ProofFetched { root: Hash256, proof_type: u8 },
}

static MOCK_REGISTRY: LazyLock<parking_lot::Mutex<HashMap<usize, Arc<MockProofNodeClient>>>> =
    LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

/// Register a mock at `index`. Must be called before `ExecutionLayer::from_config`.
pub fn register_mock_proof_engine(
    index: usize,
    callback_delay_ms: u64,
) -> Arc<MockProofNodeClient> {
    let client = Arc::new(MockProofNodeClient::new(callback_delay_ms));
    MOCK_REGISTRY.lock().insert(index, client.clone());
    client
}

/// Fetch a registered mock by index (returns a clone sharing internal state).
pub fn get_mock_proof_engine(index: usize) -> Option<Arc<MockProofNodeClient>> {
    MOCK_REGISTRY.lock().get(&index).cloned()
}

/// URL encoding an index: `"http://mock/{n}/"`.
pub fn mock_proof_engine_url(index: usize) -> String {
    format!("http://mock/{}/", index)
}

/// Parse the index from a mock URL. Returns `None` for non-mock URLs.
pub fn parse_mock_index(url: &str) -> Option<usize> {
    url.strip_prefix("http://mock/").map(|s| {
        let s = s.strip_suffix('/').unwrap_or(s);
        if s.is_empty() {
            0
        } else {
            s.parse().unwrap_or(0)
        }
    })
}

/// Decode SSZ bytes as a `NewPayloadRequestFulu<MainnetEthSpec>` and compute
/// the tree-hash root.
///
/// Decodes each field individually via `SszDecoderBuilder`, constructs a
/// `NewPayloadRequestFulu` borrowing the owned fields, and returns the
/// tree-hash root of the real superstruct type.
fn decode_fulu_tree_hash_root(ssz_body: &[u8]) -> Result<Hash256, ssz::DecodeError> {
    let mut builder = SszDecoderBuilder::new(ssz_body);
    builder.register_type::<ExecutionPayloadFulu<MainnetEthSpec>>()?;
    builder.register_type::<VariableList<VersionedHash, <MainnetEthSpec as EthSpec>::MaxBlobCommitmentsPerBlock>>()?;
    builder.register_type::<Hash256>()?;
    builder.register_type::<ExecutionRequests<MainnetEthSpec>>()?;
    let mut decoder = builder.build()?;

    let execution_payload: ExecutionPayloadFulu<MainnetEthSpec> = decoder.decode_next()?;
    let versioned_hashes: VariableList<
        VersionedHash,
        <MainnetEthSpec as EthSpec>::MaxBlobCommitmentsPerBlock,
    > = decoder.decode_next()?;
    let parent_beacon_block_root: Hash256 = decoder.decode_next()?;
    let execution_requests: ExecutionRequests<MainnetEthSpec> = decoder.decode_next()?;

    let request = NewPayloadRequestFulu {
        execution_payload: &execution_payload,
        versioned_hashes,
        parent_beacon_block_root,
        execution_requests: &execution_requests,
    };
    Ok(request.tree_hash_root())
}

/// Build a test SSZ body encoding a `NewPayloadRequestFulu` with the given
/// parent beacon block root. Returns `(ssz_bytes, expected_tree_hash_root)`.
pub fn make_test_fulu_ssz(parent_root: Hash256) -> (Vec<u8>, Hash256) {
    let execution_payload = ExecutionPayloadFulu::<MainnetEthSpec>::default();
    let versioned_hashes = VariableList::<
        VersionedHash,
        <MainnetEthSpec as EthSpec>::MaxBlobCommitmentsPerBlock,
    >::default();
    let execution_requests = ExecutionRequests::<MainnetEthSpec>::default();
    let request = NewPayloadRequestFulu {
        execution_payload: &execution_payload,
        versioned_hashes,
        parent_beacon_block_root: parent_root,
        execution_requests: &execution_requests,
    };
    (request.as_ssz_bytes(), request.tree_hash_root())
}

/// In-memory proof node client for testing.
///
/// Each call to [`request_proofs`] decodes the SSZ body as a Fulu
/// `NewPayloadRequest`, computes the tree-hash root, records the raw SSZ body,
/// and schedules a [`ProofEvent::ProofComplete`] event for each requested
/// proof type after `callback_delay_ms` milliseconds.
///
/// Call [`subscribe_client_events`] to receive a [`MockClientEvent`] stream
/// that fires once per method invocation — useful for asserting that the proof
/// engine issues the expected calls without polling shared state.
///
/// [`request_proofs`]: MockProofNodeClient::request_proofs
/// [`subscribe_client_events`]: MockProofNodeClient::subscribe_client_events
#[derive(Clone)]
pub struct MockProofNodeClient {
    /// Received SSZ request bodies in order of arrival.
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Broadcast channel for in-memory SSE events.
    event_tx: broadcast::Sender<ProofEvent>,
    /// Broadcast channel for method-invocation events.
    call_tx: broadcast::Sender<MockClientEvent>,
    /// Delay in milliseconds before broadcasting proof complete events.
    callback_delay_ms: u64,
}

impl MockProofNodeClient {
    /// Create a new mock client.
    ///
    /// `callback_delay_ms` controls how long after `request_proofs` the
    /// proof complete events are broadcast.
    pub fn new(callback_delay_ms: u64) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        let (call_tx, _) = broadcast::channel(256);
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            event_tx,
            call_tx,
            callback_delay_ms,
        }
    }

    /// Returns the number of proof requests received.
    pub fn request_count(&self) -> usize {
        self.requests.lock().len()
    }

    /// Returns a clone of all received SSZ request bodies.
    pub fn received_requests(&self) -> Vec<Vec<u8>> {
        self.requests.lock().clone()
    }

    /// Subscribe to method-invocation events.
    ///
    /// Each call to `request_proofs`, `verify_proof`, or `get_proof` on this
    /// client sends one [`MockClientEvent`] to all active receivers.  Use this
    /// in tests to assert that the proof engine issues the expected calls.
    pub fn subscribe_client_events(&self) -> broadcast::Receiver<MockClientEvent> {
        self.call_tx.subscribe()
    }
}

#[async_trait::async_trait]
impl ProofNodeClient for MockProofNodeClient {
    async fn request_proofs(
        &self,
        ssz_body: Vec<u8>,
        proof_attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError> {
        let root = decode_fulu_tree_hash_root(&ssz_body)
            .map_err(|e| ProofEngineError::InvalidPayload(format!("SSZ decode failed: {e:?}")))?;

        self.requests.lock().push(ssz_body.clone());

        let _ = self.call_tx.send(MockClientEvent::ProofRequested {
            ssz_body,
            proof_attributes: proof_attributes.clone(),
            root,
        });

        let event_tx = self.event_tx.clone();
        let delay = self.callback_delay_ms;
        let proof_types = proof_attributes.proof_types.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            for proof_type in proof_types {
                let _ = event_tx.send(ProofEvent::ProofComplete(ProofComplete {
                    new_payload_request_root: root,
                    proof_type,
                }));
            }
        });

        Ok(root)
    }

    async fn verify_proof(
        &self,
        root: Hash256,
        proof_type: u8,
        _proof_data: &[u8],
    ) -> Result<ProofStatus, ProofEngineError> {
        let _ = self
            .call_tx
            .send(MockClientEvent::ProofVerified { root, proof_type });
        Ok(ProofStatus::Valid)
    }

    async fn get_proof(&self, root: Hash256, proof_type: u8) -> Result<Bytes, ProofEngineError> {
        let _ = self
            .call_tx
            .send(MockClientEvent::ProofFetched { root, proof_type });
        Ok(Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]))
    }

    fn subscribe_client_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<crate::test_utils::MockClientEvent>> {
        Some(self.call_tx.subscribe())
    }

    fn subscribe_proof_events(
        &self,
        filter_root: Option<Hash256>,
    ) -> Pin<Box<dyn Stream<Item = Result<ProofEvent, ProofEngineError>> + Send + '_>> {
        let rx = self.event_tx.subscribe();
        let stream = BroadcastStream::new(rx).filter_map(move |result| match result {
            Ok(event) => {
                if filter_root.is_some_and(|root| event.new_payload_request_root() != root) {
                    return None;
                }
                Some(Ok(event))
            }
            Err(_) => None,
        });
        Box::pin(stream)
    }
}

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
use bls::FixedBytesExtended;
use bytes::Bytes;
use futures::stream::Stream;
use parking_lot::Mutex;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use types::Hash256;
use types::execution::eip8025::{ProofAttributes, ProofStatus};

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

/// Sentinel URL that triggers instantiation of [`MockProofNodeClient`] inside
/// [`ExecutionLayer::from_config`] instead of opening a real HTTP connection.
pub const MOCK_PROOF_ENGINE_URL: &str = "http://mock";

/// In-memory proof node client for testing.
///
/// Each call to [`request_proofs`] assigns a sequential `Hash256` root,
/// records the raw SSZ body, and schedules a [`ProofEvent::ProofComplete`]
/// event for each requested proof type after `callback_delay_ms` milliseconds.
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
    /// Counter used to generate unique sequential roots.
    next_root: Arc<AtomicU64>,
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
            next_root: Arc::new(AtomicU64::new(1)),
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
        let idx = self.next_root.fetch_add(1, Ordering::SeqCst);
        let root = Hash256::from_low_u64_be(idx);

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

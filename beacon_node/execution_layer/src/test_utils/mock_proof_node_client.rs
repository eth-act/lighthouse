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
use bytes::Bytes;
use futures::stream::Stream;
use parking_lot::Mutex;
use ssz::{Decode, Encode};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};
use ssz_types::VariableList;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use superstruct::superstruct;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash as TreeHashDerive;
use types::execution::eip8025::{ProofAttributes, ProofStatus};
use types::{
    BeaconStateError, EthSpec, ExecutionPayloadBellatrix, ExecutionPayloadCapella,
    ExecutionPayloadDeneb, ExecutionPayloadElectra, ExecutionPayloadFulu, ExecutionPayloadGloas,
    ExecutionRequests, Hash256, MainnetEthSpec, VersionedHash,
};

/// Owned version of `NewPayloadRequest` used only for SSZ decoding inside the mock.
///
/// The production `NewPayloadRequest<'block, E>` holds `&'block` references (zero-copy
/// during block processing), which prevents deriving `ssz::Decode`. This local owned
/// superstruct enum mirrors all fork variants with owned fields and is used exclusively
/// to decode the SSZ bytes sent to `request_proofs` and compute `tree_hash_root`.
#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu, Gloas),
    variant_attributes(derive(SszEncode, SszDecode, TreeHashDerive)),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[derive(SszEncode, SszDecode, TreeHashDerive)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub(crate) struct OwnedNewPayloadRequest<E: EthSpec> {
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "execution_payload_bellatrix")
    )]
    pub execution_payload: ExecutionPayloadBellatrix<E>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: ExecutionPayloadDeneb<E>,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    pub execution_payload: ExecutionPayloadElectra<E>,
    #[superstruct(only(Fulu), partial_getter(rename = "execution_payload_fulu"))]
    pub execution_payload: ExecutionPayloadFulu<E>,
    #[superstruct(only(Gloas), partial_getter(rename = "execution_payload_gloas"))]
    pub execution_payload: ExecutionPayloadGloas<E>,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas))]
    pub versioned_hashes: VariableList<VersionedHash, E::MaxBlobCommitmentsPerBlock>,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas))]
    pub parent_beacon_block_root: Hash256,
    #[superstruct(only(Electra, Fulu, Gloas))]
    pub execution_requests: ExecutionRequests<E>,
}

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

/// The registry stores a concrete `MockProofNodeClient<MainnetEthSpec>` as a
/// non-generic stand-in. All fields are Arc-wrapped, so `get_mock_proof_engine`
/// can construct a `MockProofNodeClient<E>` for any `E` by sharing those Arcs.
static MOCK_REGISTRY: LazyLock<
    parking_lot::Mutex<HashMap<usize, Arc<MockProofNodeClient<MainnetEthSpec>>>>,
> = LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

/// Register a mock at `index`. Must be called before `ExecutionLayer::from_config`.
///
/// Stores the mock as `MainnetEthSpec` internally and returns a `MockProofNodeClient<E>`
/// that shares the same Arc-backed state but decodes SSZ using `E`.
pub fn register_mock_proof_engine<E: EthSpec>(
    index: usize,
    callback_delay_ms: u64,
) -> MockProofNodeClient<E> {
    let stored = Arc::new(MockProofNodeClient::<MainnetEthSpec>::new(
        callback_delay_ms,
    ));
    let typed = MockProofNodeClient::<E> {
        requests: stored.requests.clone(),
        event_tx: stored.event_tx.clone(),
        call_tx: stored.call_tx.clone(),
        callback_delay_ms: stored.callback_delay_ms,
        _phantom: PhantomData,
    };
    MOCK_REGISTRY.lock().insert(index, stored);
    typed
}

/// Fetch a registered mock by index as a `MockProofNodeClient<E>`.
///
/// Constructs the typed client by sharing the Arc fields of the stored
/// `MockProofNodeClient<MainnetEthSpec>`, so all state (requests, events) is shared.
pub fn get_mock_proof_engine<E: EthSpec>(index: usize) -> Option<MockProofNodeClient<E>> {
    MOCK_REGISTRY
        .lock()
        .get(&index)
        .map(|stored| MockProofNodeClient::<E> {
            requests: stored.requests.clone(),
            event_tx: stored.event_tx.clone(),
            call_tx: stored.call_tx.clone(),
            callback_delay_ms: stored.callback_delay_ms,
            _phantom: PhantomData,
        })
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

/// Build a test SSZ body encoding a `NewPayloadRequestFulu<E>` with the given
/// parent beacon block root. Returns `(ssz_bytes, expected_tree_hash_root)`.
pub fn make_test_fulu_ssz<E: EthSpec>(parent_root: Hash256) -> (Vec<u8>, Hash256) {
    let request = OwnedNewPayloadRequestFulu::<E> {
        execution_payload: ExecutionPayloadFulu::default(),
        versioned_hashes: VariableList::default(),
        parent_beacon_block_root: parent_root,
        execution_requests: ExecutionRequests::default(),
    };
    let request = OwnedNewPayloadRequest::Fulu(request);
    (request.as_ssz_bytes(), request.tree_hash_root())
}

/// In-memory proof node client for testing, generic over [`EthSpec`].
///
/// Each call to [`request_proofs`] decodes the SSZ body using `E`, records the
/// raw SSZ body, and schedules a [`ProofEvent::ProofComplete`] event for each
/// requested proof type after `callback_delay_ms` milliseconds.
///
/// Call [`subscribe_client_events`] to receive a [`MockClientEvent`] stream
/// that fires once per method invocation — useful for asserting that the proof
/// engine issues the expected calls without polling shared state.
///
/// [`request_proofs`]: MockProofNodeClient::request_proofs
/// [`subscribe_client_events`]: MockProofNodeClient::subscribe_client_events
pub struct MockProofNodeClient<E: EthSpec> {
    /// Received SSZ request bodies in order of arrival.
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Broadcast channel for in-memory SSE events.
    event_tx: broadcast::Sender<ProofEvent>,
    /// Broadcast channel for method-invocation events.
    call_tx: broadcast::Sender<MockClientEvent>,
    /// Delay in milliseconds before broadcasting proof complete events.
    callback_delay_ms: u64,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Clone for MockProofNodeClient<E> {
    fn clone(&self) -> Self {
        Self {
            requests: self.requests.clone(),
            event_tx: self.event_tx.clone(),
            call_tx: self.call_tx.clone(),
            callback_delay_ms: self.callback_delay_ms,
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> MockProofNodeClient<E> {
    /// Create a new unregistered mock client.
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
            _phantom: PhantomData,
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
impl<E: EthSpec> ProofNodeClient for MockProofNodeClient<E> {
    async fn request_proofs(
        &self,
        ssz_body: Vec<u8>,
        proof_attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError> {
        let root = OwnedNewPayloadRequest::<E>::from_ssz_bytes(&ssz_body)
            .map_err(|e| ProofEngineError::InvalidPayload(format!("SSZ decode failed: {e:?}")))?
            .tree_hash_root();

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

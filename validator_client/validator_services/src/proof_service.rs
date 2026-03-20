//! EIP-8025 Execution Proof Service
//!
//! This service handles execution proof requests, signing and resigning workflows.
//!
//! Three concurrent tasks:
//! 1. **Beacon event monitor**: subscribes to beacon node SSE for new blocks and
//!    validated-proof events — requests proofs and resigns validated proofs.
//! 2. **Proof engine event monitor**: subscribes to proof engine SSE for proof
//!    completion/failure events — fetches completed proofs, signs them, and
//!    submits to the beacon node.
//! 3. **Reactive HTTP handler**: receives proofs from proof engine callbacks.

use beacon_node_fallback::BeaconNodeFallback;
use bls::PublicKey;
use eth2::types::{BlockId, EventKind, EventTopic, SseExecutionProofValidated};
use execution_layer::NewPayloadRequest;
use execution_layer::eip8025::{HttpProofEngine, ProofEvent};
use futures::StreamExt;
use parking_lot::RwLock;
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use task_executor::TaskExecutor;
use tracing::{debug, error, info, warn};
use types::execution::eip8025::{ProofAttributes, ProofData, PublicInput};
use types::{Epoch, EthSpec, ExecutionProof, Hash256};
use validator_store::{DoppelgangerStatus, ValidatorStore};

/// Discard tracking entries older than this.
const PROOF_REQUEST_STALE_TIMEOUT: Duration = Duration::from_secs(300);

/// An outstanding proof request awaiting completion from the proof engine.
struct OutstandingProofRequest {
    /// Proof types we are still waiting for.
    pending_proof_types: HashSet<u8>,
    /// Slot of the block (for epoch derivation during signing).
    slot: types::Slot,
    /// When the request was made.
    requested_at: Instant,
}

/// Background service for execution proof handling
pub struct ProofService<S: ValidatorStore, T: SlotClock> {
    inner: Arc<Inner<S, T>>,
}

struct Inner<S: ValidatorStore, T: SlotClock> {
    validator_store: Arc<S>,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    proof_engine: Arc<HttpProofEngine>,
    slot_clock: T,
    executor: TaskExecutor,
    proof_types: Vec<u8>,
    /// Outstanding proof requests keyed by `new_payload_request_root`.
    outstanding_requests: RwLock<HashMap<Hash256, OutstandingProofRequest>>,
}

impl<S: ValidatorStore + 'static, T: 'static + SlotClock + Clone> ProofService<S, T> {
    /// Create a new proof service
    pub fn new(
        validator_store: Arc<S>,
        beacon_nodes: Arc<BeaconNodeFallback<T>>,
        proof_engine: Arc<HttpProofEngine>,
        slot_clock: T,
        executor: TaskExecutor,
        proof_types: Option<Vec<u8>>,
    ) -> Self {
        // Default to all available proof types if not specified
        // TODO: Update when proof types are standardized
        let proof_types = proof_types.unwrap_or_else(|| vec![0, 1, 2]);

        Self {
            inner: Arc::new(Inner {
                validator_store,
                beacon_nodes,
                proof_engine,
                slot_clock,
                executor,
                proof_types,
                outstanding_requests: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// Start the proof service background tasks
    pub fn start_service(self: Arc<Self>) -> Result<(), String> {
        let inner = self.inner.clone();
        self.inner.executor.spawn(
            async move { inner.monitor_events_task().await },
            "proof_service_monitor",
        );

        let inner = self.inner.clone();
        self.inner.executor.spawn(
            async move { inner.monitor_proof_engine_events_task().await },
            "proof_service_proof_engine_monitor",
        );

        info!("Proof service started - monitoring beacon events and proof engine events");
        Ok(())
    }

    /// Public method called by HTTP API when proof engine callbacks with unsigned proof
    ///
    /// This is the reactive endpoint that receives proofs from the proof engine
    /// and signs them with validator keys before submitting to beacon nodes.
    pub async fn handle_proof_request(
        &self,
        pubkey: PublicKey,
        execution_proof: ExecutionProof,
        epoch: Option<Epoch>,
    ) -> Result<(), String> {
        self.inner
            .sign_and_submit_proof(pubkey, execution_proof, epoch)
            .await
    }
}

impl<S: ValidatorStore + 'static, T: 'static + SlotClock + Clone> Inner<S, T> {
    // ─── Beacon node event monitoring (existing) ────────────────────────

    /// Subscribe to both `Block` and `ExecutionProofValidated` events via a single SSE stream.
    async fn subscribe_to_events(
        &self,
    ) -> Result<
        impl futures::Stream<Item = Result<eth2::types::EventKind<S::E>, eth2::Error>>,
        String,
    > {
        self.beacon_nodes
            .first_success(|node| async move {
                node.get_events::<S::E>(&[EventTopic::Block, EventTopic::ExecutionProofValidated])
                    .await
            })
            .await
            .map_err(|e| format!("All beacon nodes failed to provide event stream: {}", e))
    }

    /// Monitor block and validated-proof events over a single SSE connection.
    async fn monitor_events_task(self: Arc<Self>) {
        info!("Starting proof service event monitoring via SSE");

        loop {
            match self.subscribe_to_events().await {
                Ok(mut stream) => {
                    info!("Successfully subscribed to block and execution proof events");

                    while let Some(event_result) = stream.next().await {
                        match event_result {
                            Ok(EventKind::Block(sse_block)) => {
                                if sse_block.execution_optimistic {
                                    debug!(
                                        slot = sse_block.slot.as_u64(),
                                        "Skipping execution optimistic block"
                                    );
                                    continue;
                                }
                                self.handle_block_event(sse_block.block, sse_block.slot)
                                    .await;
                            }
                            Ok(EventKind::ExecutionProofValidated(proof_event)) => {
                                self.handle_validated_proof(proof_event).await;
                            }
                            Ok(_) => {}
                            Err(e) => {
                                warn!(error = %e, "Error receiving event, will reconnect");
                                break;
                            }
                        }
                    }

                    warn!("Event stream ended, reconnecting...");
                }
                Err(e) => {
                    error!(error = %e, "Failed to subscribe to events, retrying...");
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Handle a new block event by fetching the full block via RPC then requesting proofs.
    async fn handle_block_event(&self, block_root: Hash256, slot: types::Slot) {
        info!(
            slot = slot.as_u64(),
            block = %block_root,
            "New block detected, fetching full block via RPC"
        );

        let signed_block = match self
            .beacon_nodes
            .first_success(|node| async move {
                node.get_beacon_blocks::<S::E>(BlockId::Root(block_root))
                    .await
            })
            .await
        {
            Ok(Some(response)) => response.data().clone(),
            Ok(None) => {
                warn!(block = %block_root, "Block not found on beacon node");
                return;
            }
            Err(e) => {
                error!(block = %block_root, error = %e, "Failed to fetch block via RPC");
                return;
            }
        };

        let new_payload_request = match NewPayloadRequest::try_from(signed_block.message()) {
            Ok(req) => req,
            Err(e) => {
                error!(block = %block_root, error = ?e, "Failed to construct NewPayloadRequest");
                return;
            }
        };

        let proof_attributes = ProofAttributes {
            proof_types: self.proof_types.clone(),
        };

        match self
            .proof_engine
            .request_proofs(new_payload_request, proof_attributes)
            .await
        {
            Ok(new_payload_request_root) => {
                let pending_proof_types: HashSet<u8> = self.proof_types.iter().copied().collect();
                let num_types = pending_proof_types.len();
                self.outstanding_requests.write().insert(
                    new_payload_request_root,
                    OutstandingProofRequest {
                        pending_proof_types,
                        slot,
                        requested_at: Instant::now(),
                    },
                );
                debug!(
                    root = %new_payload_request_root,
                    block = %block_root,
                    num_proof_types = num_types,
                    "Proof generation requested, tracking for completion"
                );
            }
            Err(e) => {
                error!(block = %block_root, error = ?e, "Failed to request proofs from proof engine");
            }
        }
    }

    /// Handle a validated proof event by resigning with the first local validator key.
    async fn handle_validated_proof(&self, event: SseExecutionProofValidated) {
        let execution_proof = event.execution_proof;
        let epoch = Epoch::new(event.epoch);

        let Some(pubkey) = self
            .validator_store
            .voting_pubkeys::<Vec<_>, _>(DoppelgangerStatus::ignored)
            .first()
            .cloned()
        else {
            warn!("No local validators available to resign proof");
            return;
        };

        match self
            .validator_store
            .sign_execution_proof(pubkey, execution_proof, epoch)
            .await
        {
            Ok(signed_proof) => {
                match self
                    .beacon_nodes
                    .first_success(move |node| {
                        let proof = signed_proof.clone();
                        async move { node.post_beacon_execution_proofs(&[proof]).await }
                    })
                    .await
                {
                    Ok(_) => {
                        info!(?pubkey, "Resigned proof submitted");
                    }
                    Err(e) => {
                        warn!(?pubkey, error = %e, "Failed to submit resigned proof");
                    }
                }
            }
            Err(e) => {
                warn!(?pubkey, error = ?e, "Failed to sign proof for validator");
            }
        }
    }

    // ─── Proof engine event monitoring (new) ────────────────────────────

    /// Monitor proof engine SSE events for proof completion, failure, and timeouts.
    async fn monitor_proof_engine_events_task(self: Arc<Self>) {
        info!("Starting proof engine event monitoring via SSE");

        loop {
            let mut stream = self.proof_engine.subscribe_proof_events(None);

            loop {
                tokio::select! {
                    event = stream.next() => {
                        match event {
                            Some(Ok(proof_event)) => {
                                self.handle_proof_engine_event(proof_event).await;
                            }
                            Some(Err(e)) => {
                                warn!(error = %e, "Proof engine SSE error, will reconnect");
                                break;
                            }
                            None => {
                                warn!("Proof engine SSE stream ended, reconnecting...");
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep(PROOF_REQUEST_STALE_TIMEOUT) => {
                        self.cleanup_stale_requests();
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Process a single proof engine SSE event.
    async fn handle_proof_engine_event(&self, event: ProofEvent) {
        let root = event.new_payload_request_root();
        let proof_type = event.proof_type();

        // Only process events for tracked requests and requested proof types.
        let is_tracked = self
            .outstanding_requests
            .read()
            .get(&root)
            .map(|req| req.pending_proof_types.contains(&proof_type))
            .unwrap_or(false);

        if !is_tracked {
            return;
        }

        match event {
            ProofEvent::ProofComplete(complete) => {
                self.handle_proof_complete(complete.new_payload_request_root, complete.proof_type)
                    .await;
            }
            ProofEvent::ProofFailure(failure) => {
                warn!(
                    root = %failure.new_payload_request_root,
                    proof_type = failure.proof_type,
                    error = %failure.error,
                    "Proof generation failed"
                );
                self.remove_pending_proof_type(
                    failure.new_payload_request_root,
                    failure.proof_type,
                );
            }
            ProofEvent::WitnessTimeout(ref info) | ProofEvent::ProofTimeout(ref info) => {
                warn!(
                    root = %info.new_payload_request_root,
                    proof_type = info.proof_type,
                    "Proof generation timed out"
                );
                self.remove_pending_proof_type(info.new_payload_request_root, info.proof_type);
            }
        }
    }

    /// Fetch a completed proof from the proof engine, sign it, and submit to the beacon node.
    async fn handle_proof_complete(&self, root: Hash256, proof_type: u8) {
        // Download proof bytes from proof engine.
        let proof_bytes = match self.proof_engine.get_proof(root, proof_type).await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!(root = %root, proof_type, error = ?e, "Failed to fetch completed proof");
                return;
            }
        };

        // Construct ExecutionProof.
        let proof_data = match ProofData::new(proof_bytes.to_vec()) {
            Ok(data) => data,
            Err(e) => {
                error!(root = %root, proof_type, error = ?e, "Proof data exceeds max size");
                return;
            }
        };

        let execution_proof = ExecutionProof {
            proof_data,
            proof_type,
            public_input: PublicInput {
                new_payload_request_root: root,
            },
        };

        // Derive signing epoch from the stored slot.
        let epoch = self
            .outstanding_requests
            .read()
            .get(&root)
            .map(|req| req.slot.epoch(S::E::slots_per_epoch()));

        let Some(epoch) = epoch else {
            // Entry was removed (e.g. by stale cleanup) between the is_tracked check
            // and here — nothing to do.
            return;
        };

        // Resolve a safe validator for signing.
        let Some(pubkey) = self
            .validator_store
            .voting_pubkeys::<Vec<_>, _>(DoppelgangerStatus::only_safe)
            .first()
            .cloned()
        else {
            warn!("No safe validators available to sign completed proof");
            return;
        };

        // Sign and submit.
        match self
            .validator_store
            .sign_execution_proof(pubkey, execution_proof, epoch)
            .await
        {
            Ok(signed_proof) => {
                match self
                    .beacon_nodes
                    .first_success(move |node| {
                        let proof = signed_proof.clone();
                        async move { node.post_beacon_execution_proofs(&[proof]).await }
                    })
                    .await
                {
                    Ok(_) => {
                        info!(root = %root, proof_type, ?pubkey, "Completed proof signed and submitted");
                    }
                    Err(e) => {
                        warn!(root = %root, proof_type, error = %e, "Failed to submit completed proof");
                    }
                }
            }
            Err(e) => {
                warn!(root = %root, proof_type, error = ?e, "Failed to sign completed proof");
            }
        }

        // Remove this proof type from the outstanding set.
        self.remove_pending_proof_type(root, proof_type);
    }

    // ─── Outstanding request management ─────────────────────────────────

    /// Remove a single proof type from an outstanding request.
    ///
    /// If all requested proof types have been resolved the entry is removed entirely.
    fn remove_pending_proof_type(&self, root: Hash256, proof_type: u8) {
        let mut requests = self.outstanding_requests.write();
        if let Some(entry) = requests.get_mut(&root) {
            entry.pending_proof_types.remove(&proof_type);
            if entry.pending_proof_types.is_empty() {
                requests.remove(&root);
                debug!(root = %root, "All proof types resolved, removing from tracker");
            }
        }
    }

    /// Remove outstanding requests that have exceeded the stale timeout.
    fn cleanup_stale_requests(&self) {
        let mut requests = self.outstanding_requests.write();
        let before = requests.len();
        requests.retain(|root, req| {
            let stale = req.requested_at.elapsed() > PROOF_REQUEST_STALE_TIMEOUT;
            if stale {
                warn!(root = %root, "Removing stale proof request (timed out)");
            }
            !stale
        });
        let removed = before - requests.len();
        if removed > 0 {
            info!(removed, "Cleaned up stale proof requests");
        }
    }

    // ─── Reactive signing (existing) ────────────────────────────────────

    /// Reactive: Sign and submit proof (called by HTTP API)
    async fn sign_and_submit_proof(
        &self,
        pubkey: PublicKey,
        execution_proof: ExecutionProof,
        epoch: Option<Epoch>,
    ) -> Result<(), String> {
        // Determine epoch for signing context
        let epoch = epoch.unwrap_or_else(|| {
            self.slot_clock
                .now()
                .map(|slot| slot.epoch(S::E::slots_per_epoch()))
                .unwrap_or(Epoch::new(0))
        });

        let pubkey_bytes = pubkey.clone();
        info!(
            validator = %pubkey,
            %epoch,
            "Signing execution proof"
        );

        // Sign the proof
        let signed_proof = self
            .validator_store
            .sign_execution_proof(pubkey_bytes.into(), execution_proof, epoch)
            .await
            .map_err(|e| format!("Failed to sign execution proof: {:?}", e))?;

        // Submit to beacon node
        let signed_proof_for_submission = signed_proof.clone();
        self.beacon_nodes
            .first_success(move |node| {
                let proof_clone = signed_proof_for_submission.clone();
                async move { node.post_beacon_execution_proofs(&[proof_clone]).await }
            })
            .await
            .map_err(|e| format!("Failed to submit proof to beacon node: {}", e))?;

        info!(
            validator = %pubkey,
            "Successfully submitted signed execution proof to beacon node"
        );

        Ok(())
    }
}

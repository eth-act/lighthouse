//! EIP-8025 Execution Proof Service
//!
//! This service handles proactive, reactive, and resigning execution proof workflows:
//!
//! 1. **Proactive Mode**: Monitors beacon chain for new blocks via SSE and requests
//!    proofs from the configured proof engine
//! 2. **Reactive Mode**: Receives proof requests from HTTP API (proof engine callbacks)
//!    and signs/submits them to the beacon chain
//! 3. **Resigning Mode**: Subscribes to `execution_proof_validated` SSE events and
//!    resigns validated proofs with each local validator's key

use beacon_node_fallback::BeaconNodeFallback;
use bls::PublicKey;
use eth2::types::{EventKind, EventTopic, SseExecutionProofValidated};
use execution_layer::NewPayloadRequest;
use execution_layer::eip8025::{HttpProofEngine, ProofEngine};
use futures::StreamExt;
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use task_executor::TaskExecutor;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use types::execution::eip8025::ProofAttributes;
use types::{BeaconBlock, Epoch, EthSpec, ExecutionProof, Hash256};
use validator_store::{DoppelgangerStatus, ValidatorStore};

use bls::PublicKeyBytes;

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
    /// Tracks (validator_pubkey, new_payload_request_root) to prevent resigning loops.
    resigned_proofs: RwLock<HashMap<(PublicKeyBytes, Hash256), Instant>>,
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
                resigned_proofs: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// Start the proof service background tasks
    pub fn start_service(self: Arc<Self>) -> Result<(), String> {
        // Proactive: monitor blocks for proof requests
        let inner = self.inner.clone();
        self.inner
            .executor
            .spawn(async move { inner.monitor_blocks_task().await }, "proof_service_monitor");

        // Resigning: monitor validated proofs and resign with local validator keys
        let inner2 = self.inner.clone();
        self.inner
            .executor
            .spawn(async move { inner2.monitor_validated_proofs_task().await }, "proof_service_resigning");

        info!("Proof service started - monitoring for new blocks and validated proofs");

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
    /// Proactive: Monitor beacon node for new blocks and request proofs
    async fn monitor_blocks_task(self: Arc<Self>) {
        info!("Starting proof service block monitoring via SSE");

        loop {
            // Attempt to subscribe to block events from beacon node
            match self.subscribe_to_blocks().await {
                Ok(mut stream) => {
                    info!("Successfully subscribed to block events");

                    // Process events from the stream
                    while let Some(event_result) = stream.next().await {
                        match event_result {
                            Ok(eth2::types::EventKind::BlockFull(block_event)) => {
                                let block = block_event.data;
                                if block.execution_optimistic {
                                    debug!(
                                        slot = block.slot.as_u64(),
                                        "Received execution optimistic block event"
                                    );
                                }
                                self.handle_block_event(&block.block, block.slot).await;
                            }
                            Ok(_) => {
                                // Ignore other event types (shouldn't happen with our topic filter)
                                debug!("Received non-block event in block_full stream");
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "Error receiving block event, will reconnect"
                                );
                                break; // Break inner loop to reconnect
                            }
                        }
                    }

                    // Stream ended or errored - reconnect
                    warn!("Block event stream ended, reconnecting...");
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "Failed to subscribe to block events, retrying..."
                    );
                }
            }
        }
    }

    /// Resigning: Monitor validated proofs and resign with local validator keys
    async fn monitor_validated_proofs_task(self: Arc<Self>) {
        info!("Starting proof resigning service via SSE");

        loop {
            match self.subscribe_to_validated_proofs().await {
                Ok(mut stream) => {
                    info!("Subscribed to execution_proof_validated events");

                    while let Some(event_result) = stream.next().await {
                        match event_result {
                            Ok(EventKind::ExecutionProofValidated(proof_event)) => {
                                self.handle_validated_proof(proof_event).await;
                            }
                            Ok(_) => {
                                debug!("Received non-proof event in validated proof stream");
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "Error receiving proof event, will reconnect"
                                );
                                break;
                            }
                        }
                    }

                    warn!("Validated proof event stream ended, reconnecting...");
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "Failed to subscribe to proof events, retrying..."
                    );
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Helper method to establish SSE subscription with beacon node fallback
    async fn subscribe_to_blocks(
        &self,
    ) -> Result<
        impl futures::Stream<Item = Result<eth2::types::EventKind<S::E>, eth2::Error>>,
        String,
    > {
        self.beacon_nodes
            .first_success(
                |node| async move { node.get_events::<S::E>(&[EventTopic::BlockFull]).await },
            )
            .await
            .map_err(|e| format!("All beacon nodes failed to provide event stream: {}", e))
    }

    /// Helper method to establish SSE subscription for validated proof events
    async fn subscribe_to_validated_proofs(
        &self,
    ) -> Result<
        impl futures::Stream<Item = Result<eth2::types::EventKind<S::E>, eth2::Error>>,
        String,
    > {
        self.beacon_nodes
            .first_success(|node| async move {
                node.get_events::<S::E>(&[EventTopic::ExecutionProofValidated])
                    .await
            })
            .await
            .map_err(|e| format!("All beacon nodes failed to provide event stream: {}", e))
    }

    /// Handle a new block event by requesting proofs from proof engine
    async fn handle_block_event(&self, block: &BeaconBlock<S::E>, slot: types::Slot) {
        let block_root = block.canonical_root();

        info!(
            slot = slot.as_u64(),
            block = %block_root,
            "New block detected, requesting proofs from proof engine"
        );

        // Construct NewPayloadRequest from beacon block
        let new_payload_request = match NewPayloadRequest::try_from(block.to_ref()) {
            Ok(req) => req,
            Err(e) => {
                error!(
                    error = ?e,
                    block = %block_root,
                    "Failed to construct NewPayloadRequest from block"
                );
                return;
            }
        };

        // Use configured proof types
        let proof_attributes = ProofAttributes {
            proof_types: self.proof_types.clone(),
        };

        // Request proofs from proof engine - HttpProofEngine handles JSON serialization
        match self
            .proof_engine
            .request_proofs(new_payload_request, proof_attributes)
            .await
        {
            Ok(proof_gen_id) => {
                debug!(
                    proof_gen_id = ?proof_gen_id,
                    block = %block_root,
                    "Proof generation requested, awaiting callback to HTTP API"
                );
            }
            Err(e) => {
                error!(
                    error = ?e,
                    block = %block_root,
                    "Failed to request proofs from proof engine"
                );
            }
        }
    }

    /// Handle a validated proof event by resigning with each local validator key
    async fn handle_validated_proof(&self, event: SseExecutionProofValidated) {
        let execution_proof = event.execution_proof;
        let request_root = execution_proof.public_input.new_payload_request_root;

        let epoch = self
            .slot_clock
            .now()
            .map(|slot| slot.epoch(S::E::slots_per_epoch()))
            .unwrap_or(Epoch::new(0));

        // Get all validator pubkeys (non-slashable — bypass doppelganger)
        let all_pubkeys: Vec<PublicKeyBytes> =
            self.validator_store.voting_pubkeys(DoppelgangerStatus::ignored);

        for pubkey in all_pubkeys {
            // Dedup: skip if this validator already resigned this proof
            let dedup_key = (pubkey, request_root);
            {
                let cache = self.resigned_proofs.read().await;
                if cache.contains_key(&dedup_key) {
                    debug!(
                        ?pubkey,
                        ?request_root,
                        "Skipping already-resigned proof"
                    );
                    continue;
                }
            }

            // Sign the proof with this validator's key
            match self
                .validator_store
                .sign_execution_proof(pubkey, execution_proof.clone(), epoch)
                .await
            {
                Ok(signed_proof) => {
                    let signed_proof_clone = signed_proof.clone();
                    match self
                        .beacon_nodes
                        .first_success(move |node| {
                            let proof = signed_proof_clone.clone();
                            async move { node.post_beacon_execution_proofs(&[proof]).await }
                        })
                        .await
                    {
                        Ok(_) => {
                            info!(
                                ?pubkey,
                                ?request_root,
                                "Resigned proof submitted"
                            );
                            self.resigned_proofs
                                .write()
                                .await
                                .insert(dedup_key, Instant::now());
                        }
                        Err(e) => {
                            warn!(
                                ?pubkey,
                                error = %e,
                                "Failed to submit resigned proof"
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        ?pubkey,
                        error = ?e,
                        "Failed to sign proof for validator"
                    );
                }
            }
        }

        // Periodic cache pruning (entries older than ~2 epochs ≈ 12.8 min)
        self.prune_resigned_cache().await;
    }

    /// Remove expired entries from the dedup cache
    async fn prune_resigned_cache(&self) {
        let cutoff = Instant::now() - Duration::from_secs(768);
        let mut cache = self.resigned_proofs.write().await;
        cache.retain(|_, timestamp| *timestamp > cutoff);
    }

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

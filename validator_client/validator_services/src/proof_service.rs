//! EIP-8025 Execution Proof Service
//!
//! This service handles both proactive and reactive execution proof workflows:
//!
//! 1. **Proactive Mode**: Monitors beacon chain for new blocks via SSE and requests
//!    proofs from the configured proof engine
//! 2. **Reactive Mode**: Receives proof requests from HTTP API (proof engine callbacks)
//!    and signs/submits them to the beacon chain
//!
//! The service bridges the gap between external proof engines, validator keys, and
//! beacon nodes, providing a complete end-to-end execution proof flow.

use beacon_node_fallback::BeaconNodeFallback;
use bls::PublicKey;
use eth2::types::EventTopic;
use execution_layer::NewPayloadRequest;
use execution_layer::eip8025::{HttpProofEngine, ProofEngine};
use futures::StreamExt;
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tracing::{debug, error, info, warn};
use types::execution::eip8025::ProofAttributes;
use types::{BeaconBlock, Epoch, EthSpec, ExecutionProof};
use validator_store::ValidatorStore;

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
            }),
        }
    }

    /// Start the proof service background task (proactive monitoring)
    pub fn start_service(self: Arc<Self>) -> Result<(), String> {
        // Only start monitoring if proof engine is configured
        let inner = self.inner.clone();
        let service_fut = async move {
            inner.monitor_blocks_task().await;
        };
        self.inner
            .executor
            .spawn(service_fut, "proof_service_monitor");

        info!("Proof service started - monitoring for new blocks");

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
                                if block_event.execution_optimistic {
                                    debug!(
                                        slot = block_event.slot.as_u64(),
                                        "Received execution optimistic block event"
                                    );
                                }
                                self.handle_block_event(&block_event.block, block_event.slot)
                                    .await;
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

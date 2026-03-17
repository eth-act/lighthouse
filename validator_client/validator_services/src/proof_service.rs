//! EIP-8025 Execution Proof Service
//!
//! This service handles execution proof requests, signing and resigning workflows.

use beacon_node_fallback::BeaconNodeFallback;
use bls::PublicKey;
use eth2::types::{BlockId, EventKind, EventTopic, SseExecutionProofValidated};
use execution_layer::NewPayloadRequest;
use execution_layer::eip8025::{HttpProofEngine, ProofEngine};
use futures::StreamExt;
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tracing::{debug, error, info, warn};
use types::execution::eip8025::ProofAttributes;
use types::{Epoch, EthSpec, ExecutionProof, Hash256};
use validator_store::{DoppelgangerStatus, ValidatorStore};

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

    /// Start the proof service background tasks
    pub fn start_service(self: Arc<Self>) -> Result<(), String> {
        let inner = self.inner.clone();
        self.inner.executor.spawn(
            async move { inner.monitor_events_task().await },
            "proof_service_monitor",
        );
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

    /// Handle a new block event by fetching the full block via RPC then requesting proofs
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
            Ok(proof_gen_id) => {
                debug!(
                    proof_gen_id = ?proof_gen_id,
                    block = %block_root,
                    "Proof generation requested, awaiting callback to HTTP API"
                );
            }
            Err(e) => {
                error!(block = %block_root, error = ?e, "Failed to request proofs from proof engine");
            }
        }
    }

    /// Handle a validated proof event by resigning with the first local validator key
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

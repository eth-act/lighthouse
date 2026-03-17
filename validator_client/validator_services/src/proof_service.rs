//! EIP-8025 Execution Proof Service
//!
//! This service handles both proactive and reactive execution proof workflows:
//!
//! 1. **Proactive Mode**: Monitors beacon chain for new blocks via SSE, requests
//!    proofs from the proof engine, subscribes to proof completion events via SSE,
//!    downloads completed proofs, signs them, and submits to the beacon chain.
//! 2. **Reactive Mode**: Receives proof requests from HTTP API and signs/submits
//!    them to the beacon chain.
//!
//! The service bridges the gap between external proof engines, validator keys, and
//! beacon nodes, providing a complete end-to-end execution proof flow.

use beacon_node_fallback::BeaconNodeFallback;
use bls::{PublicKey, PublicKeyBytes};
use eth2::types::EventTopic;
use execution_layer::NewPayloadRequest;
use execution_layer::eip8025::{HttpProofEngine, ProofEngine, ProofEvent};
use futures::StreamExt;
use slot_clock::SlotClock;
use ssz_types::VariableList;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tracing::{debug, error, info, warn};
use types::execution::eip8025::{ProofAttributes, PublicInput};
use types::{BeaconBlock, Epoch, EthSpec, ExecutionProof, Hash256};
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

    /// Start the proof service background task (proactive monitoring)
    pub fn start_service(self: Arc<Self>) -> Result<(), String> {
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

    /// Public method called by HTTP API when externally-submitted proofs arrive.
    ///
    /// This is the reactive endpoint that receives proofs and signs them with
    /// validator keys before submitting to beacon nodes.
    pub async fn handle_proof_request(
        &self,
        pubkey: PublicKey,
        execution_proof: ExecutionProof,
        epoch: Option<Epoch>,
    ) -> Result<(), String> {
        self.inner
            .sign_and_submit_proof(pubkey.into(), execution_proof, epoch)
            .await
    }
}

impl<S: ValidatorStore + 'static, T: 'static + SlotClock + Clone> Inner<S, T> {
    /// Proactive: Monitor beacon node for new blocks and request proofs
    async fn monitor_blocks_task(self: Arc<Self>) {
        info!("Starting proof service block monitoring via SSE");

        loop {
            match self.subscribe_to_blocks().await {
                Ok(mut stream) => {
                    info!("Successfully subscribed to block events");

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
                                self.clone()
                                    .handle_block_event(&block.block, block.slot)
                                    .await;
                            }
                            Ok(_) => {
                                debug!("Received non-block event in block_full stream");
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "Error receiving block event, will reconnect"
                                );
                                break;
                            }
                        }
                    }

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

    /// Handle a new block event by requesting proofs and subscribing to SSE events
    async fn handle_block_event(self: Arc<Self>, block: &BeaconBlock<S::E>, slot: types::Slot) {
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

        let proof_attributes = ProofAttributes {
            proof_types: self.proof_types.clone(),
        };

        // Request proofs from proof engine via REST+SSZ API
        let new_payload_request_root = match self
            .proof_engine
            .request_proofs(new_payload_request, proof_attributes.clone())
            .await
        {
            Ok(root) => {
                debug!(
                    %root,
                    block = %block_root,
                    "Proof generation requested via REST API"
                );
                root
            }
            Err(e) => {
                error!(
                    error = ?e,
                    block = %block_root,
                    "Failed to request proofs from proof engine"
                );
                return;
            }
        };

        // Spawn a task to subscribe to SSE events and handle proof completion
        let inner = self.clone();
        let proof_types = proof_attributes.proof_types.clone();
        self.executor.spawn(
            async move {
                inner
                    .handle_proof_events(new_payload_request_root, proof_types)
                    .await;
            },
            "proof_event_handler",
        );
    }

    /// Subscribe to SSE proof events and handle completed proofs
    async fn handle_proof_events(
        self: Arc<Self>,
        new_payload_request_root: Hash256,
        expected_proof_types: Vec<u8>,
    ) {
        let mut stream = self
            .proof_engine
            .subscribe_proof_events(Some(new_payload_request_root));
        let mut remaining: std::collections::HashSet<u8> =
            expected_proof_types.into_iter().collect();

        while !remaining.is_empty() {
            let Some(event_result) = stream.next().await else {
                warn!(
                    %new_payload_request_root,
                    "Proof event stream ended before all proofs received"
                );
                break;
            };

            let event = match event_result {
                Ok(event) => event,
                Err(e) => {
                    warn!(
                        %new_payload_request_root,
                        error = %e,
                        "Error receiving proof event"
                    );
                    break;
                }
            };

            remaining.remove(&event.proof_type());

            match event {
                ProofEvent::ProofComplete(proof_complete) => {
                    info!(
                        %new_payload_request_root,
                        proof_type = proof_complete.proof_type,
                        "Proof complete, downloading and submitting"
                    );

                    if let Err(e) = self
                        .download_sign_and_submit(
                            new_payload_request_root,
                            proof_complete.proof_type,
                        )
                        .await
                    {
                        error!(
                            %new_payload_request_root,
                            proof_type = proof_complete.proof_type,
                            error = %e,
                            "Failed to process completed proof"
                        );
                    }
                }
                ProofEvent::ProofFailure(failure) => {
                    warn!(
                        %new_payload_request_root,
                        proof_type = failure.proof_type,
                        error = %failure.error,
                        "Proof generation failed"
                    );
                }
                ProofEvent::WitnessTimeout(info) => {
                    warn!(
                        %new_payload_request_root,
                        proof_type = info.proof_type,
                        "Witness fetch timed out"
                    );
                }
                ProofEvent::ProofTimeout(info) => {
                    warn!(
                        %new_payload_request_root,
                        proof_type = info.proof_type,
                        "Proof generation timed out"
                    );
                }
            }
        }

        info!(
            %new_payload_request_root,
            "All proof events processed"
        );
    }

    /// Download a completed proof, construct an ExecutionProof, sign it, and submit
    async fn download_sign_and_submit(
        &self,
        new_payload_request_root: Hash256,
        proof_type: u8,
    ) -> Result<(), String> {
        // Download proof bytes from proof engine
        let proof_bytes = self
            .proof_engine
            .get_proof(new_payload_request_root, proof_type)
            .await
            .map_err(|e| format!("Failed to download proof: {e}"))?;

        // Construct ExecutionProof
        let execution_proof = ExecutionProof {
            proof_data: VariableList::new(proof_bytes.to_vec())
                .map_err(|e| format!("Proof data too large: {e:?}"))?,
            proof_type,
            public_input: PublicInput {
                new_payload_request_root,
            },
        };

        // Select first available validator for signing
        let all_pubkeys: Vec<_> = self
            .validator_store
            .voting_pubkeys(DoppelgangerStatus::ignored);
        let pubkey = all_pubkeys
            .into_iter()
            .next()
            .ok_or_else(|| "No validators available for proof signing".to_string())?;

        self.sign_and_submit_proof(pubkey, execution_proof, None)
            .await
    }

    /// Sign and submit proof (called by HTTP API or SSE handler)
    async fn sign_and_submit_proof(
        &self,
        pubkey: PublicKeyBytes,
        execution_proof: ExecutionProof,
        epoch: Option<Epoch>,
    ) -> Result<(), String> {
        let epoch = epoch.unwrap_or_else(|| {
            self.slot_clock
                .now()
                .map(|slot| slot.epoch(S::E::slots_per_epoch()))
                .unwrap_or(Epoch::new(0))
        });

        info!(
            validator = %pubkey,
            %epoch,
            "Signing execution proof"
        );

        let signed_proof = self
            .validator_store
            .sign_execution_proof(pubkey, execution_proof, epoch)
            .await
            .map_err(|e| format!("Failed to sign execution proof: {:?}", e))?;

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

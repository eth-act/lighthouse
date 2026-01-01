use clap::Parser;
use eth2::types::{BlockId, EventKind, EventTopic};
use eth2::{BeaconNodeHttpClient, Timeouts};
use futures::StreamExt;
use sensitive_url::SensitiveUrl;
use std::time::Duration;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, info, warn};
use types::{ExecPayload, ExecutionBlockHash, ExecutionProofId, Hash256, MainnetEthSpec, Slot};
use zkvm_execution_layer::dummy_proof_gen::DummyProofGenerator;
use zkvm_execution_layer::proof_generation::ProofGenerator;

const DEFAULT_TIMEOUT_SECS: u64 = 12;

/// Generate and submit dummy execution proofs to a beacon node.
#[derive(Parser, Debug)]
#[command(name = "dummy-prover")]
struct Cli {
    /// Beacon node HTTP endpoint to submit proofs to.
    #[arg(long, default_value = "http://localhost:5052")]
    beacon_node: String,

    /// Beacon node HTTP endpoint to source blocks from (defaults to --beacon-node).
    #[arg(long)]
    source_beacon_node: Option<String>,

    /// Number of proof IDs to submit per block (max 8).
    #[arg(long, default_value_t = 1)]
    proofs_per_block: usize,

    /// Delay in milliseconds to simulate proof generation time.
    #[arg(long, default_value_t = 1000)]
    proof_delay_ms: u64,

    /// Start backfill when sync_distance is >= this many slots.
    #[arg(long, default_value_t = 32)]
    backfill_threshold_slots: u64,

    /// Backfill check interval in seconds.
    #[arg(long, default_value_t = 10)]
    backfill_interval_secs: u64,
}

#[derive(Clone, Copy)]
struct BlockProofInputs {
    slot: Slot,
    block_root: Hash256,
    block_hash: ExecutionBlockHash,
}

struct Prover {
    source: BeaconNodeHttpClient,
    target: BeaconNodeHttpClient,
    proof_ids: Vec<ExecutionProofId>,
    proof_delay: Duration,
    backfill_threshold_slots: u64,
}

impl Prover {
    async fn handle_block_gossip(&self, block_root: Hash256, slot: Slot) {
        let Some(inputs) = self
            .fetch_block_for_proofs(BlockId::Root(block_root), Some(slot))
            .await
        else {
            return;
        };

        if inputs.block_root != block_root {
            debug!(
                expected = ?block_root,
                actual = ?inputs.block_root,
                "Block root mismatch"
            );
        }

        self.submit_dummy_proofs(inputs).await;
    }

    async fn backfill_missing_slots(&self) {
        if self.backfill_threshold_slots == 0 {
            return;
        }

        let syncing = match self.target.get_node_syncing().await {
            Ok(response) => response.data,
            Err(err) => {
                warn!(error = ?err, "Failed to query target sync status");
                return;
            }
        };

        let sync_distance = syncing.sync_distance.as_u64();
        if sync_distance < self.backfill_threshold_slots {
            return;
        }

        let slots_to_backfill = sync_distance.min(self.backfill_threshold_slots);
        let head_slot = syncing.head_slot;
        info!(
            ?head_slot,
            sync_distance, slots_to_backfill, "Backfilling dummy proofs"
        );

        for offset in 1..=slots_to_backfill {
            let slot = head_slot.saturating_add(Slot::new(offset));
            let Some(inputs) = self
                .fetch_block_for_proofs(BlockId::Slot(slot), Some(slot))
                .await
            else {
                continue;
            };

            self.submit_dummy_proofs(inputs).await;
        }
    }

    async fn submit_dummy_proofs(&self, inputs: BlockProofInputs) {
        let BlockProofInputs {
            slot,
            block_root,
            block_hash,
        } = inputs;

        for proof_id in &self.proof_ids {
            let generator = DummyProofGenerator::with_delay(*proof_id, self.proof_delay);
            let proof = match generator.generate(slot, &block_hash, &block_root).await {
                Ok(proof) => proof,
                Err(err) => {
                    warn!(
                        ?block_root,
                        ?slot,
                        ?proof_id,
                        error = ?err,
                        "Failed to build dummy proof"
                    );
                    continue;
                }
            };

            if let Err(err) = self.target.post_beacon_pool_execution_proofs(&proof).await {
                debug!(
                    ?block_root,
                    ?slot,
                    ?proof_id,
                    error = ?err,
                    "Failed to submit dummy proof"
                );
            } else {
                debug!(?block_root, ?slot, ?proof_id, "Submitted dummy proof");
            }
        }
    }

    async fn fetch_block_for_proofs(
        &self,
        block_id: BlockId,
        slot_hint: Option<Slot>,
    ) -> Option<BlockProofInputs> {
        let block = match self
            .source
            .get_beacon_blinded_blocks::<MainnetEthSpec>(block_id)
            .await
        {
            Ok(Some(response)) => response,
            Ok(None) => {
                debug!(?block_id, ?slot_hint, "Block not found in source node");
                return None;
            }
            Err(err) => {
                warn!(?block_id, ?slot_hint, error = ?err, "Failed to fetch block");
                return None;
            }
        };

        let block = block.data();
        let slot = block.slot();
        if let Some(expected_slot) = slot_hint {
            if slot != expected_slot {
                debug!(
                    ?block_id,
                    expected = ?expected_slot,
                    actual = ?slot,
                    "Block slot mismatch"
                );
            }
        }

        let Ok(payload) = block.message().body().execution_payload() else {
            debug!(?block_id, ?slot, "Block has no execution payload");
            return None;
        };

        Some(BlockProofInputs {
            slot,
            block_root: block.canonical_root(),
            block_hash: payload.block_hash(),
        })
    }
}

fn build_proof_ids(count: usize) -> Vec<ExecutionProofId> {
    let mut ids = ExecutionProofId::all();
    ids.truncate(count.min(ids.len()));
    ids
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("dummy_prover=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    let target_url = SensitiveUrl::parse(&cli.beacon_node)?;
    let source_url = SensitiveUrl::parse(
        cli.source_beacon_node
            .as_deref()
            .unwrap_or(&cli.beacon_node),
    )?;

    let timeouts = Timeouts::set_all(Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    let target = BeaconNodeHttpClient::new(target_url, timeouts.clone());
    let source = BeaconNodeHttpClient::new(source_url, timeouts);

    let proof_ids = build_proof_ids(cli.proofs_per_block);
    if proof_ids.is_empty() {
        warn!("No proof IDs configured, exiting");
        return Ok(());
    }

    let prover = Prover {
        source,
        target,
        proof_ids,
        proof_delay: Duration::from_millis(cli.proof_delay_ms),
        backfill_threshold_slots: cli.backfill_threshold_slots,
    };

    info!(
        target = %cli.beacon_node,
        source = %prover.source.server(),
        proofs_per_block = prover.proof_ids.len(),
        proof_delay_ms = cli.proof_delay_ms,
        backfill_threshold_slots = prover.backfill_threshold_slots,
        "Starting dummy prover"
    );

    let mut events = prover
        .source
        .get_events::<MainnetEthSpec>(&[EventTopic::BlockGossip])
        .await
        .map_err(|e| format!("Failed to subscribe to events: {:?}", e))?;
    let mut backfill_interval = interval(Duration::from_secs(cli.backfill_interval_secs));
    backfill_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown requested");
                break;
            }
            _ = backfill_interval.tick() => {
                prover.backfill_missing_slots().await;
            }
            maybe_event = events.next() => {
                let Some(event) = maybe_event else {
                    warn!("Event stream ended");
                    break;
                };
                match event {
                    Ok(EventKind::BlockGossip(gossip)) => {
                        prover.handle_block_gossip(gossip.block, gossip.slot).await;
                    }
                    Ok(_) => {}
                    Err(err) => {
                        warn!(error = ?err, "Event stream error");
                    }
                }
            }
        }
    }

    Ok(())
}

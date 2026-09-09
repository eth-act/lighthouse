//! Tests for beacon chains built without an execution layer (proof-only nodes).

use beacon_chain::graffiti_calculator::GraffitiSettings;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType, test_spec};
use beacon_chain::{BeaconChainError, BlockProductionError, ProduceBlockVerification};
use bls::Keypair;
use eth2::types::BlockProductionVersion;
use proof_engine::{ProofEngine, test_utils::MockProofEngine};
use std::sync::Arc;
use std::sync::LazyLock;
use types::{ChainSpec, MinimalEthSpec};

type E = MinimalEthSpec;

const VALIDATOR_COUNT: usize = 32;

static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

/// `test_spec` starts at Bellatrix or later, so execution is always enabled in these harnesses.
fn spec() -> Arc<ChainSpec> {
    Arc::new(test_spec::<E>())
}

fn harness_builder() -> BeaconChainHarness<EphemeralHarnessType<E>> {
    BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec())
        .keypairs(KEYPAIRS.clone())
        .fresh_ephemeral_store()
        .build()
}

/// A proof-only harness: no execution layer, but a proof engine to verify execution proofs.
fn proof_only_harness() -> BeaconChainHarness<EphemeralHarnessType<E>> {
    BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec())
        .keypairs(KEYPAIRS.clone())
        .fresh_ephemeral_store()
        .proof_engine(Some(ProofEngine::new(MockProofEngine::default())))
        .build()
}

/// An ordinary execution-layer-backed harness.
fn execution_backed_harness() -> BeaconChainHarness<EphemeralHarnessType<E>> {
    BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec())
        .keypairs(KEYPAIRS.clone())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build()
}

#[tokio::test]
async fn proof_only_chain_builds_without_execution_layer() {
    let harness = proof_only_harness();

    assert!(
        harness.chain.execution_layer.is_none(),
        "a proof-only chain has no execution layer"
    );
    assert!(
        harness.chain.proof_engine.is_some(),
        "a proof-only chain has a proof engine"
    );
}

#[tokio::test]
async fn execution_backed_chain_retains_execution_layer() {
    let harness = execution_backed_harness();

    assert!(
        harness.chain.execution_layer.is_some(),
        "an execution-layer-backed chain keeps its execution layer"
    );
    assert!(
        harness.chain.proof_engine.is_none(),
        "an execution-layer-backed chain has no proof engine by default"
    );
}

/// A proof-only node has no execution layer to be offline, so it must not report itself as such.
/// Validator clients refuse to use a node whose execution layer is offline.
#[tokio::test]
async fn proof_only_chain_is_not_execution_layer_offline() {
    let harness = proof_only_harness();

    assert!(!harness.chain.is_execution_layer_offline().await);
}

/// A chain with neither an execution layer nor a proof engine cannot validate execution at all,
/// so it reports itself as offline. `get_config` rejects that combination on a real node.
#[tokio::test]
async fn chain_without_any_execution_validation_is_offline() {
    let harness = harness_builder();

    assert!(harness.chain.is_execution_layer_offline().await);
}

/// An execution-layer-backed node reports the status of its engine, which is online here.
#[tokio::test]
async fn execution_backed_chain_reports_engine_status() {
    let harness = execution_backed_harness();
    harness
        .chain
        .execution_layer
        .as_ref()
        .expect("harness has an execution layer")
        .upcheck()
        .await;

    assert!(!harness.chain.is_execution_layer_offline().await);
}

/// Proposer preparation needs an engine to send payload attributes to. Without one it reports the
/// absence rather than panicking. The periodic callers skip it entirely.
#[tokio::test]
async fn prepare_beacon_proposer_reports_missing_execution_layer() {
    let harness = proof_only_harness();
    let current_slot = harness.chain.slot().expect("chain has a slot");

    assert!(
        !harness.chain.slot_is_prior_to_bellatrix(current_slot + 1),
        "test harness must have execution enabled"
    );
    assert!(matches!(
        harness.chain.prepare_beacon_proposer(current_slot).await,
        Err(BeaconChainError::ExecutionLayerMissing)
    ));
}

/// Block production needs an engine to build a payload. Without one it reports the absence rather
/// than producing a block with a placeholder payload.
#[tokio::test]
async fn block_production_reports_missing_execution_layer() {
    let harness = proof_only_harness();
    harness.advance_slot();
    let mut state = harness.get_current_state();
    state.build_caches(&harness.spec).expect("builds caches");

    let slot = harness.chain.slot().expect("chain has a slot");
    let proposer_index = state
        .get_beacon_proposer_index(slot, &harness.spec)
        .expect("has a proposer");
    let randao_reveal = harness.sign_randao_reveal(&state, proposer_index, slot);

    let result = harness
        .chain
        .produce_block_on_state(
            state,
            None,
            slot,
            randao_reveal,
            GraffitiSettings::Unspecified,
            ProduceBlockVerification::VerifyRandao,
            None,
            BlockProductionVersion::V3,
        )
        .await;

    match result {
        Err(BlockProductionError::ExecutionLayerMissing) => {}
        other => panic!(
            "unexpected block production result: {:?}",
            other.map(|_| ())
        ),
    }
}

/// Fork choice must not attempt to notify an engine that does not exist. `recompute_head_at_slot`
/// spawns the execution layer update task, which returns early on a proof-only node.
#[tokio::test]
async fn recompute_head_succeeds_without_execution_layer() {
    let harness = proof_only_harness();
    let slot = harness.chain.slot().expect("chain has a slot");

    harness.chain.recompute_head_at_slot(slot).await;
}

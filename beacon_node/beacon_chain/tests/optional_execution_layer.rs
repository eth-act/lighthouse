//! Tests for beacon chains built without an execution layer (proof-only nodes).

use beacon_chain::graffiti_calculator::GraffitiSettings;
use beacon_chain::pending_payload_cache::REQUIRED_EXECUTION_PROOFS;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType, test_spec};
use beacon_chain::{BeaconChainError, BlockProductionError, ProduceBlockVerification};
use bls::Keypair;
use eth2::types::BlockProductionVersion;
use proof_engine::{ProofEngine, test_utils::MockProofEngine};
use state_processing::state_advance::complete_state_advance;
use std::sync::Arc;
use std::sync::LazyLock;
use types::{ChainSpec, MinimalEthSpec};

type E = MinimalEthSpec;

const VALIDATOR_COUNT: usize = 32;

static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

/// Bellatrix or later, so execution is always enabled in these harnesses.
fn spec() -> Arc<ChainSpec> {
    Arc::new(test_spec::<E>())
}

/// A harness running both an execution engine and a proof engine.
fn engine_and_proof_engine_harness() -> BeaconChainHarness<EphemeralHarnessType<E>> {
    BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec())
        .keypairs(KEYPAIRS.clone())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .proof_engine(Some(ProofEngine::new(MockProofEngine::default())))
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

/// Reporting itself offline would make validator clients refuse the node.
#[tokio::test]
async fn proof_only_chain_is_not_execution_layer_offline() {
    let harness = proof_only_harness();

    assert!(!harness.chain.is_execution_layer_offline().await);
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

/// Only a node validating by proofs alone waits on them before importing a payload.
#[tokio::test]
async fn only_a_proof_only_node_gates_import_on_proofs() {
    assert_eq!(
        proof_only_harness()
            .chain
            .pending_payload_cache
            .required_execution_proofs(),
        REQUIRED_EXECUTION_PROOFS,
        "a proof-only node has nothing else to validate execution with"
    );
    assert_eq!(
        execution_backed_harness()
            .chain
            .pending_payload_cache
            .required_execution_proofs(),
        0,
        "an engine-backed node validates by re-execution"
    );
    assert_eq!(
        engine_and_proof_engine_harness()
            .chain
            .pending_payload_cache
            .required_execution_proofs(),
        0,
        "an engine still validates by re-execution when proofs are also verified"
    );
}

/// Without an engine there is nowhere to send payload attributes, so this reports the absence
/// rather than panicking. The periodic callers skip it entirely.
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

/// Local payload building needs an engine, so without one this reports the absence rather than
/// producing a placeholder.
///
/// Gloas is skipped for want of test setup, not because it behaves differently: this harness
/// fails earlier on the state variant.
#[tokio::test]
async fn block_production_reports_missing_execution_layer() {
    let harness = proof_only_harness();
    harness.advance_slot();
    let mut state = harness.get_current_state();
    let slot = harness.chain.slot().expect("chain has a slot");

    if harness.spec.fork_name_at_slot::<E>(slot).gloas_enabled() {
        return;
    }

    // Advance the state to the production slot, as the harness does before producing a block.
    complete_state_advance(&mut state, None, slot, None, &harness.spec)
        .expect("advances the state to the production slot");
    state.build_caches(&harness.spec).expect("builds caches");

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

/// Recomputing the head must not attempt to notify an engine that does not exist.
#[tokio::test]
async fn recompute_head_succeeds_without_execution_layer() {
    let harness = proof_only_harness();
    let slot = harness.chain.slot().expect("chain has a slot");

    harness.chain.recompute_head_at_slot(slot).await;
}

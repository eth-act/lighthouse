//! Scenario tests over several network configurations. Each one starts its own network; see
//! the crate documentation for how to run them.

use crate::{NodeSpec, ProofNetwork, ProofNetworkConfig, ProverSpec};
use std::time::Duration;
use tracing::info;
use types::Hash256;

const VALID_TYPE_1: &[u8] = b"execution_proof_network_tests: valid proof, type 1";
const VALID_TYPE_2: &[u8] = b"execution_proof_network_tests: valid proof, type 2";
const INVALID: &[u8] = b"execution_proof_network_tests: proof no engine accepts";
/// Validator whose deterministic key signs the proofs.
const PROVER: u64 = 0;
/// Validator used to show that a rejected proof does not suppress other provers.
const SECOND_PROVER: u64 = 1;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(20);
/// Peer score below which a node has applied at least one gossip penalty.
const PENALISED_SCORE: f64 = -5.0;

fn accepts_both() -> Vec<Vec<u8>> {
    vec![VALID_TYPE_1.to_vec(), VALID_TYPE_2.to_vec()]
}

fn both_types() -> Vec<(u8, Vec<u8>)> {
    vec![(1, VALID_TYPE_1.to_vec()), (2, VALID_TYPE_2.to_vec())]
}

/// Four nodes: a verifier (execution layer plus proof engine) that submits proofs, two
/// execution-layer nodes carrying the validators, and a proof-only node accepting
/// `proof_only_accepts`.
fn standard(proof_only_accepts: Vec<Vec<u8>>) -> ProofNetworkConfig {
    ProofNetworkConfig::new(vec![
        NodeSpec::verifier(accepts_both()),
        NodeSpec::plain().with_validators(),
        NodeSpec::plain().with_validators(),
        NodeSpec::proof_only(proof_only_accepts),
    ])
}

/// Six nodes: two verifiers, two validator nodes and two proof-only nodes.
fn large() -> ProofNetworkConfig {
    ProofNetworkConfig::new(vec![
        NodeSpec::verifier(accepts_both()),
        NodeSpec::plain().with_validators(),
        NodeSpec::plain().with_validators(),
        NodeSpec::verifier(accepts_both()),
        NodeSpec::proof_only(accepts_both()),
        NodeSpec::proof_only(accepts_both()),
    ])
}

/// Two nodes: one validator node and one proof-only node that is also the only verifier.
fn minimal() -> ProofNetworkConfig {
    ProofNetworkConfig::new(vec![
        NodeSpec::plain().with_validators(),
        NodeSpec::proof_only(accepts_both()),
    ])
}

/// Three nodes: a proving verifier with validators whose execution layer proves both types,
/// a plain validator node, and a proof-only node.
fn proving() -> ProofNetworkConfig {
    ProofNetworkConfig::new(vec![
        NodeSpec::verifier(accepts_both())
            .with_validators()
            .proving(ProverSpec {
                proofs: both_types(),
                validator_index: PROVER,
            }),
        NodeSpec::plain().with_validators(),
        NodeSpec::proof_only(accepts_both()),
    ])
}

/// Three nodes: two proving verifiers with validators, each proving one type with its own
/// validator key, and a proof-only node that needs both.
fn two_provers() -> ProofNetworkConfig {
    ProofNetworkConfig::new(vec![
        NodeSpec::verifier(accepts_both())
            .with_validators()
            .proving(ProverSpec {
                proofs: vec![(1, VALID_TYPE_1.to_vec())],
                validator_index: PROVER,
            }),
        NodeSpec::verifier(accepts_both())
            .with_validators()
            .proving(ProverSpec {
                proofs: vec![(2, VALID_TYPE_2.to_vec())],
                validator_index: SECOND_PROVER,
            }),
        NodeSpec::proof_only(accepts_both()),
    ])
}

/// Wait for genesis and connectivity, then for node `proof_only` to import at least
/// `payloads` payloads proved on the network. Returns the block root of the last one that both
/// the prover records and the proof-only node has imported.
async fn wait_for_proven_payloads(
    net: &ProofNetwork,
    provers: &[usize],
    proof_only: usize,
    payloads: usize,
) -> Result<Hash256, String> {
    net.wait_for_genesis().await?;
    let all: Vec<usize> = (0..net.node_count()).collect();
    net.wait_for_peers(&all, net.node_count() - 1, STARTUP_TIMEOUT)
        .await?;
    let slot_duration = net.slot_duration();
    let mut last = None;
    net.wait_for(
        &format!("node {proof_only} to import {payloads} proved payloads"),
        slot_duration * (payloads as u32 + 6) + STARTUP_TIMEOUT,
        |net| {
            let proven = net.proven_payloads(provers[0])?;
            let imported: Vec<Hash256> = proven
                .iter()
                .map(|payload| payload.block_root)
                .filter(|root| {
                    net.proof_status(proof_only, *root, 0)
                        .map(|status| status.payload_received)
                        .unwrap_or(false)
                })
                .collect();
            last = imported.last().copied();
            Ok(imported.len() >= payloads)
        },
    )
    .await?;
    last.ok_or("no proved payload imported".to_string())
}

/// Wait for genesis and full connectivity, then return the first full block: nodes with an
/// execution layer have imported its payload, every proof engine knows it, and the proof-only
/// node `proof_only` holds its envelope pending proofs.
async fn ready(net: &ProofNetwork, proof_only: usize) -> Result<Hash256, String> {
    net.wait_for_genesis().await?;
    let all: Vec<usize> = (0..net.node_count()).collect();
    net.wait_for_peers(&all, net.node_count() - 1, STARTUP_TIMEOUT)
        .await?;
    let block_root = net
        .wait_for_pending_payload(proof_only, STARTUP_TIMEOUT)
        .await?;
    let executing = net.nodes_where(|spec| spec.execution_layer);
    net.wait_for_payload_received(&executing, block_root, PROPAGATION_TIMEOUT)
        .await?;
    let verifying = net.nodes_where(|spec| spec.has_proof_engine());
    net.wait_for_block_known(&verifying, block_root, PROPAGATION_TIMEOUT)
        .await?;
    info!(?block_root, "Target block ready");
    Ok(block_root)
}

/// Nodes with an execution layer import payloads as soon as they execute them, whether or not
/// they run a proof engine; a proof-only node holds the envelope in its pending cache, unstored
/// and unimported, and stops following the chain until proofs arrive.
#[test]
#[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
fn execution_layer_nodes_import_payloads_while_proof_only_nodes_wait() {
    ProofNetwork::run(standard(accepts_both()), |net| async move {
        let block_root = ready(&net, 3).await?;

        for node in [0, 1, 2] {
            let status = net.proof_status(node, block_root, 1)?;
            assert_eq!(status.required_proofs, 0, "{status:?}");
            assert!(status.payload_received, "{status:?}");
            assert!(status.envelope_stored, "{status:?}");
        }
        let status = net.proof_status(3, block_root, 1)?;
        assert_eq!(status.required_proofs, 2, "{status:?}");
        assert!(status.block_known, "{status:?}");
        assert!(status.envelope_pending, "{status:?}");
        assert!(!status.envelope_stored, "{status:?}");
        assert!(!status.payload_received, "{status:?}");
        assert!(status.cached_proof_types.is_empty(), "{status:?}");

        // The validator nodes keep producing blocks; the proof-only node stays put.
        let stalled_slot = status.head_slot;
        net.wait_for_head_slot(1, stalled_slot + 2, PROPAGATION_TIMEOUT)
            .await?;
        let status = net.proof_status(3, block_root, 1)?;
        assert_eq!(status.head_slot, stalled_slot, "{status:?}");
        Ok(())
    })
    .unwrap()
}

/// End to end over the Beacon API: proofs of two types posted to node 0 are verified there,
/// propagate over gossip to the proof-only node, are verified, cached and retrievable on both,
/// and the second type unlocks the proof-only node's payload import.
#[test]
#[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
fn proofs_posted_to_the_beacon_api_reach_every_verifier_and_unlock_proof_only_import() {
    ProofNetwork::run(standard(accepts_both()), |net| async move {
        let block_root = ready(&net, 3).await?;

        let first = net.signed_execution_proof(0, block_root, 1, VALID_TYPE_1.to_vec(), PROVER)?;
        net.submit_execution_proof(0, first).await?;
        net.wait_for_valid_proof(&[0, 3], block_root, 1, PROPAGATION_TIMEOUT)
            .await?;
        net.wait_for_cached_proof_types(&[0, 3], block_root, &[1], PROPAGATION_TIMEOUT)
            .await?;
        let status = net.proof_status(3, block_root, 1)?;
        assert!(
            !status.payload_received,
            "one proof type must not unlock: {status:?}"
        );

        let second = net.signed_execution_proof(0, block_root, 2, VALID_TYPE_2.to_vec(), PROVER)?;
        net.submit_execution_proof(0, second).await?;
        net.wait_for_valid_proof(&[0, 3], block_root, 2, PROPAGATION_TIMEOUT)
            .await?;
        net.wait_for_cached_proof_types(&[0, 3], block_root, &[1, 2], PROPAGATION_TIMEOUT)
            .await?;
        net.wait_for_payload_received(&[3], block_root, PROPAGATION_TIMEOUT)
            .await?;
        let status = net.proof_status(3, block_root, 1)?;
        assert!(status.envelope_stored, "{status:?}");

        // Retrieval through the Beacon API serves the cached proofs on every proof engine.
        for node in [0, 3] {
            assert_eq!(
                net.retrieved_proof_types(node, block_root).await?,
                vec![1, 2]
            );
        }
        // Nodes without a proof engine neither see the topic nor serve the endpoint.
        for node in [1, 2] {
            for proof_type in [1, 2] {
                let status = net.proof_status(node, block_root, proof_type)?;
                assert!(!status.valid_proof_verified, "{status:?}");
                assert!(status.cached_proof_types.is_empty(), "{status:?}");
            }
            assert!(net.retrieved_proof_types(node, block_root).await.is_err());
        }
        Ok(())
    })
    .unwrap()
}

/// A proving execution layer proves every payload its node executes and posts the proofs to
/// the node's Beacon API, so a proof-only node keeps following the chain without any test
/// code submitting proofs.
#[test]
#[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
fn proving_execution_layer_keeps_a_proof_only_node_in_sync() {
    ProofNetwork::run(proving(), |net| async move {
        let block_root = wait_for_proven_payloads(&net, &[0], 2, 4).await?;

        let proven = net.proven_payloads(0)?;
        assert!(
            proven
                .iter()
                .all(|payload| payload.proof_types == vec![1, 2]),
            "{proven:?}"
        );
        for node in [0, 2] {
            net.wait_for_cached_proof_types(&[node], block_root, &[1, 2], PROPAGATION_TIMEOUT)
                .await?;
            assert_eq!(
                net.retrieved_proof_types(node, block_root).await?,
                vec![1, 2]
            );
        }
        let status = net.proof_status(2, block_root, 1)?;
        assert!(status.payload_received, "{status:?}");
        assert!(status.envelope_stored, "{status:?}");
        info!(
            proven = proven.len(),
            "Proving execution layer kept the proof-only node in sync"
        );
        Ok(())
    })
    .unwrap()
}

/// Two proving execution layers each supply one proof type from a different validator; the
/// proof-only node only imports once it holds both.
#[test]
#[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
fn proofs_from_two_provers_combine_to_unlock_import() {
    ProofNetwork::run(two_provers(), |net| async move {
        let block_root = wait_for_proven_payloads(&net, &[0, 1], 2, 3).await?;

        for (node, proof_type) in [(0, 1), (1, 2)] {
            let proven = net.proven_payloads(node)?;
            assert!(
                proven
                    .iter()
                    .all(|payload| payload.proof_types == vec![proof_type]),
                "{proven:?}"
            );
            assert!(
                proven
                    .iter()
                    .any(|payload| payload.block_root == block_root)
            );
        }
        net.wait_for_cached_proof_types(&[0, 1, 2], block_root, &[1, 2], PROPAGATION_TIMEOUT)
            .await?;
        let status = net.proof_status(2, block_root, 1)?;
        assert!(status.payload_received, "{status:?}");
        assert_eq!(net.retrieved_proof_types(2, block_root).await?, vec![1, 2]);
        Ok(())
    })
    .unwrap()
}

/// A proof-only node that joins a few slots behind uses lookup sync, whose envelopes go through
/// the proof gate. The proofs for those payloads were gossiped before it existed and nothing
/// re-serves them, so it stops at the first full block. Blocks after it are never admitted, so
/// the proofs it does receive for later payloads are dropped as unknown blocks, even though the
/// prover still serves the missed proofs over its Beacon API. Recursion-aware gating or proof
/// retrieval from peers would let it recover; this base has neither.
#[test]
#[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
fn late_joining_proof_only_node_stalls_on_proofs_it_missed() {
    let config = ProofNetworkConfig::new(vec![
        NodeSpec::verifier(accepts_both())
            .with_validators()
            .proving(ProverSpec {
                proofs: both_types(),
                validator_index: PROVER,
            }),
        NodeSpec::plain().with_validators(),
    ]);
    ProofNetwork::run(config, |mut net| async move {
        net.wait_for_genesis().await?;
        net.wait_for_peers(&[0, 1], 1, STARTUP_TIMEOUT).await?;
        net.wait_for(
            "the prover to prove three payloads",
            STARTUP_TIMEOUT,
            |net| Ok(net.proven_payloads(0)?.len() >= 3),
        )
        .await?;
        let first_proven = net.proven_payloads(0)?[0].block_root;
        let join_slot = net.head_slot(0)?;

        let joiner = net.add_node(NodeSpec::proof_only(accepts_both())).await?;
        net.wait_for_peers(&[joiner], 2, STARTUP_TIMEOUT).await?;

        // The joiner admits blocks up to the first full payload, which it cannot prove.
        let stalled_root = net
            .wait_for_pending_payload(joiner, STARTUP_TIMEOUT)
            .await?;
        assert_eq!(stalled_root, first_proven, "{}", net.describe());
        let stalled = net.proof_status(joiner, stalled_root, 1)?;
        assert!(stalled.head_slot < join_slot, "{stalled:?}");
        assert!(stalled.cached_proof_types.is_empty(), "{stalled:?}");

        // The prover keeps proving; the joiner does not move.
        net.wait_for_head_slot(0, join_slot + 4, STARTUP_TIMEOUT)
            .await?;
        let later = net.proof_status(joiner, stalled_root, 1)?;
        assert_eq!(later.head_slot, stalled.head_slot, "{later:?}");
        assert!(!later.payload_received, "{later:?}");
        assert!(later.cached_proof_types.is_empty(), "{later:?}");

        // Proofs for payloads proven after the join reach the joiner over gossip but are dropped:
        // their blocks were never admitted.
        let recent = net
            .proven_payloads(0)?
            .into_iter()
            .filter(|payload| payload.slot > join_slot)
            .next_back()
            .ok_or("no payload proven after the join")?;
        let dropped = net.proof_status(joiner, recent.block_root, 1)?;
        assert!(!dropped.block_known, "{dropped:?}");
        assert!(!dropped.valid_proof_verified, "{dropped:?}");

        // The missed proofs still exist on the prover's node; the joiner has no way to ask.
        assert_eq!(
            net.retrieved_proof_types(0, stalled_root).await?,
            vec![1, 2]
        );
        assert_eq!(
            net.retrieved_proof_types(joiner, stalled_root).await?,
            Vec::<u8>::new()
        );
        info!(
            ?stalled_root,
            "Late joiner stalled on proofs gossiped before it joined"
        );
        Ok(())
    })
    .unwrap()
}

/// With six nodes, proofs posted to one verifier reach both verifiers and both proof-only nodes
/// over gossip, and unlock the payload on both proof-only nodes.
#[test]
#[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
fn larger_network_delivers_proofs_to_every_verifier() {
    ProofNetwork::run(large(), |net| async move {
        let block_root = ready(&net, 4).await?;
        net.wait_for(
            "the second proof-only node to hold the same payload",
            PROPAGATION_TIMEOUT,
            |net| Ok(net.proof_status(5, block_root, 1)?.envelope_pending),
        )
        .await?;

        for (proof_type, proof_data) in both_types() {
            let proof =
                net.signed_execution_proof(0, block_root, proof_type, proof_data, PROVER)?;
            net.submit_execution_proof(0, proof).await?;
            net.wait_for_valid_proof(&[0, 3, 4, 5], block_root, proof_type, PROPAGATION_TIMEOUT)
                .await?;
        }
        net.wait_for_cached_proof_types(&[0, 3, 4, 5], block_root, &[1, 2], PROPAGATION_TIMEOUT)
            .await?;
        net.wait_for_payload_received(&[4, 5], block_root, PROPAGATION_TIMEOUT)
            .await?;
        for node in [1, 2] {
            let status = net.proof_status(node, block_root, 1)?;
            assert!(!status.valid_proof_verified, "{status:?}");
            assert!(status.cached_proof_types.is_empty(), "{status:?}");
        }
        Ok(())
    })
    .unwrap()
}

/// Proof bytes an engine does not accept are rejected: by the Beacon API at submission, and on
/// gossip by every verifier, which penalises the sender. The proof-only node accepts only the
/// type 1 bytes, so the type 2 proof node 0 accepts is rejected by node 3 alone and its payload
/// stays locked.
#[test]
#[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
fn invalid_proof_data_is_rejected_by_verifiers_that_do_not_accept_it() {
    ProofNetwork::run(standard(vec![VALID_TYPE_1.to_vec()]), |net| async move {
        let block_root = ready(&net, 3).await?;

        let bogus = net.signed_execution_proof(0, block_root, 1, INVALID.to_vec(), PROVER)?;
        let error = net
            .submit_execution_proof(0, bogus.clone())
            .await
            .expect_err("no engine accepts the bogus proof");
        assert!(error.contains("InvalidProof"), "{error}");

        net.publish_execution_proof(0, bogus)?;
        net.wait_for("node 3 to penalise node 0", PROPAGATION_TIMEOUT, |net| {
            Ok(net
                .peer_score(3, 0)?
                .is_some_and(|score| score < PENALISED_SCORE))
        })
        .await?;
        for node in [0, 3] {
            let status = net.proof_status(node, block_root, 1)?;
            assert!(!status.valid_proof_verified, "{status:?}");
            assert!(status.cached_proof_types.is_empty(), "{status:?}");
        }

        // A rejected proof does not suppress an honest prover of the same type.
        let honest =
            net.signed_execution_proof(0, block_root, 1, VALID_TYPE_1.to_vec(), SECOND_PROVER)?;
        net.submit_execution_proof(0, honest).await?;
        net.wait_for_valid_proof(&[0, 3], block_root, 1, PROPAGATION_TIMEOUT)
            .await?;
        net.wait_for_cached_proof_types(&[0, 3], block_root, &[1], PROPAGATION_TIMEOUT)
            .await?;

        // Node 0 accepts the type 2 bytes, node 3 does not.
        let score_before = net.peer_score(3, 0)?.ok_or("node 3 lost node 0")?;
        let disputed =
            net.signed_execution_proof(0, block_root, 2, VALID_TYPE_2.to_vec(), PROVER)?;
        net.submit_execution_proof(0, disputed).await?;
        net.wait_for_valid_proof(&[0], block_root, 2, PROPAGATION_TIMEOUT)
            .await?;
        net.wait_for_cached_proof_types(&[0], block_root, &[1, 2], PROPAGATION_TIMEOUT)
            .await?;
        net.wait_for(
            "node 3 to penalise node 0 again",
            PROPAGATION_TIMEOUT,
            |net| {
                Ok(net
                    .peer_score(3, 0)?
                    .is_some_and(|score| score < score_before))
            },
        )
        .await?;
        let status = net.proof_status(3, block_root, 2)?;
        assert!(!status.valid_proof_verified, "{status:?}");
        assert_eq!(status.cached_proof_types, vec![1], "{status:?}");
        assert!(!status.payload_received, "{status:?}");
        assert_eq!(net.retrieved_proof_types(3, block_root).await?, vec![1]);
        Ok(())
    })
    .unwrap()
}

/// A proof type outside the specification is rejected before any verification work, by the
/// Beacon API and by gossip peers, which penalise the sender.
#[test]
#[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
fn unsupported_proof_type_is_rejected_before_verification() {
    ProofNetwork::run(standard(accepts_both()), |net| async move {
        let block_root = ready(&net, 3).await?;

        let proof = net.signed_execution_proof(0, block_root, 4, VALID_TYPE_1.to_vec(), PROVER)?;
        let error = net
            .submit_execution_proof(0, proof.clone())
            .await
            .expect_err("proof type 4 is unsupported");
        assert!(error.contains("UnsupportedProofType"), "{error}");

        net.publish_execution_proof(0, proof)?;
        net.wait_for("node 3 to penalise node 0", PROPAGATION_TIMEOUT, |net| {
            Ok(net
                .peer_score(3, 0)?
                .is_some_and(|score| score < PENALISED_SCORE))
        })
        .await?;
        for node in [0, 3] {
            let status = net.proof_status(node, block_root, 4)?;
            assert!(!status.valid_proof_verified, "{status:?}");
            assert!(status.cached_proof_types.is_empty(), "{status:?}");
        }
        Ok(())
    })
    .unwrap()
}

/// In a two-node network the proof-only node is the only verifier: proofs posted to its own
/// Beacon API verify locally, are cached and retrievable, and unlock its payload import even
/// though no peer subscribes to the proof topic.
#[test]
#[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
fn proof_only_node_can_submit_its_own_proofs() {
    ProofNetwork::run(minimal(), |net| async move {
        let block_root = ready(&net, 1).await?;

        for (proof_type, proof_data) in both_types() {
            let proof =
                net.signed_execution_proof(1, block_root, proof_type, proof_data, PROVER)?;
            net.submit_execution_proof(1, proof).await?;
            net.wait_for_valid_proof(&[1], block_root, proof_type, PROPAGATION_TIMEOUT)
                .await?;
        }
        net.wait_for_cached_proof_types(&[1], block_root, &[1, 2], PROPAGATION_TIMEOUT)
            .await?;
        net.wait_for_payload_received(&[1], block_root, PROPAGATION_TIMEOUT)
            .await?;
        assert_eq!(net.retrieved_proof_types(1, block_root).await?, vec![1, 2]);

        let status = net.proof_status(0, block_root, 1)?;
        assert!(status.payload_received, "{status:?}");
        assert!(!status.valid_proof_verified, "{status:?}");
        Ok(())
    })
    .unwrap()
}

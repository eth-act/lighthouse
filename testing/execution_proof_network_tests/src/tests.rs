//! Scenario tests. Each one starts its own network; see the crate documentation for how to run
//! them.

use crate::{NodeSpec, ProofNetwork, ProofNetworkConfig};
use beacon_chain::AvailabilityProcessingStatus;
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
const STARTUP_TIMEOUT: Duration = Duration::from_secs(40);
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(20);
/// Peer score below which a node has applied at least one gossip penalty.
const PENALISED_SCORE: f64 = -5.0;

fn accepts_both() -> Vec<Vec<u8>> {
    vec![VALID_TYPE_1.to_vec(), VALID_TYPE_2.to_vec()]
}

/// Nodes 1 and 2 carry the validators and run without a proof engine, so they keep the chain
/// moving; nodes 0 and 3 verify proofs. Node 0 accepts both valid byte strings, node 3 accepts
/// `node_3_accepts`.
fn verifier_topology(node_3_accepts: Vec<Vec<u8>>) -> ProofNetworkConfig {
    ProofNetworkConfig::new(vec![
        NodeSpec::verifier(accepts_both()),
        NodeSpec::plain().with_validators(),
        NodeSpec::plain().with_validators(),
        NodeSpec::verifier(node_3_accepts),
    ])
}

/// Wait for genesis and full connectivity, then return the first full block: the validator
/// nodes have imported its payload, while both verifiers hold the executed envelope pending
/// proofs and cannot follow the chain past it until proofs arrive.
async fn ready(net: &ProofNetwork) -> Result<Hash256, String> {
    net.wait_for_genesis().await?;
    let all: Vec<usize> = (0..net.node_count()).collect();
    net.wait_for_peers(&all, net.node_count() - 1, STARTUP_TIMEOUT)
        .await?;
    let block_root = net.wait_for_pending_payload(0, STARTUP_TIMEOUT).await?;
    net.wait_for(
        "node 3 to hold the same payload pending proofs",
        PROPAGATION_TIMEOUT,
        |net| Ok(net.proof_status(3, block_root, 1)?.envelope_pending),
    )
    .await?;
    net.wait_for_payload_received(&[1, 2], block_root, PROPAGATION_TIMEOUT)
        .await?;
    info!(?block_root, "Target block ready");
    Ok(block_root)
}

/// Nodes without a proof engine import payloads immediately; verifiers execute the envelope
/// but hold it in the pending payload cache, unstored and unimported, until two proof types
/// arrive.
#[test]
#[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
fn gloas_network_imports_payload_envelopes() {
    ProofNetwork::run(verifier_topology(accepts_both()), |net| async move {
        let block_root = ready(&net).await?;

        for node in [1, 2] {
            let status = net.proof_status(node, block_root, 1)?;
            assert!(status.payload_received, "{status:?}");
            assert!(status.envelope_stored, "{status:?}");
        }
        for node in [0, 3] {
            let status = net.proof_status(node, block_root, 1)?;
            assert!(status.block_known, "{status:?}");
            assert!(status.envelope_pending, "{status:?}");
            assert!(!status.envelope_stored, "{status:?}");
            assert!(!status.payload_received, "{status:?}");
            assert!(status.cached_proof_types.is_empty(), "{status:?}");
        }
        Ok(())
    })
    .unwrap()
}

/// End to end: proofs of two types submitted through node 0 are verified there, propagate over
/// gossip to node 3, are verified and cached on both, and unlock the payload import on both.
#[test]
#[ignore = "blocked on optional-proofs-gloas base 535046063: proof gossip verification loads the envelope from the store, which proof-engine nodes fill only after two proofs, so submission fails with PayloadUnavailable (see fork PR #42)"]
fn execution_proofs_propagate_verify_and_unlock_payload_import() {
    ProofNetwork::run(verifier_topology(accepts_both()), |net| async move {
        let block_root = ready(&net).await?;

        let first = net.signed_execution_proof(0, block_root, 1, VALID_TYPE_1.to_vec(), PROVER)?;
        let status = net.submit_execution_proof(0, first).await?;
        assert!(
            matches!(status, AvailabilityProcessingStatus::MissingComponents(..)),
            "one proof type must not unlock the payload: {status:?}"
        );
        net.wait_for_valid_proof(&[0, 3], block_root, 1, PROPAGATION_TIMEOUT)
            .await?;

        let second = net.signed_execution_proof(0, block_root, 2, VALID_TYPE_2.to_vec(), PROVER)?;
        let status = net.submit_execution_proof(0, second).await?;
        assert!(
            matches!(status, AvailabilityProcessingStatus::Imported(..)),
            "the second proof type must unlock the payload: {status:?}"
        );
        net.wait_for_valid_proof(&[0, 3], block_root, 2, PROPAGATION_TIMEOUT)
            .await?;
        net.wait_for_payload_received(&[0, 3], block_root, PROPAGATION_TIMEOUT)
            .await?;

        for node in [0, 3] {
            let status = net.proof_status(node, block_root, 1)?;
            assert_eq!(status.cached_proof_types, vec![1, 2], "{status:?}");
            assert!(status.envelope_stored, "{status:?}");
        }
        // Nodes without a proof engine never see the proof topic.
        for node in [1, 2] {
            for proof_type in [1, 2] {
                let status = net.proof_status(node, block_root, proof_type)?;
                assert!(!status.valid_proof_verified, "{status:?}");
                assert!(status.cached_proof_types.is_empty(), "{status:?}");
            }
        }
        Ok(())
    })
    .unwrap()
}

/// Proof bytes an engine does not accept are rejected: at submission on the local node, and on
/// gossip by every verifier, which penalises the sender. Node 3 accepts only the type 1 bytes,
/// so the type 2 proof node 0 accepts is rejected by node 3 alone.
#[test]
#[ignore = "blocked on optional-proofs-gloas base 535046063: proof gossip verification loads the envelope from the store, which proof-engine nodes fill only after two proofs, so submission fails with PayloadUnavailable (see fork PR #42)"]
fn invalid_proof_data_is_rejected_by_verifiers_that_do_not_accept_it() {
    ProofNetwork::run(
        verifier_topology(vec![VALID_TYPE_1.to_vec()]),
        |net| async move {
            let block_root = ready(&net).await?;

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

            // Node 0 accepts the type 2 bytes, node 3 does not.
            let score_before = net.peer_score(3, 0)?.ok_or("node 3 lost node 0")?;
            let disputed =
                net.signed_execution_proof(0, block_root, 2, VALID_TYPE_2.to_vec(), PROVER)?;
            net.submit_execution_proof(0, disputed).await?;
            net.wait_for_valid_proof(&[0], block_root, 2, PROPAGATION_TIMEOUT)
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
            Ok(())
        },
    )
    .unwrap()
}

/// A proof type outside the specification is rejected before any verification work, locally
/// and by gossip peers, which penalise the sender.
#[test]
#[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
fn unsupported_proof_type_is_rejected_before_verification() {
    ProofNetwork::run(verifier_topology(accepts_both()), |net| async move {
        let block_root = ready(&net).await?;

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

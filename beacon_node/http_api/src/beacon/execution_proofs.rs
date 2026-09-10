//! EIP-8025 execution proof endpoints.
//!
//! - `POST /eth/v1/beacon/execution_proofs`: verify validator-signed proof envelopes exactly as
//!   the `execution_proof` gossip topic would, publish the ones that pass, and cache them.
//! - `GET /eth/v1/beacon/execution_proofs/{block_id}`: return the proof envelopes cached for a
//!   block's payload.
//!
//! Both endpoints answer `501 Not Implemented` on nodes without a proof engine, which neither
//! verify nor store proofs.

use crate::block_id::BlockId;
use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{
    ChainFilter, EthV1Filter, NetworkTxFilter, ResponseFilter, TaskSpawnerFilter,
    publish_pubsub_message,
};
use crate::version::add_ssz_content_type_header;
use beacon_chain::execution_proof_verification::Error as ProofError;
use beacon_chain::{AvailabilityProcessingStatus, BeaconChain, BeaconChainTypes};
use bytes::Bytes;
use eth2::types::{self as api_types, Failure};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use ssz::{Decode, Encode};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};
use types::execution::{SignedExecutionProofEnvelope, SignedExecutionProofEnvelopes};
use warp::{
    Filter, Rejection,
    http::response::Builder,
    reply::{Reply, Response},
};

/// Reject with `501 Not Implemented` unless the node runs a proof engine.
fn require_proof_engine<T: BeaconChainTypes>(chain: &BeaconChain<T>) -> Result<(), Rejection> {
    if chain.proof_engine.is_some() {
        Ok(())
    } else {
        Err(warp_utils::reject::custom_not_implemented(
            "proof engine not configured; start with --proof-engine to enable EIP-8025 \
             execution proofs"
                .to_string(),
        ))
    }
}

// GET beacon/execution_proofs/{block_id}
pub(crate) fn get_beacon_execution_proofs<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    block_id_or_err: impl Filter<Extract = (BlockId,), Error = Rejection>
    + Clone
    + Send
    + Sync
    + 'static,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_proofs"))
        .and(block_id_or_err)
        .and(warp::path::end())
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(warp::header::optional::<api_types::Accept>("accept"))
        .then(
            |block_id: BlockId,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             accept_header: Option<api_types::Accept>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    require_proof_engine(&chain)?;
                    let (block_root, execution_optimistic, finalized) = block_id.root(&chain)?;
                    let proofs = SignedExecutionProofEnvelopes::new(
                        chain
                            .pending_payload_cache
                            .get_execution_proofs(&block_root)
                            .iter()
                            .map(|proof| proof.as_ref().clone())
                            .collect(),
                    )
                    .map_err(|e| {
                        warp_utils::reject::custom_server_error(format!(
                            "cached execution proofs exceed the per-payload bound: {e:?}"
                        ))
                    })?;

                    match accept_header {
                        Some(api_types::Accept::Ssz) => Builder::new()
                            .status(200)
                            .body(proofs.as_ssz_bytes())
                            .map(add_ssz_content_type_header)
                            .map_err(|e| {
                                warp_utils::reject::custom_server_error(format!(
                                    "failed to create response: {e}"
                                ))
                            }),
                        _ => Ok(warp::reply::json(
                            &api_types::GenericResponse::from(proofs)
                                .add_execution_optimistic_finalized(
                                    execution_optimistic,
                                    finalized,
                                ),
                        )
                        .into_response()),
                    }
                })
            },
        )
        .boxed()
}

// POST beacon/execution_proofs
pub(crate) fn post_beacon_execution_proofs<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_proofs"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(network_tx_filter)
        .then(
            |proofs: SignedExecutionProofEnvelopes,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P1, async move {
                    publish_execution_proofs(proofs, chain, &network_tx).await
                })
            },
        )
        .boxed()
}

// POST beacon/execution_proofs (SSZ)
pub(crate) fn post_beacon_execution_proofs_ssz<T: BeaconChainTypes>(
    eth_v1: EthV1Filter,
    task_spawner_filter: TaskSpawnerFilter<T>,
    chain_filter: ChainFilter<T>,
    network_tx_filter: NetworkTxFilter<T>,
) -> ResponseFilter {
    eth_v1
        .and(warp::path("beacon"))
        .and(warp::path("execution_proofs"))
        .and(warp::path::end())
        .and(warp::body::bytes())
        .and(task_spawner_filter)
        .and(chain_filter)
        .and(network_tx_filter)
        .then(
            |body_bytes: Bytes,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.spawn_async_with_rejection(Priority::P1, async move {
                    let proofs = SignedExecutionProofEnvelopes::from_ssz_bytes(&body_bytes)
                        .map_err(|e| {
                            warp_utils::reject::custom_bad_request(format!("invalid SSZ: {e:?}"))
                        })?;
                    publish_execution_proofs(proofs, chain, &network_tx).await
                })
            },
        )
        .boxed()
}

/// Verify, publish and cache each proof.
///
/// `200` means every proof is on the network, published now or already known. Proofs that
/// gossip would drop are reported per index with `400`; a proof engine or beacon chain fault
/// aborts the batch with `500`.
pub async fn publish_execution_proofs<T: BeaconChainTypes>(
    proofs: SignedExecutionProofEnvelopes,
    chain: Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<Response, Rejection> {
    require_proof_engine(&chain)?;
    if proofs.is_empty() {
        return Err(warp_utils::reject::custom_bad_request(
            "no execution proofs supplied".to_string(),
        ));
    }

    let mut failures = vec![];
    for (index, proof) in Vec::from(proofs).into_iter().enumerate() {
        match publish_execution_proof(&chain, network_tx, Arc::new(proof)).await {
            Ok(()) => {}
            Err(ProofFailure::Rejected(message)) => failures.push(Failure::new(index, message)),
            Err(ProofFailure::Internal(message)) => {
                return Err(warp_utils::reject::custom_server_error(message));
            }
        }
    }

    if failures.is_empty() {
        Ok(warp::reply().into_response())
    } else {
        Err(warp_utils::reject::indexed_bad_request(
            "error processing execution proofs".to_string(),
            failures,
        ))
    }
}

enum ProofFailure {
    /// The proof will not be propagated; the message tells the submitter why.
    Rejected(String),
    /// The node could not verify or publish the proof.
    Internal(String),
}

async fn publish_execution_proof<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    network_tx: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    proof: Arc<SignedExecutionProofEnvelope>,
) -> Result<(), ProofFailure> {
    let beacon_block_root = proof.beacon_block_root();
    let proof_type = proof.proof_type();
    let validator_index = proof.validator_index;

    let verified = match chain.verify_execution_proof_for_gossip(proof.clone()).await {
        Ok(verified) => verified,
        // This proof, or a valid proof of the same type, is already on the network. Fallback
        // beacon nodes commonly resubmit, so the submitter has nothing to act on.
        Err(ProofError::ProofAlreadySeen | ProofError::ValidProofAlreadyKnown) => {
            debug!(
                %beacon_block_root,
                proof_type,
                validator_index,
                "Execution proof already known"
            );
            return Ok(());
        }
        Err(
            error @ (ProofError::ProofEngineMissing
            | ProofError::ProofEngine(_)
            | ProofError::BeaconChainError(_)),
        ) => {
            warn!(
                %beacon_block_root,
                proof_type,
                validator_index,
                ?error,
                "Could not verify execution proof"
            );
            return Err(ProofFailure::Internal(format!(
                "execution proof verification failed: {error:?}"
            )));
        }
        Err(error) => {
            debug!(
                %beacon_block_root,
                proof_type,
                validator_index,
                ?error,
                "Rejecting execution proof"
            );
            return Err(ProofFailure::Rejected(format!("{error:?}")));
        }
    };

    publish_pubsub_message(network_tx, PubsubMessage::ExecutionProof(proof))
        .map_err(|_| ProofFailure::Internal("unable to publish to network channel".to_string()))?;
    info!(
        %beacon_block_root,
        proof_type,
        validator_index,
        "Published execution proof"
    );

    // Mirror the gossip path: cache the proof and import the payload envelope if this was the
    // last missing piece. The proof is already published, so caching faults are logged, not
    // returned.
    match chain
        .check_execution_proof_availability_and_import(verified)
        .await
    {
        Ok(AvailabilityProcessingStatus::Imported(slot, block_root)) => {
            info!(
                %block_root,
                %slot,
                "Execution payload envelope imported after execution proof"
            );
            chain.recompute_head_at_current_slot().await;
        }
        Ok(AvailabilityProcessingStatus::MissingComponents(..)) => {}
        Err(error) => {
            debug!(
                %beacon_block_root,
                proof_type,
                ?error,
                "Could not cache execution proof"
            );
        }
    }

    Ok(())
}

use crate::task_spawner::{Priority, TaskSpawner};
use crate::utils::{
    NetworkTxFilter, OptionalConsensusVersionHeaderFilter, ResponseFilter, SyncTxFilter,
};
use crate::version::{
    ResponseIncludesVersion, V1, V2, add_consensus_version_header, beacon_response,
    unsupported_version_rejection,
};
use crate::{sync_committees, utils};
use beacon_chain::execution_proof_verification::{
    GossipExecutionProofError, GossipVerifiedExecutionProof,
};
use beacon_chain::observed_data_sidecars::Observe;
use beacon_chain::observed_operations::ObservationOutcome;
use beacon_chain::{AvailabilityProcessingStatus, BeaconChain, BeaconChainTypes};
use eth2::types::{AttestationPoolQuery, EndpointVersion, Failure, GenericResponse};
use lighthouse_network::PubsubMessage;
use network::{NetworkMessage, SyncMessage};
use operation_pool::ReceivedPreCapella;
use slot_clock::SlotClock;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, info, warn};
use types::{
    Attestation, AttestationData, AttesterSlashing, ExecutionProof, ForkName, ProposerSlashing,
    SignedBlsToExecutionChange, SignedVoluntaryExit, SingleAttestation, SyncCommitteeMessage,
};
use warp::filters::BoxedFilter;
use warp::{Filter, Reply};
use warp_utils::reject::convert_rejection;

pub type BeaconPoolPathFilter<T> = BoxedFilter<(
    TaskSpawner<<T as BeaconChainTypes>::EthSpec>,
    Arc<BeaconChain<T>>,
)>;
pub type BeaconPoolPathV2Filter<T> = BoxedFilter<(
    TaskSpawner<<T as BeaconChainTypes>::EthSpec>,
    Arc<BeaconChain<T>>,
)>;
pub type BeaconPoolPathAnyFilter<T> = BoxedFilter<(
    EndpointVersion,
    TaskSpawner<<T as BeaconChainTypes>::EthSpec>,
    Arc<BeaconChain<T>>,
)>;

/// POST beacon/pool/bls_to_execution_changes
pub fn post_beacon_pool_bls_to_execution_changes<T: BeaconChainTypes>(
    network_tx_filter: &NetworkTxFilter<T>,
    beacon_pool_path: &BeaconPoolPathFilter<T>,
) -> ResponseFilter {
    beacon_pool_path
        .clone()
        .and(warp::path("bls_to_execution_changes"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(network_tx_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             address_changes: Vec<SignedBlsToExecutionChange>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    let mut failures = vec![];

                    for (index, address_change) in address_changes.into_iter().enumerate() {
                        let validator_index = address_change.message.validator_index;

                        match chain.verify_bls_to_execution_change_for_http_api(address_change) {
                            Ok(ObservationOutcome::New(verified_address_change)) => {
                                let validator_index =
                                    verified_address_change.as_inner().message.validator_index;
                                let address = verified_address_change
                                    .as_inner()
                                    .message
                                    .to_execution_address;

                                // New to P2P *and* op pool, gossip immediately if post-Capella.
                                let received_pre_capella =
                                    if chain.current_slot_is_post_capella().unwrap_or(false) {
                                        ReceivedPreCapella::No
                                    } else {
                                        ReceivedPreCapella::Yes
                                    };
                                if matches!(received_pre_capella, ReceivedPreCapella::No) {
                                    utils::publish_pubsub_message(
                                        &network_tx,
                                        PubsubMessage::BlsToExecutionChange(Box::new(
                                            verified_address_change.as_inner().clone(),
                                        )),
                                    )?;
                                }

                                // Import to op pool (may return `false` if there's a race).
                                let imported = chain.import_bls_to_execution_change(
                                    verified_address_change,
                                    received_pre_capella,
                                );

                                info!(
                                    %validator_index,
                                    ?address,
                                    published =
                                        matches!(received_pre_capella, ReceivedPreCapella::No),
                                    imported,
                                    "Processed BLS to execution change"
                                );
                            }
                            Ok(ObservationOutcome::AlreadyKnown) => {
                                debug!(%validator_index, "BLS to execution change already known");
                            }
                            Err(e) => {
                                warn!(
                                    validator_index,
                                    reason = ?e,
                                    source = "HTTP",
                                    "Invalid BLS to execution change"
                                );
                                failures.push(Failure::new(index, format!("invalid: {e:?}")));
                            }
                        }
                    }

                    if failures.is_empty() {
                        Ok(())
                    } else {
                        Err(warp_utils::reject::indexed_bad_request(
                            "some BLS to execution changes failed to verify".into(),
                            failures,
                        ))
                    }
                })
            },
        )
        .boxed()
}

/// GET beacon/pool/bls_to_execution_changes
pub fn get_beacon_pool_bls_to_execution_changes<T: BeaconChainTypes>(
    beacon_pool_path: &BeaconPoolPathFilter<T>,
) -> ResponseFilter {
    beacon_pool_path
        .clone()
        .and(warp::path("bls_to_execution_changes"))
        .and(warp::path::end())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let address_changes = chain.op_pool.get_all_bls_to_execution_changes();
                    Ok(GenericResponse::from(address_changes))
                })
            },
        )
        .boxed()
}

/// POST beacon/pool/sync_committees
pub fn post_beacon_pool_sync_committees<T: BeaconChainTypes>(
    network_tx_filter: &NetworkTxFilter<T>,
    beacon_pool_path: &BeaconPoolPathFilter<T>,
) -> ResponseFilter {
    beacon_pool_path
        .clone()
        .and(warp::path("sync_committees"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(network_tx_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             signatures: Vec<SyncCommitteeMessage>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    sync_committees::process_sync_committee_signatures(
                        signatures, network_tx, &chain,
                    )?;
                    Ok(GenericResponse::from(()))
                })
            },
        )
        .boxed()
}

/// GET beacon/pool/voluntary_exits
pub fn get_beacon_pool_voluntary_exits<T: BeaconChainTypes>(
    beacon_pool_path: &BeaconPoolPathFilter<T>,
) -> ResponseFilter {
    beacon_pool_path
        .clone()
        .and(warp::path("voluntary_exits"))
        .and(warp::path::end())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let attestations = chain.op_pool.get_all_voluntary_exits();
                    Ok(GenericResponse::from(attestations))
                })
            },
        )
        .boxed()
}

/// POST beacon/pool/voluntary_exits
pub fn post_beacon_pool_voluntary_exits<T: BeaconChainTypes>(
    network_tx_filter: &NetworkTxFilter<T>,
    beacon_pool_path: &BeaconPoolPathFilter<T>,
) -> ResponseFilter {
    beacon_pool_path
        .clone()
        .and(warp::path("voluntary_exits"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(network_tx_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             exit: SignedVoluntaryExit,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    let outcome = chain
                        .verify_voluntary_exit_for_gossip(exit.clone())
                        .map_err(|e| {
                            warp_utils::reject::object_invalid(format!(
                                "gossip verification failed: {:?}",
                                e
                            ))
                        })?;

                    // Notify the validator monitor.
                    chain
                        .validator_monitor
                        .read()
                        .register_api_voluntary_exit(&exit.message);

                    if let ObservationOutcome::New(exit) = outcome {
                        utils::publish_pubsub_message(
                            &network_tx,
                            PubsubMessage::VoluntaryExit(Box::new(exit.clone().into_inner())),
                        )?;

                        chain.import_voluntary_exit(exit);
                    }

                    Ok(())
                })
            },
        )
        .boxed()
}

/// GET beacon/pool/proposer_slashings
pub fn get_beacon_pool_proposer_slashings<T: BeaconChainTypes>(
    beacon_pool_path: &BeaconPoolPathFilter<T>,
) -> ResponseFilter {
    beacon_pool_path
        .clone()
        .and(warp::path("proposer_slashings"))
        .and(warp::path::end())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>, chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_json_task(Priority::P1, move || {
                    let attestations = chain.op_pool.get_all_proposer_slashings();
                    Ok(GenericResponse::from(attestations))
                })
            },
        )
        .boxed()
}

/// POST beacon/pool/proposer_slashings
pub fn post_beacon_pool_proposer_slashings<T: BeaconChainTypes>(
    network_tx_filter: &NetworkTxFilter<T>,
    beacon_pool_path: &BeaconPoolPathFilter<T>,
) -> ResponseFilter {
    beacon_pool_path
        .clone()
        .and(warp::path("proposer_slashings"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(network_tx_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             slashing: ProposerSlashing,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    let outcome = chain
                        .verify_proposer_slashing_for_gossip(slashing.clone())
                        .map_err(|e| {
                            warp_utils::reject::object_invalid(format!(
                                "gossip verification failed: {:?}",
                                e
                            ))
                        })?;

                    // Notify the validator monitor.
                    chain
                        .validator_monitor
                        .read()
                        .register_api_proposer_slashing(&slashing);

                    if let ObservationOutcome::New(slashing) = outcome {
                        utils::publish_pubsub_message(
                            &network_tx,
                            PubsubMessage::ProposerSlashing(Box::new(
                                slashing.clone().into_inner(),
                            )),
                        )?;

                        chain.import_proposer_slashing(slashing);
                    }

                    Ok(())
                })
            },
        )
        .boxed()
}

/// GET beacon/pool/attester_slashings
pub fn get_beacon_pool_attester_slashings<T: BeaconChainTypes>(
    beacon_pool_path_any: &BeaconPoolPathAnyFilter<T>,
) -> ResponseFilter {
    beacon_pool_path_any
        .clone()
        .and(warp::path("attester_slashings"))
        .and(warp::path::end())
        .then(
            |endpoint_version: EndpointVersion,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let slashings = chain.op_pool.get_all_attester_slashings();

                    // Use the current slot to find the fork version, and convert all messages to the
                    // current fork's format. This is to ensure consistent message types matching
                    // `Eth-Consensus-Version`.
                    let current_slot =
                        chain
                            .slot_clock
                            .now()
                            .ok_or(warp_utils::reject::custom_server_error(
                                "unable to read slot clock".to_string(),
                            ))?;
                    let fork_name = chain.spec.fork_name_at_slot::<T::EthSpec>(current_slot);
                    let slashings = slashings
                        .into_iter()
                        .filter(|slashing| {
                            (fork_name.electra_enabled()
                                && matches!(slashing, AttesterSlashing::Electra(_)))
                                || (!fork_name.electra_enabled()
                                    && matches!(slashing, AttesterSlashing::Base(_)))
                        })
                        .collect::<Vec<_>>();

                    let require_version = match endpoint_version {
                        V1 => ResponseIncludesVersion::No,
                        V2 => ResponseIncludesVersion::Yes(fork_name),
                        _ => return Err(unsupported_version_rejection(endpoint_version)),
                    };

                    let res = beacon_response(require_version, &slashings);
                    Ok(add_consensus_version_header(
                        warp::reply::json(&res).into_response(),
                        fork_name,
                    ))
                })
            },
        )
        .boxed()
}

// POST beacon/pool/attester_slashings
pub fn post_beacon_pool_attester_slashings<T: BeaconChainTypes>(
    network_tx_filter: &NetworkTxFilter<T>,
    beacon_pool_path_any: &BeaconPoolPathAnyFilter<T>,
) -> ResponseFilter {
    beacon_pool_path_any
        .clone()
        .and(warp::path("attester_slashings"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(network_tx_filter.clone())
        .then(
            // V1 and V2 are identical except V2 has a consensus version header in the request.
            // We only require this header for SSZ deserialization, which isn't supported for
            // this endpoint presently.
            |_endpoint_version: EndpointVersion,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             slashing: AttesterSlashing<T::EthSpec>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| {
                task_spawner.blocking_json_task(Priority::P0, move || {
                    let outcome = chain
                        .verify_attester_slashing_for_gossip(slashing.clone())
                        .map_err(|e| {
                            warp_utils::reject::object_invalid(format!(
                                "gossip verification failed: {:?}",
                                e
                            ))
                        })?;

                    // Notify the validator monitor.
                    chain
                        .validator_monitor
                        .read()
                        .register_api_attester_slashing(slashing.to_ref());

                    if let ObservationOutcome::New(slashing) = outcome {
                        utils::publish_pubsub_message(
                            &network_tx,
                            PubsubMessage::AttesterSlashing(Box::new(
                                slashing.clone().into_inner(),
                            )),
                        )?;

                        chain.import_attester_slashing(slashing);
                    }

                    Ok(())
                })
            },
        )
        .boxed()
}

/// GET beacon/pool/attestations?committee_index,slot
pub fn get_beacon_pool_attestations<T: BeaconChainTypes>(
    beacon_pool_path_any: &BeaconPoolPathAnyFilter<T>,
) -> ResponseFilter {
    beacon_pool_path_any
        .clone()
        .and(warp::path("attestations"))
        .and(warp::path::end())
        .and(warp::query::<AttestationPoolQuery>())
        .then(
            |endpoint_version: EndpointVersion,
             task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             query: AttestationPoolQuery| {
                task_spawner.blocking_response_task(Priority::P1, move || {
                    let query_filter = |data: &AttestationData, committee_indices: HashSet<u64>| {
                        query.slot.is_none_or(|slot| slot == data.slot)
                            && query
                                .committee_index
                                .is_none_or(|index| committee_indices.contains(&index))
                    };

                    let mut attestations = chain.op_pool.get_filtered_attestations(query_filter);
                    attestations.extend(
                        chain
                            .naive_aggregation_pool
                            .read()
                            .iter()
                            .filter(|&att| {
                                query_filter(att.data(), att.get_committee_indices_map())
                            })
                            .cloned(),
                    );
                    // Use the current slot to find the fork version, and convert all messages to the
                    // current fork's format. This is to ensure consistent message types matching
                    // `Eth-Consensus-Version`.
                    let current_slot =
                        chain
                            .slot_clock
                            .now()
                            .ok_or(warp_utils::reject::custom_server_error(
                                "unable to read slot clock".to_string(),
                            ))?;
                    let fork_name = chain.spec.fork_name_at_slot::<T::EthSpec>(current_slot);
                    let attestations = attestations
                        .into_iter()
                        .filter(|att| {
                            (fork_name.electra_enabled() && matches!(att, Attestation::Electra(_)))
                                || (!fork_name.electra_enabled()
                                    && matches!(att, Attestation::Base(_)))
                        })
                        .collect::<Vec<_>>();

                    let require_version = match endpoint_version {
                        V1 => ResponseIncludesVersion::No,
                        V2 => ResponseIncludesVersion::Yes(fork_name),
                        _ => return Err(unsupported_version_rejection(endpoint_version)),
                    };

                    let res = beacon_response(require_version, &attestations);
                    Ok(add_consensus_version_header(
                        warp::reply::json(&res).into_response(),
                        fork_name,
                    ))
                })
            },
        )
        .boxed()
}

pub fn post_beacon_pool_attestations_v2<T: BeaconChainTypes>(
    network_tx_filter: &NetworkTxFilter<T>,
    optional_consensus_version_header_filter: OptionalConsensusVersionHeaderFilter,
    beacon_pool_path_v2: &BeaconPoolPathV2Filter<T>,
) -> ResponseFilter {
    beacon_pool_path_v2
        .clone()
        .and(warp::path("attestations"))
        .and(warp::path::end())
        .and(warp_utils::json::json::<Vec<SingleAttestation>>())
        .and(optional_consensus_version_header_filter)
        .and(network_tx_filter.clone())
        .then(
            |task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             attestations: Vec<SingleAttestation>,
             _fork_name: Option<ForkName>,
             network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>| async move {
                let result = crate::publish_attestations::publish_attestations(
                    task_spawner,
                    chain,
                    attestations,
                    network_tx,
                    true,
                )
                .await
                .map(|()| warp::reply::json(&()));
                convert_rejection(result).await
            },
        )
        .boxed()
}

/// POST beacon/pool/execution_proofs
///
/// Submits an execution proof to the beacon node.
/// The proof will be validated and stored in the data availability checker.
/// If valid, the proof will be published to the gossip network.
/// If the proof makes a block available, the block will be imported.
pub fn post_beacon_pool_execution_proofs<T: BeaconChainTypes>(
    network_tx_filter: &NetworkTxFilter<T>,
    sync_tx_filter: &SyncTxFilter<T>,
    beacon_pool_path: &BeaconPoolPathFilter<T>,
) -> ResponseFilter {
    beacon_pool_path
        .clone()
        .and(warp::path("execution_proofs"))
        .and(warp::path::end())
        .and(warp_utils::json::json())
        .and(network_tx_filter.clone())
        .and(sync_tx_filter.clone())
        .then(
            |_task_spawner: TaskSpawner<T::EthSpec>,
             chain: Arc<BeaconChain<T>>,
             proof: ExecutionProof,
             network_tx_filter: UnboundedSender<NetworkMessage<T::EthSpec>>,
             sync_tx_filter: UnboundedSender<SyncMessage<T::EthSpec>>| async move {
                let result =
                    publish_execution_proof(chain, proof, network_tx_filter, sync_tx_filter).await;
                convert_rejection(result.map(|()| warp::reply::json(&()))).await
            },
        )
        .boxed()
}

/// Validate, publish, and process an execution proof.
async fn publish_execution_proof<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    proof: ExecutionProof,
    network_tx: UnboundedSender<NetworkMessage<T::EthSpec>>,
    sync_tx: UnboundedSender<SyncMessage<T::EthSpec>>,
) -> Result<(), warp::Rejection> {
    let proof = Arc::new(proof);

    // Validate the proof using the same logic as gossip validation
    let verified_proof: GossipVerifiedExecutionProof<T, Observe> =
        GossipVerifiedExecutionProof::new(proof.clone(), &chain).map_err(|e| match e {
            GossipExecutionProofError::PriorKnown {
                slot,
                block_root,
                proof_id,
            } => {
                debug!(
                    %slot,
                    %block_root,
                    %proof_id,
                    "Execution proof already known"
                );
                warp_utils::reject::custom_bad_request(format!(
                    "proof already known for slot {} block_root {} proof_id {}",
                    slot, block_root, proof_id
                ))
            }
            GossipExecutionProofError::PriorKnownUnpublished => {
                // Proof is valid but was received via non-gossip source
                // It's in the DA checker, so we should publish it to gossip
                warp_utils::reject::custom_bad_request(
                    "proof already received but not yet published".to_string(),
                )
            }
            _ => warp_utils::reject::object_invalid(format!("proof verification failed: {:?}", e)),
        })?;

    let slot = verified_proof.slot();
    let block_root = verified_proof.block_root();
    let proof_id = verified_proof.subnet_id();

    // Publish the proof to the gossip network
    utils::publish_pubsub_message(
        &network_tx,
        PubsubMessage::ExecutionProof(verified_proof.clone().into_inner()),
    )?;

    // Store the proof in the data availability checker and check if block is now available.
    // This properly triggers block import if all components are now available.
    match chain
        .process_rpc_execution_proofs(slot, block_root, vec![verified_proof.into_inner()])
        .await
    {
        Ok(status) => {
            info!(
                %slot,
                %block_root,
                %proof_id,
                ?status,
                "Execution proof submitted and published"
            );

            if let AvailabilityProcessingStatus::Imported(_) = status {
                chain.recompute_head_at_current_slot().await;

                // Notify that block was imported via HTTP API
                if let Err(e) = sync_tx.send(SyncMessage::GossipBlockProcessResult {
                    block_root,
                    imported: true,
                }) {
                    debug!(error = %e, "Could not send message to the sync service")
                };
            }
        }
        Err(e) => {
            // Log the error but don't fail the request - the proof was already
            // published to gossip and stored in the DA checker. The error is
            // likely due to the block already being imported or similar.
            debug!(
                %slot,
                %block_root,
                %proof_id,
                error = ?e,
                "Error processing execution proof availability (proof was still published)"
            );
        }
    }

    Ok(())
}

use super::*;
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::status::ToStatusMessage;
use crate::sync::SyncMessage;
use crate::sync::manager::SLOT_IMPORT_TOLERANCE;
use crate::sync::network_context::RangeRequestId;
use crate::sync::proof_sync::ProofSyncState;
use crate::sync::range_sync::RangeSyncType;
use beacon_chain::data_column_verification::CustodyDataColumn;
use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use beacon_chain::{EngineState, NotifyExecutionLayer, block_verification_types::RpcBlock};
use beacon_processor::WorkType;
use bls::SignatureBytes;
use execution_layer::MissingProofInfo;
use lighthouse_network::rpc::RequestType;
use lighthouse_network::rpc::methods::{
    BlobsByRangeRequest, DataColumnsByRangeRequest, ExecutionProofStatus, OldBlocksByRangeRequest,
    OldBlocksByRangeRequestV2, StatusMessageV2,
};
use lighthouse_network::service::api_types::{
    AppRequestId, BlobsByRangeRequestId, BlocksByRangeRequestId, DataColumnsByRangeRequestId,
    ExecutionProofStatusRequestId, ExecutionProofsByRangeRequestId, ExecutionProofsByRootRequestId,
    SyncRequestId,
};
use lighthouse_network::{PeerId, SyncInfo};
use std::sync::Arc;
use std::time::Duration;
use types::{
    BlobSidecarList, BlockImportSource, Epoch, EthSpec, Hash256, MinimalEthSpec as E,
    SignedBeaconBlock, SignedBeaconBlockHash, Slot,
};

const D: Duration = Duration::new(0, 0);

pub(crate) enum DataSidecars<E: EthSpec> {
    Blobs(BlobSidecarList<E>),
    DataColumns(Vec<CustodyDataColumn<E>>),
}

enum ByRangeDataRequestIds {
    PreDeneb,
    PrePeerDAS(BlobsByRangeRequestId, PeerId),
    PostPeerDAS(Vec<(DataColumnsByRangeRequestId, PeerId)>),
}

/// Sync tests are usually written in the form:
/// - Do some action
/// - Expect a request to be sent
/// - Complete the above request
///
/// To make writting tests succint, the machinery in this testing rig automatically identifies
/// _which_ request to complete. Picking the right request is critical for tests to pass, so this
/// filter allows better expressivity on the criteria to identify the right request.
#[derive(Default, Debug, Clone)]
struct RequestFilter {
    peer: Option<PeerId>,
    epoch: Option<u64>,
}

impl RequestFilter {
    fn peer(mut self, peer: PeerId) -> Self {
        self.peer = Some(peer);
        self
    }

    fn epoch(mut self, epoch: u64) -> Self {
        self.epoch = Some(epoch);
        self
    }
}

fn filter() -> RequestFilter {
    RequestFilter::default()
}

impl TestRig {
    /// Produce a head peer with an advanced head
    fn add_head_peer(&mut self) -> PeerId {
        self.add_head_peer_with_root(Hash256::random())
    }

    /// Produce a head peer with an advanced head
    fn add_head_peer_with_root(&mut self, head_root: Hash256) -> PeerId {
        let local_info = self.local_info();
        self.add_supernode_peer(SyncInfo {
            head_root,
            head_slot: local_info.head_slot + 1 + Slot::new(SLOT_IMPORT_TOLERANCE as u64),
            ..local_info
        })
    }

    // Produce a finalized peer with an advanced finalized epoch
    fn add_finalized_peer(&mut self) -> PeerId {
        self.add_finalized_peer_with_root(Hash256::random())
    }

    // Produce a finalized peer with an advanced finalized epoch
    fn add_finalized_peer_with_root(&mut self, finalized_root: Hash256) -> PeerId {
        let local_info = self.local_info();
        let finalized_epoch = local_info.finalized_epoch + 2;
        self.add_supernode_peer(SyncInfo {
            finalized_epoch,
            finalized_root,
            head_slot: finalized_epoch.start_slot(E::slots_per_epoch()),
            head_root: Hash256::random(),
            earliest_available_slot: None,
        })
    }

    fn finalized_remote_info_advanced_by(&self, advanced_epochs: Epoch) -> SyncInfo {
        let local_info = self.local_info();
        let finalized_epoch = local_info.finalized_epoch + advanced_epochs;
        SyncInfo {
            finalized_epoch,
            finalized_root: Hash256::random(),
            head_slot: finalized_epoch.start_slot(E::slots_per_epoch()),
            head_root: Hash256::random(),
            earliest_available_slot: None,
        }
    }

    fn local_info(&self) -> SyncInfo {
        let StatusMessageV2 {
            fork_digest: _,
            finalized_root,
            finalized_epoch,
            head_root,
            head_slot,
            earliest_available_slot,
        } = self.harness.chain.status_message().status_v2();
        SyncInfo {
            head_slot,
            head_root,
            finalized_epoch,
            finalized_root,
            earliest_available_slot: Some(earliest_available_slot),
        }
    }

    fn add_fullnode_peer(&mut self, remote_info: SyncInfo) -> PeerId {
        let peer_id = self.new_connected_peer();
        self.send_sync_message(SyncMessage::AddPeer(peer_id, remote_info));
        peer_id
    }

    fn add_supernode_peer(&mut self, remote_info: SyncInfo) -> PeerId {
        // Create valid peer known to network globals
        // TODO(fulu): Using supernode peers to ensure we have peer across all column
        // subnets for syncing. Should add tests connecting to full node peers.
        let peer_id = self.new_connected_supernode_peer();
        // Send peer to sync
        self.send_sync_message(SyncMessage::AddPeer(peer_id, remote_info));
        peer_id
    }

    fn add_fullnode_peers(&mut self, remote_info: SyncInfo, peer_count: usize) {
        for _ in 0..peer_count {
            let peer = self.new_connected_peer();
            self.send_sync_message(SyncMessage::AddPeer(peer, remote_info.clone()));
        }
    }

    fn assert_state(&self, state: RangeSyncType) {
        assert_eq!(
            self.sync_manager
                .range_sync_state()
                .expect("State is ok")
                .expect("Range should be syncing, there are no chains")
                .0,
            state,
            "not expected range sync state"
        );
    }

    fn assert_no_chains_exist(&self) {
        if let Some(chain) = self.sync_manager.get_range_sync_chains().unwrap() {
            panic!("There still exists a chain {chain:?}");
        }
    }

    fn assert_no_failed_chains(&mut self) {
        assert_eq!(
            self.sync_manager.__range_failed_chains(),
            Vec::<Hash256>::new(),
            "Expected no failed chains"
        )
    }

    #[track_caller]
    fn expect_chain_segments(&mut self, count: usize) {
        for i in 0..count {
            self.pop_received_processor_event(|ev| {
                (ev.work_type() == beacon_processor::WorkType::ChainSegment).then_some(())
            })
            .unwrap_or_else(|e| panic!("Expect ChainSegment work event count {i}: {e:?}"));
        }
    }

    fn update_execution_engine_state(&mut self, state: EngineState) {
        self.log(&format!("execution engine state updated: {state:?}"));
        self.sync_manager.update_execution_engine_state(state);
    }

    fn find_blocks_by_range_request(
        &mut self,
        request_filter: RequestFilter,
    ) -> ((BlocksByRangeRequestId, PeerId), ByRangeDataRequestIds) {
        let filter_f = |peer: PeerId, start_slot: u64| {
            if let Some(expected_epoch) = request_filter.epoch {
                let epoch = Slot::new(start_slot).epoch(E::slots_per_epoch()).as_u64();
                if epoch != expected_epoch {
                    return false;
                }
            }
            if let Some(expected_peer) = request_filter.peer
                && peer != expected_peer
            {
                return false;
            }

            true
        };

        let block_req = self
            .pop_received_network_event(|ev| match ev {
                NetworkMessage::SendRequest {
                    peer_id,
                    request:
                        RequestType::BlocksByRange(OldBlocksByRangeRequest::V2(
                            OldBlocksByRangeRequestV2 { start_slot, .. },
                        )),
                    app_request_id: AppRequestId::Sync(SyncRequestId::BlocksByRange(id)),
                } if filter_f(*peer_id, *start_slot) => Some((*id, *peer_id)),
                _ => None,
            })
            .unwrap_or_else(|e| {
                panic!("Should have a BlocksByRange request, filter {request_filter:?}: {e:?}")
            });

        let by_range_data_requests = if self.after_fulu() {
            let mut data_columns_requests = vec![];
            while let Ok(data_columns_request) = self.pop_received_network_event(|ev| match ev {
                NetworkMessage::SendRequest {
                    peer_id,
                    request:
                        RequestType::DataColumnsByRange(DataColumnsByRangeRequest {
                            start_slot, ..
                        }),
                    app_request_id: AppRequestId::Sync(SyncRequestId::DataColumnsByRange(id)),
                } if filter_f(*peer_id, *start_slot) => Some((*id, *peer_id)),
                _ => None,
            }) {
                data_columns_requests.push(data_columns_request);
            }
            if data_columns_requests.is_empty() {
                panic!("Found zero DataColumnsByRange requests, filter {request_filter:?}");
            }
            ByRangeDataRequestIds::PostPeerDAS(data_columns_requests)
        } else if self.after_deneb() {
            let (id, peer) = self
                .pop_received_network_event(|ev| match ev {
                    NetworkMessage::SendRequest {
                        peer_id,
                        request: RequestType::BlobsByRange(BlobsByRangeRequest { start_slot, .. }),
                        app_request_id: AppRequestId::Sync(SyncRequestId::BlobsByRange(id)),
                    } if filter_f(*peer_id, *start_slot) => Some((*id, *peer_id)),
                    _ => None,
                })
                .unwrap_or_else(|e| {
                    panic!("Should have a blobs by range request, filter {request_filter:?}: {e:?}")
                });
            ByRangeDataRequestIds::PrePeerDAS(id, peer)
        } else {
            ByRangeDataRequestIds::PreDeneb
        };

        (block_req, by_range_data_requests)
    }

    fn find_and_complete_blocks_by_range_request(
        &mut self,
        request_filter: RequestFilter,
    ) -> RangeRequestId {
        let ((blocks_req_id, block_peer), by_range_data_request_ids) =
            self.find_blocks_by_range_request(request_filter);

        // Complete the request with a single stream termination
        self.log(&format!(
            "Completing BlocksByRange request {blocks_req_id:?} with empty stream"
        ));
        self.send_sync_message(SyncMessage::RpcBlock {
            sync_request_id: SyncRequestId::BlocksByRange(blocks_req_id),
            peer_id: block_peer,
            beacon_block: None,
            seen_timestamp: D,
        });

        match by_range_data_request_ids {
            ByRangeDataRequestIds::PreDeneb => {}
            ByRangeDataRequestIds::PrePeerDAS(id, peer_id) => {
                // Complete the request with a single stream termination
                self.log(&format!(
                    "Completing BlobsByRange request {id:?} with empty stream"
                ));
                self.send_sync_message(SyncMessage::RpcBlob {
                    sync_request_id: SyncRequestId::BlobsByRange(id),
                    peer_id,
                    blob_sidecar: None,
                    seen_timestamp: D,
                });
            }
            ByRangeDataRequestIds::PostPeerDAS(data_column_req_ids) => {
                // Complete the request with a single stream termination
                for (id, peer_id) in data_column_req_ids {
                    self.log(&format!(
                        "Completing DataColumnsByRange request {id:?} with empty stream"
                    ));
                    self.send_sync_message(SyncMessage::RpcDataColumn {
                        sync_request_id: SyncRequestId::DataColumnsByRange(id),
                        peer_id,
                        data_column: None,
                        seen_timestamp: D,
                    });
                }
            }
        }

        blocks_req_id.parent_request_id.requester
    }

    /// Assert an `ExecutionProofsByRange` RPC was sent to the network.
    /// Returns `(request_id, peer_id)`.
    fn find_execution_proofs_by_range_request(
        &mut self,
    ) -> (ExecutionProofsByRangeRequestId, PeerId) {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::ExecutionProofsByRange(_),
                app_request_id: AppRequestId::Sync(SyncRequestId::ExecutionProofsByRange(id)),
            } => Some((*id, *peer_id)),
            _ => None,
        })
        .unwrap_or_else(|e| panic!("Expected ExecutionProofsByRange request: {e:?}"))
    }

    /// Assert no `ExecutionProofsByRange` RPC exists in the queue.
    #[track_caller]
    fn expect_no_execution_proof_range_request(&mut self) {
        self.drain_network_rx();
        let found = self.network_rx_queue.iter().any(|ev| {
            matches!(
                ev,
                NetworkMessage::SendRequest {
                    request: RequestType::ExecutionProofsByRange(_),
                    ..
                }
            )
        });
        assert!(
            !found,
            "Expected no ExecutionProofsByRange request, but one was found"
        );
    }

    /// Assert an `ExecutionProofsByRoot` RPC was sent; return `(id, peer_id)`.
    fn find_execution_proofs_by_root_request(
        &mut self,
    ) -> (ExecutionProofsByRootRequestId, PeerId) {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::ExecutionProofsByRoot(_),
                app_request_id: AppRequestId::Sync(SyncRequestId::ExecutionProofsByRoot(id)),
            } => Some((*id, *peer_id)),
            _ => None,
        })
        .unwrap_or_else(|e| panic!("Expected ExecutionProofsByRoot request: {e:?}"))
    }

    /// Send stream-termination for an `ExecutionProofsByRange` request.
    fn terminate_execution_proofs_by_range(
        &mut self,
        req_id: ExecutionProofsByRangeRequestId,
        peer_id: PeerId,
    ) {
        self.send_sync_message(SyncMessage::RpcExecutionProof {
            sync_request_id: SyncRequestId::ExecutionProofsByRange(req_id),
            peer_id,
            execution_proof: None,
        });
    }

    /// Send stream-termination for an `ExecutionProofsByRoot` request.
    fn terminate_execution_proofs_by_root(
        &mut self,
        req_id: ExecutionProofsByRootRequestId,
        peer_id: PeerId,
    ) {
        self.send_sync_message(SyncMessage::RpcExecutionProof {
            sync_request_id: SyncRequestId::ExecutionProofsByRoot(req_id),
            peer_id,
            execution_proof: None,
        });
    }

    /// Find an outbound `ExecutionProofStatus` RPC request; returns `(request_id, peer_id)`.
    fn find_execution_proof_status_request(&mut self) -> (ExecutionProofStatusRequestId, PeerId) {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::ExecutionProofStatus(_),
                app_request_id: AppRequestId::Sync(SyncRequestId::ExecutionProofStatus(id)),
            } => Some((*id, *peer_id)),
            _ => None,
        })
        .unwrap_or_else(|e| panic!("Expected ExecutionProofStatus request: {e:?}"))
    }

    /// Drain all pending `ExecutionProofStatus` outbound requests from the network queue.
    ///
    /// Called after `start_proof_sync()` (or `bootstrap_proof_sync_to_fill_mode()`) to
    /// prevent those requests from leaking into assertions in the caller.
    fn drain_execution_proof_status_requests(&mut self) {
        self.drain_network_rx();
        self.network_rx_queue.retain(|ev| {
            !matches!(
                ev,
                NetworkMessage::SendRequest {
                    request: RequestType::ExecutionProofStatus(_),
                    ..
                }
            )
        });
    }

    /// Connect a proof-capable peer and deliver an `ExecutionProofStatus` for `peer_slot`.
    ///
    /// For slots within our head the block root is looked up so the entry is verified.
    /// For slots ahead of our head the entry is cached as unverified (optimistic) but
    /// still eligible for peer selection.
    fn new_proof_peer_with_status(&mut self, peer_slot: u64) -> PeerId {
        let peer_id = self.new_connected_proof_capable_peer();
        let best_slot = self.harness.chain.best_slot();
        let block_root = if Slot::new(peer_slot) <= best_slot {
            self.harness
                .chain
                .block_root_at_slot(Slot::new(peer_slot), beacon_chain::WhenSlotSkipped::None)
                .ok()
                .flatten()
                .unwrap_or_else(Hash256::random)
        } else {
            Hash256::random()
        };
        self.send_sync_message(SyncMessage::RpcExecutionProofStatus {
            peer_id,
            request_id: None,
            status: ExecutionProofStatus {
                slot: peer_slot,
                block_root,
            },
        });
        peer_id
    }

    fn find_and_complete_processing_chain_segment(&mut self, id: ChainSegmentProcessId) {
        self.pop_received_processor_event(|ev| {
            (ev.work_type() == WorkType::ChainSegment).then_some(())
        })
        .unwrap_or_else(|e| panic!("Expected chain segment work event: {e}"));

        self.log(&format!(
            "Completing ChainSegment processing work {id:?} with success"
        ));
        self.send_sync_message(SyncMessage::BatchProcessed {
            sync_type: id,
            result: crate::sync::BatchProcessResult::Success {
                sent_blocks: 8,
                imported_blocks: 8,
            },
        });
    }

    fn complete_and_process_range_sync_until(
        &mut self,
        last_epoch: u64,
        request_filter: RequestFilter,
    ) {
        for epoch in 0..last_epoch {
            // Note: In this test we can't predict the block peer
            let id =
                self.find_and_complete_blocks_by_range_request(request_filter.clone().epoch(epoch));
            if let RangeRequestId::RangeSync { batch_id, .. } = id {
                assert_eq!(batch_id.as_u64(), epoch, "Unexpected batch_id");
            } else {
                panic!("unexpected RangeRequestId {id:?}");
            }

            let id = match id {
                RangeRequestId::RangeSync { chain_id, batch_id } => {
                    ChainSegmentProcessId::RangeBatchId(chain_id, batch_id)
                }
                RangeRequestId::BackfillSync { batch_id } => {
                    ChainSegmentProcessId::BackSyncBatchId(batch_id)
                }
            };

            self.find_and_complete_processing_chain_segment(id);
            if epoch < last_epoch - 1 {
                self.assert_state(RangeSyncType::Finalized);
            } else {
                self.assert_no_chains_exist();
                self.assert_no_failed_chains();
            }
        }
    }

    async fn create_canonical_block(&mut self) -> (SignedBeaconBlock<E>, Option<DataSidecars<E>>) {
        self.harness.advance_slot();

        let block_root = self
            .harness
            .extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        let store = &self.harness.chain.store;
        let block = store.get_full_block(&block_root).unwrap().unwrap();
        let fork = block.fork_name_unchecked();

        let data_sidecars = if fork.fulu_enabled() {
            store
                .get_data_columns(&block_root)
                .unwrap()
                .map(|columns| {
                    columns
                        .into_iter()
                        .map(CustodyDataColumn::from_asserted_custody)
                        .collect()
                })
                .map(DataSidecars::DataColumns)
        } else if fork.deneb_enabled() {
            store
                .get_blobs(&block_root)
                .unwrap()
                .blobs()
                .map(DataSidecars::Blobs)
        } else {
            None
        };

        (block, data_sidecars)
    }

    async fn remember_block(
        &mut self,
        (block, data_sidecars): (SignedBeaconBlock<E>, Option<DataSidecars<E>>),
    ) {
        // This code is kind of duplicated from Harness::process_block, but takes sidecars directly.
        let block_root = block.canonical_root();
        self.harness.set_current_slot(block.slot());
        let _: SignedBeaconBlockHash = self
            .harness
            .chain
            .process_block(
                block_root,
                build_rpc_block(block.into(), &data_sidecars),
                NotifyExecutionLayer::Yes,
                BlockImportSource::RangeSync,
                || Ok(()),
            )
            .await
            .unwrap()
            .try_into()
            .unwrap();
        self.harness.chain.recompute_head_at_current_slot().await;
    }
}

fn build_rpc_block(
    block: Arc<SignedBeaconBlock<E>>,
    data_sidecars: &Option<DataSidecars<E>>,
) -> RpcBlock<E> {
    match data_sidecars {
        Some(DataSidecars::Blobs(blobs)) => {
            RpcBlock::new(None, block, Some(blobs.clone())).unwrap()
        }
        Some(DataSidecars::DataColumns(columns)) => {
            RpcBlock::new_with_custody_columns(None, block, columns.clone()).unwrap()
        }
        // Block has no data, expects zero columns
        None => RpcBlock::new_without_blobs(None, block),
    }
}

#[test]
fn head_chain_removed_while_finalized_syncing() {
    // NOTE: this is a regression test.
    // Added in PR https://github.com/sigp/lighthouse/pull/2821
    let mut rig = TestRig::test_setup();

    // Get a peer with an advanced head
    let head_peer = rig.add_head_peer();
    rig.assert_state(RangeSyncType::Head);

    // Sync should have requested a batch, grab the request.
    let _ = rig.find_blocks_by_range_request(filter().peer(head_peer));

    // Now get a peer with an advanced finalized epoch.
    let finalized_peer = rig.add_finalized_peer();
    rig.assert_state(RangeSyncType::Finalized);

    // Sync should have requested a batch, grab the request
    let _ = rig.find_blocks_by_range_request(filter().peer(finalized_peer));

    // Fail the head chain by disconnecting the peer.
    rig.peer_disconnected(head_peer);
    rig.assert_state(RangeSyncType::Finalized);
}

#[tokio::test]
async fn state_update_while_purging() {
    // NOTE: this is a regression test.
    // Added in PR https://github.com/sigp/lighthouse/pull/2827
    let mut rig = TestRig::test_setup();

    // Create blocks on a separate harness
    let mut rig_2 = TestRig::test_setup();
    // Need to create blocks that can be inserted into the fork-choice and fit the "known
    // conditions" below.
    let head_peer_block = rig_2.create_canonical_block().await;
    let head_peer_root = head_peer_block.0.canonical_root();
    let finalized_peer_block = rig_2.create_canonical_block().await;
    let finalized_peer_root = finalized_peer_block.0.canonical_root();

    // Get a peer with an advanced head
    let head_peer = rig.add_head_peer_with_root(head_peer_root);
    rig.assert_state(RangeSyncType::Head);

    // Sync should have requested a batch, grab the request.
    let _ = rig.find_blocks_by_range_request(filter().peer(head_peer));

    // Now get a peer with an advanced finalized epoch.
    let finalized_peer = rig.add_finalized_peer_with_root(finalized_peer_root);
    rig.assert_state(RangeSyncType::Finalized);

    // Sync should have requested a batch, grab the request
    let _ = rig.find_blocks_by_range_request(filter().peer(finalized_peer));

    // Now the chain knows both chains target roots.
    rig.remember_block(head_peer_block).await;
    rig.remember_block(finalized_peer_block).await;

    // Add an additional peer to the second chain to make range update it's status
    rig.add_finalized_peer();
}

#[test]
fn pause_and_resume_on_ee_offline() {
    let mut rig = TestRig::test_setup();

    // add some peers
    let peer1 = rig.add_head_peer();
    // make the ee offline
    rig.update_execution_engine_state(EngineState::Offline);
    // send the response to the request
    rig.find_and_complete_blocks_by_range_request(filter().peer(peer1).epoch(0));
    // the beacon processor shouldn't have received any work
    rig.expect_empty_processor();

    // while the ee is offline, more peers might arrive. Add a new finalized peer.
    let _peer2 = rig.add_finalized_peer();

    // send the response to the request
    // Don't filter requests and the columns requests may be sent to peer1 or peer2
    // We need to filter by epoch, because the previous batch eagerly sent requests for the next
    // epoch for the other batch. So we can either filter by epoch of by sync type.
    rig.find_and_complete_blocks_by_range_request(filter().epoch(0));
    // the beacon processor shouldn't have received any work
    rig.expect_empty_processor();
    // make the beacon processor available again.
    // update_execution_engine_state implicitly calls resume
    // now resume range, we should have two processing requests in the beacon processor.
    rig.update_execution_engine_state(EngineState::Online);

    // The head chain and finalized chain (2) should be in the processing queue
    rig.expect_chain_segments(2);
}

/// To attempt to finalize the peer's status finalized checkpoint we synced to its finalized epoch +
/// 2 epochs + 1 slot.
const EXTRA_SYNCED_EPOCHS: u64 = 2 + 1;

#[test]
fn finalized_sync_enough_global_custody_peers_few_chain_peers() {
    // Run for all forks
    let mut r = TestRig::test_setup();

    let advanced_epochs: u64 = 2;
    let remote_info = r.finalized_remote_info_advanced_by(advanced_epochs.into());

    // Generate enough peers and supernodes to cover all custody columns
    let peer_count = 100;
    r.add_fullnode_peers(remote_info.clone(), peer_count);
    r.add_supernode_peer(remote_info);
    r.assert_state(RangeSyncType::Finalized);

    let last_epoch = advanced_epochs + EXTRA_SYNCED_EPOCHS;
    r.complete_and_process_range_sync_until(last_epoch, filter());
}

#[test]
fn finalized_sync_not_enough_custody_peers_on_start() {
    let mut r = TestRig::test_setup();
    // Only run post-PeerDAS
    if !r.fork_name.fulu_enabled() {
        return;
    }

    let advanced_epochs: u64 = 2;
    let remote_info = r.finalized_remote_info_advanced_by(advanced_epochs.into());

    // Unikely that the single peer we added has enough columns for us. Tests are deterministic and
    // this error should never be hit
    r.add_fullnode_peer(remote_info.clone());
    r.assert_state(RangeSyncType::Finalized);

    // Because we don't have enough peers on all columns we haven't sent any request.
    // NOTE: There's a small chance that this single peer happens to custody exactly the set we
    // expect, in that case the test will fail. Find a way to make the test deterministic.
    r.expect_empty_network();

    // Generate enough peers and supernodes to cover all custody columns
    let peer_count = 100;
    r.add_fullnode_peers(remote_info.clone(), peer_count);
    r.add_supernode_peer(remote_info);

    let last_epoch = advanced_epochs + EXTRA_SYNCED_EPOCHS;
    r.complete_and_process_range_sync_until(last_epoch, filter());
}

// --- ProofSync state-machine tests ---

// These tests exercise the `ProofSync` state machine directly, covering its full lifecycle:
// Idle → Syncing (range request for large gaps, by-root fill for small gaps),
// pause/resume semantics, concurrency cap, in-flight deduplication, and response forwarding.
//
// In tests, range_request_threshold = 0, so any non-zero slot gap triggers a range request.
// At genesis (slot 0, gap = 0) the poll goes directly to by-root fill requests.

/// Drive ProofSync through a range request cycle and terminate it, leaving the state in
/// `Syncing` with no active range request (ready for by-root fill on the next poll).
///
/// Advances the harness slot clock by 1 to produce a non-zero slot gap, which triggers
/// a range request (range_request_threshold = 0 in tests).
fn bootstrap_proof_sync_to_fill_mode(
    rig: &mut TestRig,
) -> (ExecutionProofsByRangeRequestId, PeerId) {
    rig.harness.advance_slot();
    rig.sync_manager.start_proof_sync();
    rig.sync_manager.poll_proof_sync();
    let (req_id, peer_id) = rig.find_execution_proofs_by_range_request();
    rig.drain_execution_proof_status_requests();
    rig.terminate_execution_proofs_by_range(req_id, peer_id);
    assert_eq!(
        rig.sync_manager.proof_sync().state(),
        ProofSyncState::Syncing
    );
    assert!(!rig.sync_manager.proof_sync().range_request().is_some());
    (req_id, peer_id)
}

/// Build a `MissingProofInfo` with a fresh random root for test seeding.
fn missing_proof(root: Hash256) -> MissingProofInfo {
    MissingProofInfo {
        root,
        existing_proof_types: vec![],
    }
}

/// Build a minimal `SignedExecutionProof` suitable for RPC response messages.
fn make_signed_proof() -> Arc<types::SignedExecutionProof> {
    Arc::new(types::SignedExecutionProof {
        message: types::ExecutionProof::default(),
        validator_index: 0,
        signature: SignatureBytes::empty(),
    })
}

/// Test 1: The default initial state of ProofSync is Idle and polling it emits no network events.
#[test]
fn test_proof_sync_starts_in_idle() {
    let mut rig = TestRig::test_setup();
    assert_eq!(rig.sync_manager.proof_sync().state(), ProofSyncState::Idle);
    rig.sync_manager.poll_proof_sync();
    rig.expect_empty_network();
}

/// Test 2: After `start()`, the next `poll()` sends an `ExecutionProofsByRange` RPC.
/// (slot gap = 1 > range_request_threshold = 0 in tests → range request).
#[test]
fn test_proof_sync_pending_range_issues_request_on_poll() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(1);
    rig.harness.advance_slot();

    rig.sync_manager.start_proof_sync();
    assert_eq!(
        rig.sync_manager.proof_sync().state(),
        ProofSyncState::Syncing
    );

    rig.sync_manager.poll_proof_sync();
    let _ = rig.find_execution_proofs_by_range_request();
    assert!(
        rig.sync_manager.proof_sync().range_request().is_some(),
        "Range request should be in-flight after poll"
    );
}

/// Test 3: With no proof-capable peer, `poll()` emits no request (soft failure).
/// Adding a peer and polling again sends the range request.
#[test]
fn test_proof_sync_no_peer_stays_pending() {
    let mut rig = TestRig::test_setup();
    rig.harness.advance_slot();

    rig.sync_manager.start_proof_sync();
    rig.sync_manager.poll_proof_sync();
    rig.expect_no_execution_proof_range_request();
    assert_eq!(
        rig.sync_manager.proof_sync().state(),
        ProofSyncState::Syncing
    );
    assert!(!rig.sync_manager.proof_sync().range_request().is_some());

    // Adding a proof-capable peer; the next poll sends the request.
    let _proof_peer = rig.new_proof_peer_with_status(1);
    rig.sync_manager.poll_proof_sync();
    let _ = rig.find_execution_proofs_by_range_request();
    assert!(rig.sync_manager.proof_sync().range_request().is_some());
}

/// Test 4: While a range request is in-flight, `poll()` must not send any new requests.
#[test]
fn test_proof_sync_in_flight_poll_is_noop() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(1);
    rig.harness.advance_slot();

    rig.sync_manager.start_proof_sync();
    rig.sync_manager.poll_proof_sync();
    let _ = rig.find_execution_proofs_by_range_request();
    rig.drain_execution_proof_status_requests();
    assert!(rig.sync_manager.proof_sync().range_request().is_some());

    // A second poll while a range request is in-flight should produce nothing.
    rig.sync_manager.poll_proof_sync();
    rig.expect_empty_network();
    assert!(rig.sync_manager.proof_sync().range_request().is_some());
}

/// Test 5: Stream termination with the correct ID clears the in-flight range request.
/// The next poll will then issue by-root fill requests (gap is now 0 at genesis).
#[test]
fn test_proof_sync_range_termination_enters_fill_mode() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(1);
    rig.harness.advance_slot();

    rig.sync_manager.start_proof_sync();
    rig.sync_manager.poll_proof_sync();
    let (req_id, peer_id) = rig.find_execution_proofs_by_range_request();
    assert!(rig.sync_manager.proof_sync().range_request().is_some());

    rig.terminate_execution_proofs_by_range(req_id, peer_id);
    assert_eq!(
        rig.sync_manager.proof_sync().state(),
        ProofSyncState::Syncing
    );
    assert!(
        !rig.sync_manager.proof_sync().range_request().is_some(),
        "Range request should be cleared after stream termination"
    );
}

/// Test 6: Stream termination with a wrong ID is ignored; the range request stays in-flight.
#[test]
fn test_proof_sync_wrong_id_termination_ignored() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(1);
    rig.harness.advance_slot();

    rig.sync_manager.start_proof_sync();
    rig.sync_manager.poll_proof_sync();
    let (_req_id, peer_id) = rig.find_execution_proofs_by_range_request();
    assert!(rig.sync_manager.proof_sync().range_request().is_some());

    // Terminate with a different (fake) ID — should be ignored.
    let fake_id = ExecutionProofsByRangeRequestId { id: 9999 };
    rig.terminate_execution_proofs_by_range(fake_id, peer_id);
    assert!(
        rig.sync_manager.proof_sync().range_request().is_some(),
        "Wrong ID should not clear the in-flight range request"
    );
}

/// Test 7: With no missing proofs, `poll()` in `Syncing` is a no-op.
#[test]
fn test_proof_sync_fill_mode_no_missing_proofs() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(0);

    // At genesis (gap = 0) start() transitions directly to by-root fill behaviour.
    rig.sync_manager.start_proof_sync();
    rig.drain_execution_proof_status_requests();

    // test_missing_proofs is None → chain returns empty → no requests sent.
    rig.sync_manager.poll_proof_sync();
    rig.expect_empty_network();
    assert_eq!(
        rig.sync_manager.proof_sync().state(),
        ProofSyncState::Syncing
    );
}

/// Test 8: With seeded missing proofs, `poll()` sends one `ExecutionProofsByRoot`
/// request per missing proof.
#[test]
fn test_proof_sync_fill_mode_issues_by_root_requests() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(0);

    rig.sync_manager.start_proof_sync();
    rig.drain_execution_proof_status_requests();

    let missing = vec![
        missing_proof(Hash256::random()),
        missing_proof(Hash256::random()),
    ];
    rig.sync_manager.proof_sync_mut().test_missing_proofs = Some(missing);
    rig.sync_manager.poll_proof_sync();

    let _ = rig.find_execution_proofs_by_root_request();
    let _ = rig.find_execution_proofs_by_root_request();
    assert_eq!(rig.sync_manager.proof_sync().in_flight().len(), 2);
}

/// Test 9: `poll()` must not exceed `DEFAULT_MAX_CONCURRENT = 4` in-flight requests
/// even when more missing proofs are present.
#[test]
fn test_proof_sync_fill_mode_respects_max_concurrent() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(0);

    rig.sync_manager.start_proof_sync();
    rig.drain_execution_proof_status_requests();

    // Seed 6 distinct missing proofs; only 4 should be requested.
    let missing: Vec<MissingProofInfo> = (0..6).map(|_| missing_proof(Hash256::random())).collect();
    rig.sync_manager.proof_sync_mut().test_missing_proofs = Some(missing);
    rig.sync_manager.poll_proof_sync();

    // Consume exactly 4 requests.
    for _ in 0..4 {
        let _ = rig.find_execution_proofs_by_root_request();
    }
    assert_eq!(
        rig.sync_manager.proof_sync().in_flight().len(),
        4,
        "Should have exactly 4 in-flight requests (max_concurrent)"
    );
    // No 5th request should be present.
    rig.expect_empty_network();
}

/// Test 10: In-flight roots must not be re-requested on a subsequent poll.
#[test]
fn test_proof_sync_fill_mode_skips_in_flight_roots() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(0);

    rig.sync_manager.start_proof_sync();
    rig.drain_execution_proof_status_requests();

    let missing = vec![
        missing_proof(Hash256::random()),
        missing_proof(Hash256::random()),
    ];
    rig.sync_manager.proof_sync_mut().test_missing_proofs = Some(missing);

    // First poll: 2 requests sent, in_flight = 2.
    rig.sync_manager.poll_proof_sync();
    let _ = rig.find_execution_proofs_by_root_request();
    let _ = rig.find_execution_proofs_by_root_request();
    assert_eq!(rig.sync_manager.proof_sync().in_flight().len(), 2);

    // Second poll with same missing list: roots already in-flight, no new requests.
    rig.sync_manager.poll_proof_sync();
    rig.expect_empty_network();
    assert_eq!(
        rig.sync_manager.proof_sync().in_flight().len(),
        2,
        "In-flight count should be unchanged after second poll"
    );
}

/// Test 11: With no proof-capable peer, `poll()` in `Syncing` emits no requests.
#[test]
fn test_proof_sync_fill_mode_no_peer_breaks() {
    let mut rig = TestRig::test_setup();
    // Force Syncing with no proof-capable peer — best_proof_peer() returns None.
    rig.sync_manager
        .proof_sync_mut()
        .set_state(ProofSyncState::Syncing);

    let missing = vec![
        missing_proof(Hash256::random()),
        missing_proof(Hash256::random()),
    ];
    rig.sync_manager.proof_sync_mut().test_missing_proofs = Some(missing);
    rig.sync_manager.poll_proof_sync();

    rig.expect_empty_network();
    assert_eq!(
        rig.sync_manager.proof_sync().in_flight().len(),
        0,
        "NoPeer should break iteration leaving in_flight empty"
    );
}

/// Test 12: `on_request_terminated` removes the entry from `in_flight`.
#[test]
fn test_proof_sync_on_request_terminated_clears_in_flight() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(0);

    rig.sync_manager.start_proof_sync();
    rig.drain_execution_proof_status_requests();

    let missing = vec![missing_proof(Hash256::random())];
    rig.sync_manager.proof_sync_mut().test_missing_proofs = Some(missing);
    rig.sync_manager.poll_proof_sync();

    let (req_id, peer_id) = rig.find_execution_proofs_by_root_request();
    assert_eq!(rig.sync_manager.proof_sync().in_flight().len(), 1);

    rig.terminate_execution_proofs_by_root(req_id, peer_id);
    assert_eq!(
        rig.sync_manager.proof_sync().in_flight().len(),
        0,
        "in_flight should be empty after termination"
    );
}

/// Test 13: `pause()` resets state to `Idle` but leaves in-flight by-root requests open
/// so that any responses that arrive can still be processed.
#[test]
fn test_proof_sync_pause_resets_to_idle() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(0);

    rig.sync_manager.start_proof_sync();
    rig.drain_execution_proof_status_requests();

    // Seed some in-flight requests.
    let missing = vec![
        missing_proof(Hash256::random()),
        missing_proof(Hash256::random()),
    ];
    rig.sync_manager.proof_sync_mut().test_missing_proofs = Some(missing);
    rig.sync_manager.poll_proof_sync();
    let _ = rig.find_execution_proofs_by_root_request();
    let _ = rig.find_execution_proofs_by_root_request();
    assert!(rig.sync_manager.proof_sync().in_flight().len() > 0);

    // Pause resets state but preserves in-flight by-root entries.
    rig.sync_manager.proof_sync_mut().pause();
    assert_eq!(rig.sync_manager.proof_sync().state(), ProofSyncState::Idle);
    assert!(
        rig.sync_manager.proof_sync().in_flight().len() > 0,
        "in-flight by-root requests are preserved across pause so responses can still land"
    );

    // Polling in Idle emits nothing new.
    rig.sync_manager.poll_proof_sync();
    rig.expect_empty_network();
}

/// Test 14: Re-entering range sync (pause) then completing again issues a fresh range request.
#[test]
fn test_proof_sync_re_enter_range_resets_then_restarts() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(1);
    rig.harness.advance_slot();

    // First range request cycle.
    rig.sync_manager.start_proof_sync();
    rig.sync_manager.poll_proof_sync();
    let (req_id, peer_id) = rig.find_execution_proofs_by_range_request();
    rig.terminate_execution_proofs_by_range(req_id, peer_id);
    assert!(!rig.sync_manager.proof_sync().range_request().is_some());

    // Re-entering range sync pauses ProofSync.
    rig.sync_manager.proof_sync_mut().pause();
    assert_eq!(rig.sync_manager.proof_sync().state(), ProofSyncState::Idle);

    // Range sync completes again → start() → Syncing.
    rig.sync_manager.start_proof_sync();
    assert_eq!(
        rig.sync_manager.proof_sync().state(),
        ProofSyncState::Syncing
    );

    // New poll sends a fresh range request (slot gap still > 0).
    rig.sync_manager.poll_proof_sync();
    let _ = rig.find_execution_proofs_by_range_request();
    assert!(rig.sync_manager.proof_sync().range_request().is_some());
}

/// Test 15: At genesis (slot gap = 0 ≤ range_request_threshold = 0), no range request
/// is issued — `poll()` goes directly to the by-root fill path.
#[test]
fn test_proof_sync_count_zero_skips_to_fill() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(0);

    rig.sync_manager.start_proof_sync();
    rig.drain_execution_proof_status_requests();
    rig.sync_manager.poll_proof_sync();

    rig.expect_no_execution_proof_range_request();
    assert_eq!(
        rig.sync_manager.proof_sync().state(),
        ProofSyncState::Syncing
    );
    assert!(!rig.sync_manager.proof_sync().range_request().is_some());
}

/// Test 16: A proof arriving on an `ExecutionProofsByRange` stream must be forwarded
/// to the beacon processor as `GossipExecutionProof` work.
#[test]
fn test_proof_sync_range_response_forwarded_to_processor() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(1);
    rig.harness.advance_slot();

    rig.sync_manager.start_proof_sync();
    rig.sync_manager.poll_proof_sync();
    let (req_id, peer_id) = rig.find_execution_proofs_by_range_request();
    assert!(rig.sync_manager.proof_sync().range_request().is_some());

    // Send a proof (non-termination) response.
    rig.send_sync_message(SyncMessage::RpcExecutionProof {
        sync_request_id: SyncRequestId::ExecutionProofsByRange(req_id),
        peer_id,
        execution_proof: Some(make_signed_proof()),
    });

    rig.pop_received_processor_event(|ev| {
        (ev.work_type() == WorkType::GossipExecutionProof).then_some(())
    })
    .unwrap_or_else(|e| panic!("Expected GossipExecutionProof work event: {e:?}"));

    // Range request is still in-flight (stream not yet terminated).
    assert!(rig.sync_manager.proof_sync().range_request().is_some());
}

/// Test 17: A proof arriving on an `ExecutionProofsByRoot` stream must be forwarded
/// to the beacon processor as `GossipExecutionProof` work.
#[test]
fn test_proof_sync_root_response_forwarded_to_processor() {
    let mut rig = TestRig::test_setup();
    let _proof_peer = rig.new_proof_peer_with_status(0);

    // At genesis (gap = 0) poll goes directly to by-root fill.
    rig.sync_manager.start_proof_sync();
    rig.drain_execution_proof_status_requests();

    let missing = vec![missing_proof(Hash256::random())];
    rig.sync_manager.proof_sync_mut().test_missing_proofs = Some(missing);
    rig.sync_manager.poll_proof_sync();

    let (req_id, peer_id) = rig.find_execution_proofs_by_root_request();

    // Send a proof (non-termination) response on the by-root stream.
    rig.send_sync_message(SyncMessage::RpcExecutionProof {
        sync_request_id: SyncRequestId::ExecutionProofsByRoot(req_id),
        peer_id,
        execution_proof: Some(make_signed_proof()),
    });

    rig.pop_received_processor_event(|ev| {
        (ev.work_type() == WorkType::GossipExecutionProof).then_some(())
    })
    .unwrap_or_else(|e| panic!("Expected GossipExecutionProof work event: {e:?}"));
}

/// Test 18: A peer that claims an implausible block root (slot we have, wrong root)
/// must be ignored — an implausible status must not overwrite a valid cached entry.
#[test]
fn test_implausible_block_root_ignored() {
    let mut rig = TestRig::test_setup();
    let proof_peer = rig.new_connected_proof_capable_peer();

    // Send a valid inbound status at slot 0 with the correct genesis block root.
    let genesis_root = rig
        .harness
        .chain
        .canonical_head
        .cached_head()
        .head_block_root();
    rig.send_sync_message(SyncMessage::RpcExecutionProofStatus {
        peer_id: proof_peer,
        request_id: None,
        status: ExecutionProofStatus {
            slot: 0,
            block_root: genesis_root,
        },
    });

    assert!(
        rig.sync_manager
            .proof_sync()
            .peer_status(&proof_peer)
            .is_some(),
        "Peer should be cached after valid status"
    );
    assert_eq!(
        rig.sync_manager
            .proof_sync()
            .peer_status(&proof_peer)
            .map(|s| s.verified),
        Some(true),
        "Cached entry should be verified"
    );

    // Send an inbound status with a wrong block root for a slot we have.
    rig.send_sync_message(SyncMessage::RpcExecutionProofStatus {
        peer_id: proof_peer,
        request_id: None,
        status: ExecutionProofStatus {
            slot: 0,
            block_root: Hash256::random(),
        },
    });

    // The implausible status must be dropped; the original valid entry should remain.
    assert!(
        rig.sync_manager
            .proof_sync()
            .peer_status(&proof_peer)
            .is_some(),
        "Valid cached entry must survive an implausible status update"
    );
    assert_eq!(
        rig.sync_manager
            .proof_sync()
            .peer_status(&proof_peer)
            .map(|s| s.verified),
        Some(true),
        "Cached entry should still be verified after implausible status"
    );
}

/// Test 19: A peer that claims a slot ahead of our head is cached optimistically
/// with `verified = false`.
#[test]
fn test_optimistic_caching_for_ahead_peer() {
    let mut rig = TestRig::test_setup();
    let proof_peer = rig.new_connected_proof_capable_peer();

    // best_slot() == 0 at genesis; slot 999 is well ahead of our head.
    rig.send_sync_message(SyncMessage::RpcExecutionProofStatus {
        peer_id: proof_peer,
        request_id: None, // inbound (peer-initiated)
        status: ExecutionProofStatus {
            slot: 999,
            block_root: Hash256::random(),
        },
    });

    assert!(
        rig.sync_manager
            .proof_sync()
            .peer_status(&proof_peer)
            .is_some(),
        "Ahead-of-head peer should be cached optimistically"
    );
    assert_eq!(
        rig.sync_manager
            .proof_sync()
            .peer_status(&proof_peer)
            .map(|s| s.verified),
        Some(false),
        "Ahead-of-head peer must be cached as unverified"
    );
}

/// Test 20: `start()` re-requests status for a peer whose cached entry is unverified.
///
/// `needs_refresh()` returns `true` for unverified entries, so a subsequent `start()`
/// should issue a fresh `ExecutionProofStatus` request for that peer.
#[test]
fn test_start_refreshes_unverified_entries() {
    let mut rig = TestRig::test_setup();
    let proof_peer = rig.new_connected_proof_capable_peer();

    // Override the peer's initial (verified) cache entry with an optimistic one by sending
    // an inbound status with a slot beyond our head — this makes the entry unverified.
    rig.send_sync_message(SyncMessage::RpcExecutionProofStatus {
        peer_id: proof_peer,
        request_id: None,
        status: ExecutionProofStatus {
            slot: 999,
            block_root: Hash256::random(),
        },
    });
    assert_eq!(
        rig.sync_manager
            .proof_sync()
            .peer_status(&proof_peer)
            .map(|s| s.verified),
        Some(false),
        "Entry should be unverified after optimistic caching"
    );

    // First start(): peer is unverified → needs_refresh=true → sends a status request.
    rig.sync_manager.start_proof_sync();
    let (id1, _) = rig.find_execution_proof_status_request();

    // Respond with another optimistic status so the entry stays unverified.
    rig.send_sync_message(SyncMessage::RpcExecutionProofStatus {
        peer_id: proof_peer,
        request_id: Some(id1),
        status: ExecutionProofStatus {
            slot: 999,
            block_root: Hash256::random(),
        },
    });
    assert_eq!(
        rig.sync_manager
            .proof_sync()
            .peer_status(&proof_peer)
            .map(|s| s.verified),
        Some(false),
        "Entry should still be unverified"
    );

    // Pause and restart — start() must re-request because the entry is still unverified.
    rig.sync_manager.proof_sync_mut().pause();
    rig.sync_manager.start_proof_sync();

    // If this succeeds, start() issued a fresh status request for the unverified peer.
    let (_id2, peer2) = rig.find_execution_proof_status_request();
    assert_eq!(
        peer2, proof_peer,
        "New status request should target the same proof peer"
    );
}

/// Test 21: An inbound `ExecutionProofStatus` (peer-initiated, `request_id = None`)
/// populates the proof-sync peer cache exactly as an outbound response does.
#[test]
fn test_inbound_status_populates_cache() {
    let mut rig = TestRig::test_setup();
    let proof_peer = rig.new_connected_proof_capable_peer();

    // Simulate a peer-initiated status exchange: the peer sends us their status.
    rig.send_sync_message(SyncMessage::RpcExecutionProofStatus {
        peer_id: proof_peer,
        request_id: None,
        status: ExecutionProofStatus {
            slot: 42,
            block_root: Hash256::random(),
        },
    });

    assert!(
        rig.sync_manager
            .proof_sync()
            .peer_status(&proof_peer)
            .is_some(),
        "Inbound status must populate the cache"
    );
    // Slot 42 > best_slot(0) → optimistically cached as unverified.
    assert_eq!(
        rig.sync_manager
            .proof_sync()
            .peer_status(&proof_peer)
            .map(|s| s.verified),
        Some(false),
        "Slot ahead of head must be cached as unverified"
    );
}

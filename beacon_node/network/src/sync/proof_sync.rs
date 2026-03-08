//! ProofSync: catch-up mechanism for EIP-8025 execution proofs.
//!
//! After range sync completes, `ProofSync` issues an `ExecutionProofsByRange` request to
//! bootstrap proofs for the newly-synced window (bootstrap mode), then switches to
//! `FillingByRoot` mode where it issues targeted `ExecutionProofsByRoot` requests for any
//! individual blocks that are still missing proofs.

use super::network_context::{CachedExecutionProofStatus, SyncNetworkContext};
use beacon_chain::{BeaconChain, BeaconChainTypes, WhenSlotSkipped};
use execution_layer::MissingProofInfo;
use fnv::FnvHashMap;
use lighthouse_network::PeerId;
use lighthouse_network::rpc::methods::ExecutionProofStatus;
use lighthouse_network::service::api_types::{
    ExecutionProofStatusRequestId, ExecutionProofsByRangeRequestId, ExecutionProofsByRootRequestId,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tracing::debug;
use types::{EthSpec, Hash256, Slot};

/// Maximum number of concurrent `ExecutionProofsByRoot` requests.
const DEFAULT_MAX_CONCURRENT: usize = 4;

/// Operating mode for the proof sync subsystem.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProofSyncState {
    /// Not running - range sync is active.
    Idle,
    /// Range sync is completed. Next poll will issue an `ExecutionProofsByRange` request.
    PendingRangeRequest,
    /// An `ExecutionProofsByRange` request is in-flight. Waiting for the stream to drain.
    RangeRequestInFlight,
    /// Bootstrap complete. Requesting any remaining missing proofs by root on each poll.
    /// Terminal active state until range sync restarts, which resets to `Idle`.
    FillingByRoot,
}

/// Proof sync subsystem for EIP-8025.
///
/// Operates as a state machine with four modes:
/// - `Idle`: no work to do (range sync active or not yet triggered).
/// - `PendingRangeRequest`: range sync is completed; next poll sends the bootstrap range request.
/// - `RangeRequestInFlight`: waiting for the bootstrap range stream to drain.
/// - `FillingByRoot`: terminal active state; issues per-block by-root requests each poll.
///
/// Re-entering range sync resets state to `Idle` (via ProofSync::pause()), which cancels any in-flight requests and clears state. Proof sync will
/// automatically restart when range sync completes (via ProofSync::start()), which transitions to `PendingRangeRequest`.
pub struct ProofSync<T: BeaconChainTypes> {
    /// The beacon chain.
    chain: Arc<BeaconChain<T>>,
    /// The current state of the proof sync subsystem.
    state: ProofSyncState,
    /// Tracks the in-flight range request ID while in `RangeRequestInFlight` state.
    /// `None` in all other states.
    range_request_id: Option<ExecutionProofsByRangeRequestId>,
    /// In-flight by-root request IDs → `MissingProofInfo` (fill mode).
    /// Keeping the full info preserves `existing_proof_types` for awareness of what
    /// proof types the remote peer should supply.
    in_flight: FnvHashMap<ExecutionProofsByRootRequestId, MissingProofInfo>,
    /// Maximum number of concurrent by-root requests in `FillingByRoot` state.
    max_concurrent: usize,
    /// Cached `ExecutionProofStatus` responses from proof-capable peers (peer → cached status).
    peer_execution_proof_statuses: HashMap<PeerId, CachedExecutionProofStatus>,
    /// In-flight `ExecutionProofStatus` request IDs (peer → request ID).
    in_flight_execution_proof_status: HashMap<PeerId, ExecutionProofStatusRequestId>,
    /// Injected missing-proof list for unit testing fill-mode behaviour.
    #[cfg(test)]
    pub test_missing_proofs: Option<Vec<MissingProofInfo>>,
}

impl<T: BeaconChainTypes> ProofSync<T> {
    pub fn new(chain: Arc<BeaconChain<T>>) -> Self {
        Self {
            state: ProofSyncState::Idle,
            range_request_id: None,
            chain,
            in_flight: FnvHashMap::default(),
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            peer_execution_proof_statuses: HashMap::default(),
            in_flight_execution_proof_status: HashMap::default(),
            #[cfg(test)]
            test_missing_proofs: None,
        }
    }

    /// Returns the current state of the proof sync subsystem.
    #[cfg(test)]
    pub fn state(&self) -> ProofSyncState {
        self.state
    }

    #[cfg(test)]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Force-enter `FillingByRoot` state for tests that need to exercise fill-mode
    /// behaviour without going through the bootstrap range cycle.
    #[cfg(test)]
    pub fn enter_fill_mode_for_testing(&mut self) {
        self.state = ProofSyncState::FillingByRoot;
    }

    /// Returns `true` if a cached status entry exists for `peer_id`.
    #[cfg(test)]
    pub fn peer_status_cached(&self, peer_id: &PeerId) -> bool {
        self.peer_execution_proof_statuses.contains_key(peer_id)
    }

    /// Returns the `verified` flag of the cached entry for `peer_id`, if present.
    #[cfg(test)]
    pub fn peer_status_verified_flag(&self, peer_id: &PeerId) -> Option<bool> {
        self.peer_execution_proof_statuses
            .get(peer_id)
            .map(|c| c.verified)
    }

    /// Called by `SyncManager::update_sync_state()` when range sync completes.
    ///
    /// Refreshes `ExecutionProofStatus` for all connected proof-capable peers whose cached entry
    /// is stale (TTL-expired) or unverified, then transitions to `PendingRangeRequest`.
    pub fn start(&mut self, cx: &mut SyncNetworkContext<T>) {
        debug!("ProofSync: range sync complete, refreshing peer statuses");
        for peer_id in cx.connected_proof_capable_peers() {
            let needs_refresh = self
                .peer_execution_proof_statuses
                .get(&peer_id)
                .map(|c| c.needs_refresh())
                .unwrap_or(true);
            if needs_refresh && !self.in_flight_execution_proof_status.contains_key(&peer_id) {
                match cx.request_execution_proof_status(peer_id) {
                    Ok(id) => {
                        self.in_flight_execution_proof_status.insert(peer_id, id);
                    }
                    Err(e) => {
                        debug!(error = ?e, %peer_id, "ProofSync: failed to refresh status at start");
                    }
                }
            }
        }
        self.state = ProofSyncState::PendingRangeRequest;
    }

    /// Called by `SyncManager::update_sync_state()` when entering range sync.
    ///
    /// Stops any in-progress proof sync activity and resets to `Idle`.
    /// Proof sync will automatically restart when range sync completes.
    pub fn pause(&mut self) {
        debug!("ProofSync: pausing and resetting to Idle");
        self.state = ProofSyncState::Idle;
        self.range_request_id = None;
        self.in_flight.clear();
    }

    /// Drive one polling cycle.
    ///
    /// Resets to `Idle` if the node has re-entered range sync. Otherwise dispatches
    /// work according to the current state.
    pub fn poll(&mut self, cx: &mut SyncNetworkContext<T>) {
        match &self.state {
            ProofSyncState::Idle | ProofSyncState::RangeRequestInFlight => {}
            ProofSyncState::PendingRangeRequest => {
                self.request_proof_range(cx);
            }
            ProofSyncState::FillingByRoot => {
                // Terminal active state: remain here until range sync restarts.
                // On each poll, issue by-root requests for any missing proofs up to
                // the concurrency limit.
                #[cfg(not(test))]
                let missing = self.chain.missing_execution_proofs();
                #[cfg(test)]
                let missing = self
                    .test_missing_proofs
                    .clone()
                    .unwrap_or_else(|| self.chain.missing_execution_proofs());
                let in_flight_roots: HashSet<Hash256> =
                    self.in_flight.values().map(|i| i.root).collect();
                let available = self.max_concurrent.saturating_sub(self.in_flight.len());
                let Some(peer_id) =
                    cx.find_best_proof_capable_peer(&self.peer_execution_proof_statuses)
                else {
                    debug!("ProofSync: no proof-capable peer, will retry next poll");
                    return;
                };
                for info in missing
                    .into_iter()
                    .filter(|info| !in_flight_roots.contains(&info.root))
                    .take(available)
                {
                    match cx.request_execution_proofs_by_root(peer_id, info.root) {
                        Ok(id) => {
                            debug!(
                                block_root = %info.root,
                                existing_proof_types = ?info.existing_proof_types,
                                "ProofSync: requesting missing proof"
                            );
                            self.in_flight.insert(id, info);
                        }
                        Err(e) => {
                            debug!(error = ?e, "ProofSync: failed to send proof request");
                        }
                    }
                }
            }
        }
    }

    /// Called when an `ExecutionProofsByRange` RPC stream terminates (response `None`).
    ///
    /// Transitions from `RangeRequestInFlight` to `FillingByRoot`.
    pub fn on_range_request_terminated(&mut self, id: &ExecutionProofsByRangeRequestId) {
        if matches!(&self.state, ProofSyncState::RangeRequestInFlight)
            && self.range_request_id.as_ref() == Some(id)
        {
            debug!("ProofSync: bootstrap range stream complete, switching to fill mode");
            self.range_request_id = None;
            self.state = ProofSyncState::FillingByRoot;
        }
    }

    /// Called when an `ExecutionProofsByRoot` RPC stream terminates (response `None`).
    pub fn on_request_terminated(&mut self, id: &ExecutionProofsByRootRequestId) {
        self.in_flight.remove(id);
    }

    /// Called when a proof-capable peer connects.
    ///
    /// Sends an `ExecutionProofStatus` request unless one is already in-flight for this peer.
    pub fn on_proof_capable_peer_connected(
        &mut self,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        if self.in_flight_execution_proof_status.contains_key(&peer_id) {
            return;
        }
        match cx.request_execution_proof_status(peer_id) {
            Ok(id) => {
                debug!(%peer_id, %id, "ProofSync: queried peer execution proof status");
                self.in_flight_execution_proof_status.insert(peer_id, id);
            }
            Err(e) => {
                debug!(error = ?e, %peer_id, "ProofSync: failed to query peer status on connect");
            }
        }
    }

    /// Called when a proof-capable peer disconnects.
    pub fn on_proof_capable_peer_disconnected(&mut self, peer_id: &PeerId) {
        self.peer_execution_proof_statuses.remove(peer_id);
        self.in_flight_execution_proof_status.remove(peer_id);
    }

    /// Called when an `ExecutionProofStatus` arrives from a peer.
    ///
    /// `request_id` is `Some` for outbound (we initiated) responses and `None` for inbound
    /// (peer-initiated) requests.  In the inbound case the peer's status is still cached.
    pub fn on_peer_execution_proof_status(
        &mut self,
        peer_id: PeerId,
        request_id: Option<ExecutionProofStatusRequestId>,
        status: ExecutionProofStatus,
        cx: &mut SyncNetworkContext<T>,
    ) {
        if let Some(id) = request_id {
            self.in_flight_execution_proof_status.remove(&peer_id);
            cx.on_execution_proof_status_terminated(&id);
        }

        debug!(
            %peer_id,
            slot = status.slot,
            block_root = %status.block_root,
            "ProofSync: received ExecutionProofStatus"
        );

        // Verify the peer's claimed block root against our local chain.
        let best_slot = self.chain.best_slot();
        let verified = if status.slot <= best_slot.as_u64() {
            // We have (or should have) this slot — verify the block root.
            match self
                .chain
                .block_root_at_slot(Slot::new(status.slot), WhenSlotSkipped::None)
            {
                Ok(Some(root)) if root == status.block_root => true,
                _ => {
                    debug!(
                        %peer_id,
                        slot = status.slot,
                        "ProofSync: peer block root mismatch, ignoring status"
                    );
                    return;
                }
            }
        } else {
            // Peer is ahead of our head — cache optimistically as unverified.
            false
        };

        self.peer_execution_proof_statuses.insert(
            peer_id,
            CachedExecutionProofStatus {
                status,
                timestamp: Instant::now(),
                verified,
            },
        );
    }

    /// Called when an `ExecutionProofStatus` request errors.
    ///
    /// Removes the in-flight entry. Does not penalize the peer.
    pub fn on_peer_execution_proof_status_error(
        &mut self,
        peer_id: PeerId,
        request_id: ExecutionProofStatusRequestId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        self.in_flight_execution_proof_status.remove(&peer_id);
        cx.on_execution_proof_status_terminated(&request_id);
        debug!(%peer_id, %request_id, "ProofSync: ExecutionProofStatus request failed (soft)");
    }

    /// Issue an `ExecutionProofsByRange` bootstrap request covering finalized+1 through head.
    ///
    /// Transitions to `RangeRequestInFlight` on success, stays `PendingRangeRequest` if no
    /// proof-capable peer is available.
    fn request_proof_range(&mut self, cx: &mut SyncNetworkContext<T>) {
        let finalized_slot = self
            .chain
            .canonical_head
            .cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());
        let start_slot = finalized_slot + 1;
        // Use the slot clock so the range covers any EL-processed slots beyond the head block.
        let current_slot = self.chain.slot().unwrap_or_else(|_| self.chain.best_slot());
        if current_slot < start_slot {
            debug!("ProofSync: current slot is behind start_slot, switching directly to fill mode");
            self.state = ProofSyncState::FillingByRoot;
            return;
        }
        let count = current_slot.as_u64() - start_slot.as_u64() + 1;

        let Some(peer_id) = cx.find_best_proof_capable_peer(&self.peer_execution_proof_statuses)
        else {
            debug!("ProofSync: no proof-capable peer for range request, will retry next poll");
            // State stays PendingRangeRequest.
            return;
        };
        match cx.request_execution_proofs_by_range(peer_id, start_slot, count) {
            Ok(id) => {
                debug!(
                    %start_slot,
                    %current_slot,
                    count,
                    "ProofSync: bootstrap range request sent"
                );
                self.range_request_id = Some(id);
                self.state = ProofSyncState::RangeRequestInFlight;
            }
            Err(e) => {
                debug!(error = ?e, "ProofSync: range request error");
            }
        }
    }
}

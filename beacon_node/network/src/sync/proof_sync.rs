//! Catch-up mechanism for EIP-8025 execution proofs.
//!
//! Defines [`ProofSync`], the subsystem responsible for requesting execution proofs
//! that are missing from the local proof engine after block sync completes. It manages
//! peer status tracking, decides between bulk range requests and targeted by-root
//! requests, and coordinates the cooldown period between request batches.

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
use tracing::{debug, info};
use types::{EthSpec, Hash256, Slot};

/// Default slot gap above which a bulk `ExecutionProofsByRange` request is preferred over
/// individual `ExecutionProofsByRoot` requests.
const DEFAULT_RANGE_REQUEST_THRESHOLD: u64 = 16;

/// Tracks the single in-flight `ExecutionProofsByRange` request.
///
/// The request ID and serving peer are always set and cleared together, so they are
/// co-located.
pub(crate) struct RangeRequest {
    pub(crate) id: ExecutionProofsByRangeRequestId,
    pub(crate) peer_id: PeerId,
}

/// Maximum number of concurrent `ExecutionProofsByRoot` requests.
const DEFAULT_MAX_CONCURRENT: usize = 4;

/// Operating mode for the proof sync subsystem.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProofSyncState {
    /// Range sync is active; proof sync is paused.
    Idle,
    /// Waiting for the beacon processor to finish importing range sync blocks.
    /// The inner value counts down remaining slot ticks before activation.
    Waiting(u64),
    /// Proof sync is active. Each poll chooses between a range request (large slot gap)
    /// or by-root fill requests (small gap) based on current chain state.
    Syncing,
}

/// Proof sync subsystem for EIP-8025.
///
/// Operates as a three-state machine: `Idle` while range sync is active, `Waiting(n)`
/// after range sync completes (counting down n slot ticks to let the beacon processor
/// finish importing blocks), and `Syncing` once active. In `Syncing`, each poll computes
/// the slot gap between the max(finalized epoch, local verified head) and peer verified
/// head to determine the most efficient request strategy. In-flight by-root and range
/// responses are always processed regardless of state transitions — the proofs are valid
/// independent of sync progress.
pub struct ProofSync<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
    state: ProofSyncState,
    /// Tracks the single in-flight `ExecutionProofsByRange` request (ID + serving peer).
    range_request: Option<RangeRequest>,
    /// In-flight by-root request IDs → `MissingProofInfo`.
    in_flight: FnvHashMap<ExecutionProofsByRootRequestId, MissingProofInfo>,
    /// Slot gap above which a `ByRange` request is preferred over `ByRoot` fill requests.
    range_request_threshold: u64,
    /// Maximum number of concurrent by-root requests.
    max_concurrent: usize,
    /// Cached `ExecutionProofStatus` responses, keyed by peer.
    peer_statuses: HashMap<PeerId, CachedExecutionProofStatus>,
    /// In-flight `ExecutionProofStatus` request IDs, keyed by peer.
    status_in_flight: HashMap<PeerId, ExecutionProofStatusRequestId>,
    /// Number of slot ticks to wait after `start()` or a range response before issuing
    /// the next `ExecutionProofsByRange` request.
    activation_slots: u64,
    /// Suppresses repeated "no proof-capable peer" logs: set when the message is first
    /// emitted, cleared when a peer becomes available.
    logged_no_peer: bool,
    /// Injected missing-proof list for unit testing by-root behaviour.
    #[cfg(test)]
    pub test_missing_proofs: Option<Vec<MissingProofInfo>>,
}

impl<T: BeaconChainTypes> ProofSync<T> {
    /// Creates a new `ProofSync` instance in the `Idle` state.
    ///
    /// `activation_slots` controls how many slot ticks to wait after `start()` or a
    /// completed range response before issuing the next request batch.
    pub fn new(chain: Arc<BeaconChain<T>>, activation_slots: u64) -> Self {
        Self {
            state: ProofSyncState::Idle,
            range_request: None,
            chain,
            in_flight: FnvHashMap::default(),
            range_request_threshold: DEFAULT_RANGE_REQUEST_THRESHOLD,
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            peer_statuses: HashMap::default(),
            status_in_flight: HashMap::default(),
            activation_slots,
            logged_no_peer: false,
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
    pub fn in_flight(&self) -> &FnvHashMap<ExecutionProofsByRootRequestId, MissingProofInfo> {
        &self.in_flight
    }

    #[cfg(test)]
    pub fn set_state(&mut self, state: ProofSyncState) {
        self.state = state;
    }

    #[cfg(test)]
    pub fn set_range_request_threshold(&mut self, threshold: u64) {
        self.range_request_threshold = threshold;
    }

    #[cfg(test)]
    pub fn range_request(&self) -> Option<&RangeRequest> {
        self.range_request.as_ref()
    }

    #[cfg(test)]
    pub fn peer_status(&self, peer_id: &PeerId) -> Option<&CachedExecutionProofStatus> {
        self.peer_statuses.get(peer_id)
    }

    /// Called by `SyncManager` when range sync completes.
    ///
    /// Kicks off peer status refreshes and transitions to `Waiting`, which counts down
    /// slot ticks before activating. This delay allows the beacon processor to finish
    /// importing range sync blocks before proof requests go out.
    pub fn start(&mut self, cx: &mut SyncNetworkContext<T>) {
        info!(
            activation_slots = self.activation_slots,
            "ProofSync: starting, waiting before activation"
        );
        self.refresh_peer_statuses(cx);
        self.state = ProofSyncState::Waiting(self.activation_slots);
    }

    /// Called by `SyncManager` when range sync re-enters.
    ///
    /// Stops new proof requests from being issued. Any already in-flight responses
    /// are still processed as they arrive.
    pub fn pause(&mut self) {
        debug!("ProofSync: pausing");
        self.state = ProofSyncState::Idle;
    }

    /// Drive one polling cycle.
    ///
    /// In `Waiting`, counts down the activation delay. In `Syncing`, computes the slot
    /// gap and dispatches either a range request (gap > `range_request_threshold`) or
    /// by-root fill requests (gap ≤ threshold). Does nothing if a range request is
    /// already in-flight. Peer status refreshes run in the background and do not block
    /// request dispatch.
    pub fn poll(&mut self, cx: &mut SyncNetworkContext<T>) {
        match self.state {
            ProofSyncState::Idle => return,
            ProofSyncState::Waiting(0) => {
                info!("ProofSync: activation delay elapsed, transitioning to Syncing");
                self.state = ProofSyncState::Syncing;
            }
            ProofSyncState::Waiting(ref mut n) => {
                *n -= 1;
                return;
            }
            ProofSyncState::Syncing => {}
        }

        // If a range request is already in-flight, wait for it to drain.
        if self.range_request.is_some() {
            return;
        }

        // Compute the start slot: the higher of the finalized slot and our own verified proof slot,
        // so we don't re-request proofs we've already processed.
        let finalized_slot = self
            .chain
            .canonical_head
            .cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());
        let local_proof_slot = Slot::new(cx.local_execution_proof_status().slot);
        let start_slot = finalized_slot.max(local_proof_slot) + 1;

        let Some((peer_id, peer_slot)) = self.best_peer(cx) else {
            return;
        };

        let gap = peer_slot
            .as_u64()
            .checked_add(1)
            .and_then(|end| end.checked_sub(start_slot.as_u64()))
            .unwrap_or(0);

        if gap > self.range_request_threshold {
            match cx.request_execution_proofs_by_range(peer_id, start_slot, gap) {
                Ok(id) => {
                    debug!(%start_slot, %peer_slot, gap, "ProofSync: range request sent");
                    self.range_request = Some(RangeRequest { id, peer_id });
                }
                Err(e) => {
                    debug!(error = ?e, "ProofSync: range request error");
                }
            }
            return;
        }

        #[cfg(not(test))]
        let missing = self.chain.missing_execution_proofs();
        #[cfg(test)]
        let missing = self
            .test_missing_proofs
            .clone()
            .unwrap_or_else(|| self.chain.missing_execution_proofs());
        let in_flight_roots: HashSet<Hash256> = self.in_flight.values().map(|i| i.root).collect();
        let available = self.max_concurrent.saturating_sub(self.in_flight.len());
        for info in missing
            .into_iter()
            .filter(|info| !in_flight_roots.contains(&info.root))
            .take(available)
        {
            if peer_slot < info.slot {
                debug!(
                    block_root = %info.root,
                    slot = %info.slot,
                    %peer_slot,
                    "ProofSync: best peer slot behind missing block, skipping"
                );
                continue;
            }
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

    /// Called when an `ExecutionProofsByRange` RPC stream terminates (response `None`).
    ///
    /// Transitions back to `Waiting` to give the proof engine time to process the
    /// received proofs before the next request is issued.
    pub fn on_range_request_terminated(&mut self, id: &ExecutionProofsByRangeRequestId) {
        if self.range_request.as_ref().map(|r| &r.id) == Some(id) {
            info!("ProofSync: range stream complete, cooling down before next request");
            self.range_request = None;
            self.state = ProofSyncState::Waiting(self.activation_slots);
        }
    }

    /// Called when an `ExecutionProofsByRange` RPC request errors.
    ///
    /// Clears the in-flight range request so the next `poll()` can retry.
    pub fn on_range_request_error(&mut self, id: &ExecutionProofsByRangeRequestId) {
        if self.range_request.as_ref().map(|r| &r.id) == Some(id) {
            debug!("ProofSync: range request failed, will retry next poll");
            self.range_request = None;
        }
    }

    /// Called when an `ExecutionProofsByRoot` RPC request errors.
    ///
    /// Removes the entry from the in-flight map so the slot is eligible for retry on
    /// the next `poll()`.
    pub fn on_root_request_error(&mut self, id: &ExecutionProofsByRootRequestId) {
        self.in_flight.remove(id);
    }

    /// Called when an `ExecutionProofsByRoot` RPC stream terminates (response `None`).
    ///
    /// Removes the entry from the in-flight map. The proof engine is responsible for
    /// deciding whether the received proofs satisfy the request; this just frees the
    /// concurrency slot.
    pub fn on_root_request_terminated(&mut self, id: &ExecutionProofsByRootRequestId) {
        self.in_flight.remove(id);
    }

    /// Called when a proof-capable peer connects.
    ///
    /// Always issues a fresh `ExecutionProofStatus` request, overwriting any stale
    /// in-flight entry from a prior connection.
    pub fn add_peer(&mut self, peer_id: PeerId, cx: &mut SyncNetworkContext<T>) {
        match cx.request_execution_proof_status(peer_id) {
            Ok(id) => {
                debug!(%peer_id, %id, "ProofSync: queried peer execution proof status");
                self.status_in_flight.insert(peer_id, id);
            }
            Err(e) => {
                debug!(error = ?e, %peer_id, "ProofSync: failed to query peer status on connect");
            }
        }
    }

    /// Called when a proof-capable peer disconnects.
    ///
    /// Removes the peer's cached status and any in-flight status request. If this peer
    /// was serving the active range request, that request is also cleared so the next
    /// `poll()` can retry with a different peer.
    pub fn on_proof_capable_peer_disconnected(&mut self, peer_id: &PeerId) {
        self.peer_statuses.remove(peer_id);
        self.status_in_flight.remove(peer_id);
        // If this peer was serving our range request, clear it so the next poll retries.
        if self
            .range_request
            .as_ref()
            .map(|r| &r.peer_id)
            .filter(|p| *p == peer_id)
            .is_some()
        {
            self.range_request = None;
        }
    }

    /// Called when an `ExecutionProofStatus` arrives from a peer.
    ///
    /// `request_id` is `Some` for responses to our outbound requests and `None` for
    /// peer-initiated status announcements.
    ///
    /// The status is stored with a `verified` flag: `true` if the peer's announced
    /// `(slot, block_root)` pair matches our canonical chain at that slot, `false` if
    /// the slot is ahead of our head (and therefore unverifiable locally). A mismatch —
    /// where the slot is within our chain but the root differs — causes the status to be
    /// discarded and the peer's re-poll timer to be reset.
    pub fn on_peer_execution_proof_status(
        &mut self,
        peer_id: PeerId,
        _request_id: Option<ExecutionProofStatusRequestId>,
        status: ExecutionProofStatus,
    ) {
        debug!(
            %peer_id,
            slot = status.slot,
            block_root = %status.block_root,
            "ProofSync: received ExecutionProofStatus"
        );

        let best_slot = self.chain.best_slot();
        let verified = if status.slot <= best_slot.as_u64() {
            match self
                .chain
                .block_root_at_slot(Slot::new(status.slot), WhenSlotSkipped::None)
            {
                Ok(Some(root)) if root == status.block_root => true,
                _ => {
                    debug!(
                        %peer_id,
                        slot = status.slot,
                        claimed_root = %status.block_root,
                        "ProofSync: peer block root mismatch, ignoring status"
                    );
                    self.on_peer_status_failed(peer_id);
                    return;
                }
            }
        } else {
            false
        };

        self.status_in_flight.remove(&peer_id);
        self.peer_statuses.insert(
            peer_id,
            CachedExecutionProofStatus {
                status,
                timestamp: Instant::now(),
                verified,
            },
        );
    }

    /// Called when an outbound `ExecutionProofStatus` request errors.
    ///
    /// Delegates to `on_peer_status_failed`, which resets the peer's re-poll timer to
    /// defer the next refresh attempt.
    pub fn on_peer_execution_proof_status_error(
        &mut self,
        peer_id: PeerId,
        request_id: ExecutionProofStatusRequestId,
    ) {
        debug!(%peer_id, %request_id, "ProofSync: ExecutionProofStatus request failed (soft)");
        self.on_peer_status_failed(peer_id);
    }

    /// Clears the in-flight status entry and resets the peer's timestamp to defer re-polling.
    /// Inserts a zero-slot placeholder if no prior entry exists.
    fn on_peer_status_failed(&mut self, peer_id: PeerId) {
        debug!(%peer_id, "ProofSync: peer status failed, deferring re-poll");
        self.status_in_flight.remove(&peer_id);
        self.peer_statuses
            .entry(peer_id)
            .and_modify(|entry| entry.timestamp = Instant::now())
            .or_insert_with(|| CachedExecutionProofStatus {
                status: ExecutionProofStatus {
                    slot: 0,
                    block_root: Hash256::ZERO,
                },
                timestamp: Instant::now(),
                verified: false,
            });
    }

    /// Triggers refresh requests for stale or unverified peer entries.
    fn refresh_peer_statuses(&mut self, cx: &mut SyncNetworkContext<T>) {
        for (peer_id, status) in self.peer_statuses.iter() {
            if status.needs_refresh() && !self.status_in_flight.contains_key(peer_id) {
                match cx.request_execution_proof_status(*peer_id) {
                    Ok(id) => {
                        self.status_in_flight.insert(*peer_id, id);
                    }
                    Err(e) => {
                        debug!(error = ?e, %peer_id, "ProofSync: failed to refresh status");
                    }
                }
            }
        }
    }

    /// Triggers refresh requests for stale peer entries, then returns the peer with the
    /// highest announced slot if all outstanding status polls have resolved.
    ///
    /// Verified peers are preferred (their slot is confirmed on-chain), but unverified
    /// peers (whose announced slot is ahead of our head) are also eligible — the proofs
    /// they serve are validated independently on receipt.
    fn best_peer(&mut self, cx: &mut SyncNetworkContext<T>) -> Option<(PeerId, Slot)> {
        self.refresh_peer_statuses(cx);

        let result = self
            .peer_statuses
            .iter()
            .max_by_key(|(_, c)| (c.verified, c.status.slot))
            .map(|(peer_id, c)| (*peer_id, Slot::new(c.status.slot)));

        match result {
            None if !self.logged_no_peer => {
                debug!("ProofSync: no proof-capable peer, will retry next poll");
                self.logged_no_peer = true;
            }
            Some(_) => {
                self.logged_no_peer = false;
            }
            _ => {}
        }

        result
    }
}

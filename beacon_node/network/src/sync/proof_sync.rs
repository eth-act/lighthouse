//! Catch-up mechanism for EIP-8025 execution proofs.
//!
//! Defines [`ProofSync`], the subsystem responsible for requesting execution proofs
//! that are missing from the local proof engine after block sync completes. It manages
//! peer status tracking and, at each slot tick, consults the proof engine directly to
//! decide the most bandwidth-efficient request strategy:
//!
//! - The SSZ-encoded sizes of an `ExecutionProofsByRange` request (20-byte fixed header
//!   plus `proof_filters` for partially-held blocks) and an `ExecutionProofsByRoot` request
//!   (one identifier per missing block) are compared over the full set of servable missing
//!   proofs. Whichever encoding is smaller is used.
//! - `proof_filters` lets the server skip proof types the requester already holds, so
//!   partially-covered blocks do not waste bandwidth even in a range request.
//!
//! The protocol is driven entirely by what the proof engine reports as missing, not by
//! the distance between peer and local verified heads.

use super::network_context::{CachedExecutionProofStatus, SyncNetworkContext};
use crate::metrics;
use beacon_chain::{BeaconChain, BeaconChainTypes, WhenSlotSkipped};
use execution_layer::MissingProofInfo;
use lighthouse_network::PeerId;
use lighthouse_network::rpc::methods::ExecutionProofStatus;
use lighthouse_network::service::api_types::{
    ExecutionProofStatusRequestId, ExecutionProofsByRangeRequestId, ExecutionProofsByRootRequestId,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};
use types::{Hash256, Slot};

/// Tracks the single in-flight `ExecutionProofsByRange` request.
///
/// The request ID and serving peer are always set and cleared together, so they are
/// co-located.
pub(crate) struct ByRangeRequest {
    pub(crate) id: ExecutionProofsByRangeRequestId,
    pub(crate) peer_id: PeerId,
}

/// Tracks the single in-flight `ExecutionProofsByRoot` batch request.
pub(crate) struct ByRootRequest {
    pub(crate) id: ExecutionProofsByRootRequestId,
    pub(crate) peer_id: PeerId,
}

/// Operating mode for the proof sync subsystem.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProofSyncState {
    /// Range sync is active; proof sync is paused.
    Idle,
    /// Proof sync is active. Each poll queries the proof engine for missing proofs and
    /// chooses between range or by-root requests based on byte-efficiency.
    Syncing,
}

/// Number of slot ticks to skip after a proof response stream completes before issuing
/// the next request. Gives the beacon processor time to import received proofs so they
/// no longer appear in `missing_execution_proofs()`.
const POST_REQUEST_COOLDOWN_SLOTS: u64 = 1;

/// Proof sync subsystem for EIP-8025.
///
/// Operates as a two-state machine: `Idle` while range sync is active, `Syncing` once
/// activated. In `Syncing`, each poll queries the proof engine for missing proofs and
/// chooses the most byte-efficient request strategy (range vs by-root). A brief
/// `post_request_cooldown` counter prevents immediate re-requesting after a response
/// stream completes, giving the beacon processor time to import the received proofs.
/// In-flight responses are always processed regardless of state transitions.
pub struct ProofSync<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
    state: ProofSyncState,
    /// Tracks the single in-flight `ExecutionProofsByRange` request (ID + serving peer).
    range_request: Option<ByRangeRequest>,
    /// Tracks the single in-flight `ExecutionProofsByRoot` batch request (ID + serving peer).
    root_request: Option<ByRootRequest>,
    /// Slot ticks remaining before the next request may be issued after a response stream
    /// completes. Set to `POST_REQUEST_COOLDOWN_SLOTS` on termination, decremented each
    /// poll, and blocks new requests until it reaches zero.
    post_request_cooldown: u64,
    /// Cached `ExecutionProofStatus` responses, keyed by peer.
    peer_statuses: HashMap<PeerId, CachedExecutionProofStatus>,
    /// In-flight `ExecutionProofStatus` request IDs, keyed by peer.
    status_in_flight: HashMap<PeerId, ExecutionProofStatusRequestId>,
    /// Suppresses repeated "no proof-capable peer" logs: set when the message is first
    /// emitted, cleared when a peer becomes available.
    logged_no_peer: bool,
    /// Injected missing-proof list for unit testing by-root behaviour.
    #[cfg(test)]
    pub test_missing_proofs: Option<Vec<MissingProofInfo>>,
}

impl<T: BeaconChainTypes> ProofSync<T> {
    /// Creates a new `ProofSync` instance in the `Idle` state.
    pub fn new(chain: Arc<BeaconChain<T>>) -> Self {
        Self {
            state: ProofSyncState::Idle,
            range_request: None,
            root_request: None,
            chain,
            post_request_cooldown: 0,
            peer_statuses: HashMap::default(),
            status_in_flight: HashMap::default(),
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
    pub fn by_root_request(&self) -> Option<&ByRootRequest> {
        self.root_request.as_ref()
    }

    #[cfg(test)]
    pub fn set_state(&mut self, state: ProofSyncState) {
        self.state = state;
    }

    #[cfg(test)]
    pub fn by_range_request(&self) -> Option<&ByRangeRequest> {
        self.range_request.as_ref()
    }

    #[cfg(test)]
    pub fn peer_status(&self, peer_id: &PeerId) -> Option<&CachedExecutionProofStatus> {
        self.peer_statuses.get(peer_id)
    }

    /// Called by `SyncManager` when range sync completes.
    ///
    /// Kicks off peer status refreshes and transitions directly to `Syncing`. The proof
    /// engine is the authoritative source of missing proofs — it only reports entries after
    /// blocks are imported, so no artificial delay is needed before the first poll.
    pub fn start(&mut self, cx: &mut SyncNetworkContext<T>) {
        info!("ProofSync: starting");
        self.post_request_cooldown = 0;
        self.refresh_peer_statuses(cx);
        self.state = ProofSyncState::Syncing;
        metrics::set_gauge(&metrics::PROOF_SYNC_STATE, 1);
    }

    /// Called by `SyncManager` when range sync re-enters.
    ///
    /// Stops new proof requests from being issued. Any already in-flight responses
    /// are still processed as they arrive.
    pub fn pause(&mut self) {
        debug!("ProofSync: pausing");
        self.state = ProofSyncState::Idle;
        metrics::set_gauge(&metrics::PROOF_SYNC_STATE, 0);
    }

    /// Drive one polling cycle.
    ///
    /// In `Syncing`, consults the proof engine for missing proofs and decides the most
    /// request-efficient strategy:
    ///
    /// - Finds the consecutive run of missing slots with the highest byte savings over
    ///   an equivalent `ExecutionProofsByRoot` request.
    /// - If a run's savings are positive it sends `ExecutionProofsByRange` for that run
    ///   (with `proof_filters` covering partially-held blocks so the peer skips redundant
    ///   proof types).
    /// - Otherwise sends a single `ExecutionProofsByRoot` batch for all servable missing
    ///   proofs.
    ///
    /// Does nothing if a range request is already in-flight or a post-request cooldown is
    /// active. Peer status refreshes run in the background and do not block request dispatch.
    pub fn poll(&mut self, cx: &mut SyncNetworkContext<T>) {
        if self.state == ProofSyncState::Idle {
            return;
        }

        // Drain post-request cooldown before issuing the next request.
        if self.post_request_cooldown > 0 {
            self.post_request_cooldown -= 1;
            return;
        }

        // If a range request is already in-flight, wait for it to drain.
        if self.range_request.is_some() {
            return;
        }

        // Ask the proof engine what it still needs — this is the authoritative source.
        #[cfg(not(test))]
        let missing = self.chain.missing_execution_proofs();
        #[cfg(test)]
        let missing = self
            .test_missing_proofs
            .clone()
            .unwrap_or_else(|| self.chain.missing_execution_proofs());

        if missing.is_empty() {
            return;
        }

        let Some((peer_id, peer_slot)) = self.best_peer(cx) else {
            return;
        };

        // Keep only entries the best peer can serve; sort by slot for run analysis.
        let mut servable: Vec<MissingProofInfo> = missing
            .into_iter()
            .filter(|info| {
                if peer_slot < info.slot {
                    debug!(
                        block_root = %info.root,
                        slot = %info.slot,
                        %peer_slot,
                        "ProofSync: best peer slot behind missing block, skipping"
                    );
                    false
                } else {
                    true
                }
            })
            .collect();

        if servable.is_empty() {
            return;
        }

        servable.sort_unstable_by_key(|m| m.slot);

        let num_types = cx.configured_proof_types_count();

        // Partition into blocks still needing at least one proof type and blocks
        // that are already complete in the proof engine buffer.
        let (actually_missing, complete_in_window): (Vec<MissingProofInfo>, Vec<MissingProofInfo>) =
            servable
                .into_iter()
                .partition(|m| m.existing_proof_types.len() < num_types);

        if actually_missing.is_empty() {
            return;
        }

        // Build filter_entries for the range request:
        //   - partial entries (some types present, some missing) → peer returns only needed types
        //   - complete entries → peer skips the block entirely (empty proof_types in filter)
        // Fully-missing entries are excluded from the filter; the peer returns all types for them.
        let filter_entries: Vec<MissingProofInfo> = actually_missing
            .iter()
            .filter(|m| !m.existing_proof_types.is_empty())
            .cloned()
            .chain(complete_in_window)
            .collect();

        let range_bytes = by_range_request_size(&filter_entries, num_types);
        let root_bytes = by_root_request_size(&actually_missing, num_types);

        // A single range request covers all servable slots with a fixed 20-byte header plus
        // proof_filters for partial and complete blocks. If cheaper than naming every block
        // individually in a root request, use range; otherwise use root.
        if range_bytes < root_bytes {
            let start_slot = actually_missing[0].slot;
            // count spans from first to last missing slot inclusive.
            let count =
                (actually_missing.last().expect("non-empty").slot - start_slot).as_u64() + 1;

            match cx.request_execution_proofs_by_range(peer_id, start_slot, count, &filter_entries)
            {
                Ok(id) => {
                    debug!(
                        start_slot = %start_slot,
                        count,
                        num_filters = filter_entries.len(),
                        range_bytes,
                        root_bytes,
                        "ProofSync: range request sent"
                    );
                    self.range_request = Some(ByRangeRequest { id, peer_id });
                    metrics::inc_counter_vec(
                        &metrics::PROOF_SYNC_RANGE_REQUESTS_TOTAL,
                        &["success"],
                    );
                    metrics::set_gauge(&metrics::PROOF_SYNC_RANGE_REQUEST_IN_FLIGHT, 1);
                }
                Err(e) => {
                    debug!(error = ?e, "ProofSync: range request error");
                    metrics::inc_counter_vec(&metrics::PROOF_SYNC_RANGE_REQUESTS_TOTAL, &["error"]);
                }
            }
            return;
        }

        // Root request is smaller — name every block and proof type still needed.
        if self.root_request.is_some() {
            return;
        }

        match cx.request_execution_proofs_by_root(peer_id, &actually_missing) {
            Ok(id) => {
                debug!(
                    num_roots = actually_missing.len(),
                    root_bytes, range_bytes, "ProofSync: by-root batch sent"
                );
                self.root_request = Some(ByRootRequest { id, peer_id });
                metrics::inc_counter_vec(&metrics::PROOF_SYNC_ROOT_REQUESTS_TOTAL, &["success"]);
                metrics::set_gauge(&metrics::PROOF_SYNC_ROOT_REQUEST_IN_FLIGHT, 1);
            }
            Err(e) => {
                debug!(error = ?e, "ProofSync: failed to send proof batch request");
                metrics::inc_counter_vec(&metrics::PROOF_SYNC_ROOT_REQUESTS_TOTAL, &["error"]);
            }
        }
    }

    /// Called when an `ExecutionProofsByRange` RPC stream terminates (response `None`).
    ///
    /// Clears the in-flight request and starts a brief cooldown so the beacon processor
    /// has time to import the received proofs before the next request is issued.
    pub fn on_range_request_terminated(&mut self, id: &ExecutionProofsByRangeRequestId) {
        if self.range_request.as_ref().map(|r| &r.id) == Some(id) {
            debug!("ProofSync: range stream complete");
            self.range_request = None;
            self.post_request_cooldown = POST_REQUEST_COOLDOWN_SLOTS;
            metrics::set_gauge(&metrics::PROOF_SYNC_RANGE_REQUEST_IN_FLIGHT, 0);
        }
    }

    /// Called when an `ExecutionProofsByRange` RPC request errors.
    ///
    /// Clears the in-flight range request so the next `poll()` can retry.
    pub fn on_range_request_error(&mut self, id: &ExecutionProofsByRangeRequestId) {
        if self.range_request.as_ref().map(|r| &r.id) == Some(id) {
            debug!("ProofSync: range request failed, will retry next poll");
            self.range_request = None;
            metrics::set_gauge(&metrics::PROOF_SYNC_RANGE_REQUEST_IN_FLIGHT, 0);
        }
    }

    /// Called when an `ExecutionProofsByRoot` RPC request errors.
    ///
    /// Clears the in-flight root request so the next `poll()` can retry.
    pub fn on_root_request_error(&mut self, id: &ExecutionProofsByRootRequestId) {
        if self.root_request.as_ref().map(|r| &r.id) == Some(id) {
            debug!("ProofSync: root batch request failed, will retry next poll");
            self.root_request = None;
            metrics::set_gauge(&metrics::PROOF_SYNC_ROOT_REQUEST_IN_FLIGHT, 0);
        }
    }

    /// Called when an `ExecutionProofsByRoot` RPC stream terminates (response `None`).
    ///
    /// Clears the in-flight root request and starts a brief cooldown so the beacon
    /// processor has time to import the received proofs before the next request is issued.
    pub fn on_root_request_terminated(&mut self, id: &ExecutionProofsByRootRequestId) {
        if self.root_request.as_ref().map(|r| &r.id) == Some(id) {
            self.root_request = None;
            self.post_request_cooldown = POST_REQUEST_COOLDOWN_SLOTS;
            metrics::set_gauge(&metrics::PROOF_SYNC_ROOT_REQUEST_IN_FLIGHT, 0);
        }
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
                metrics::inc_counter(&metrics::PROOF_SYNC_STATUS_REQUESTS_TOTAL);
            }
            Err(e) => {
                debug!(error = ?e, %peer_id, "ProofSync: failed to query peer status on connect");
            }
        }
    }

    /// Called when a proof-capable peer disconnects.
    ///
    /// Removes the peer's cached status and any in-flight status request. If this peer
    /// was serving the active range or root request, that request is also cleared so the
    /// next `poll()` can retry with a different peer.
    pub fn on_proof_capable_peer_disconnected(&mut self, peer_id: &PeerId) {
        self.peer_statuses.remove(peer_id);
        self.status_in_flight.remove(peer_id);
        if self
            .range_request
            .as_ref()
            .map(|r| &r.peer_id)
            .filter(|p| *p == peer_id)
            .is_some()
        {
            self.range_request = None;
            metrics::set_gauge(&metrics::PROOF_SYNC_RANGE_REQUEST_IN_FLIGHT, 0);
        }
        if self
            .root_request
            .as_ref()
            .map(|r| &r.peer_id)
            .filter(|p| *p == peer_id)
            .is_some()
        {
            self.root_request = None;
            metrics::set_gauge(&metrics::PROOF_SYNC_ROOT_REQUEST_IN_FLIGHT, 0);
        }
        metrics::inc_counter(&metrics::PROOF_SYNC_PEER_DISCONNECTS_TOTAL);
        metrics::set_gauge(
            &metrics::PROOF_SYNC_PEER_COUNT,
            self.peer_statuses.len() as i64,
        );
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
        let verified_label = if verified { "true" } else { "false" };
        metrics::inc_counter_vec(
            &metrics::PROOF_SYNC_STATUS_RESPONSES_TOTAL,
            &[verified_label],
        );
        metrics::set_gauge(
            &metrics::PROOF_SYNC_PEER_COUNT,
            self.peer_statuses.len() as i64,
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

// ── Request-size helpers ──────────────────────────────────────────────────────

/// SSZ encoded byte cost of one `ProofByRootIdentifier` entry when it appears inside a
/// variable-length list.
///
/// Layout:
/// - 4 bytes — list offset-table entry (one u32 pointer per variable-length item)
/// - 32 bytes — `block_root: Hash256` (fixed field within the container)
/// - 4 bytes — SSZ offset for `proof_types` (variable field pointer within the container)
/// - `needed` × 1 byte — the proof type values themselves (`ProofType` encodes as one `u8`)
///
/// `needed` = `num_configured_types` − `existing_proof_types.len()`, i.e. the types still
/// outstanding for this block.
fn per_identifier_ssz_bytes(info: &MissingProofInfo, num_configured_types: usize) -> usize {
    let needed = num_configured_types.saturating_sub(info.existing_proof_types.len());
    4 + 32 + 4 + needed
}

/// Byte size of an `ExecutionProofsByRoot` request encoding `missing` identifiers.
///
/// The request body is `List[ProofByRootIdentifier, ...]`; each entry pays the full
/// per-identifier cost regardless of whether it is fully or partially missing.
pub(crate) fn by_root_request_size(
    missing: &[MissingProofInfo],
    num_configured_types: usize,
) -> usize {
    missing
        .iter()
        .map(|m| per_identifier_ssz_bytes(m, num_configured_types))
        .sum()
}

/// Byte size of an `ExecutionProofsByRange` request.
///
/// Layout:
/// - 20 bytes — fixed header: `start_slot` (8) + `count` (8) + `proof_filters` offset (4)
/// - `proof_filters` — partial entries (some types held, some needed) and complete entries
///   (empty `proof_types` list tells the peer to skip the block). Fully-missing blocks are
///   absent; the peer returns all proof types for them by default.
///
/// `filter_entries` should contain partial and complete entries only (not fully-missing ones).
pub(crate) fn by_range_request_size(
    filter_entries: &[MissingProofInfo],
    num_configured_types: usize,
) -> usize {
    let filter_bytes: usize = filter_entries
        .iter()
        .map(|m| per_identifier_ssz_bytes(m, num_configured_types))
        .sum();
    20 + filter_bytes
}

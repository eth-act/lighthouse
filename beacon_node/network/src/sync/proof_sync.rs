//! Catch-up mechanism for optional EIP-8025 execution proofs.

use super::network_context::{CachedExecutionProofStatus, SyncNetworkContext};
use beacon_chain::{BeaconChain, BeaconChainTypes, WhenSlotSkipped};
use lighthouse_network::PeerId;
use lighthouse_network::rpc::methods::ExecutionProofStatus;
use lighthouse_network::service::api_types::{
    ExecutionProofStatusRequestId, ExecutionProofsByRangeRequestId, ExecutionProofsByRootRequestId,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};
use types::{EthSpec, ProofType, Slot};

use beacon_chain::eip8025::MissingExecutionProofInfo;

pub(crate) struct ByRangeRequest {
    pub(crate) id: ExecutionProofsByRangeRequestId,
    pub(crate) peer_id: PeerId,
}

pub(crate) struct ByRootRequest {
    pub(crate) id: ExecutionProofsByRootRequestId,
    pub(crate) peer_id: PeerId,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProofSyncState {
    Idle,
    Syncing,
}

const POST_REQUEST_COOLDOWN_SLOTS: u64 = 1;

pub struct ProofSync<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
    state: ProofSyncState,
    range_request: Option<ByRangeRequest>,
    root_request: Option<ByRootRequest>,
    post_request_cooldown: u64,
    peer_statuses: HashMap<PeerId, CachedExecutionProofStatus>,
    status_in_flight: HashMap<PeerId, ExecutionProofStatusRequestId>,
    logged_no_peer: bool,
}

impl<T: BeaconChainTypes> ProofSync<T> {
    pub fn new(chain: Arc<BeaconChain<T>>) -> Self {
        Self {
            chain,
            state: ProofSyncState::Idle,
            range_request: None,
            root_request: None,
            post_request_cooldown: 0,
            peer_statuses: HashMap::default(),
            status_in_flight: HashMap::default(),
            logged_no_peer: false,
        }
    }

    pub fn start(&mut self, cx: &mut SyncNetworkContext<T>) {
        if self.state == ProofSyncState::Syncing {
            return;
        }
        info!("Proof sync starting");
        self.post_request_cooldown = 0;
        self.refresh_peer_statuses(cx);
        self.state = ProofSyncState::Syncing;
    }

    pub fn pause(&mut self) {
        if self.state == ProofSyncState::Idle {
            return;
        }
        debug!("Proof sync pausing");
        self.state = ProofSyncState::Idle;
    }

    pub fn poll(&mut self, cx: &mut SyncNetworkContext<T>) {
        if self.state == ProofSyncState::Idle {
            return;
        }

        if self.post_request_cooldown > 0 {
            self.post_request_cooldown = self.post_request_cooldown.saturating_sub(1);
            return;
        }

        if self.range_request.is_some() || self.root_request.is_some() {
            return;
        }

        let configured_proof_types = cx.configured_proof_types_vec();
        let missing = self.chain.missing_execution_proofs(&configured_proof_types);
        if missing.is_empty() {
            return;
        }

        let needed_types: HashSet<ProofType> = missing
            .iter()
            .flat_map(|info| {
                configured_proof_types
                    .iter()
                    .copied()
                    .filter(|proof_type| !info.existing_proof_types.contains(proof_type))
            })
            .collect();
        if needed_types.is_empty() {
            return;
        }

        let Some((peer_id, peer_slot)) = self.best_peer(cx, &needed_types) else {
            return;
        };

        let finalized_slot = finalized_request_start_slot(&self.chain);
        let missing =
            servable_missing_proofs(missing, peer_slot, finalized_slot, &configured_proof_types);

        if missing.is_empty() {
            return;
        }

        let range_bytes = by_range_request_size(configured_proof_types.len());
        let root_bytes = by_root_request_size(&missing, configured_proof_types.len());
        let start_slot = missing[0].slot;
        let Some(count) = missing
            .last()
            .and_then(|last| last.slot.as_u64().checked_sub(start_slot.as_u64()))
            .and_then(|delta| delta.checked_add(1))
        else {
            return;
        };
        let dense_enough = (count as usize) <= missing.len().saturating_mul(2);

        if dense_enough && range_bytes < root_bytes {
            match cx.request_execution_proofs_by_range(peer_id, start_slot, count) {
                Ok(id) => {
                    debug!(
                        %start_slot,
                        count,
                        range_bytes,
                        root_bytes,
                        "Proof sync range request sent"
                    );
                    self.range_request = Some(ByRangeRequest { id, peer_id });
                }
                Err(error) => {
                    debug!(?error, "Proof sync range request failed");
                }
            }
            return;
        }

        match cx.request_execution_proofs_by_root(peer_id, &missing) {
            Ok(id) => {
                debug!(
                    num_roots = missing.len(),
                    root_bytes, range_bytes, "Proof sync by-root request sent"
                );
                self.root_request = Some(ByRootRequest { id, peer_id });
            }
            Err(error) => {
                debug!(?error, "Proof sync by-root request failed");
            }
        }
    }

    pub fn on_range_request_terminated(&mut self, id: &ExecutionProofsByRangeRequestId) {
        if self.range_request.as_ref().map(|request| &request.id) == Some(id) {
            self.range_request = None;
            self.post_request_cooldown = POST_REQUEST_COOLDOWN_SLOTS;
        }
    }

    pub fn on_root_request_terminated(&mut self, id: &ExecutionProofsByRootRequestId) {
        if self.root_request.as_ref().map(|request| &request.id) == Some(id) {
            self.root_request = None;
            self.post_request_cooldown = POST_REQUEST_COOLDOWN_SLOTS;
        }
    }

    pub fn on_range_request_error(&mut self, id: &ExecutionProofsByRangeRequestId) {
        if self.range_request.as_ref().map(|request| &request.id) == Some(id) {
            self.range_request = None;
        }
    }

    pub fn on_root_request_error(&mut self, id: &ExecutionProofsByRootRequestId) {
        if self.root_request.as_ref().map(|request| &request.id) == Some(id) {
            self.root_request = None;
        }
    }

    pub fn add_peer(&mut self, peer_id: PeerId, cx: &mut SyncNetworkContext<T>) {
        match cx.request_execution_proof_status(peer_id) {
            Ok(id) => {
                self.status_in_flight.insert(peer_id, id);
            }
            Err(error) => {
                debug!(?error, %peer_id, "Proof sync status request failed");
            }
        }
    }

    pub fn on_proof_capable_peer_disconnected(&mut self, peer_id: &PeerId) {
        self.peer_statuses.remove(peer_id);
        self.status_in_flight.remove(peer_id);
        if self
            .range_request
            .as_ref()
            .is_some_and(|request| &request.peer_id == peer_id)
        {
            self.range_request = None;
        }
        if self
            .root_request
            .as_ref()
            .is_some_and(|request| &request.peer_id == peer_id)
        {
            self.root_request = None;
        }
    }

    pub fn on_peer_execution_proof_status(
        &mut self,
        peer_id: PeerId,
        _request_id: Option<ExecutionProofStatusRequestId>,
        status: ExecutionProofStatus,
    ) {
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
                        "Ignoring mismatched execution proof status"
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

    pub fn on_peer_execution_proof_status_error(
        &mut self,
        peer_id: PeerId,
        _request_id: ExecutionProofStatusRequestId,
    ) {
        self.on_peer_status_failed(peer_id);
    }

    fn on_peer_status_failed(&mut self, peer_id: PeerId) {
        self.status_in_flight.remove(&peer_id);
        self.peer_statuses
            .entry(peer_id)
            .and_modify(|entry| entry.timestamp = Instant::now())
            .or_insert_with(|| CachedExecutionProofStatus {
                status: ExecutionProofStatus::default(),
                timestamp: Instant::now(),
                verified: false,
            });
    }

    fn refresh_peer_statuses(&mut self, cx: &mut SyncNetworkContext<T>) {
        for (peer_id, status) in self.peer_statuses.iter() {
            if status.needs_refresh() && !self.status_in_flight.contains_key(peer_id) {
                match cx.request_execution_proof_status(*peer_id) {
                    Ok(id) => {
                        self.status_in_flight.insert(*peer_id, id);
                    }
                    Err(error) => {
                        debug!(?error, %peer_id, "Proof sync status refresh failed");
                    }
                }
            }
        }
    }

    fn best_peer(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
        needed_types: &HashSet<ProofType>,
    ) -> Option<(PeerId, Slot)> {
        self.refresh_peer_statuses(cx);

        let result = self
            .peer_statuses
            .iter()
            .filter(|(_, cached)| {
                cached
                    .status
                    .proof_types
                    .iter()
                    .any(|proof_type| needed_types.contains(proof_type))
            })
            .max_by_key(|(_, cached)| {
                let supported_needed_types = cached
                    .status
                    .proof_types
                    .iter()
                    .filter(|proof_type| needed_types.contains(proof_type))
                    .count();
                (cached.verified, supported_needed_types, cached.status.slot)
            })
            .map(|(peer_id, cached)| (*peer_id, Slot::new(cached.status.slot)));

        match result {
            None if !self.logged_no_peer => {
                debug!("Proof sync has no proof-capable peer");
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

fn finalized_request_start_slot<T: BeaconChainTypes>(chain: &BeaconChain<T>) -> Slot {
    chain
        .canonical_head
        .cached_head()
        .finalized_checkpoint()
        .epoch
        .start_slot(T::EthSpec::slots_per_epoch())
}

fn servable_missing_proofs(
    missing: Vec<MissingExecutionProofInfo>,
    peer_slot: Slot,
    finalized_slot: Slot,
    configured_proof_types: &[ProofType],
) -> Vec<MissingExecutionProofInfo> {
    let mut missing = missing
        .into_iter()
        .filter(|info| {
            if info.slot < finalized_slot {
                debug!(
                    block_root = %info.root,
                    slot = %info.slot,
                    %finalized_slot,
                    "Proof sync skipping missing proof before finalized request window"
                );
                false
            } else if peer_slot < info.slot {
                debug!(
                    block_root = %info.root,
                    slot = %info.slot,
                    %peer_slot,
                    "Proof sync peer is behind missing proof block"
                );
                false
            } else {
                configured_proof_types
                    .iter()
                    .any(|proof_type| !info.existing_proof_types.contains(proof_type))
            }
        })
        .collect::<Vec<_>>();
    missing.sort_unstable_by_key(|info| info.slot);
    missing
}

fn per_identifier_ssz_bytes(
    info: &MissingExecutionProofInfo,
    num_configured_types: usize,
) -> usize {
    let needed = num_configured_types.saturating_sub(info.existing_proof_types.len());
    4 + 32 + 4 + needed
}

fn by_root_request_size(
    missing: &[MissingExecutionProofInfo],
    num_configured_types: usize,
) -> usize {
    missing
        .iter()
        .map(|info| per_identifier_ssz_bytes(info, num_configured_types))
        .sum()
}

fn by_range_request_size(num_configured_types: usize) -> usize {
    20 + num_configured_types
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use types::Hash256;

    fn missing_at(
        slot: u64,
        existing_proof_types: impl IntoIterator<Item = ProofType>,
    ) -> MissingExecutionProofInfo {
        MissingExecutionProofInfo {
            root: Hash256::with_last_byte((slot & 0xff) as u8),
            slot: Slot::new(slot),
            existing_proof_types: existing_proof_types.into_iter().collect::<HashSet<_>>(),
        }
    }

    #[test]
    fn servable_missing_proofs_starts_at_finalized_slot() {
        let configured_proof_types = vec![0, 1];
        let missing = vec![
            missing_at(7, []),
            missing_at(8, []),
            missing_at(9, [0, 1]),
            missing_at(10, [0]),
            missing_at(11, []),
        ];

        let servable = servable_missing_proofs(
            missing,
            Slot::new(10),
            Slot::new(8),
            &configured_proof_types,
        );

        assert_eq!(
            servable
                .iter()
                .map(|info| info.slot.as_u64())
                .collect::<Vec<_>>(),
            vec![8, 10],
        );
    }
}

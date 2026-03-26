use crate::{
    ForkchoiceState, ForkchoiceUpdatedResponse, MissingProofInfo, PayloadStatusV1,
    PayloadStatusV1Status,
};
use crate::{NewPayloadRequest, eip8025::errors::ProofEngineStateError};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::mem;
use tree_hash::TreeHash;
use types::{EthSpec, ExecutionBlockHash, Hash256, SignedExecutionProof};
use types::{MIN_REQUIRED_EXECUTION_PROOFS, ProofStatus};

// TODO: Consider refactoring to use proto-array style state structure for better performance.
// TODO: Add metrics for latency, state size, buffer size, proof counts, etc.
// TODO: If we continue to use HashMaps then consider using ahash or foldhash for better performance (keys are cryptographic digests and as such random).

#[derive(Debug, Clone)]
pub struct State {
    /// The latest fork choice state received that has not yet been marked as valid.
    pub latest_fcs: Option<ForkchoiceState>,
    /// The last fork choice state that was marked as valid.
    pub last_valid_fcs: ForkchoiceState,
    /// State of the execution proofs tree.
    pub tree: TreeState,
    /// Buffer of unassociated execution proofs.
    pub buffer: RequestBuffer,
    /// The minimum number of proofs required for a request to be promotable from buffer to tree.
    pub min_required_proofs: usize,
}

impl Default for State {
    /// Create a new State with default min required proofs.
    fn default() -> Self {
        Self {
            latest_fcs: None,
            last_valid_fcs: ForkchoiceState {
                head_block_hash: ExecutionBlockHash::zero(),
                safe_block_hash: ExecutionBlockHash::zero(),
                finalized_block_hash: ExecutionBlockHash::zero(),
            },
            tree: TreeState::default(),
            buffer: RequestBuffer::default(),
            min_required_proofs: MIN_REQUIRED_EXECUTION_PROOFS,
        }
    }
}

impl State {
    /// Create a new State with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return buffer entries that do not yet have sufficient proofs for promotion,
    /// restricted to those on the ancestor path required to satisfy `latest_fcs`.
    ///
    /// If `latest_fcs` is unset there is no pending fork-choice update to satisfy, so
    /// nothing is returned. Otherwise the buffer is walked backwards from
    /// `latest_fcs.head_block_hash`; entries that lack sufficient proofs are collected
    /// until a block is not found in the buffer (reached the tree or an unseen block).
    pub fn missing_proofs(&self) -> Vec<MissingProofInfo> {
        let Some(latest_fcs) = &self.latest_fcs else {
            return vec![];
        };

        // Build block_hash → &PayloadRequest for O(1) lookup during the walk.
        let buffer_by_block_hash: HashMap<ExecutionBlockHash, &PayloadRequest> = self
            .buffer
            .proofs
            .values()
            .map(|p| (p.metadata.block_hash, p))
            .collect();

        // Walk backwards from the FCS head through buffer entries, collecting
        // those that still lack sufficient proofs. Stop when a block is not in
        // the buffer (reached the tree or an unseen block).
        let mut result = Vec::new();
        let mut current = latest_fcs.head_block_hash;
        loop {
            let Some(req) = buffer_by_block_hash.get(&current) else {
                break;
            };
            if req.proofs.len() < self.min_required_proofs {
                result.push(MissingProofInfo {
                    root: req.metadata.request_root,
                    existing_proof_types: req.proofs.iter().map(|p| p.message.proof_type).collect(),
                    slot: Default::default(), // populated by BeaconChain::missing_execution_proofs()
                });
            }
            current = req.metadata.parent_hash;
        }

        result
    }

    /// Check if the state contains any proofs associated with the given new payload request root.
    pub fn contains_request_root(&self, request_root: &Hash256) -> bool {
        self.tree
            .request_root_to_block_hash
            .contains_key(request_root)
            || self.buffer.proofs.contains_key(request_root)
    }

    /// Buffer a new payload request for future proof association.
    pub fn buffer_request(&mut self, request: RequestMetadata) {
        if self
            .tree
            .request_root_to_block_hash
            .contains_key(&request.request_root)
        {
            tracing::warn!(target: "execution_layer", request_root = ?request.request_root, "Attempting to buffer a request that is already associated with a block hash in the tree - skipping buffer insertion");
            return;
        }

        if self.buffer.proofs.contains_key(&request.request_root) {
            tracing::debug!(target: "execution_layer", request_root = ?request.request_root, "Request is already buffered - skipping buffer insertion");
            return;
        }

        self.buffer.insert(request);
    }

    /// Validate and update the latest fork choice state.
    pub fn forkchoice_updated(
        &mut self,
        forkchoice_state: ForkchoiceState,
    ) -> Result<ForkchoiceUpdatedResponse, ProofEngineStateError> {
        let head = forkchoice_state.head_block_hash;
        let safe = forkchoice_state.safe_block_hash;
        let finalized = forkchoice_state.finalized_block_hash;

        // When tree is empty, always update last_valid_fcs to track finalized block
        // This allows finalized to advance during sync before any blocks are promoted
        // TODO: Reconsider this logic - maybe we just always update the finalized block in last_valid_fcs and allow syncing until we have observed the head block hash?
        if self.tree.is_empty() && finalized != ExecutionBlockHash::zero() {
            // Create a baseline forkchoice state anchored at finalized block
            let bootstrap_fcs = ForkchoiceState {
                head_block_hash: finalized,
                safe_block_hash: finalized,
                finalized_block_hash: finalized,
            };
            self.last_valid_fcs = bootstrap_fcs;
            self.latest_fcs = Some(forkchoice_state);
            self.tree.current_canonical_head = finalized;

            tracing::info!(target: "execution_layer", ?finalized, "Updated last_valid_fcs to finalized block (tree empty)");

            // Check if any buffered requests can be promoted based on the new last_valid_fcs.
            let mut promote_requests = Vec::new();
            for request in self.buffer.proofs.keys() {
                if self.can_promote(request)? {
                    promote_requests.push(*request);
                }
            }
            // Promote any buffered requests that can now be associated with the tree state.
            for request_root in promote_requests {
                if let Some(latest_canonical_head) = self.promote_buffered_requests(request_root)? {
                    tracing::info!(target: "execution_layer", ?latest_canonical_head, "Updated canonical head after promoting buffered proofs");
                }
            }

            return Ok(self.forkchoice_response_syncing());
        }

        let new_safe_zero = safe.is_zero();
        let new_finalized_zero = finalized.is_zero();
        let safe = if !new_safe_zero {
            safe
        } else {
            self.last_valid_fcs.safe_block_hash
        };
        let finalized = if !new_finalized_zero {
            finalized
        } else {
            self.last_valid_fcs.finalized_block_hash
        };

        // If we have not observed the head block hash yet, we cannot validate the forkchoice
        if !self.tree.proofs_by_block_hash.contains_key(&head) {
            tracing::debug!(target: "execution_layer", ?head, "Forkchoice update head not found in tree state, marking as syncing");
            self.latest_fcs = Some(forkchoice_state);
            return Ok(self.forkchoice_response_syncing());
        }

        // Validate that the safe block is in the tree (this is a quick sanity check so we don't have to traverse the tree)
        if !new_safe_zero && !self.tree.proofs_by_block_hash.contains_key(&safe) {
            tracing::warn!(target: "execution_layer", ?safe, "Forkchoice update safe block hash not found in tree state - invalid forkchoice");
            return Ok(self.forkchoice_response_invalid());
        }

        // Validate that the finalized block is in the tree (this is a quick sanity check so we don't have to traverse the tree)
        if !new_finalized_zero && !self.tree.proofs_by_block_hash.contains_key(&finalized) {
            tracing::warn!(target: "execution_layer", ?finalized, "Forkchoice update finalized block hash not found in tree state - invalid forkchoice");
            return Ok(self.forkchoice_response_invalid());
        }

        // Validate the ancestry chain: head -> safe -> finalized
        if !self.is_descendant(safe, head) {
            tracing::error!(target: "execution_layer", ?head, ?safe, "Forkchoice update is invalid - safe block is not an ancestor of head");
            return Ok(self.forkchoice_response_invalid());
        }

        if !new_safe_zero && !self.is_descendant(finalized, safe) {
            tracing::error!(target: "execution_layer", ?safe, ?finalized, "Forkchoice update is invalid - finalized block is not an ancestor of safe");
            return Ok(self.forkchoice_response_invalid());
        }

        if !self.is_descendant(self.last_valid_fcs.finalized_block_hash, finalized) {
            tracing::error!(target: "execution_layer", ?head, ?safe, ?finalized, "Forkchoice update is invalid -  new finalized block is not a descendant of last valid finalized block");
            return Ok(self.forkchoice_response_invalid());
        }

        // Determine if we need to update the canonical head
        let update_canonical_head = if head == self.tree.current_canonical_head {
            tracing::debug!(target: "execution_layer", ?head, "Forkchoice update head matches current canonical head");
            false
        } else if self.is_descendant(head, self.tree.current_canonical_head) {
            tracing::debug!(target: "execution_layer", ?head, "Forkchoice update head is a ancestor of current canonical head - skip head update");
            false
        } else {
            tracing::debug!(target: "execution_layer", ?head, "Forkchoice update head is on a fork, updating canonical head pending validation");
            true
        };

        if update_canonical_head {
            tracing::info!(target: "execution_layer", ?head, "Updating canonical head to new forkchoice head");
            self.tree.current_canonical_head = head;
        }

        let prune_finalized =
            !new_finalized_zero && (self.last_valid_fcs.finalized_block_hash != finalized);

        if prune_finalized {
            self.prune_finalized_sidechains(finalized)?;
        }

        self.last_valid_fcs = ForkchoiceState {
            head_block_hash: head,
            safe_block_hash: safe,
            finalized_block_hash: finalized,
        };
        Ok(self.forkchoice_response_valid())
    }

    /// Get all execution proofs associated with the given new payload request root.
    pub fn get_proofs(&self, root: &Hash256) -> Option<&[SignedExecutionProof]> {
        self.tree
            .request_root_to_block_hash
            .get(root)
            .and_then(|h| self.tree.proofs_by_block_hash.get(h))
            .map(|p| p.proofs.as_slice())
            .or_else(|| self.buffer.proofs.get(root).map(|b| b.proofs.as_slice()))
            .filter(|slice| !slice.is_empty())
    }

    /// Insert a new execution proof into state.
    pub fn insert_proof(
        &mut self,
        proof: SignedExecutionProof,
    ) -> Result<ProofStatus, ProofEngineStateError> {
        let request_root = proof.request_root();

        // Insert into the tree if associated block hash is found.
        if let Some(block_hash) = self.tree.request_root_to_block_hash.get(&request_root) {
            // Insert into the tree associated with the block hash.
            let proofs = self.tree.proofs_by_block_hash.get_mut(block_hash).ok_or(
                ProofEngineStateError::BlockHashNotFoundForRequestRoot {
                    request_root,
                    block_hash: *block_hash,
                },
            )?;
            proofs.proofs.push(proof);
            return Ok(ProofStatus::Accepted);
        }

        // Insert into the buffer if associated request root is found.
        if let Some(buffered_request) = self.buffer.proofs.get_mut(&request_root) {
            buffered_request.proofs.push(proof);
        } else {
            // We only process proofs that are associated with a request root from an observed beacon block.
            return Err(ProofEngineStateError::ProofRequestRootNotSeen(request_root));
        };

        if self.can_promote(&request_root)?
            && let Some(latest_canonical_head) = self.promote_buffered_requests(request_root)?
        {
            tracing::info!(target: "execution_layer", ?latest_canonical_head, "Updated canonical head after promoting buffered proofs");
            return Ok(ProofStatus::Valid);
        }

        Ok(ProofStatus::Accepted)
    }

    /// Promote buffered requests that can now be associated with the tree state.
    ///
    /// Returns the latest canonical head if it was updated.
    fn promote_buffered_requests(
        &mut self,
        request_root: Hash256,
    ) -> Result<Option<ExecutionBlockHash>, ProofEngineStateError> {
        let (block_hash, updated_head) = self.promote_buffered_request(request_root)?;
        let mut latest_head = if updated_head {
            Some(self.tree.current_canonical_head)
        } else {
            None
        };

        // Promote any child requests that can now be associated that have sufficient proofs.
        let mut queue = vec![block_hash];
        while let Some(parent_hash) = queue.pop() {
            let promotable_roots: Vec<Hash256> = self
                .buffer
                .proofs
                .iter()
                .filter(|(_, buffered)| {
                    buffered.metadata.parent_hash == parent_hash
                        && buffered.proofs.len() >= MIN_REQUIRED_EXECUTION_PROOFS
                })
                .map(|(root, _)| *root)
                .collect();

            for request_root in promotable_roots {
                let (block_hash, updated_head) = self.promote_buffered_request(request_root)?;
                if updated_head {
                    latest_head = Some(self.tree.current_canonical_head);
                }
                queue.push(block_hash);
            }
        }

        Ok(latest_head)
    }

    /// Promote a buffered request into the tree state.
    ///
    /// Returns the block hash and whether the canonical head was updated.
    fn promote_buffered_request(
        &mut self,
        request_root: Hash256,
    ) -> Result<(ExecutionBlockHash, bool), ProofEngineStateError> {
        let buffered_request = self
            .buffer
            .proofs
            .remove(&request_root)
            .ok_or(ProofEngineStateError::BufferedRequestNotFound(request_root))?;
        let RequestMetadata {
            block_hash,
            parent_hash,
            ..
        } = buffered_request.metadata;

        self.tree
            .block_number_to_block_hash
            .entry(buffered_request.metadata.block_number)
            .or_default()
            .insert(block_hash);

        self.tree
            .parent_to_children
            .entry(parent_hash)
            .or_default()
            .insert(block_hash);
        self.tree
            .proofs_by_block_hash
            .insert(block_hash, buffered_request);
        self.tree
            .request_root_to_block_hash
            .insert(request_root, block_hash);

        // If the promoted block is the parent of the current canonical head, update the canonical head to the promoted block.
        if self.tree.current_canonical_head == parent_hash {
            self.tree.current_canonical_head = block_hash;
            return Ok((block_hash, true));
        }

        // If the promoted block is equal to the current canonical head, we return the block hash and return true to indicate the tree head has been updated.
        if self.tree.current_canonical_head == block_hash {
            return Ok((block_hash, true));
        }

        Ok((block_hash, false))
    }

    fn forkchoice_response_valid(&self) -> ForkchoiceUpdatedResponse {
        ForkchoiceUpdatedResponse {
            payload_status: PayloadStatusV1 {
                status: PayloadStatusV1Status::Valid,
                latest_valid_hash: self.tree.current_canonical_head.into(),
                validation_error: None,
            },
            payload_id: None,
        }
    }

    fn forkchoice_response_syncing(&self) -> ForkchoiceUpdatedResponse {
        ForkchoiceUpdatedResponse {
            payload_status: PayloadStatusV1 {
                status: PayloadStatusV1Status::Syncing,
                latest_valid_hash: None,
                validation_error: None,
            },
            payload_id: None,
        }
    }

    fn forkchoice_response_invalid(&self) -> ForkchoiceUpdatedResponse {
        ForkchoiceUpdatedResponse {
            payload_status: PayloadStatusV1 {
                status: PayloadStatusV1Status::Invalid,
                latest_valid_hash: self.tree.current_canonical_head.into(),
                validation_error: Some("invalid forkchoice state".to_string()),
            },
            payload_id: None,
        }
    }

    /// Check if a block can be promoted from buffer to tree.
    ///
    /// A block can be promoted if:
    /// 1. Its parent is already in the tree (normal case), OR
    /// 2. It's a finalized block:
    ///    - Block hash matches last_valid_fcs.finalized_block_hash
    fn can_promote(&self, request: &Hash256) -> Result<bool, ProofEngineStateError> {
        let request = self
            .buffer
            .proofs
            .get(request)
            .ok_or(ProofEngineStateError::BufferedRequestNotFound(*request))?;

        if request.proofs.len() < self.min_required_proofs {
            return Ok(false);
        }

        // Normal case: parent already in tree
        if self
            .tree
            .proofs_by_block_hash
            .contains_key(&request.metadata.parent_hash)
        {
            return Ok(true);
        }

        // Bootstrap case: allow finalized block when starting empty tree
        if request.metadata.block_hash == self.tree.current_canonical_head
            || request.metadata.parent_hash == self.tree.current_canonical_head
        {
            tracing::debug!(target: "execution_layer", block_hash = ?request.metadata.block_hash, "Allowing promotion of finalized block during bootstrap");
            return Ok(true);
        }

        Ok(false)
    }

    /// Check if `target` is a descendant of `ancestor` in the tree.
    fn is_descendant(&self, ancestor: ExecutionBlockHash, target: ExecutionBlockHash) -> bool {
        let mut current = target;

        loop {
            if current == ancestor {
                return true;
            }

            let Some(proofs) = self.tree.proofs_by_block_hash.get(&current) else {
                return false;
            };

            current = proofs.metadata.parent_hash;
        }
    }

    fn block_number_for_hash(&self, block_hash: ExecutionBlockHash) -> Option<u64> {
        self.tree
            .proofs_by_block_hash
            .get(&block_hash)
            .map(|p| p.metadata.block_number)
    }

    // TODO: We should also prune buffered requests that are associated with sidechains that have been removed using parent to children mapping.
    fn prune_finalized_sidechains(
        &mut self,
        finalized_hash: ExecutionBlockHash,
    ) -> Result<(), ProofEngineStateError> {
        // Get the finalized block number.
        // TODO: Maybe this should just return SYNCING instead.
        let finalized_number = self
            .block_number_for_hash(finalized_hash)
            .ok_or(ProofEngineStateError::BlockNumberNotFound(finalized_hash))?;

        // Remove buffered proofs below or at the finalized block number.
        self.buffer.proofs.retain(|_root, entry| {
            (entry.metadata.block_number > finalized_number)
                || (entry.metadata.block_hash == finalized_hash)
        });

        // Remove all blocks with a block number below the finalized number.
        let mut block_hashes_to_remove = self
            .tree
            .block_number_to_block_hash
            .split_off(&finalized_number);
        mem::swap(
            &mut block_hashes_to_remove,
            &mut self.tree.block_number_to_block_hash,
        );

        for hashes in block_hashes_to_remove.into_values().flatten() {
            // Remove all block hash from state. We ignore returned children as they will have been
            // removed in this loop already. Any children on sidechains with a higher block number will be
            // removed in the next step.
            let _ = self.remove_request(hashes)?;
        }

        // Remove all block hashes at the finalized block number except the finalized hash.
        let mut to_remove: Vec<_> = if let Some(hashes) = self
            .tree
            .block_number_to_block_hash
            .get_mut(&finalized_number)
        {
            let mut to_remove = mem::replace(hashes, HashSet::from([finalized_hash]));
            to_remove.remove(&finalized_hash);
            to_remove.into_iter().collect()
        } else {
            return Ok(());
        };

        // Recursively remove children of the removed block hashes.
        while let Some(block_hash) = to_remove.pop() {
            if let Some(children) = self.remove_request(block_hash)? {
                to_remove.extend(children);
            }
        }

        Ok(())
    }

    /// Remove a request and its associated proofs from the tree state.
    fn remove_request(
        &mut self,
        block_hash: ExecutionBlockHash,
    ) -> Result<Option<HashSet<ExecutionBlockHash>>, ProofEngineStateError> {
        // TODO: Update to proper error handling
        let entry = self
            .tree
            .proofs_by_block_hash
            .remove(&block_hash)
            .ok_or(ProofEngineStateError::BlockNumberNotFound(block_hash))?;
        self.tree
            .request_root_to_block_hash
            .remove(&entry.metadata.request_root);
        let children = self.tree.parent_to_children.remove(&block_hash);
        if let Entry::Occupied(mut occ) = self
            .tree
            .block_number_to_block_hash
            .entry(entry.metadata.block_number)
        {
            occ.get_mut().remove(&block_hash);
            if occ.get().is_empty() {
                occ.remove();
            }
        }
        Ok(children)
    }

    /// Create a new State with the specified minimum required proofs for promotion.
    #[cfg(test)]
    pub fn with_min_required_proofs(min_required_proofs: usize) -> Self {
        Self {
            latest_fcs: None,
            last_valid_fcs: ForkchoiceState {
                head_block_hash: ExecutionBlockHash::zero(),
                safe_block_hash: ExecutionBlockHash::zero(),
                finalized_block_hash: ExecutionBlockHash::zero(),
            },
            tree: TreeState::default(),
            buffer: RequestBuffer::default(),
            min_required_proofs,
        }
    }
}

/// Keeps track of execution proofs in a tree structure.
///
/// - All proofs are associated with EL blocks connected to the current canonical chain.
#[derive(Debug, Default, Clone)]
pub struct TreeState {
    /// Map of execution block hash to execution proofs.
    pub proofs_by_block_hash: HashMap<ExecutionBlockHash, PayloadRequest>,
    /// Map of new payload request root to execution block hash.
    pub request_root_to_block_hash: HashMap<Hash256, ExecutionBlockHash>,
    /// Map of parent block hash to child block hashes.
    pub parent_to_children: HashMap<ExecutionBlockHash, HashSet<ExecutionBlockHash>>,
    /// Map of block number to block hashes at that height.
    pub block_number_to_block_hash: BTreeMap<u64, HashSet<ExecutionBlockHash>>,
    /// The current canonical head block hash.
    pub current_canonical_head: ExecutionBlockHash,
}

impl TreeState {
    /// Check if the tree is empty (no blocks inserted yet)
    pub fn is_empty(&self) -> bool {
        self.proofs_by_block_hash.is_empty()
    }
}

/// A buffer of new payload requests and their associated execution proofs.
#[derive(Debug, Default, Clone)]
pub struct RequestBuffer {
    /// Map of new payload request root to execution proofs.
    pub proofs: HashMap<Hash256, PayloadRequest>,
}

impl RequestBuffer {
    /// Insert a new payload request into the buffer.
    ///
    /// This will not overwrite existing requests.
    pub fn insert(&mut self, request: RequestMetadata) {
        self.proofs
            .entry(request.request_root)
            .or_insert_with(|| PayloadRequest::new(request));
    }
}

#[derive(Debug, Clone)]
pub struct PayloadRequest {
    /// The new payload request root associated with these proofs.
    pub metadata: RequestMetadata,
    /// Collection of signed execution proofs.
    pub proofs: Vec<SignedExecutionProof>,
}

impl PayloadRequest {
    pub fn new(metadata: RequestMetadata) -> Self {
        Self {
            metadata,
            proofs: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct RequestMetadata {
    /// The new payload request root associated with the request.
    pub request_root: Hash256,
    /// The execution block hash associated with the new payload request.
    pub block_hash: ExecutionBlockHash,
    /// The parent block hash of the new payload request.
    pub parent_hash: ExecutionBlockHash,
    /// The block number of the new payload request.
    pub block_number: u64,
}

impl<E: EthSpec> From<&NewPayloadRequest<'_, E>> for RequestMetadata {
    fn from(request: &NewPayloadRequest<'_, E>) -> Self {
        Self {
            request_root: request.clone().tree_hash_root(),
            block_hash: request.block_hash(),
            parent_hash: request.parent_hash(),
            block_number: request.block_number(),
        }
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use bls::SignatureBytes;
    use ssz_types::VariableList;
    use types::{ExecutionProof, PublicInput};

    pub fn test_hash(byte: u8) -> Hash256 {
        Hash256::repeat_byte(byte)
    }

    pub fn test_exec_hash(byte: u8) -> ExecutionBlockHash {
        ExecutionBlockHash::repeat_byte(byte)
    }

    pub fn create_request_metadata(
        request_root: Hash256,
        block_hash: ExecutionBlockHash,
        parent_hash: ExecutionBlockHash,
        block_number: u64,
    ) -> RequestMetadata {
        RequestMetadata {
            request_root,
            block_hash,
            parent_hash,
            block_number,
        }
    }

    pub fn create_signed_proof(
        request_root: Hash256,
        validator_index: u64,
    ) -> SignedExecutionProof {
        create_signed_proof_with_type(request_root, validator_index, 1)
    }

    pub fn create_signed_proof_with_type(
        request_root: Hash256,
        validator_index: u64,
        proof_type: u8,
    ) -> SignedExecutionProof {
        SignedExecutionProof {
            message: ExecutionProof {
                proof_data: VariableList::new(vec![0xaa, 0xbb, 0xcc]).unwrap(),
                proof_type,
                public_input: PublicInput {
                    new_payload_request_root: request_root,
                },
            },
            validator_index,
            signature: SignatureBytes::empty(),
        }
    }

    pub fn create_forkchoice_state(
        head: ExecutionBlockHash,
        safe: ExecutionBlockHash,
        finalized: ExecutionBlockHash,
    ) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: head,
            safe_block_hash: safe,
            finalized_block_hash: finalized,
        }
    }

    /// Test data provider for state tests
    ///
    /// Generates payload requests, proofs, and hashes.
    pub struct TestStateFixture {
        /// Generated block data
        /// blocks[0] = canonical chain
        /// blocks[1] = fork 0
        /// blocks[2] = fork 1
        /// etc.
        pub blocks: Vec<Vec<PayloadRequest>>,
    }

    impl TestStateFixture {
        /// Get the genesis fcs
        ///
        /// Defined as the first block in the canonical chain
        pub fn genesis_fcs(&self) -> ForkchoiceState {
            let finalized_block = &self.blocks[0][0];
            create_forkchoice_state(
                finalized_block.metadata.block_hash,
                finalized_block.metadata.block_hash,
                finalized_block.metadata.block_hash,
            )
        }

        /// Get canonical chain block data
        pub fn canonical(&self, index: usize) -> &PayloadRequest {
            &self.blocks[0][index]
        }

        /// Get fork block data
        pub fn fork(&self, fork_id: usize, index: usize) -> &PayloadRequest {
            &self.blocks[fork_id + 1][index]
        }

        /// Get canonical block hash
        pub fn canonical_block_hash(&self, index: usize) -> ExecutionBlockHash {
            self.canonical(index).metadata.block_hash
        }

        /// Get fork block hash
        pub fn fork_block_hash(&self, fork_id: usize, index: usize) -> ExecutionBlockHash {
            self.fork(fork_id, index).metadata.block_hash
        }

        /// Get canonical request root
        pub fn canonical_request_root(&self, index: usize) -> Hash256 {
            self.canonical(index).metadata.request_root
        }

        /// Get canonical metadata
        pub fn canonical_metadata(&self, index: usize) -> RequestMetadata {
            self.canonical(index).metadata.clone()
        }

        /// Get fork metadata
        pub fn fork_metadata(&self, fork_id: usize, index: usize) -> RequestMetadata {
            self.fork(fork_id, index).metadata.clone()
        }

        /// Get canonical proofs
        pub fn canonical_proofs(&self, index: usize) -> &[SignedExecutionProof] {
            &self.canonical(index).proofs
        }

        /// Get fork proofs
        pub fn fork_proofs(&self, fork_id: usize, index: usize) -> &[SignedExecutionProof] {
            &self.fork(fork_id, index).proofs
        }

        pub fn bootstrap_canonical(&self, state: &mut State) -> anyhow::Result<()> {
            state.forkchoice_updated(self.genesis_fcs())?;
            self.insert_canonical(state, None)?;
            Ok(())
        }

        /// Insert the canonical chain into state (buffer + add proofs)
        pub fn insert_canonical(
            &self,
            state: &mut State,
            block_index: Option<usize>,
        ) -> anyhow::Result<()> {
            let range = match block_index {
                Some(i) => i..=i,
                None => 0..=self.blocks[0].len() - 1,
            };
            for index in range {
                state.buffer_request(self.canonical_metadata(index));
                for proof in self.canonical_proofs(index) {
                    let _ = state.insert_proof(proof.clone())?;
                }
            }
            Ok(())
        }

        /// Insert a fork into state (buffer + add proofs)
        pub fn insert_fork(
            &self,
            state: &mut State,
            fork_id: usize,
            block_index: Option<usize>,
        ) -> anyhow::Result<()> {
            let range = match block_index {
                Some(i) => i..=i,
                None => 0..=self.blocks[fork_id + 1].len() - 1,
            };
            for index in range {
                state.buffer_request(self.fork_metadata(fork_id, index));
                for proof in self.fork_proofs(fork_id, index) {
                    let _ = state.insert_proof(proof.clone())?;
                }
            }

            Ok(())
        }
    }

    /// Builder for test state fixture
    pub struct TestStateFixtureBuilder {
        /// Number of blocks in canonical chain
        pub canonical_chain_length: usize,

        /// Fork configurations (branch_point, fork_length, proofs_per_block)
        pub forks: Vec<(usize, usize, Option<usize>)>,

        /// Default proofs per block
        pub proofs_per_block: usize,

        /// Starting block number
        pub starting_block_number: u64,
    }

    impl Default for TestStateFixtureBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TestStateFixtureBuilder {
        /// Create new builder
        pub fn new() -> Self {
            Self {
                canonical_chain_length: 0,
                forks: Vec::new(),
                proofs_per_block: MIN_REQUIRED_EXECUTION_PROOFS,
                starting_block_number: 0,
            }
        }

        /// Create a simple chain with 3 blocks in the canonical chain
        pub fn simple_chain() -> Self {
            Self::new().with_canonical_chain(3)
        }

        /// Set default proofs per block
        pub fn with_proofs_per_block(mut self, proofs: usize) -> Self {
            self.proofs_per_block = proofs;
            self
        }

        /// Set canonical chain length
        pub fn with_canonical_chain(mut self, length: usize) -> Self {
            self.canonical_chain_length = length;
            self
        }

        /// Add a fork (uses default proofs per block)
        pub fn with_fork(
            mut self,
            branch_point: usize,
            fork_length: usize,
            proofs_per_block: Option<usize>,
        ) -> Self {
            self.forks
                .push((branch_point, fork_length, proofs_per_block));
            self
        }

        /// Build the fixture
        pub fn build(self) -> TestStateFixture {
            let mut fixture = TestStateFixture {
                blocks: vec![Vec::new()], // Start with empty canonical chain
            };

            // Generate canonical chain (chain_id = 0)
            for i in 0..self.canonical_chain_length {
                let parent_hash = if i == 0 {
                    test_exec_hash(0xff) // Genesis parent
                } else {
                    fixture.blocks[0][i - 1].metadata.block_hash
                };

                let block_number = self.starting_block_number + i as u64;
                let block_data = self.generate_block(
                    0, // chain_id
                    i, // block index within chain
                    parent_hash,
                    block_number,
                    self.proofs_per_block,
                );

                fixture.blocks[0].push(block_data);
            }

            // Generate forks
            for (fork_idx, (branch_point, fork_length, custom_proofs)) in
                self.forks.iter().enumerate()
            {
                let proof_count = custom_proofs.unwrap_or(self.proofs_per_block);
                let mut fork_blocks: Vec<PayloadRequest> = Vec::new();

                for i in 0..*fork_length {
                    let parent_hash = if i == 0 {
                        // First fork block connects to canonical chain
                        fixture.blocks[0][*branch_point].metadata.block_hash
                    } else {
                        // Subsequent blocks connect to previous fork block
                        fork_blocks[i - 1].metadata.block_hash
                    };

                    let block_number =
                        self.starting_block_number + *branch_point as u64 + i as u64 + 1;

                    let block_data = self.generate_block(
                        fork_idx + 1, // chain_id (fork 0 = chain 1, fork 1 = chain 2, etc.)
                        i,
                        parent_hash,
                        block_number,
                        proof_count,
                    );

                    fork_blocks.push(block_data);
                }

                fixture.blocks.push(fork_blocks);
            }

            fixture
        }

        /// Generate data for a single block
        pub fn generate_block(
            &self,
            chain_id: usize,
            block_index: usize,
            parent_hash: ExecutionBlockHash,
            block_number: u64,
            proof_count: usize,
        ) -> PayloadRequest {
            // Create unique hashes based on chain_id and block_index
            let hash_seed = (chain_id * 1000 + block_index) % 256;
            let block_hash = test_exec_hash(hash_seed as u8);
            let request_root = test_hash(((hash_seed + 0x10) % 256) as u8);

            let metadata =
                create_request_metadata(request_root, block_hash, parent_hash, block_number);

            // Generate proofs with distinct proof types to avoid deduplication.
            let mut proofs = Vec::new();
            for i in 0..proof_count {
                proofs.push(create_signed_proof_with_type(
                    request_root,
                    request_root.0[0] as u64 + i as u64,
                    (i as u8).wrapping_add(1), // types 1, 2, 3, ... (avoid 0)
                ));
            }

            PayloadRequest { metadata, proofs }
        }
    }
} // end test_utils

#[cfg(test)]
mod tests {
    use super::test_utils::*;
    use super::*;

    #[test]
    fn test_buffer_request_new() {
        let fixture = TestStateFixtureBuilder::new()
            .with_canonical_chain(1)
            .build();

        let request = fixture.canonical(0);

        let mut state = State::new();
        state.buffer_request(request.metadata.clone());

        assert_eq!(
            state.buffer.proofs.len(),
            1,
            "buffer should contain exactly one request"
        );
        assert!(
            state
                .buffer
                .proofs
                .contains_key(&request.metadata.request_root),
            "buffer should contain the request root"
        );
        let buffered = state
            .buffer
            .proofs
            .get(&request.metadata.request_root)
            .expect("buffered request should exist");
        assert_eq!(
            buffered.metadata.block_hash, request.metadata.block_hash,
            "buffered request should have correct block hash"
        );
        assert_eq!(
            buffered.proofs.len(),
            0,
            "newly buffered request should have no proofs"
        );
    }

    #[test]
    fn test_buffer_request_preserves_proofs_on_duplicate() -> anyhow::Result<()> {
        let fixture = TestStateFixtureBuilder::new()
            .with_proofs_per_block(4)
            .with_canonical_chain(1)
            .build();
        let mut state = State::with_min_required_proofs(3);

        // Buffer request
        let request = fixture.canonical(0);
        state.buffer_request(request.metadata.clone());

        // Add multiple proofs
        for i in 0..2 {
            state.insert_proof(request.proofs[i].clone())?;
        }

        // Verify proofs exist
        let proofs_before = state
            .buffer
            .proofs
            .get(&request.metadata.request_root)
            .expect("request should be buffered")
            .proofs
            .len();
        assert_eq!(
            proofs_before, 2,
            "should have 2 proofs before re-buffer attempt"
        );

        // Attempt to buffer again
        state.buffer_request(request.metadata.clone());

        // Verify proofs preserved
        assert_eq!(
            state.buffer.proofs.len(),
            1,
            "buffer should still contain exactly one request"
        );
        let proofs_after = state
            .buffer
            .proofs
            .get(&request.metadata.request_root)
            .expect("request should still be buffered")
            .proofs
            .len();
        assert_eq!(
            proofs_after, 2,
            "all proofs should be preserved after duplicate buffer attempt"
        );

        Ok(())
    }

    #[test]
    fn test_buffer_request_skips_if_promoted_exists() -> anyhow::Result<()> {
        let fixture = TestStateFixtureBuilder::simple_chain().build();
        let mut state = State::new();
        fixture.bootstrap_canonical(&mut state)?;

        let request = fixture.canonical(2);

        // Assert promoted
        assert!(
            state
                .tree
                .proofs_by_block_hash
                .contains_key(&request.metadata.block_hash),
            "block should be promoted to tree"
        );
        assert!(
            !state
                .buffer
                .proofs
                .contains_key(&request.metadata.request_root),
            "block should be removed from buffer after promotion"
        );

        // Try buffer again
        state.buffer_request(request.metadata.clone());

        // Verify it stays in tree and is not re-added to buffer
        assert!(
            state
                .tree
                .proofs_by_block_hash
                .contains_key(&request.metadata.block_hash),
            "block should remain in tree"
        );
        assert!(
            !state
                .buffer
                .proofs
                .contains_key(&request.metadata.request_root),
            "block should not be added back to buffer"
        );

        Ok(())
    }

    #[test]
    fn test_insert_proof_unknown_request_root() {
        let fixture = TestStateFixtureBuilder::new()
            .with_canonical_chain(1)
            .build();
        let mut state = State::new();

        let request = fixture.canonical(0);
        let result = state.insert_proof(request.proofs[0].clone());

        assert!(
            result.is_err(),
            "inserting proof for unknown request root should return error"
        );
        match result {
            Err(ProofEngineStateError::ProofRequestRootNotSeen(root)) => {
                assert_eq!(
                    root, request.metadata.request_root,
                    "error should contain the unknown root"
                );
            }
            _ => panic!("expected ProofRequestRootNotSeen error"),
        }
    }

    #[test]
    fn test_promotion() -> anyhow::Result<()> {
        let fixture = TestStateFixtureBuilder::simple_chain()
            .with_proofs_per_block(4)
            .with_fork(1, 1, None)
            .build();
        let mut state = State::with_min_required_proofs(4);

        let request = fixture.canonical(0);
        state.forkchoice_updated(fixture.genesis_fcs())?;
        state.buffer_request(request.metadata.clone());
        for i in 0..request.proofs.len() - 1 {
            assert_eq!(
                state
                    .insert_proof(request.proofs[i].clone())
                    .expect("proof insertion should succeed"),
                ProofStatus::Accepted,
                "proof insertion should be accepted before reaching threshold"
            );
        }

        // Verify no promotion yet
        assert!(
            state
                .buffer
                .proofs
                .contains_key(&request.metadata.request_root),
            "request should still be in buffer before reaching proof threshold"
        );
        assert!(
            !state
                .tree
                .proofs_by_block_hash
                .contains_key(&request.metadata.block_hash),
            "block should not be in tree before reaching proof threshold"
        );

        // Insert final proof to trigger promotion
        assert_eq!(
            state
                .insert_proof(request.proofs[request.proofs.len() - 1].clone())
                .expect("proof insertion should succeed"),
            ProofStatus::Valid
        );

        // Verify promotion occurred
        assert!(
            !state
                .buffer
                .proofs
                .contains_key(&request.metadata.request_root),
            "promoted request should be removed from buffer"
        );
        assert!(
            state
                .tree
                .proofs_by_block_hash
                .contains_key(&request.metadata.block_hash),
            "promoted request should be added to tree"
        );
        assert!(
            state
                .tree
                .request_root_to_block_hash
                .contains_key(&request.metadata.request_root),
            "request root mapping should be created"
        );
        assert_eq!(
            state.tree.current_canonical_head, request.metadata.block_hash,
            "canonical head should be updated to child of previous head"
        );

        // Verify parent-child relationship
        let children = state
            .tree
            .parent_to_children
            .get(&request.metadata.parent_hash)
            .expect("parent should have children");
        assert!(
            children.contains(&request.metadata.block_hash),
            "parent should reference child in parent_to_children map"
        );

        // Verify block number mapping
        let blocks_at_height = state
            .tree
            .block_number_to_block_hash
            .get(&0)
            .expect("height 0 should exist");
        assert!(
            blocks_at_height.contains(&request.metadata.block_hash),
            "block should be in block_number_to_block_hash map"
        );

        // Now insert canonical block 2 with all proof - there should be no promotion yet as block 1 is not in the tree
        fixture.insert_canonical(&mut state, Some(2))?;

        // Verify block 2 is still in buffer
        let request2 = fixture.canonical(2);
        assert!(
            state
                .buffer
                .proofs
                .contains_key(&request2.metadata.request_root),
            "block 2 should remain in buffer as parent is not in tree"
        );

        // Now insert block 1 insert the buffer and this should cascade promote block 1 and block 2 and update the canonical head to block 2
        fixture.insert_canonical(&mut state, Some(1))?;

        // Verify block 1 promoted
        let request1 = fixture.canonical(1);
        assert!(
            !state
                .buffer
                .proofs
                .contains_key(&request1.metadata.request_root),
            "block 1 should be promoted from buffer"
        );
        assert!(
            state
                .tree
                .proofs_by_block_hash
                .contains_key(&request1.metadata.block_hash),
            "block 1 should be in tree"
        );

        // Verify block 2 promoted
        assert!(
            !state
                .buffer
                .proofs
                .contains_key(&request2.metadata.request_root),
            "block 2 should be promoted from buffer"
        );
        assert!(
            state
                .tree
                .proofs_by_block_hash
                .contains_key(&request2.metadata.block_hash),
            "block 2 should be in tree"
        );

        // Verify canonical head updated to block 2
        assert_eq!(
            state.tree.current_canonical_head, request2.metadata.block_hash,
            "canonical head should be updated to block 2"
        );

        // Now lets insert the fork into the tree and assert its promoted but does not affect the canonical head
        fixture.insert_fork(&mut state, 0, None)?;

        // Verify fork block promoted
        let fork_request = fixture.fork(0, 0);
        assert!(
            !state
                .buffer
                .proofs
                .contains_key(&fork_request.metadata.request_root),
            "fork block should be promoted from buffer"
        );
        assert!(
            state
                .tree
                .proofs_by_block_hash
                .contains_key(&fork_request.metadata.block_hash),
            "fork block should be in tree"
        );
        assert_eq!(
            state.tree.current_canonical_head, request2.metadata.block_hash,
            "canonical head should remain at block 2 after fork promotion"
        );

        Ok(())
    }

    #[test]
    fn test_forkchoice_updated_head_not_in_tree() -> anyhow::Result<()> {
        let mut state = State::new();
        let fixture = TestStateFixtureBuilder::simple_chain().build();

        // Bootstrap and insert canonical chain
        fixture.bootstrap_canonical(&mut state)?;

        // Update forkchoice with unknown head
        let finalized_hash = fixture.canonical_block_hash(0);
        let safe_hash = fixture.canonical_block_hash(0);
        let unknown_head_hash = test_exec_hash(0xee);
        let fcs = create_forkchoice_state(unknown_head_hash, safe_hash, finalized_hash);

        // Perform forkchoice update
        let response = state.forkchoice_updated(fcs)?;

        assert_eq!(
            response.payload_status.status,
            PayloadStatusV1Status::Syncing,
            "forkchoice update with unknown head should return SYNCING"
        );

        Ok(())
    }

    #[test]
    fn test_forkchoice_invalid_ancestry_chain() -> anyhow::Result<()> {
        let mut state = State::new();
        let fixture = TestStateFixtureBuilder::simple_chain()
            .with_fork(1, 1, None)
            .build();

        // Bootstrap and insert canonical chain
        fixture.bootstrap_canonical(&mut state)?;

        // Create a forkchoice state where the safe is not an ancestor of head and is not in the tree
        let head_hash = fixture.canonical_block_hash(2);
        let finalized_hash = fixture.canonical_block_hash(0);
        let unknown_safe_hash = test_exec_hash(0xee);
        let fcs = create_forkchoice_state(head_hash, unknown_safe_hash, finalized_hash);

        // Perform forkchoice update
        let response = state.forkchoice_updated(fcs)?;

        // Verify INVALID response
        assert_eq!(
            response.payload_status.status,
            PayloadStatusV1Status::Invalid,
            "forkchoice update with invalid ancestry should return INVALID"
        );

        // Create a forkchoice state where the finalized is not an ancestor of safe and is not in the tree
        let safe_hash = fixture.canonical_block_hash(1);
        let unknown_finalized_hash = test_exec_hash(0xee);
        let fcs = create_forkchoice_state(head_hash, safe_hash, unknown_finalized_hash);

        // Perform forkchoice update
        let response = state.forkchoice_updated(fcs)?;

        // Verify INVALID response
        assert_eq!(
            response.payload_status.status,
            PayloadStatusV1Status::Invalid,
            "forkchoice update with invalid ancestry should return INVALID"
        );

        // Create a forkchoice state where safe is not an ancestor of head but is in the tree
        let unknown_safe_hash = fixture.fork_block_hash(0, 0);
        let fcs = create_forkchoice_state(head_hash, unknown_safe_hash, finalized_hash);

        // Perform forkchoice update
        let response = state.forkchoice_updated(fcs)?;

        // Verify INVALID response
        assert_eq!(
            response.payload_status.status,
            PayloadStatusV1Status::Invalid,
            "forkchoice update with invalid ancestry should return INVALID"
        );

        Ok(())
    }

    #[test]
    fn test_valid_forkchoice_update_with_new_fork_head() -> anyhow::Result<()> {
        let fixture = TestStateFixtureBuilder::simple_chain()
            .with_fork(1, 1, None)
            .build();
        let mut state = State::new();

        // Bootstrap and insert canonical chain
        fixture.bootstrap_canonical(&mut state)?;

        // Extract canonical block hashes
        let block_0_hash = fixture.canonical_block_hash(0);
        let block_1_hash = fixture.canonical_block_hash(1);
        let block_2_hash = fixture.canonical_block_hash(2);

        // Assert that the tree canonical head is block 2
        assert_eq!(
            state.tree.current_canonical_head, block_2_hash,
            "canonical head should be block 2"
        );

        // Create and update forkchoice state pointing to block 1 as head and block 0 as safe/finalized
        let fcs = create_forkchoice_state(block_1_hash, block_0_hash, block_0_hash);
        let response = state.forkchoice_updated(fcs)?;

        // Assert that the response is VALID and the canonical head remains at block 2
        assert_eq!(
            response.payload_status.status,
            PayloadStatusV1Status::Valid,
            "forkchoice update should return VALID"
        );
        assert_eq!(
            state.tree.current_canonical_head, block_2_hash,
            "canonical head should not change when updating to ancestor"
        );

        // Create and update forkchoice state pointing to block 2 as head and block 1 as safe and block 0 as finalized
        let fcs = create_forkchoice_state(block_2_hash, block_1_hash, block_0_hash);

        // Perform forkchoice update
        let response = state.forkchoice_updated(fcs).unwrap();

        assert_eq!(
            response.payload_status.status,
            PayloadStatusV1Status::Valid,
            "forkchoice update should return VALID"
        );
        assert_eq!(
            state.tree.current_canonical_head, block_2_hash,
            "canonical head should not revert to ancestor"
        );

        // Insert the fork chain and update forkchoice to point to the fork head
        fixture.insert_fork(&mut state, 0, None)?;
        let fork_head_hash = fixture.fork_block_hash(0, 0);
        let fcs = create_forkchoice_state(fork_head_hash, block_1_hash, block_0_hash);

        // Perform forkchoice update
        let response = state.forkchoice_updated(fcs)?;

        // Verify VALID response and head updated to fork
        assert_eq!(
            response.payload_status.status,
            PayloadStatusV1Status::Valid,
            "forkchoice update to fork head should return VALID"
        );
        assert_eq!(
            state.tree.current_canonical_head, fork_head_hash,
            "canonical head should be updated to fork head"
        );

        Ok(())
    }

    // TODO: We need to update this test when we update the prune logic for fork -> buffer mapping
    #[test]
    fn test_prune() -> anyhow::Result<()> {
        let fixture = TestStateFixtureBuilder::simple_chain()
            .with_proofs_per_block(4)
            .with_fork(0, 4, None)
            .with_fork(0, 4, Some(1))
            .build();
        let mut state = State::with_min_required_proofs(4);
        // Bootstrap with canonical chain
        fixture.bootstrap_canonical(&mut state)?;

        // Insert fork chain which should also insert the fork block into the tree
        fixture.insert_fork(&mut state, 0, None)?;

        // Insert another fork with only 1 proof to ensure it is not promoted to the tree
        // TODO: When logic is added to prune buffer properly then add this.

        // Assert tree contains expected blocks
        assert_eq!(
            state.tree.proofs_by_block_hash.len(),
            7,
            "tree should contain 7 blocks before pruning"
        );

        // Issue forkchoice update that will prune the sidechain from the tree.
        let finalized_hash = fixture.canonical_block_hash(1);
        let safe_hash = finalized_hash;
        let head_hash = fixture.canonical_block_hash(2);
        let fcs = create_forkchoice_state(head_hash, safe_hash, finalized_hash);

        // Perform forkchoice update
        let response = state.forkchoice_updated(fcs)?;

        // Assert the response is VALID
        assert_eq!(
            response.payload_status.status,
            PayloadStatusV1Status::Valid,
            "forkchoice update should return VALID"
        );

        // Assert that the fork chain has been pruned from the tree as has the canonical block 0 but the canonical blocks 1 and 2 remain
        assert_eq!(
            state.tree.proofs_by_block_hash.len(),
            2,
            "tree should contain 2 blocks after pruning"
        );

        Ok(())
    }

    #[test]
    fn test_get_proofs_from_tree() -> anyhow::Result<()> {
        let fixture = TestStateFixtureBuilder::simple_chain().build();
        let mut state = State::new();

        // Bootstrap and insert canonical chain
        fixture.bootstrap_canonical(&mut state)?;

        // Retrieve proofs for genesis request root
        let genesis_request = fixture.canonical(0);
        let proofs = state.get_proofs(&genesis_request.metadata.request_root);

        assert!(proofs.is_some(), "should retrieve proofs from tree");
        assert_eq!(
            proofs.unwrap().len(),
            MIN_REQUIRED_EXECUTION_PROOFS,
            "should retrieve all proofs from tree"
        );

        Ok(())
    }

    #[test]
    fn test_get_proofs_from_buffer() -> anyhow::Result<()> {
        let fixture = TestStateFixtureBuilder::simple_chain()
            .with_fork(0, 1, Some(1))
            .build();
        let mut state = State::new();

        // Bootstrap and insert canonical chain
        fixture.bootstrap_canonical(&mut state)?;

        // Insert fork into state (this will be buffered only)
        fixture.insert_fork(&mut state, 0, None)?;

        // Retrieve proofs for fork request root
        let fork_request = fixture.fork(0, 0);
        let proofs = state.get_proofs(&fork_request.metadata.request_root);

        assert!(proofs.is_some(), "should retrieve proofs from buffer");
        assert_eq!(
            proofs.unwrap().len(),
            1,
            "should retrieve all proofs from buffer"
        );

        Ok(())
    }

    #[test]
    fn test_get_proofs_empty_list() {
        let fixture = TestStateFixtureBuilder::simple_chain().build();
        let mut state = State::new();

        // Insert a request into the buffer with no proofs
        let request = fixture.canonical(0);
        state.buffer_request(request.metadata.clone());

        // Retrieve proofs for the request root
        let proofs = state.get_proofs(&request.metadata.request_root);

        // The request exists in the buffer but has no proofs, so it should return None
        assert!(
            proofs.is_none(),
            "should return None for known request with no proofs"
        );
    }

    #[test]
    fn test_tree_state_consistency_after_promotion() -> anyhow::Result<()> {
        let fixture = TestStateFixtureBuilder::simple_chain().build();
        let mut state = State::new();

        // Bootstrap and insert canonical chain
        fixture.bootstrap_canonical(&mut state).unwrap();

        // Extract block hashes and request roots for all blocks in the canonical chain
        let genesis_hash = fixture.canonical_block_hash(0);
        let block1_hash = fixture.canonical_block_hash(1);
        let block2_hash = fixture.canonical_block_hash(2);

        let genesis_root = fixture.canonical_request_root(0);
        let block1_root = fixture.canonical_request_root(1);
        let block2_root = fixture.canonical_request_root(2);

        // Verify all tree mappings are consistent

        // proofs_by_block_hash
        assert_eq!(
            state.tree.proofs_by_block_hash.len(),
            3,
            "tree should contain exactly 3 blocks"
        );

        // request_root_to_block_hash
        assert_eq!(
            state.tree.request_root_to_block_hash.len(),
            3,
            "request_root_to_block_hash should have 3 entries"
        );
        assert_eq!(
            state
                .tree
                .request_root_to_block_hash
                .get(&genesis_root)
                .copied(),
            Some(genesis_hash),
            "genesis root should map to genesis hash"
        );
        assert_eq!(
            state
                .tree
                .request_root_to_block_hash
                .get(&block1_root)
                .copied(),
            Some(block1_hash),
            "block1 root should map to block1 hash"
        );
        assert_eq!(
            state
                .tree
                .request_root_to_block_hash
                .get(&block2_root)
                .copied(),
            Some(block2_hash),
            "block2 root should map to block2 hash"
        );

        // parent_to_children
        let genesis_parent = test_exec_hash(0xff);
        let genesis_parent_children = state
            .tree
            .parent_to_children
            .get(&genesis_parent)
            .expect("genesis parent should have children");
        assert!(
            genesis_parent_children.contains(&genesis_hash),
            "genesis parent should reference genesis"
        );

        let genesis_children = state
            .tree
            .parent_to_children
            .get(&genesis_hash)
            .expect("genesis should have children");
        assert!(
            genesis_children.contains(&block1_hash),
            "genesis should reference block1"
        );

        let block1_children = state
            .tree
            .parent_to_children
            .get(&block1_hash)
            .expect("block1 should have children");
        assert!(
            block1_children.contains(&block2_hash),
            "block1 should reference block2"
        );

        // block_number_to_block_hash
        assert!(
            state
                .tree
                .block_number_to_block_hash
                .get(&0)
                .unwrap()
                .contains(&genesis_hash),
            "genesis should be at height 0"
        );
        assert!(
            state
                .tree
                .block_number_to_block_hash
                .get(&1)
                .unwrap()
                .contains(&block1_hash),
            "block1 should be at height 1"
        );
        assert!(
            state
                .tree
                .block_number_to_block_hash
                .get(&2)
                .unwrap()
                .contains(&block2_hash),
            "block2 should be at height 2"
        );

        Ok(())
    }
}

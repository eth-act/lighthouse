//! Persistent storage types for ProofEngine state (EIP-8025).
//!
//! These structs are the SSZ-serializable forms of the in-memory `State`, `TreeState`,
//! and `RequestBuffer`. HashMaps/HashSets are flattened to Vecs for SSZ compatibility.
//!
//! Note: DB operations (compression, column writes) live in beacon_chain, not here.

use super::state::{PayloadRequest, RequestBuffer, RequestMetadata, State, TreeState};
use crate::ForkchoiceState;
use ssz_derive::{Decode, Encode};
use std::collections::{BTreeMap, HashMap, HashSet};
use types::{ExecutionBlockHash, Hash256, SignedExecutionProof};

/// Version field for future format migrations within the ProofEngine state.
pub const PROOF_ENGINE_STATE_VERSION: u64 = 1;

/// Top-level persisted state for the ProofEngine.
#[derive(Encode, Decode)]
pub struct PersistedProofEngineState {
    /// Schema version for future migrations.
    pub version: u64,
    /// The last fork choice state marked as valid (inlined — ForkchoiceState lacks SSZ derives).
    pub last_valid_head_block_hash: ExecutionBlockHash,
    pub last_valid_safe_block_hash: ExecutionBlockHash,
    pub last_valid_finalized_block_hash: ExecutionBlockHash,
    /// Whether latest_fcs is Some (Option encoded as flag + fields).
    pub has_latest_fcs: bool,
    pub latest_head_block_hash: ExecutionBlockHash,
    pub latest_safe_block_hash: ExecutionBlockHash,
    pub latest_finalized_block_hash: ExecutionBlockHash,
    /// Persisted tree state (accepted proofs).
    pub tree: PersistedTreeState,
    /// Persisted request buffer (pending proofs).
    pub buffer: PersistedRequestBuffer,
}

/// Persisted form of TreeState. HashMaps flattened to Vecs for SSZ.
#[derive(Encode, Decode)]
pub struct PersistedTreeState {
    pub proofs_by_block_hash: Vec<PersistedBlockProofs>,
    pub request_root_to_block_hash: Vec<RequestRootMapping>,
    pub parent_to_children: Vec<PersistedParentChildren>,
    pub block_number_to_block_hash: Vec<PersistedBlockNumberMapping>,
    pub current_canonical_head: ExecutionBlockHash,
}

/// Flattened PayloadRequest: RequestMetadata + Vec<SignedExecutionProof>.
#[derive(Encode, Decode)]
pub struct PersistedBlockProofs {
    pub block_hash: ExecutionBlockHash,
    pub request_root: Hash256,
    pub parent_hash: ExecutionBlockHash,
    pub block_number: u64,
    pub proofs: Vec<SignedExecutionProof>,
}

#[derive(Encode, Decode)]
pub struct RequestRootMapping {
    pub request_root: Hash256,
    pub block_hash: ExecutionBlockHash,
}

#[derive(Encode, Decode)]
pub struct PersistedParentChildren {
    pub parent: ExecutionBlockHash,
    pub children: Vec<ExecutionBlockHash>,
}

#[derive(Encode, Decode)]
pub struct PersistedBlockNumberMapping {
    pub block_number: u64,
    pub block_hashes: Vec<ExecutionBlockHash>,
}

#[derive(Encode, Decode)]
pub struct PersistedRequestBuffer {
    pub requests: Vec<PersistedBlockProofs>,
}

// --- Conversion: in-memory → persisted ---

impl PersistedProofEngineState {
    pub fn from_state(state: &State) -> Self {
        let zero = ExecutionBlockHash::zero();
        let (has_latest_fcs, latest_head, latest_safe, latest_finalized) =
            if let Some(fcs) = &state.latest_fcs {
                (
                    true,
                    fcs.head_block_hash,
                    fcs.safe_block_hash,
                    fcs.finalized_block_hash,
                )
            } else {
                (false, zero, zero, zero)
            };

        Self {
            version: PROOF_ENGINE_STATE_VERSION,
            last_valid_head_block_hash: state.last_valid_fcs.head_block_hash,
            last_valid_safe_block_hash: state.last_valid_fcs.safe_block_hash,
            last_valid_finalized_block_hash: state.last_valid_fcs.finalized_block_hash,
            has_latest_fcs,
            latest_head_block_hash: latest_head,
            latest_safe_block_hash: latest_safe,
            latest_finalized_block_hash: latest_finalized,
            tree: PersistedTreeState::from_tree(&state.tree),
            buffer: PersistedRequestBuffer::from_buffer(&state.buffer),
        }
    }

    pub fn to_state(&self) -> State {
        let latest_fcs = if self.has_latest_fcs {
            Some(ForkchoiceState {
                head_block_hash: self.latest_head_block_hash,
                safe_block_hash: self.latest_safe_block_hash,
                finalized_block_hash: self.latest_finalized_block_hash,
            })
        } else {
            None
        };

        State {
            latest_fcs,
            last_valid_fcs: ForkchoiceState {
                head_block_hash: self.last_valid_head_block_hash,
                safe_block_hash: self.last_valid_safe_block_hash,
                finalized_block_hash: self.last_valid_finalized_block_hash,
            },
            tree: self.tree.to_tree(),
            buffer: self.buffer.to_buffer(),
            min_required_proofs: types::MIN_REQUIRED_EXECUTION_PROOFS,
        }
    }
}

impl PersistedTreeState {
    fn from_tree(tree: &TreeState) -> Self {
        let proofs_by_block_hash = tree
            .proofs_by_block_hash
            .iter()
            .map(|(block_hash, payload_req)| PersistedBlockProofs {
                block_hash: *block_hash,
                request_root: payload_req.metadata.request_root,
                parent_hash: payload_req.metadata.parent_hash,
                block_number: payload_req.metadata.block_number,
                proofs: payload_req.proofs.clone(),
            })
            .collect();

        let request_root_to_block_hash = tree
            .request_root_to_block_hash
            .iter()
            .map(|(root, hash)| RequestRootMapping {
                request_root: *root,
                block_hash: *hash,
            })
            .collect();

        let parent_to_children = tree
            .parent_to_children
            .iter()
            .map(|(parent, children)| PersistedParentChildren {
                parent: *parent,
                children: children.iter().copied().collect(),
            })
            .collect();

        let block_number_to_block_hash = tree
            .block_number_to_block_hash
            .iter()
            .map(|(num, hashes)| PersistedBlockNumberMapping {
                block_number: *num,
                block_hashes: hashes.iter().copied().collect(),
            })
            .collect();

        Self {
            proofs_by_block_hash,
            request_root_to_block_hash,
            parent_to_children,
            block_number_to_block_hash,
            current_canonical_head: tree.current_canonical_head,
        }
    }

    fn to_tree(&self) -> TreeState {
        let proofs_by_block_hash: HashMap<ExecutionBlockHash, PayloadRequest> = self
            .proofs_by_block_hash
            .iter()
            .map(|p| {
                (
                    p.block_hash,
                    PayloadRequest {
                        metadata: RequestMetadata {
                            request_root: p.request_root,
                            block_hash: p.block_hash,
                            parent_hash: p.parent_hash,
                            block_number: p.block_number,
                        },
                        proofs: p.proofs.clone(),
                    },
                )
            })
            .collect();

        let request_root_to_block_hash: HashMap<Hash256, ExecutionBlockHash> = self
            .request_root_to_block_hash
            .iter()
            .map(|m| (m.request_root, m.block_hash))
            .collect();

        let parent_to_children: HashMap<ExecutionBlockHash, HashSet<ExecutionBlockHash>> = self
            .parent_to_children
            .iter()
            .map(|p| (p.parent, p.children.iter().copied().collect()))
            .collect();

        let block_number_to_block_hash: BTreeMap<u64, HashSet<ExecutionBlockHash>> = self
            .block_number_to_block_hash
            .iter()
            .map(|m| (m.block_number, m.block_hashes.iter().copied().collect()))
            .collect();

        TreeState {
            proofs_by_block_hash,
            request_root_to_block_hash,
            parent_to_children,
            block_number_to_block_hash,
            current_canonical_head: self.current_canonical_head,
        }
    }
}

impl PersistedRequestBuffer {
    fn from_buffer(buffer: &RequestBuffer) -> Self {
        let requests = buffer
            .proofs
            .iter()
            .map(|(_, payload_req)| PersistedBlockProofs {
                block_hash: payload_req.metadata.block_hash,
                request_root: payload_req.metadata.request_root,
                parent_hash: payload_req.metadata.parent_hash,
                block_number: payload_req.metadata.block_number,
                proofs: payload_req.proofs.clone(),
            })
            .collect();
        Self { requests }
    }

    fn to_buffer(&self) -> RequestBuffer {
        let proofs: HashMap<Hash256, PayloadRequest> = self
            .requests
            .iter()
            .map(|p| {
                (
                    p.request_root,
                    PayloadRequest {
                        metadata: RequestMetadata {
                            request_root: p.request_root,
                            block_hash: p.block_hash,
                            parent_hash: p.parent_hash,
                            block_number: p.block_number,
                        },
                        proofs: p.proofs.clone(),
                    },
                )
            })
            .collect();
        RequestBuffer { proofs }
    }
}

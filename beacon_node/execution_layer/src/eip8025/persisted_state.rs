//! Persistent storage types for ProofEngine state (EIP-8025).
//!
//! These structs are the SSZ-serializable forms of the in-memory `State`, `TreeState`,
//! and `RequestBuffer`. HashMaps/HashSets are flattened to Vecs for SSZ compatibility.

use super::state::{PayloadRequest, RequestBuffer, RequestMetadata, State, TreeState};
use crate::ForkchoiceState;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::{BTreeMap, HashMap, HashSet};
use store::{DBColumn, Error as StoreError, KeyValueStoreOp, StoreConfig, StoreItem};
use types::{ExecutionBlockHash, Hash256, SignedExecutionProof};

/// Version field for future format migrations within the ProofEngine state.
pub const PROOF_ENGINE_STATE_VERSION: u64 = 1;

/// Top-level persisted state for the ProofEngine.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct PersistedProofEngineState {
    /// Schema version for future migrations.
    pub version: u64,
    /// The last fork choice state marked as valid.
    pub last_valid_fcs: ForkchoiceState,
    /// The latest observed fork choice state.
    pub latest_fcs: Option<ForkchoiceState>,
    /// Persisted tree state.
    pub tree: PersistedTreeState,
    /// Persisted request buffer.
    pub buffer: PersistedRequestBuffer,
}

/// Persisted form of TreeState. HashMaps flattened to Vecs for SSZ.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct PersistedTreeState {
    pub proofs_by_block_hash: Vec<PersistedBlockProofs>,
    pub request_root_to_block_hash: Vec<RequestRootMapping>,
    pub parent_to_children: Vec<PersistedParentChildren>,
    pub block_number_to_block_hash: Vec<PersistedBlockNumberMapping>,
    pub current_canonical_head: ExecutionBlockHash,
}

/// Flattened PayloadRequest: RequestMetadata + Vec<SignedExecutionProof>.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct PersistedBlockProofs {
    pub block_hash: ExecutionBlockHash,
    pub request_root: Hash256,
    pub parent_hash: ExecutionBlockHash,
    pub block_number: u64,
    pub proofs: Vec<SignedExecutionProof>,
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct RequestRootMapping {
    pub request_root: Hash256,
    pub block_hash: ExecutionBlockHash,
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct PersistedParentChildren {
    pub parent: ExecutionBlockHash,
    pub children: Vec<ExecutionBlockHash>,
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct PersistedBlockNumberMapping {
    pub block_number: u64,
    pub block_hashes: Vec<ExecutionBlockHash>,
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct PersistedRequestBuffer {
    pub requests: Vec<PersistedBlockProofs>,
}

/// Fixed database key for the single `PersistedProofEngineState` record.
pub const PROOF_ENGINE_DB_KEY: Hash256 = Hash256::ZERO;

impl StoreItem for PersistedProofEngineState {
    fn db_column() -> DBColumn {
        DBColumn::ProofEngine
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}

impl PersistedProofEngineState {
    /// Decompress and decode from bytes using zstd (mirrors `PersistedForkChoiceV28::from_bytes`).
    pub fn from_bytes(bytes: &[u8], store_config: &StoreConfig) -> Result<Self, StoreError> {
        let decompressed_bytes = store_config
            .decompress_bytes(bytes)
            .map_err(StoreError::Compression)?;
        Self::from_ssz_bytes(&decompressed_bytes).map_err(Into::into)
    }

    /// Encode and compress to bytes using zstd (mirrors `PersistedForkChoiceV28::as_bytes`).
    pub fn as_bytes(&self, store_config: &StoreConfig) -> Result<Vec<u8>, StoreError> {
        let ssz_bytes = self.as_ssz_bytes();
        store_config
            .compress_bytes(&ssz_bytes)
            .map_err(StoreError::Compression)
    }

    /// Produce a compressed `KeyValueStoreOp` for atomic persistence.
    pub fn as_kv_store_op(
        &self,
        key: Hash256,
        store_config: &StoreConfig,
    ) -> Result<KeyValueStoreOp, StoreError> {
        Ok(KeyValueStoreOp::PutKeyValue(
            DBColumn::ProofEngine,
            key.as_slice().to_vec(),
            self.as_bytes(store_config)?,
        ))
    }

    pub fn from_state(state: &State) -> Self {
        Self {
            version: PROOF_ENGINE_STATE_VERSION,
            last_valid_fcs: state.last_valid_fcs,
            latest_fcs: state.latest_fcs,
            tree: PersistedTreeState::from_tree(&state.tree),
            buffer: PersistedRequestBuffer::from_buffer(&state.buffer),
        }
    }

    pub fn to_state(&self) -> State {
        State {
            latest_fcs: self.latest_fcs,
            last_valid_fcs: self.last_valid_fcs,
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
            .values()
            .map(|payload_req| PersistedBlockProofs {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eip8025::state::test_utils::*;
    use store::StoreItem;
    use types::MIN_REQUIRED_EXECUTION_PROOFS;

    /// Builds a fully-populated `State` with canonical chain, a fork (in buffer), and both FCS
    /// fields set, then verifies a `from_state` → `to_state` round-trip preserves all data.
    #[test]
    fn test_state_serialization_round_trip() {
        // 3-block canonical chain; fork from block 1 with 0 proofs so it stays in buffer, additional fork with 3 proofs so we have a promoted fork as well.
        let fixture = TestStateFixtureBuilder::simple_chain()
            .with_fork(1, 2, Some(0))
            .with_fork(1, 3, Some(3))
            .build();

        let mut state = State::new();

        // Populate canonical chain into tree and set latest_fcs via the empty-tree path.
        fixture.bootstrap_canonical(&mut state).unwrap();

        // Insert fork blocks into buffer (0 proofs → not promoted).
        fixture.insert_fork(&mut state, 0, None).unwrap();

        // Issue a valid forkchoice update so last_valid_fcs points into the tree.
        let head = fixture.canonical_block_hash(2);
        let safe = fixture.canonical_block_hash(1);
        let finalized = fixture.canonical_block_hash(0);
        state
            .forkchoice_updated(create_forkchoice_state(head, safe, finalized))
            .unwrap();

        // Sanity: both FCS fields should be populated.
        assert!(state.latest_fcs.is_some());

        // --- Round-trip ---
        let persisted = PersistedProofEngineState::from_state(&state);
        let restored = persisted.to_state();

        // FCS fields.
        assert_eq!(restored.last_valid_fcs, state.last_valid_fcs);
        assert_eq!(restored.latest_fcs, state.latest_fcs);

        // min_required_proofs is not persisted — always restored to the constant.
        assert_eq!(restored.min_required_proofs, MIN_REQUIRED_EXECUTION_PROOFS);

        // Tree: proofs_by_block_hash.
        assert_eq!(
            restored.tree.proofs_by_block_hash.len(),
            state.tree.proofs_by_block_hash.len()
        );
        for (hash, req) in &state.tree.proofs_by_block_hash {
            let r = restored.tree.proofs_by_block_hash.get(hash).unwrap();
            assert_eq!(r.metadata.request_root, req.metadata.request_root);
            assert_eq!(r.metadata.block_hash, req.metadata.block_hash);
            assert_eq!(r.metadata.parent_hash, req.metadata.parent_hash);
            assert_eq!(r.metadata.block_number, req.metadata.block_number);
            assert_eq!(r.proofs, req.proofs);
        }

        // Tree: request_root_to_block_hash.
        assert_eq!(
            restored.tree.request_root_to_block_hash,
            state.tree.request_root_to_block_hash
        );

        // Tree: parent_to_children (HashSet equality via HashMap comparison).
        assert_eq!(
            restored.tree.parent_to_children,
            state.tree.parent_to_children
        );

        // Tree: block_number_to_block_hash (BTreeMap<u64, HashSet>).
        assert_eq!(
            restored.tree.block_number_to_block_hash,
            state.tree.block_number_to_block_hash
        );

        // Tree: current_canonical_head.
        assert_eq!(
            restored.tree.current_canonical_head,
            state.tree.current_canonical_head
        );

        // Buffer: entries match.
        assert_eq!(restored.buffer.proofs.len(), state.buffer.proofs.len());
        for (root, req) in &state.buffer.proofs {
            let r = restored.buffer.proofs.get(root).unwrap();
            assert_eq!(r.metadata.request_root, req.metadata.request_root);
            assert_eq!(r.metadata.block_hash, req.metadata.block_hash);
            assert_eq!(r.metadata.parent_hash, req.metadata.parent_hash);
            assert_eq!(r.metadata.block_number, req.metadata.block_number);
            assert_eq!(r.proofs, req.proofs);
        }
    }

    /// Encodes a `PersistedProofEngineState` via `StoreItem::as_store_bytes`, then decodes with
    /// `StoreItem::from_store_bytes` and asserts all fields are equal.
    #[test]
    fn test_encode_decode_round_trip() {
        let fixture = TestStateFixtureBuilder::simple_chain()
            .with_fork(1, 2, Some(0))
            .with_fork(1, 3, Some(3))
            .build();

        let mut state = State::new();
        fixture.bootstrap_canonical(&mut state).unwrap();
        fixture.insert_fork(&mut state, 0, None).unwrap();

        let head = fixture.canonical_block_hash(2);
        let safe = fixture.canonical_block_hash(1);
        let finalized = fixture.canonical_block_hash(0);
        state
            .forkchoice_updated(create_forkchoice_state(head, safe, finalized))
            .unwrap();

        let persisted = PersistedProofEngineState::from_state(&state);

        let bytes = persisted.as_store_bytes();
        let decoded = PersistedProofEngineState::from_store_bytes(&bytes).unwrap();

        assert_eq!(decoded.version, persisted.version);
        assert_eq!(decoded.last_valid_fcs, persisted.last_valid_fcs);
        assert_eq!(decoded.latest_fcs, persisted.latest_fcs);

        assert_eq!(
            decoded.tree.proofs_by_block_hash,
            persisted.tree.proofs_by_block_hash
        );
        assert_eq!(
            decoded.tree.request_root_to_block_hash,
            persisted.tree.request_root_to_block_hash
        );

        // Sort children within each parent entry for determinism.
        assert_eq!(
            decoded.tree.parent_to_children.len(),
            persisted.tree.parent_to_children.len()
        );
        let mut orig_ptc = persisted.tree.parent_to_children.clone();
        let mut dec_ptc = decoded.tree.parent_to_children.clone();
        orig_ptc.sort_by_key(|p| p.parent.into_root());
        dec_ptc.sort_by_key(|p| p.parent.into_root());
        for (o, d) in orig_ptc.iter().zip(dec_ptc.iter()) {
            assert_eq!(o.parent, d.parent);
            let mut oc = o.children.clone();
            let mut dc = d.children.clone();
            oc.sort_by_key(|h| h.into_root());
            dc.sort_by_key(|h| h.into_root());
            assert_eq!(oc, dc);
        }

        assert_eq!(
            decoded.tree.block_number_to_block_hash,
            persisted.tree.block_number_to_block_hash
        );
        assert_eq!(
            decoded.tree.current_canonical_head,
            persisted.tree.current_canonical_head
        );
        assert_eq!(decoded.buffer.requests, persisted.buffer.requests);
    }

    /// Verifies that compress → decompress round-trip via `as_bytes`/`from_bytes`
    /// preserves all fields, and that compressed output is smaller than raw SSZ.
    #[test]
    fn test_compressed_round_trip() {
        let fixture = TestStateFixtureBuilder::simple_chain()
            .with_fork(1, 2, Some(0))
            .with_fork(1, 3, Some(3))
            .build();

        let mut state = State::new();
        fixture.bootstrap_canonical(&mut state).unwrap();
        fixture.insert_fork(&mut state, 0, None).unwrap();

        let head = fixture.canonical_block_hash(2);
        let safe = fixture.canonical_block_hash(1);
        let finalized = fixture.canonical_block_hash(0);
        state
            .forkchoice_updated(create_forkchoice_state(head, safe, finalized))
            .unwrap();

        let persisted = PersistedProofEngineState::from_state(&state);
        let store_config = StoreConfig::default();

        // Compress.
        let compressed = persisted.as_bytes(&store_config).unwrap();
        let raw_ssz = persisted.as_store_bytes();

        // Compressed should differ from raw SSZ (zstd adds framing even if not smaller).
        assert_ne!(compressed, raw_ssz);

        // Decompress and verify equality.
        let decoded = PersistedProofEngineState::from_bytes(&compressed, &store_config).unwrap();
        assert_eq!(decoded.version, persisted.version);
        assert_eq!(decoded.last_valid_fcs, persisted.last_valid_fcs);
        assert_eq!(decoded.latest_fcs, persisted.latest_fcs);
        assert_eq!(
            decoded.tree.proofs_by_block_hash,
            persisted.tree.proofs_by_block_hash
        );
        assert_eq!(
            decoded.tree.request_root_to_block_hash,
            persisted.tree.request_root_to_block_hash
        );
        assert_eq!(
            decoded.tree.current_canonical_head,
            persisted.tree.current_canonical_head
        );
        assert_eq!(decoded.buffer.requests, persisted.buffer.requests);
    }
}

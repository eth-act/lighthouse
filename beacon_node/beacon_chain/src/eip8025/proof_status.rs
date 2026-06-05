use super::proof_verification::{ExecutionProofError, verify_signed_execution_proof_signature};
use crate::observed_execution_proofs::ProofObservation;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, ForkChoiceError};
use execution_layer::{NewPayloadRequest, NewPayloadRequestGloas};
use lru::LruCache;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use store::DatabaseBlock;
use types::{
    EthSpec, Hash256, ProofStatus, ProofType, SignedBlindedBeaconBlock,
    SignedExecutionPayloadEnvelope, SignedExecutionProof, Slot,
};

const DEFAULT_REQUEST_ROOT_CACHE_SIZE: usize = 8192;
const DEFAULT_PROOF_CACHE_SIZE: usize = 8192;

/// Proof metadata for one beacon block / `engine_newPayload` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProofBlockStatus {
    pub block_root: Hash256,
    pub request_root: Hash256,
    pub slot: Slot,
    valid_proof_types: HashSet<ProofType>,
}

impl ExecutionProofBlockStatus {
    fn new(block_root: Hash256, request_root: Hash256, slot: Slot) -> Self {
        Self {
            block_root,
            request_root,
            slot,
            valid_proof_types: HashSet::new(),
        }
    }

    pub fn valid_proof_type_count(&self) -> usize {
        self.valid_proof_types.len()
    }

    pub fn valid_proof_types(&self) -> impl Iterator<Item = ProofType> + '_ {
        self.valid_proof_types.iter().copied()
    }
}

/// Bounded request-root ingress cache plus proof-status metadata.
///
/// This deliberately stores proof status only. Unfinalized proof bytes remain hot/prunable and are
/// not durably tracked here.
#[derive(Debug)]
pub struct ExecutionProofStatusCache {
    request_root_to_block_root: LruCache<Hash256, Hash256>,
    block_root_to_request_root: LruCache<Hash256, Hash256>,
    proofs_by_block_and_type: LruCache<(Hash256, ProofType), Arc<SignedExecutionProof>>,
    statuses_by_block_root: HashMap<Hash256, ExecutionProofBlockStatus>,
}

impl Default for ExecutionProofStatusCache {
    fn default() -> Self {
        let request_root_capacity = NonZeroUsize::new(DEFAULT_REQUEST_ROOT_CACHE_SIZE)
            .expect("default request-root cache size is non-zero");
        let proof_capacity = NonZeroUsize::new(DEFAULT_PROOF_CACHE_SIZE)
            .expect("default proof cache size is non-zero");
        Self {
            request_root_to_block_root: LruCache::new(request_root_capacity),
            block_root_to_request_root: LruCache::new(request_root_capacity),
            proofs_by_block_and_type: LruCache::new(proof_capacity),
            statuses_by_block_root: HashMap::new(),
        }
    }
}

impl ExecutionProofStatusCache {
    pub fn register_request_root(
        &mut self,
        block_root: Hash256,
        request_root: Hash256,
        slot: Slot,
    ) {
        self.request_root_to_block_root
            .put(request_root, block_root);
        self.block_root_to_request_root
            .put(block_root, request_root);
        self.statuses_by_block_root
            .entry(block_root)
            .or_insert_with(|| ExecutionProofBlockStatus::new(block_root, request_root, slot));
    }

    pub fn block_root_for_request_root(&self, request_root: &Hash256) -> Option<Hash256> {
        self.request_root_to_block_root.peek(request_root).copied()
    }

    pub fn request_root_for_block_root(&self, block_root: &Hash256) -> Option<Hash256> {
        self.block_root_to_request_root.peek(block_root).copied()
    }

    pub fn block_context_for_request_root(
        &self,
        request_root: &Hash256,
    ) -> Option<(Hash256, Slot)> {
        let block_root = self.request_root_to_block_root.peek(request_root)?;
        self.statuses_by_block_root
            .get(block_root)
            .map(|status| (status.block_root, status.slot))
    }

    pub fn observe_valid_proof(
        &mut self,
        block_root: Hash256,
        request_root: Hash256,
        slot: Slot,
        proof: Arc<SignedExecutionProof>,
    ) -> ExecutionProofStatusSummary {
        let proof_type = proof.proof_type();
        self.register_request_root(block_root, request_root, slot);
        let status = self
            .statuses_by_block_root
            .entry(block_root)
            .or_insert_with(|| ExecutionProofBlockStatus::new(block_root, request_root, slot));
        let newly_observed = status.valid_proof_types.insert(proof_type);
        self.proofs_by_block_and_type
            .put((block_root, proof_type), proof);

        ExecutionProofStatusSummary {
            block_root,
            request_root,
            slot,
            newly_observed,
            valid_proof_type_count: status.valid_proof_type_count(),
        }
    }

    pub fn status_by_block_root(&self, block_root: &Hash256) -> Option<&ExecutionProofBlockStatus> {
        self.statuses_by_block_root.get(block_root)
    }

    pub fn latest_status_with_valid_proofs(
        &self,
        configured_proof_types: &[ProofType],
    ) -> Option<ExecutionProofBlockStatus> {
        self.statuses_by_block_root
            .values()
            .filter(|status| {
                configured_proof_types
                    .iter()
                    .any(|proof_type| status.valid_proof_types.contains(proof_type))
            })
            .max_by_key(|status| status.slot)
            .cloned()
    }

    pub fn proof_by_block_root_and_type(
        &mut self,
        block_root: Hash256,
        proof_type: ProofType,
    ) -> Option<Arc<SignedExecutionProof>> {
        self.proofs_by_block_and_type
            .get(&(block_root, proof_type))
            .cloned()
    }

    pub fn missing_execution_proofs(
        &self,
        configured_proof_types: &[ProofType],
    ) -> Vec<MissingExecutionProofInfo> {
        self.statuses_by_block_root
            .values()
            .filter_map(|status| {
                let missing_any = configured_proof_types
                    .iter()
                    .any(|proof_type| !status.valid_proof_types.contains(proof_type));
                missing_any.then(|| MissingExecutionProofInfo {
                    root: status.block_root,
                    slot: status.slot,
                    existing_proof_types: status.valid_proof_types.clone(),
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProofStatusSummary {
    pub block_root: Hash256,
    pub request_root: Hash256,
    pub slot: Slot,
    pub newly_observed: bool,
    pub valid_proof_type_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingExecutionProofInfo {
    pub root: Hash256,
    pub slot: Slot,
    pub existing_proof_types: HashSet<ProofType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProofObservation {
    pub status: ProofStatus,
    pub block_root: Option<Hash256>,
    pub request_root: Hash256,
    pub valid_proof_type_count: usize,
    pub quorum_threshold: Option<usize>,
    pub proof_backed_payload_promotion: bool,
}

impl ExecutionProofObservation {
    fn syncing(request_root: Hash256, quorum_threshold: Option<usize>) -> Self {
        Self {
            status: ProofStatus::Syncing,
            block_root: None,
            request_root,
            valid_proof_type_count: 0,
            quorum_threshold,
            proof_backed_payload_promotion: false,
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Compute and cache the EIP-8025 new-payload request root for a known Gloas block root.
    pub fn register_execution_payload_request_root(
        &self,
        block_root: Hash256,
    ) -> Result<Hash256, BeaconChainError> {
        let (request_root, slot) = self.execution_payload_request_context(block_root)?;
        self.execution_proof_statuses
            .write()
            .register_request_root(block_root, request_root, slot);
        Ok(request_root)
    }

    /// Return the cached block root for an EIP-8025 new-payload request root.
    pub fn block_root_for_execution_proof_request(
        &self,
        request_root: &Hash256,
    ) -> Option<Hash256> {
        self.execution_proof_statuses
            .read()
            .block_root_for_request_root(request_root)
    }

    /// Record one externally-validated proof and optionally apply the non-default proof quorum.
    ///
    /// This function assumes BLS signature checks and proof-engine verification have already
    /// succeeded. Invalid proofs must not call this path.
    pub fn observe_valid_execution_proof(
        &self,
        proof: &SignedExecutionProof,
        block_root_hint: Option<Hash256>,
    ) -> Result<ExecutionProofObservation, BeaconChainError> {
        let request_root = proof.request_root();
        let quorum_threshold = self.config.execution_proof_quorum.threshold();

        let Some((block_root, slot)) =
            self.resolve_execution_proof_block_root(request_root, block_root_hint)?
        else {
            return Ok(ExecutionProofObservation::syncing(
                request_root,
                quorum_threshold,
            ));
        };

        let summary = self.execution_proof_statuses.write().observe_valid_proof(
            block_root,
            request_root,
            slot,
            Arc::new(proof.clone()),
        );

        self.observed_execution_proofs.write().observe_valid_proof(
            request_root,
            proof.proof_type(),
            slot,
        );

        let proof_backed_payload_promotion = if quorum_threshold
            .is_some_and(|threshold| summary.valid_proof_type_count >= threshold)
        {
            self.try_mark_proof_backed_payload_valid(block_root)?
        } else {
            false
        };

        Ok(ExecutionProofObservation {
            status: if proof_backed_payload_promotion {
                ProofStatus::Valid
            } else {
                ProofStatus::Accepted
            },
            block_root: Some(block_root),
            request_root,
            valid_proof_type_count: summary.valid_proof_type_count,
            quorum_threshold,
            proof_backed_payload_promotion,
        })
    }

    /// Verify a signed execution proof and record proof metadata if it is valid.
    ///
    /// This path keeps proof validity optional: invalid proofs never invalidate the payload and
    /// valid proofs only affect fork choice when `execution_proof_quorum` is explicitly enabled.
    pub async fn verify_and_observe_execution_proof(
        &self,
        proof: &SignedExecutionProof,
        block_root_hint: Option<Hash256>,
    ) -> Result<ExecutionProofObservation, BeaconChainError> {
        let request_root = proof.request_root();
        let proof_type = proof.proof_type();
        let quorum_threshold = self.config.execution_proof_quorum.threshold();

        match self.observed_execution_proofs.read().check(
            request_root,
            proof_type,
            proof.proof_data(),
            proof.validator_index(),
        ) {
            ProofObservation::AlreadyRejectedProof => {
                return Ok(ExecutionProofObservation {
                    status: ProofStatus::Invalid,
                    block_root: None,
                    request_root,
                    valid_proof_type_count: 0,
                    quorum_threshold,
                    proof_backed_payload_promotion: false,
                });
            }
            ProofObservation::AlreadyHaveValidProof | ProofObservation::DuplicateFromValidator => {
                return Ok(ExecutionProofObservation {
                    status: ProofStatus::Accepted,
                    block_root: self.block_root_for_execution_proof_request(&request_root),
                    request_root,
                    valid_proof_type_count: 0,
                    quorum_threshold,
                    proof_backed_payload_promotion: false,
                });
            }
            ProofObservation::New => {}
        }

        let Some((_, slot)) =
            self.resolve_execution_proof_block_root(request_root, block_root_hint)?
        else {
            return Ok(ExecutionProofObservation::syncing(
                request_root,
                quorum_threshold,
            ));
        };

        self.observed_execution_proofs
            .write()
            .observe_verification_attempt(request_root, proof_type, proof.validator_index());

        let validator_index = usize::try_from(proof.validator_index())
            .map_err(|_| ExecutionProofError::InvalidValidatorIndex)?;
        let validator_pubkey = self
            .validator_pubkey_bytes(validator_index)?
            .ok_or(ExecutionProofError::InvalidValidatorIndex)?;
        let fork_name = self.spec.fork_name_at_slot::<T::EthSpec>(slot);

        verify_signed_execution_proof_signature::<T::EthSpec>(
            proof,
            &validator_pubkey,
            fork_name,
            self.genesis_validators_root,
            &self.spec,
        )?;

        let proof_engine = self
            .execution_layer
            .as_ref()
            .and_then(|execution_layer| execution_layer.proof_engine())
            .ok_or(ExecutionProofError::NoExecutionLayer)?;

        match proof_engine.verify_execution_proof(proof).await? {
            ProofStatus::Valid => self.observe_valid_execution_proof(proof, block_root_hint),
            ProofStatus::Invalid => {
                self.observed_execution_proofs
                    .write()
                    .observe_invalid_proof(proof_type, proof.proof_data());
                Ok(ExecutionProofObservation {
                    status: ProofStatus::Invalid,
                    block_root: self.block_root_for_execution_proof_request(&request_root),
                    request_root,
                    valid_proof_type_count: 0,
                    quorum_threshold,
                    proof_backed_payload_promotion: false,
                })
            }
            status => Ok(ExecutionProofObservation {
                status,
                block_root: self.block_root_for_execution_proof_request(&request_root),
                request_root,
                valid_proof_type_count: 0,
                quorum_threshold,
                proof_backed_payload_promotion: false,
            }),
        }
    }

    fn resolve_execution_proof_block_root(
        &self,
        request_root: Hash256,
        block_root_hint: Option<Hash256>,
    ) -> Result<Option<(Hash256, Slot)>, BeaconChainError> {
        if let Some(block_root) = block_root_hint {
            let (computed_request_root, slot) =
                self.execution_payload_request_context(block_root)?;
            if computed_request_root != request_root {
                return Err(BeaconChainError::ExecutionProofError(
                    super::proof_verification::ExecutionProofError::UnknownRequestRoot(
                        request_root,
                    ),
                ));
            }
            self.execution_proof_statuses.write().register_request_root(
                block_root,
                request_root,
                slot,
            );
            return Ok(Some((block_root, slot)));
        }

        let Some((block_root, slot)) = self
            .execution_proof_statuses
            .read()
            .block_context_for_request_root(&request_root)
        else {
            return Ok(None);
        };

        Ok(Some((block_root, slot)))
    }

    fn execution_payload_request_context(
        &self,
        block_root: Hash256,
    ) -> Result<(Hash256, Slot), BeaconChainError> {
        if let Some(DatabaseBlock::Full(block)) = self.store.try_get_full_block(&block_root)?
            && !block.fork_name_unchecked().gloas_enabled()
        {
            let slot = block.slot();
            let request = NewPayloadRequest::try_from(block.message())
                .map_err(BeaconChainError::BeaconStateError)?;
            return Ok((request.request_root(), slot));
        }

        let block = self
            .get_blinded_block(&block_root)?
            .ok_or(BeaconChainError::MissingBeaconBlock(block_root))?;
        let envelope = self.get_payload_envelope(&block_root)?.ok_or(
            BeaconChainError::MissingExecutionPayloadEnvelope(block_root),
        )?;
        let slot = block.slot();
        let request = build_gloas_new_payload_request(&block, &envelope)?;

        Ok((request.request_root(), slot))
    }

    fn try_mark_proof_backed_payload_valid(
        &self,
        block_root: Hash256,
    ) -> Result<bool, BeaconChainError> {
        let block = self
            .get_blinded_block(&block_root)?
            .ok_or(BeaconChainError::MissingBeaconBlock(block_root))?;
        let is_gloas = block.fork_name_unchecked().gloas_enabled();
        if is_gloas && self.get_payload_envelope(&block_root)?.is_none() {
            return Ok(false);
        }

        let mut fork_choice = self.canonical_head.fork_choice_write_lock();
        if is_gloas {
            fork_choice
                .on_valid_payload_envelope_received(block_root)
                .map_err(map_fork_choice_error)?;
        } else {
            fork_choice
                .on_valid_execution_payload(block_root)
                .map_err(map_fork_choice_error)?;
        }

        Ok(true)
    }

    pub fn execution_proof_by_block_root_and_type(
        &self,
        block_root: Hash256,
        proof_type: ProofType,
    ) -> Option<Arc<SignedExecutionProof>> {
        self.execution_proof_statuses
            .write()
            .proof_by_block_root_and_type(block_root, proof_type)
    }

    pub fn execution_proofs_by_block_root(
        &self,
        block_root: Hash256,
        proof_types: &[ProofType],
    ) -> Vec<Arc<SignedExecutionProof>> {
        proof_types
            .iter()
            .filter_map(|proof_type| {
                self.execution_proof_by_block_root_and_type(block_root, *proof_type)
            })
            .collect()
    }

    pub fn execution_proofs_by_range(
        &self,
        start_slot: Slot,
        count: u64,
        proof_types: &[ProofType],
    ) -> Result<Vec<Arc<SignedExecutionProof>>, BeaconChainError> {
        let mut proofs = vec![];
        for offset in 0..count {
            let Some(slot) = start_slot.as_u64().checked_add(offset).map(Slot::new) else {
                break;
            };
            let Some(block_root) = self.block_root_at_slot(slot, crate::WhenSlotSkipped::None)?
            else {
                continue;
            };
            proofs.extend(self.execution_proofs_by_block_root(block_root, proof_types));
        }
        Ok(proofs)
    }

    pub fn missing_execution_proofs(
        &self,
        proof_types: &[ProofType],
    ) -> Vec<MissingExecutionProofInfo> {
        self.register_execution_proof_request_window();
        self.execution_proof_statuses
            .read()
            .missing_execution_proofs(proof_types)
    }

    pub fn latest_execution_proof_status(
        &self,
        proof_types: &[ProofType],
    ) -> Option<ExecutionProofBlockStatus> {
        self.execution_proof_statuses
            .read()
            .latest_status_with_valid_proofs(proof_types)
    }

    fn register_execution_proof_request_window(&self) {
        let head = self.canonical_head.cached_head();
        let start_slot = head
            .finalized_checkpoint()
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());
        let end_slot = head.head_slot();

        for slot in start_slot.as_u64()..=end_slot.as_u64() {
            let slot = Slot::new(slot);
            let Ok(Some(block_root)) = self.block_root_at_slot(slot, crate::WhenSlotSkipped::None)
            else {
                continue;
            };

            if self
                .execution_proof_statuses
                .read()
                .request_root_for_block_root(&block_root)
                .is_some()
            {
                continue;
            }

            let Ok((request_root, request_slot)) =
                self.execution_payload_request_context(block_root)
            else {
                continue;
            };

            self.execution_proof_statuses.write().register_request_root(
                block_root,
                request_root,
                request_slot,
            );
        }
    }
}

fn build_gloas_new_payload_request<'a, E: types::EthSpec>(
    block: &'a SignedBlindedBeaconBlock<E>,
    envelope: &'a SignedExecutionPayloadEnvelope<E>,
) -> Result<NewPayloadRequest<'a, E>, BeaconChainError> {
    let bid = &block
        .message()
        .body()
        .signed_execution_payload_bid()
        .map_err(BeaconChainError::BeaconStateError)?
        .message;

    let versioned_hashes = bid
        .blob_kzg_commitments
        .iter()
        .map(kzg_commitment_to_versioned_hash)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(BeaconChainError::SszTypesError)?;

    Ok(NewPayloadRequest::Gloas(NewPayloadRequestGloas {
        execution_payload: &envelope.message.payload,
        versioned_hashes,
        parent_beacon_block_root: envelope.message.parent_beacon_block_root,
        execution_requests: &envelope.message.execution_requests,
    }))
}

fn map_fork_choice_error(error: ForkChoiceError) -> BeaconChainError {
    BeaconChainError::ForkChoiceError(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::SignatureBytes;
    use ssz_types::VariableList;
    use types::{ExecutionProof, PublicInput};

    fn signed_proof(request_root: Hash256, proof_type: ProofType) -> Arc<SignedExecutionProof> {
        Arc::new(SignedExecutionProof {
            message: ExecutionProof {
                proof_data: VariableList::new(vec![proof_type]).unwrap(),
                proof_type,
                public_input: PublicInput {
                    new_payload_request_root: request_root,
                },
            },
            validator_index: 0,
            signature: SignatureBytes::empty(),
        })
    }

    #[test]
    fn latest_status_with_valid_proofs_ignores_empty_and_unconfigured_statuses() {
        let mut cache = ExecutionProofStatusCache::default();
        let block_root_a = Hash256::repeat_byte(0xaa);
        let block_root_b = Hash256::repeat_byte(0xbb);
        let block_root_c = Hash256::repeat_byte(0xcc);
        let request_root_a = Hash256::repeat_byte(0x0a);
        let request_root_b = Hash256::repeat_byte(0x0b);
        let request_root_c = Hash256::repeat_byte(0x0c);

        cache.register_request_root(block_root_c, request_root_c, Slot::new(30));
        assert!(
            cache.latest_status_with_valid_proofs(&[1]).is_none(),
            "request-root-only statuses must not advertise proof availability"
        );

        cache.observe_valid_proof(
            block_root_a,
            request_root_a,
            Slot::new(10),
            signed_proof(request_root_a, 1),
        );
        cache.observe_valid_proof(
            block_root_b,
            request_root_b,
            Slot::new(20),
            signed_proof(request_root_b, 2),
        );

        let status = cache
            .latest_status_with_valid_proofs(&[1])
            .expect("configured proof type should be advertised");
        assert_eq!(status.block_root, block_root_a);
        assert_eq!(status.slot, Slot::new(10));
        assert_eq!(status.valid_proof_types().collect::<Vec<_>>(), vec![1]);

        assert!(
            cache.latest_status_with_valid_proofs(&[3]).is_none(),
            "unconfigured proof types must not make a peer look useful"
        );
    }
}

use super::Error;
use crate::beacon_chain::BeaconStore;
use crate::canonical_head::CanonicalHead;
use crate::execution_proof_verification::observed_execution_proofs::{
    ObservedExecutionProofs, ProofObservation,
};
use crate::shuffling_cache::{ShufflingCache, with_cached_shuffling};
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use parking_lot::RwLock;
use proof_engine::{ProofEngine, ProofVerificationOutcome};
use state_processing::builder_deposits_cache::OnboardBuildersCache;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::execution::{
    ExecutionProof, ExecutionProofEnvelope, PublicInput, SSZNewPayloadRequest,
    STATELESS_INPUT_SCHEMA_ID, SignedExecutionProofEnvelope, VersionedHashes,
    is_supported_proof_type,
};
use types::{
    ChainSpec, Domain, EthSpec, Hash256, SignedBlindedBeaconBlock, SignedExecutionPayloadEnvelope,
    SignedRoot, Slot, kzg_ext::ProgressiveKzgCommitments,
};

pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    pub canonical_head: &'a CanonicalHead<T>,
    pub observed_execution_proofs: &'a RwLock<ObservedExecutionProofs>,
    pub validator_pubkey_cache: &'a RwLock<ValidatorPubkeyCache<T>>,
    pub shuffling_cache: &'a RwLock<ShufflingCache<T::EthSpec>>,
    pub store: &'a BeaconStore<T>,
    pub proof_engine: &'a Option<Arc<ProofEngine>>,
    pub builder_onboarding_cache: Option<&'a OnboardBuildersCache>,
    pub spec: &'a ChainSpec,
    pub genesis_validators_root: Hash256,
}

/// A `SignedExecutionProofEnvelope` verified for propagation on the gossip network.
pub struct GossipVerifiedExecutionProof {
    pub proof: Arc<SignedExecutionProofEnvelope>,
    pub block_slot: Slot,
}

impl GossipVerifiedExecutionProof {
    pub async fn new<T: BeaconChainTypes>(
        proof: Arc<SignedExecutionProofEnvelope>,
        ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, Error> {
        // [REJECT] `proof_data` is non-empty. The upper bound is enforced before SSZ decoding by
        // `PubsubMessage::decode`.
        if proof.message.proof_data.is_empty() {
            return Err(Error::EmptyProofData);
        }

        let proof_root = proof.message.tree_hash_root();
        let block_root = proof.beacon_block_root();
        let proof_type = proof.proof_type();
        let validator_index = proof.validator_index;

        // [IGNORE] The referenced beacon block is known. Its slot determines the fork for the
        // signing domain.
        let proto_block = ctx
            .canonical_head
            .fork_choice_read_lock()
            .get_block(&block_root)
            .ok_or(Error::UnknownBlockRoot {
                beacon_block_root: block_root,
            })?;
        let block_slot = proto_block.slot;

        // [REJECT] The block passed consensus validation. Presence in fork choice establishes
        // this, while loading the persisted block supplies the bid committed by the proposer.
        let block = ctx
            .store
            .get_blinded_block(&block_root)
            .map_err(BeaconChainError::from)?
            .ok_or_else(|| {
                Error::BeaconChainError(Box::new(BeaconChainError::MissingBeaconBlock(block_root)))
            })?;

        // [IGNORE] The execution payload is available.
        let payload_envelope = ctx
            .store
            .get_payload_envelope(&block_root)
            .map_err(BeaconChainError::from)?
            .ok_or(Error::PayloadUnavailable {
                beacon_block_root: block_root,
            })?;

        // [IGNORE] Deduplication rules, checked before cryptographic work.
        match ctx
            .observed_execution_proofs
            .read()
            .check(
                proof_root,
                block_root,
                proof_type,
                validator_index,
                block_slot,
            )
            .map_err(Error::from)?
        {
            ProofObservation::ProofAlreadySeen => return Err(Error::ProofAlreadySeen),
            ProofObservation::ValidProofAlreadyKnown => return Err(Error::ValidProofAlreadyKnown),
            ProofObservation::DuplicateFromValidator => {
                return Err(Error::DuplicateFromValidator { validator_index });
            }
            ProofObservation::New => {}
        }

        // [REJECT] The proof envelope is structurally valid.
        if !is_supported_proof_type(proof_type) {
            return Err(Error::UnsupportedProofType { proof_type });
        }
        if payload_envelope.beacon_block_root() != block_root {
            return Err(Error::PayloadBlockRootMismatch {
                expected: block_root,
                actual: payload_envelope.beacon_block_root(),
            });
        }

        // [REJECT] The validator is active at the epoch of the referenced block. The committee
        // cache is keyed by the block's shuffling id, so proofs for blocks on non-canonical
        // forks are judged against their own fork's active set without loading a state.
        let block_epoch = block_slot.epoch(T::EthSpec::slots_per_epoch());
        let is_active = with_cached_shuffling(
            ctx.canonical_head,
            ctx.shuffling_cache,
            ctx.store,
            ctx.builder_onboarding_cache,
            ctx.spec,
            block_root,
            block_epoch,
            |cached_shuffling, _| {
                Ok::<_, Error>(
                    cached_shuffling
                        .committee_cache
                        .shuffled_position(validator_index as usize)
                        .is_some(),
                )
            },
        )?;
        if !is_active {
            return Err(Error::ValidatorNotActive { validator_index });
        }

        // [REJECT] The signature is valid with respect to the validator's public key.
        let fork_name = ctx.spec.fork_name_at_slot::<T::EthSpec>(block_slot);
        let domain = ctx.spec.compute_domain(
            Domain::ExecutionProof,
            ctx.spec.fork_version_for_name(fork_name),
            ctx.genesis_validators_root,
        );
        let signing_root = proof.message.signing_root(domain);
        {
            let pubkey_cache = ctx.validator_pubkey_cache.read();
            let pubkey = pubkey_cache
                .get(validator_index as usize)
                .ok_or(Error::UnknownValidatorIndex(validator_index))?;
            if !proof.signature.verify(pubkey, signing_root) {
                return Err(Error::InvalidSignature);
            }
        }

        // Only record the validator's attempt after the signature binds `validator_index`;
        // recording earlier would let unauthenticated messages suppress honest provers.
        if !ctx
            .observed_execution_proofs
            .write()
            .observe_signature_verified_proof(
                proof_root,
                block_root,
                proof_type,
                validator_index,
                block_slot,
            )
            .map_err(Error::from)?
        {
            // Lost a race against a concurrent copy of the same proof.
            return Err(Error::ProofAlreadySeen);
        }

        // [REJECT] The proof verifies via the proof engine.
        //
        // Proof verification is a fast crypto check against a localhost sidecar (and may be
        // embedded in-process in the future), so awaiting it here does not hold up the processor
        // significantly.
        let proof_engine = ctx.proof_engine.as_ref().ok_or(Error::ProofEngineMissing)?;
        let execution_proof =
            reconstruct_execution_proof(&proof.message, &payload_envelope, &block, ctx.spec)?;
        match proof_engine
            .verify_execution_proof(&execution_proof)
            .await
            .map_err(Error::ProofEngine)?
        {
            ProofVerificationOutcome::Invalid => return Err(Error::InvalidProof),
            ProofVerificationOutcome::Valid => {}
        }

        ctx.observed_execution_proofs
            .write()
            .observe_valid_proof(block_root, Arc::clone(&proof));
        Ok(Self { proof, block_slot })
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn execution_proof_gossip_verification_context(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            canonical_head: &self.canonical_head,
            observed_execution_proofs: &self.observed_execution_proofs,
            validator_pubkey_cache: &self.validator_pubkey_cache,
            shuffling_cache: &self.shuffling_cache,
            store: &self.store,
            proof_engine: &self.proof_engine,
            builder_onboarding_cache: self.builder_onboarding_cache.as_deref(),
            spec: &self.spec,
            genesis_validators_root: self.genesis_validators_root,
        }
    }

    pub async fn verify_execution_proof_for_gossip(
        &self,
        proof: Arc<SignedExecutionProofEnvelope>,
    ) -> Result<GossipVerifiedExecutionProof, Error> {
        GossipVerifiedExecutionProof::new(
            proof,
            &self.execution_proof_gossip_verification_context(),
        )
        .await
    }
}

fn reconstruct_execution_proof<E: EthSpec>(
    proof_envelope: &ExecutionProofEnvelope,
    payload_envelope: &SignedExecutionPayloadEnvelope<E>,
    block: &SignedBlindedBeaconBlock<E>,
    spec: &ChainSpec,
) -> Result<ExecutionProof, Error> {
    let bid = &block
        .message()
        .body()
        .signed_execution_payload_bid()
        .map_err(BeaconChainError::from)?
        .message;
    let new_payload_request =
        build_ssz_new_payload_request(payload_envelope, &bid.blob_kzg_commitments)?;
    let public_input = PublicInput {
        new_payload_request_root: new_payload_request.tree_hash_root(),
        successful_validation: true,
        chain_id: spec.deposit_chain_id,
        schema_id: STATELESS_INPUT_SCHEMA_ID,
    };

    Ok(ExecutionProof {
        proof_data: proof_envelope.proof_data.clone(),
        proof_type: proof_envelope.proof_type,
        public_input,
    })
}

fn build_ssz_new_payload_request<E: EthSpec>(
    payload_envelope: &SignedExecutionPayloadEnvelope<E>,
    blob_kzg_commitments: &ProgressiveKzgCommitments,
) -> Result<SSZNewPayloadRequest<E>, Error> {
    let versioned_hashes = blob_kzg_commitments
        .iter()
        .map(kzg_commitment_to_versioned_hash)
        .collect();
    let versioned_hashes =
        VersionedHashes::<E>::new(versioned_hashes).map_err(BeaconChainError::from)?;
    Ok(SSZNewPayloadRequest {
        execution_payload: payload_envelope.message.payload.clone(),
        versioned_hashes,
        parent_beacon_block_root: payload_envelope.message.parent_beacon_block_root,
        execution_requests: payload_envelope.message.execution_requests.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::Signature;
    use types::{
        ExecutionPayloadEnvelope, MinimalEthSpec,
        kzg_ext::{KzgCommitment, ProgressiveKzgCommitments},
    };

    #[test]
    fn builds_spec_new_payload_request_from_accepted_envelope() {
        let payload_envelope = SignedExecutionPayloadEnvelope {
            message: ExecutionPayloadEnvelope::<MinimalEthSpec>::empty(),
            signature: Signature::empty(),
        };
        let commitment = KzgCommitment::empty_for_testing();
        let commitments = ProgressiveKzgCommitments::new(vec![commitment.clone()]);

        let request =
            build_ssz_new_payload_request(&payload_envelope, &commitments).expect("valid request");

        assert_eq!(request.execution_payload, payload_envelope.message.payload);
        assert_eq!(
            &request.versioned_hashes[..],
            &[kzg_commitment_to_versioned_hash(&commitment)]
        );
        assert_eq!(
            request.parent_beacon_block_root,
            payload_envelope.message.parent_beacon_block_root
        );
        assert_eq!(
            request.execution_requests,
            payload_envelope.message.execution_requests
        );
    }
}

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
use ssz_types::VariableList;
use state_processing::builder_deposits_cache::OnboardBuildersCache;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::execution::{
    ExecutionProof, ExecutionProofEnvelope, PublicInput, SSZNewPayloadRequest,
    STATELESS_INPUT_SCHEMA_ID, SignedExecutionProofEnvelope, is_supported_proof_type,
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
        // [REJECT] `proof.proof_data` is non-empty. The `MAX_PROOF_SIZE` upper bound is enforced
        // structurally by the SSZ type at decode.
        if proof.message.proof_data.is_empty() {
            return Err(Error::EmptyProofData);
        }

        let block_root = proof.beacon_block_root();
        let proof_type = proof.proof_type();
        let validator_index = proof.validator_index;

        // [REJECT] The proof type is supported.
        if !is_supported_proof_type(proof_type) {
            return Err(Error::UnsupportedProofType { proof_type });
        }

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

        // [IGNORE] No valid proof is known for this beacon block and proof type. Check this before
        // hashing the proof data.
        if ctx
            .observed_execution_proofs
            .read()
            .has_valid_proof(block_root, proof_type, block_slot)
            .map_err(Error::from)?
        {
            return Err(Error::ValidProofAlreadyKnown);
        }

        let proof_root = proof.message.tree_hash_root();

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

        // [IGNORE] The execution payload is available. Delay this database read until after the
        // cheap message-local and deduplication checks.
        let payload_envelope = ctx
            .store
            .get_payload_envelope(&block_root)
            .map_err(BeaconChainError::from)?
            .ok_or(Error::PayloadUnavailable {
                beacon_block_root: block_root,
            })?;

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

        // [REJECT] The proof verifies via the proof engine.
        //
        // Proof verification is a fast crypto check against a localhost sidecar (and may be
        // embedded in-process in the future), so awaiting it here does not hold up the processor
        // significantly.
        let proof_engine = ctx.proof_engine.as_ref().ok_or(Error::ProofEngineMissing)?;
        let block = ctx
            .store
            .get_blinded_block(&block_root)
            .map_err(BeaconChainError::from)?
            .ok_or_else(|| {
                Error::BeaconChainError(Box::new(BeaconChainError::MissingBeaconBlock(block_root)))
            })?;
        let execution_proof =
            reconstruct_execution_proof(&proof.message, &payload_envelope, &block, ctx.spec)?;
        let verification_outcome = proof_engine
            .verify_execution_proof(&execution_proof)
            .await
            .map_err(Error::ProofEngine)?;

        // Only record the authenticated proof and prover after the proof engine returns a
        // definitive result. Local setup and proof engine communication failures remain retryable.
        let mut observed_execution_proofs = ctx.observed_execution_proofs.write();
        if !observed_execution_proofs
            .observe_processed_proof(
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

        match verification_outcome {
            ProofVerificationOutcome::Invalid => return Err(Error::InvalidProof),
            ProofVerificationOutcome::Valid => {}
        }

        observed_execution_proofs.observe_valid_proof(block_root, proof_type);
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
    let versioned_hashes = VariableList::new(versioned_hashes).map_err(BeaconChainError::from)?;
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
    use crate::test_utils::BeaconChainHarness;
    use bls::Signature;
    use types::{
        ExecutionPayloadEnvelope, MinimalEthSpec,
        execution::{ProofData, SUPPORTED_PROOF_TYPES},
        kzg_ext::{KzgCommitment, ProgressiveKzgCommitments},
    };

    type E = MinimalEthSpec;
    fn execution_proof(
        beacon_block_root: Hash256,
        proof_type: u8,
        proof_data: Vec<u8>,
        validator_index: u64,
    ) -> SignedExecutionProofEnvelope {
        SignedExecutionProofEnvelope {
            message: ExecutionProofEnvelope {
                proof_data: ProofData::new(proof_data).expect("valid proof data"),
                proof_type,
                beacon_block_root,
            },
            validator_index,
            signature: Signature::empty(),
        }
    }

    #[tokio::test]
    async fn applies_cheap_checks_before_payload_lookup() {
        let harness = BeaconChainHarness::builder(E::default())
            .default_spec()
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();
        let chain = &harness.chain;
        let genesis_root = chain.genesis_block_root;

        assert!(
            chain
                .store
                .get_payload_envelope(&genesis_root)
                .expect("payload lookup succeeds")
                .is_none(),
            "test requires a known block without a stored payload envelope"
        );

        let unknown_root = Hash256::repeat_byte(0xaa);
        let empty_proof = execution_proof(unknown_root, SUPPORTED_PROOF_TYPES[0], vec![], 0);
        assert!(matches!(
            chain
                .verify_execution_proof_for_gossip(Arc::new(empty_proof))
                .await,
            Err(Error::EmptyProofData)
        ));

        let unsupported_proof = execution_proof(unknown_root, 0, vec![1], 0);
        assert!(matches!(
            chain
                .verify_execution_proof_for_gossip(Arc::new(unsupported_proof))
                .await,
            Err(Error::UnsupportedProofType { proof_type: 0 })
        ));

        let proof_type = SUPPORTED_PROOF_TYPES[0];
        let exact_proof = execution_proof(genesis_root, proof_type, vec![1], 0);
        assert!(
            chain
                .observed_execution_proofs
                .write()
                .observe_processed_proof(
                    exact_proof.message.tree_hash_root(),
                    genesis_root,
                    proof_type,
                    exact_proof.validator_index,
                    Slot::new(0),
                )
                .expect("proof observation succeeds")
        );
        assert!(matches!(
            chain
                .verify_execution_proof_for_gossip(Arc::new(exact_proof))
                .await,
            Err(Error::ProofAlreadySeen)
        ));

        chain
            .observed_execution_proofs
            .write()
            .observe_valid_proof(genesis_root, proof_type);
        let proof_for_known_type = execution_proof(genesis_root, proof_type, vec![1], 0);
        assert!(matches!(
            chain
                .verify_execution_proof_for_gossip(Arc::new(proof_for_known_type))
                .await,
            Err(Error::ValidProofAlreadyKnown)
        ));

        let second_proof_type = SUPPORTED_PROOF_TYPES[1];
        let prior_proof = execution_proof(genesis_root, second_proof_type, vec![3], 0);
        assert!(
            chain
                .observed_execution_proofs
                .write()
                .observe_processed_proof(
                    prior_proof.message.tree_hash_root(),
                    genesis_root,
                    second_proof_type,
                    prior_proof.validator_index,
                    Slot::new(0),
                )
                .expect("proof observation succeeds")
        );
        let duplicate_prover = execution_proof(genesis_root, second_proof_type, vec![4], 0);
        assert!(matches!(
            chain
                .verify_execution_proof_for_gossip(Arc::new(duplicate_prover))
                .await,
            Err(Error::DuplicateFromValidator { validator_index: 0 })
        ));

        let payload_unavailable = execution_proof(genesis_root, second_proof_type, vec![5], 1);
        assert!(matches!(
            chain
                .verify_execution_proof_for_gossip(Arc::new(payload_unavailable))
                .await,
            Err(Error::PayloadUnavailable {
                beacon_block_root
            }) if beacon_block_root == genesis_root
        ));
    }

    #[test]
    fn builds_spec_new_payload_request_from_accepted_envelope() {
        let payload_envelope = SignedExecutionPayloadEnvelope {
            message: ExecutionPayloadEnvelope::<MinimalEthSpec>::empty(),
            signature: Signature::empty(),
        };
        let commitment = KzgCommitment::empty_for_testing();
        let commitments = ProgressiveKzgCommitments::new(vec![commitment]);

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

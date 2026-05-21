//! Deduplication cache for execution proofs received via gossip.
//!
//! Implements gossip IGNORE rules from the EIP-8025 p2p-interface spec:
//! - IGNORE-2: No valid proof already received for `(request_root, proof_type)`
//! - IGNORE-3: First proof from validator for `(request_root, proof_type, validator_index)`
//!
//! Request-root scoped entries are evicted at finalization: proofs for finalized blocks are
//! irrelevant. Invalid proof-data entries are process-local and retained until restart.

use std::collections::{HashMap, HashSet};
use tree_hash::TreeHash;
use types::execution::eip8025::ProofData;
use types::{Hash256, ProofType, Slot};

/// Gossip deduplication cache for execution proofs.
///
/// Checked *before* BLS/proof-engine verification to avoid redundant work.
#[derive(Debug, Default)]
pub struct ObservedExecutionProofs {
    /// Tracks `(request_root, proof_type)` pairs for which we already have a *valid* proof.
    /// Used to implement IGNORE-2.
    valid_proofs: HashMap<(Hash256, ProofType), ()>,

    /// Tracks `(request_root, proof_type, validator_index)` triples we have already attempted
    /// to verify (regardless of outcome). Used to implement IGNORE-3.
    seen_from_validator: HashSet<(Hash256, ProofType, u64)>,

    /// Tracks `(proof_type, hash_tree_root(proof_data))` pairs for proofs already rejected by the
    /// proof engine.
    invalid_proofs: HashSet<(ProofType, Hash256)>,

    /// Maps slot → set of request roots observed at that slot. Populated when a valid/accepted
    /// proof is observed. Used to prune `valid_proofs` and `seen_from_validator` at finalization.
    slot_to_request_roots: HashMap<Slot, HashSet<Hash256>>,
}

/// Result of checking the dedup cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofObservation {
    /// We already rejected this `(proof_type, proof_data)` pair.
    AlreadyRejectedProof,
    /// We already have a valid proof for this `(request_root, proof_type)` — IGNORE-2.
    AlreadyHaveValidProof,
    /// We already saw a proof from this validator for this `(request_root, proof_type)` — IGNORE-3.
    DuplicateFromValidator,
    /// First time seeing this proof — proceed with verification.
    New,
}

impl ObservedExecutionProofs {
    /// Check whether a proof should be processed or ignored based on the dedup rules.
    ///
    /// This does *not* insert the proof into the cache; call [`observe_verification_attempt`]
    /// and then [`observe_invalid_proof`] or [`observe_valid_proof`] after verification completes.
    pub fn check(
        &self,
        request_root: Hash256,
        proof_type: ProofType,
        proof_data: &ProofData,
        validator_index: u64,
    ) -> ProofObservation {
        // IGNORE-2: already have a valid proof for this (root, type)
        if self.valid_proofs.contains_key(&(request_root, proof_type)) {
            return ProofObservation::AlreadyHaveValidProof;
        }

        // IGNORE-3: already saw a proof from this validator for this (root, type)
        if self
            .seen_from_validator
            .contains(&(request_root, proof_type, validator_index))
        {
            return ProofObservation::DuplicateFromValidator;
        }

        if self
            .invalid_proofs
            .contains(&(proof_type, proof_data.tree_hash_root()))
        {
            return ProofObservation::AlreadyRejectedProof;
        }

        ProofObservation::New
    }

    /// Record that we attempted to verify a proof from this validator.
    /// Must be called for every verification attempt, regardless of outcome.
    pub fn observe_verification_attempt(
        &mut self,
        request_root: Hash256,
        proof_type: ProofType,
        validator_index: u64,
    ) {
        self.seen_from_validator
            .insert((request_root, proof_type, validator_index));
    }

    /// Record that the proof engine rejected this `(proof_type, proof_data)` pair.
    /// Returns `true` if this is the first rejection recorded for the pair.
    pub fn observe_invalid_proof(&mut self, proof_type: ProofType, proof_data: &ProofData) -> bool {
        self.invalid_proofs
            .insert((proof_type, proof_data.tree_hash_root()))
    }

    /// Record that a valid proof was received for `(request_root, proof_type)` at `slot`.
    pub fn observe_valid_proof(
        &mut self,
        request_root: Hash256,
        proof_type: ProofType,
        slot: Slot,
    ) {
        self.valid_proofs.insert((request_root, proof_type), ());
        self.slot_to_request_roots
            .entry(slot)
            .or_default()
            .insert(request_root);
    }

    /// Prune entries for request roots whose slot is at or below `finalized_slot`.
    ///
    /// Call at finalization. Any proof for a finalized block will never need dedup again.
    /// Entries in `seen_from_validator` without a known slot (e.g. for proofs that failed
    /// BLS or engine verification) are retained until restart.
    pub fn prune(&mut self, finalized_slot: Slot) {
        let pruned_roots: HashSet<Hash256> = self
            .slot_to_request_roots
            .extract_if(|&slot, _| slot <= finalized_slot)
            .flat_map(|(_, roots)| roots)
            .collect();
        self.valid_proofs
            .retain(|(root, _), _| !pruned_roots.contains(root));
        self.seen_from_validator
            .retain(|(root, _, _)| !pruned_roots.contains(root));
    }

    /// Number of valid-proof entries (for metrics / tests).
    pub fn valid_proof_count(&self) -> usize {
        self.valid_proofs.len()
    }

    /// Number of seen-from-validator entries (for metrics / tests).
    pub fn seen_from_validator_count(&self) -> usize {
        self.seen_from_validator.len()
    }

    /// Number of invalid proof-data entries (for metrics / tests).
    pub fn invalid_proof_count(&self) -> usize {
        self.invalid_proofs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proof_data(bytes: &[u8]) -> ProofData {
        ProofData::new(bytes.to_vec()).expect("proof data should fit")
    }

    #[test]
    fn new_proof_is_observed() {
        let cache = ObservedExecutionProofs::default();
        let root = Hash256::repeat_byte(0x01);
        let proof_data = make_proof_data(&[1, 2, 3]);
        assert_eq!(cache.check(root, 1, &proof_data, 42), ProofObservation::New);
    }

    #[test]
    fn ignore_2_valid_proof_dedup() {
        let mut cache = ObservedExecutionProofs::default();
        let root = Hash256::repeat_byte(0x01);
        let proof_data = make_proof_data(&[1, 2, 3]);

        cache.observe_valid_proof(root, 1, Slot::new(1));

        // Same (root, type) from a different validator → still IGNORE
        assert_eq!(
            cache.check(root, 1, &proof_data, 99),
            ProofObservation::AlreadyHaveValidProof
        );

        // Different type → New
        assert_eq!(cache.check(root, 2, &proof_data, 99), ProofObservation::New);
    }

    #[test]
    fn invalid_proof_data_dedup_uses_type_and_data_root() {
        let mut cache = ObservedExecutionProofs::default();
        let root = Hash256::repeat_byte(0x01);
        let other_root = Hash256::repeat_byte(0x02);
        let proof_data = make_proof_data(&[1, 2, 3]);
        let other_proof_data = make_proof_data(&[4, 5, 6]);

        assert!(cache.observe_invalid_proof(1, &proof_data));
        assert!(!cache.observe_invalid_proof(1, &proof_data));

        assert_eq!(
            cache.check(other_root, 1, &proof_data, 99),
            ProofObservation::AlreadyRejectedProof
        );

        // Same proof data with a different type is a distinct cache key.
        assert_eq!(cache.check(root, 2, &proof_data, 42), ProofObservation::New);

        // Same type with different proof data is a distinct cache key.
        assert_eq!(
            cache.check(root, 1, &other_proof_data, 42),
            ProofObservation::New
        );

        assert_eq!(cache.invalid_proof_count(), 1);
    }

    #[test]
    fn cheap_dedup_checks_precede_invalid_proof_data_rooting() {
        let mut cache = ObservedExecutionProofs::default();
        let root = Hash256::repeat_byte(0x01);
        let proof_data = make_proof_data(&[1, 2, 3]);

        cache.observe_valid_proof(root, 1, Slot::new(1));
        cache.observe_invalid_proof(1, &proof_data);

        assert_eq!(
            cache.check(root, 1, &proof_data, 42),
            ProofObservation::AlreadyHaveValidProof
        );

        let other_root = Hash256::repeat_byte(0x02);
        cache.observe_verification_attempt(other_root, 1, 42);

        assert_eq!(
            cache.check(other_root, 1, &proof_data, 42),
            ProofObservation::DuplicateFromValidator
        );
    }

    #[test]
    fn ignore_3_validator_dedup() {
        let mut cache = ObservedExecutionProofs::default();
        let root = Hash256::repeat_byte(0x01);
        let proof_data = make_proof_data(&[1, 2, 3]);

        cache.observe_verification_attempt(root, 1, 42);

        assert_eq!(
            cache.check(root, 1, &proof_data, 42),
            ProofObservation::DuplicateFromValidator
        );

        // Same validator, different type → New
        assert_eq!(cache.check(root, 2, &proof_data, 42), ProofObservation::New);

        // Different validator, same type → New
        assert_eq!(cache.check(root, 1, &proof_data, 43), ProofObservation::New);
    }

    #[test]
    fn prune_removes_finalized_roots() {
        let mut cache = ObservedExecutionProofs::default();
        let root_a = Hash256::repeat_byte(0x01);
        let root_b = Hash256::repeat_byte(0x02);
        let proof_data = make_proof_data(&[1, 2, 3]);

        // root_a at slot 10 (will be finalized), root_b at slot 20 (will be retained).
        cache.observe_valid_proof(root_a, 1, Slot::new(10));
        cache.observe_valid_proof(root_b, 1, Slot::new(20));
        cache.observe_verification_attempt(root_a, 1, 42);
        cache.observe_verification_attempt(root_b, 1, 43);

        cache.prune(Slot::new(15));

        assert_eq!(cache.valid_proof_count(), 1);
        assert_eq!(cache.seen_from_validator_count(), 1);
        // root_b still tracked
        assert_eq!(
            cache.check(root_b, 1, &proof_data, 99),
            ProofObservation::AlreadyHaveValidProof
        );
        // root_a gone → New
        assert_eq!(
            cache.check(root_a, 1, &proof_data, 42),
            ProofObservation::New
        );
    }
}

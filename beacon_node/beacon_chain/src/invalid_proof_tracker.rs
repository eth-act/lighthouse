//! Persistent tracker for validators that sign invalid execution proofs.
//!
//! When `ProofStatus::Invalid` is returned for a BLS-valid proof, the signing validator is
//! recorded here. Future proofs from banned validators are ignored without wasting
//! verification resources.
//!
//! Design decisions:
//! - Ban threshold: 1 (a single signed invalid proof is sufficient)
//! - Ban scope: all proof types from the banned validator

use bls::PublicKeyBytes;
use ssz::{Decode, Encode};
use ssz_derive::{Decode as DeriveDecode, Encode as DeriveEncode};
use std::collections::HashSet;
use std::sync::Arc;
use store::{DBColumn, Error as StoreError, HotColdDB, ItemStore, StoreItem};
use types::{EthSpec, Hash256};

/// 32-byte key for accessing the persisted tracker. All zero because the column acts as namespace.
pub const INVALID_PROOF_TRACKER_DB_KEY: Hash256 = Hash256::ZERO;

/// Tracks validators that have signed invalid execution proofs.
///
/// The in-memory set is the source of truth during operation. Changes are persisted
/// to `HotColdDB` so bans survive restarts.
///
/// Validators are identified by their public key (48-byte compressed BLS key).
#[derive(Debug, Default)]
pub struct InvalidProofTracker {
    /// Set of validator public keys that are banned (signed at least one invalid proof).
    banned_validators: HashSet<PublicKeyBytes>,
}

/// Information recorded when a validator is banned.
#[derive(Debug, Clone)]
pub struct InvalidProofRecord {
    pub validator_pubkey: PublicKeyBytes,
    pub request_root: Hash256,
    pub proof_type: u8,
}

/// SSZ-serializable wrapper for persisting the banned validator set.
///
/// Each entry is a 48-byte compressed BLS public key, serialised as a flat `Vec<Vec<u8>>`.
/// We store the keys as raw byte vectors because `PublicKeyBytes` is a fixed-size 48-byte
/// array that SSZ-encodes as a fixed-length container, and wrapping in `Vec<u8>` gives us
/// a straightforward variable-length list for the outer container.
#[derive(Debug, Clone, DeriveEncode, DeriveDecode)]
struct PersistedInvalidProofTracker {
    /// Sorted list of banned validator public keys (each 48 bytes).
    banned_validators: Vec<Vec<u8>>,
}

impl StoreItem for PersistedInvalidProofTracker {
    fn db_column() -> DBColumn {
        DBColumn::InvalidProofTracker
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}

impl InvalidProofTracker {
    /// Load a tracker from the database. Returns `Default` if no persisted state exists.
    pub fn load_from_store<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
        store: &Arc<HotColdDB<E, Hot, Cold>>,
    ) -> Self {
        match store.get_item::<PersistedInvalidProofTracker>(&INVALID_PROOF_TRACKER_DB_KEY) {
            Ok(Some(persisted)) => {
                let banned_validators: HashSet<PublicKeyBytes> = persisted
                    .banned_validators
                    .into_iter()
                    .filter_map(|bytes| {
                        PublicKeyBytes::deserialize(&bytes)
                            .map_err(|e| {
                                tracing::warn!(
                                    error = ?e,
                                    "Skipping invalid pubkey bytes in persisted tracker"
                                );
                                e
                            })
                            .ok()
                    })
                    .collect();
                let count = banned_validators.len();
                if count > 0 {
                    tracing::info!(
                        count,
                        "Loaded invalid proof tracker from disk — {} validators banned",
                        count,
                    );
                }
                InvalidProofTracker { banned_validators }
            }
            Ok(None) => {
                tracing::debug!("No persisted invalid proof tracker found, starting fresh");
                InvalidProofTracker::default()
            }
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "Failed to load invalid proof tracker from disk, starting fresh"
                );
                InvalidProofTracker::default()
            }
        }
    }

    /// Persist the current state to the database.
    pub fn persist_to_store<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
        &self,
        store: &Arc<HotColdDB<E, Hot, Cold>>,
    ) -> Result<(), StoreError> {
        let mut sorted: Vec<Vec<u8>> = self
            .banned_validators
            .iter()
            .map(|pk| pk.serialize().to_vec())
            .collect();
        sorted.sort_unstable();
        let persisted = PersistedInvalidProofTracker {
            banned_validators: sorted,
        };
        store.put_item(&INVALID_PROOF_TRACKER_DB_KEY, &persisted)
    }

    /// Check whether a validator is banned.
    pub fn is_banned(&self, validator_pubkey: &PublicKeyBytes) -> bool {
        self.banned_validators.contains(validator_pubkey)
    }

    /// Record that a validator signed an invalid proof. Returns `true` if this is a new ban.
    ///
    /// Note: The caller is responsible for calling `persist_to_store` after this method
    /// to ensure the ban survives restarts.
    pub fn record_invalid_proof(&mut self, record: InvalidProofRecord) -> bool {
        let is_new = self.banned_validators.insert(record.validator_pubkey);
        if is_new {
            tracing::warn!(
                validator_pubkey = ?record.validator_pubkey,
                ?record.request_root,
                proof_type = record.proof_type,
                "Banning validator for signing invalid execution proof"
            );
        }
        is_new
    }

    /// Unban a specific validator.
    ///
    /// Note: The caller is responsible for calling `persist_to_store` after this method.
    pub fn unban(&mut self, validator_pubkey: &PublicKeyBytes) -> bool {
        self.banned_validators.remove(validator_pubkey)
    }

    /// Clear all bans.
    ///
    /// Note: The caller is responsible for calling `persist_to_store` after this method.
    pub fn clear(&mut self) {
        self.banned_validators.clear();
    }

    /// Number of banned validators (for metrics / tests).
    pub fn banned_count(&self) -> usize {
        self.banned_validators.len()
    }

    /// List all banned validator public keys.
    pub fn banned_validators(&self) -> impl Iterator<Item = &PublicKeyBytes> + '_ {
        self.banned_validators.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a deterministic pubkey from a seed index using the standard test utility.
    fn test_pubkey(index: usize) -> PublicKeyBytes {
        types::test_utils::generate_deterministic_keypair(index)
            .pk
            .compress()
    }

    fn make_record(seed: usize) -> InvalidProofRecord {
        InvalidProofRecord {
            validator_pubkey: test_pubkey(seed),
            request_root: Hash256::repeat_byte(0x01),
            proof_type: 1,
        }
    }

    #[test]
    fn ban_on_first_invalid_proof() {
        let mut tracker = InvalidProofTracker::default();
        let pk = test_pubkey(42);
        assert!(!tracker.is_banned(&pk));

        let is_new = tracker.record_invalid_proof(make_record(42));
        assert!(is_new);
        assert!(tracker.is_banned(&pk));
    }

    #[test]
    fn duplicate_ban_returns_false() {
        let mut tracker = InvalidProofTracker::default();
        tracker.record_invalid_proof(make_record(42));

        let is_new = tracker.record_invalid_proof(make_record(42));
        assert!(!is_new);
        assert_eq!(tracker.banned_count(), 1);
    }

    #[test]
    fn unban_removes_validator() {
        let mut tracker = InvalidProofTracker::default();
        let pk = test_pubkey(42);
        tracker.record_invalid_proof(make_record(42));

        assert!(tracker.unban(&pk));
        assert!(!tracker.is_banned(&pk));
    }

    #[test]
    fn clear_removes_all() {
        let mut tracker = InvalidProofTracker::default();
        tracker.record_invalid_proof(make_record(1));
        tracker.record_invalid_proof(make_record(2));
        tracker.record_invalid_proof(make_record(3));

        tracker.clear();
        assert_eq!(tracker.banned_count(), 0);
    }

    #[test]
    fn ban_scope_is_all_types() {
        let mut tracker = InvalidProofTracker::default();
        let pk = test_pubkey(42);
        // Ban was recorded for proof_type=1, but ban is key-scoped, not type-scoped
        tracker.record_invalid_proof(make_record(42));
        // is_banned doesn't take proof_type — all types are banned
        assert!(tracker.is_banned(&pk));
    }

    #[test]
    fn ssz_round_trip() {
        let mut tracker = InvalidProofTracker::default();
        tracker.record_invalid_proof(make_record(10));
        tracker.record_invalid_proof(make_record(20));
        tracker.record_invalid_proof(make_record(5));

        // Serialize
        let mut sorted: Vec<Vec<u8>> = tracker
            .banned_validators()
            .map(|pk| pk.serialize().to_vec())
            .collect();
        sorted.sort_unstable();
        let persisted = PersistedInvalidProofTracker {
            banned_validators: sorted.clone(),
        };
        let bytes = persisted.as_store_bytes();

        // Deserialize
        let restored =
            PersistedInvalidProofTracker::from_store_bytes(&bytes).expect("SSZ decode failed");
        assert_eq!(restored.banned_validators, sorted);
    }

    /// Helper: create an ephemeral MemoryStore for persistence tests.
    fn open_test_store() -> Arc<
        store::HotColdDB<
            types::MinimalEthSpec,
            store::MemoryStore<types::MinimalEthSpec>,
            store::MemoryStore<types::MinimalEthSpec>,
        >,
    > {
        Arc::new(
            store::HotColdDB::open_ephemeral(
                store::config::StoreConfig::default(),
                Arc::new(types::MinimalEthSpec::default_spec()),
            )
            .expect("Failed to open ephemeral store"),
        )
    }

    #[test]
    fn empty_start_fallback() {
        // Loading from an empty store should return a default (empty) tracker.
        let store = open_test_store();
        let tracker = InvalidProofTracker::load_from_store(&store);
        assert_eq!(tracker.banned_count(), 0);
        assert!(!tracker.is_banned(&test_pubkey(1)));
    }

    #[test]
    fn persist_and_reload() {
        let store = open_test_store();

        // Ban some validators and persist.
        let mut tracker = InvalidProofTracker::default();
        tracker.record_invalid_proof(make_record(10));
        tracker.record_invalid_proof(make_record(20));
        tracker.record_invalid_proof(make_record(5));
        tracker.persist_to_store(&store).expect("Failed to persist");

        // Drop the tracker and reload from the same store — simulates restart.
        drop(tracker);
        let reloaded = InvalidProofTracker::load_from_store(&store);

        assert_eq!(reloaded.banned_count(), 3);
        assert!(reloaded.is_banned(&test_pubkey(5)));
        assert!(reloaded.is_banned(&test_pubkey(10)));
        assert!(reloaded.is_banned(&test_pubkey(20)));
        assert!(!reloaded.is_banned(&test_pubkey(99)));
    }

    #[test]
    fn persist_after_unban_survives_reload() {
        let store = open_test_store();

        // Ban two validators.
        let mut tracker = InvalidProofTracker::default();
        tracker.record_invalid_proof(make_record(10));
        tracker.record_invalid_proof(make_record(20));
        tracker.persist_to_store(&store).expect("Failed to persist");

        // Unban one and re-persist.
        tracker.unban(&test_pubkey(10));
        tracker
            .persist_to_store(&store)
            .expect("Failed to persist after unban");

        // Reload — should reflect the unban.
        let reloaded = InvalidProofTracker::load_from_store(&store);
        assert_eq!(reloaded.banned_count(), 1);
        assert!(!reloaded.is_banned(&test_pubkey(10)));
        assert!(reloaded.is_banned(&test_pubkey(20)));
    }
}

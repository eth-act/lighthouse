//! Gossip verification for the EIP-8025 `execution_proof` topic.

use crate::BeaconChainError;
use proof_engine::ProofEngineError;
use types::{Hash256, Slot};

pub mod gossip_verified_execution_proof;
pub mod observed_execution_proofs;

pub use gossip_verified_execution_proof::{
    GossipVerificationContext, GossipVerifiedExecutionProof,
};
pub use observed_execution_proofs::ObservedExecutionProofs;

use observed_execution_proofs::Error as ObservationError;

#[derive(Debug)]
pub enum Error {
    /// The proof has already been seen (IGNORE).
    ProofAlreadySeen,
    /// A valid proof for this `(block_root, proof_type)` is already known (IGNORE).
    ValidProofAlreadyKnown,
    /// This validator already submitted a proof for this `(block_root, proof_type)` (IGNORE).
    DuplicateFromValidator {
        validator_index: u64,
    },
    /// The referenced beacon block is not known to fork choice (IGNORE).
    UnknownBlockRoot {
        beacon_block_root: Hash256,
    },
    /// The referenced beacon block is already finalized (IGNORE).
    PastFinalizedSlot {
        slot: Slot,
        finalized_slot: Slot,
    },
    /// `proof_data` is empty (REJECT).
    EmptyProofData,
    /// The execution payload for the referenced block is not yet available (IGNORE).
    PayloadUnavailable {
        beacon_block_root: Hash256,
    },
    /// The validator index does not exist (REJECT).
    UnknownValidatorIndex(u64),
    /// The validator is not active at the referenced block's epoch (REJECT).
    ValidatorNotActive {
        validator_index: u64,
    },
    /// The signature is invalid (REJECT).
    InvalidSignature,
    /// The proof engine rejected the proof (REJECT).
    InvalidProof,
    /// No proof engine is configured; the node should not be subscribed to the topic.
    ProofEngineMissing,
    /// The proof engine could not complete verification (IGNORE).
    ProofEngine(ProofEngineError),
    BeaconChainError(Box<BeaconChainError>),
}

impl Error {
    /// Stable, bounded labels describing how gossip verification classified this error.
    pub const fn metric_labels(&self) -> (&'static str, &'static str) {
        match self {
            Self::ProofAlreadySeen => ("ignored", "proof_already_seen"),
            Self::ValidProofAlreadyKnown => ("ignored", "valid_proof_already_known"),
            Self::DuplicateFromValidator { .. } => ("ignored", "duplicate_from_validator"),
            Self::UnknownBlockRoot { .. } => ("ignored", "unknown_block_root"),
            Self::PastFinalizedSlot { .. } => ("ignored", "past_finalized_slot"),
            Self::PayloadUnavailable { .. } => ("ignored", "payload_unavailable"),
            Self::EmptyProofData => ("rejected", "empty_proof_data"),
            Self::UnknownValidatorIndex(_) => ("rejected", "unknown_validator_index"),
            Self::ValidatorNotActive { .. } => ("rejected", "validator_not_active"),
            Self::InvalidSignature => ("rejected", "invalid_signature"),
            Self::InvalidProof => ("rejected", "invalid_proof"),
            Self::ProofEngineMissing => ("error", "proof_engine_missing"),
            Self::ProofEngine(_) => ("error", "proof_engine"),
            Self::BeaconChainError(_) => ("error", "beacon_chain"),
        }
    }
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChainError(Box::new(e))
    }
}

impl From<ObservationError> for Error {
    fn from(e: ObservationError) -> Self {
        match e {
            ObservationError::FinalizedProof {
                slot,
                finalized_slot,
            } => Error::PastFinalizedSlot {
                slot,
                finalized_slot,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_labels_follow_gossip_classification() {
        assert_eq!(
            Error::ProofAlreadySeen.metric_labels(),
            ("ignored", "proof_already_seen")
        );
        assert_eq!(
            Error::PayloadUnavailable {
                beacon_block_root: Hash256::default(),
            }
            .metric_labels(),
            ("ignored", "payload_unavailable")
        );
        assert_eq!(
            Error::InvalidSignature.metric_labels(),
            ("rejected", "invalid_signature")
        );
        assert_eq!(
            Error::ProofEngine(ProofEngineError::ProofVerifierError("failed".to_string()))
                .metric_labels(),
            ("error", "proof_engine")
        );
        assert_eq!(
            Error::BeaconChainError(Box::new(BeaconChainError::RuntimeShutdown)).metric_labels(),
            ("error", "beacon_chain")
        );
    }
}

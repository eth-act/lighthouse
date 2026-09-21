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
    /// A stable classification of this gossip verification error.
    pub const fn outcome(&self) -> &'static str {
        match self {
            Self::ProofAlreadySeen
            | Self::ValidProofAlreadyKnown
            | Self::DuplicateFromValidator { .. }
            | Self::UnknownBlockRoot { .. }
            | Self::PastFinalizedSlot { .. }
            | Self::PayloadUnavailable { .. } => "ignored",
            Self::EmptyProofData
            | Self::UnknownValidatorIndex(_)
            | Self::ValidatorNotActive { .. }
            | Self::InvalidSignature
            | Self::InvalidProof => "rejected",
            Self::ProofEngineMissing | Self::ProofEngine(_) | Self::BeaconChainError(_) => "error",
        }
    }

    /// A stable, bounded description of this gossip verification error.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ProofAlreadySeen => "proof_already_seen",
            Self::ValidProofAlreadyKnown => "valid_proof_already_known",
            Self::DuplicateFromValidator { .. } => "duplicate_from_validator",
            Self::UnknownBlockRoot { .. } => "unknown_block_root",
            Self::PastFinalizedSlot { .. } => "past_finalized_slot",
            Self::PayloadUnavailable { .. } => "payload_unavailable",
            Self::EmptyProofData => "empty_proof_data",
            Self::UnknownValidatorIndex(_) => "unknown_validator_index",
            Self::ValidatorNotActive { .. } => "validator_not_active",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidProof => "invalid_proof",
            Self::ProofEngineMissing => "proof_engine_missing",
            Self::ProofEngine(_) => "proof_engine",
            Self::BeaconChainError(_) => "beacon_chain",
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
    fn error_metric_values_are_stable() {
        assert_eq!(Error::ProofAlreadySeen.outcome(), "ignored");
        assert_eq!(Error::InvalidSignature.outcome(), "rejected");
        assert_eq!(Error::ProofEngineMissing.outcome(), "error");

        assert_eq!(Error::ProofAlreadySeen.as_str(), "proof_already_seen");
        assert_eq!(
            Error::PayloadUnavailable {
                beacon_block_root: Hash256::default(),
            }
            .as_str(),
            "payload_unavailable"
        );
        assert_eq!(Error::InvalidSignature.as_str(), "invalid_signature");
        assert_eq!(
            Error::ProofEngine(ProofEngineError::ProofVerifierError {
                message: "failed".to_string(),
                error_type: "internal",
            })
            .as_str(),
            "proof_engine"
        );
        assert_eq!(
            Error::BeaconChainError(Box::new(BeaconChainError::RuntimeShutdown)).as_str(),
            "beacon_chain"
        );
    }
}

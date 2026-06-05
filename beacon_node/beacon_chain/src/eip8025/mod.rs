//! EIP-8025: Optional Execution Proofs
//!
//! This module provides beacon chain integration for EIP-8025 optional execution proofs.
//! It includes:
//! - Proof verification logic using validator signatures
//! - TODO: integrate into proof engine

pub mod proof_status;
pub mod proof_verification;

pub use proof_status::{
    ExecutionProofBlockStatus, ExecutionProofObservation, ExecutionProofStatusCache,
    ExecutionProofStatusSummary, MissingExecutionProofInfo,
};
pub use proof_verification::{
    ExecutionProofError, compute_execution_proof_domain, compute_signing_root,
    verify_signed_execution_proof_signature,
};

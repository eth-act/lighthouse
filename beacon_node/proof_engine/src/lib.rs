//! In-process EIP-8025 proof verification.

mod config;
#[cfg(feature = "ere-verifier")]
pub mod ere;
pub mod test_utils;

use std::fmt;
use std::sync::Arc;
use types::execution::{ExecutionProof, ProofType};

pub use config::{ExecutionProofConfig, ProofEngineConfig};

/// Errors raised while initializing or running a proof verifier.
#[derive(Debug)]
pub enum ProofEngineError {
    /// The configured proof verifier could not initialize or complete verification.
    ProofVerifierError(String),
    /// No verifier is configured for the proof's EIP-8025 proof type.
    UnconfiguredProofType(ProofType),
}

impl ProofEngineError {
    /// Stable, bounded label identifying the error variant.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::ProofVerifierError(_) => "proof_verifier_error",
            Self::UnconfiguredProofType(_) => "unconfigured_proof_type",
        }
    }
}

/// Outcome of proof verification. `Invalid` means the artifact does not verify; it says nothing
/// about the validity of the payload it claims to prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerificationOutcome {
    /// The proof verifies against its reconstructed public input.
    Valid,
    /// The proof or its public values are invalid.
    Invalid,
}

impl fmt::Display for ProofVerificationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        })
    }
}

/// Interface used by the beacon chain to verify reconstructed execution proofs.
pub trait ProofEngineT: Send + Sync + 'static {
    /// Verify a reconstructed execution proof.
    fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError>;
}

/// Cloneable handle to an execution-proof verifier.
#[derive(Clone)]
pub struct ProofEngine {
    inner: Arc<dyn ProofEngineT>,
}

impl std::fmt::Debug for ProofEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofEngine").finish_non_exhaustive()
    }
}

impl ProofEngine {
    /// Wrap an execution-proof verifier in a shared handle.
    pub fn new(engine: impl ProofEngineT) -> Self {
        Self {
            inner: Arc::new(engine),
        }
    }

    /// Verify a reconstructed execution proof with the wrapped implementation.
    pub fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        self.inner.verify_execution_proof(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_verification_outcome_display_is_stable() {
        assert_eq!(ProofVerificationOutcome::Valid.to_string(), "valid");
        assert_eq!(ProofVerificationOutcome::Invalid.to_string(), "invalid");
    }

    #[test]
    fn proof_engine_error_kinds_are_stable() {
        assert_eq!(
            ProofEngineError::ProofVerifierError("failed".to_string()).kind(),
            "proof_verifier_error"
        );
        assert_eq!(
            ProofEngineError::UnconfiguredProofType(ProofType::RethSP1).kind(),
            "unconfigured_proof_type"
        );
    }
}

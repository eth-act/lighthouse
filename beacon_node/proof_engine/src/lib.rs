//! In-process EIP-8025 proof verification.

mod config;
#[cfg(feature = "ere-verifier")]
pub mod ere;
mod metrics;
pub mod test_utils;

use std::sync::Arc;
use std::time::Instant;
use types::execution::{ExecutionProof, ProofType};

pub use config::{ExecutionProofConfig, ProofEngineConfig};

/// Errors raised while initializing or running a proof verifier.
#[derive(Debug)]
pub enum ProofEngineError {
    /// The configured proof verifier could not initialize or complete verification.
    ProofVerifierError {
        message: String,
        error_type: &'static str,
    },
    /// No verifier is configured for the proof's EIP-8025 proof type.
    UnconfiguredProofType(ProofType),
}

impl ProofEngineError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ProofVerifierError { error_type, .. } => error_type,
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

impl ProofVerificationOutcome {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
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
        let started = Instant::now();
        let result = self.inner.verify_execution_proof(proof);
        let proof_type: &'static str = proof.proof_type.into();
        let (outcome, error_type) = match &result {
            Ok(outcome) => (outcome.as_str(), "none"),
            Err(error) => ("error", error.as_str()),
        };
        metrics::observe_timer_vec(
            &metrics::EXECUTION_PROOF_ENGINE_VERIFICATION_SECONDS,
            &[proof_type, outcome, error_type],
            started.elapsed(),
        );
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_verification_labels_are_stable() {
        assert_eq!(ProofVerificationOutcome::Valid.as_str(), "valid");
        assert_eq!(ProofVerificationOutcome::Invalid.as_str(), "invalid");
        assert_eq!(
            ProofEngineError::ProofVerifierError {
                message: "failed".to_string(),
                error_type: "internal",
            }
            .as_str(),
            "internal"
        );
        assert_eq!(
            ProofEngineError::UnconfiguredProofType(ProofType::RethSP1).as_str(),
            "unconfigured_proof_type"
        );
    }
}

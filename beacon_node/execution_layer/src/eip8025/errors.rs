//! Error types for EIP-8025 proof engine operations.

use pretty_reqwest_error::PrettyReqwestError;
use std::fmt;
use types::{ExecutionBlockHash, Hash256};

/// Errors that can occur during proof engine operations.
#[derive(Debug)]
pub enum ProofEngineError {
    /// The proof format is invalid.
    InvalidProofFormat(String),
    /// The proof type is invalid.
    InvalidProofType(String),
    /// The header format is invalid.
    InvalidHeaderFormat(String),
    /// The payload is invalid.
    InvalidPayload(String),
    /// Proof generation is unavailable.
    ProofGenerationUnavailable(String),
    /// HTTP request failed.
    HttpClientError(PrettyReqwestError),
    /// JSON-RPC error from the execution engine.
    JsonRpcError { code: i64, message: String },
    /// Failed to serialize/deserialize.
    SerdeError(serde_json::Error),
    /// SSZ error.
    SszError(ssz_types::Error),
    /// SSE stream error.
    SseError(String),
    /// The specified fork is not supported.
    ForkNotSupported(String),
    /// The execution engine does not support the requested proof type.
    ProofTypeNotSupported(u8),
    /// Timeout waiting for proof engine response.
    Timeout,
    /// Engine is not available.
    EngineUnavailable,
    /// State-related errors.
    StateError(ProofEngineStateError),
}

/// Errors related to the proof engine state.
#[derive(Debug)]
pub enum ProofEngineStateError {
    /// The block hash for the given request root was not found in the tree state.
    BlockHashNotFoundForRequestRoot {
        request_root: Hash256,
        block_hash: ExecutionBlockHash,
    },
    /// The request root associated with the proof has not been observed in a beacon block.
    ProofRequestRootNotSeen(Hash256),
    /// The request root was not found in the buffer when promotion was attempted.
    BufferedRequestNotFound(Hash256),
    /// The block number for the given block hash was not found.
    BlockNumberNotFound(ExecutionBlockHash),
}

impl std::error::Error for ProofEngineError {}
impl std::error::Error for ProofEngineStateError {}

impl ProofEngineError {
    /// Returns the JSON-RPC error code if this is a JSON-RPC error.
    pub fn rpc_error_code(&self) -> Option<i64> {
        match self {
            ProofEngineError::JsonRpcError { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// Returns true if this error indicates the proof type is not supported.
    pub fn is_not_supported(&self) -> bool {
        matches!(self, ProofEngineError::ProofTypeNotSupported(_))
    }
}

// JSON-RPC error codes for EIP-8025
pub mod error_codes {
    /// Invalid proof format - The execution proof structure is malformed
    pub const INVALID_PROOF_FORMAT: i64 = -39001;
    /// Invalid header format - The new payload request header structure is malformed
    pub const INVALID_HEADER_FORMAT: i64 = -39002;
    /// Invalid payload - The execution payload is invalid
    pub const INVALID_PAYLOAD: i64 = -39003;
    /// Proof generation unavailable - The client cannot generate proofs
    pub const PROOF_GENERATION_UNAVAILABLE: i64 = -39004;
}

impl fmt::Display for ProofEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofEngineError::InvalidProofFormat(msg) => {
                write!(f, "Invalid proof format: {}", msg)
            }
            ProofEngineError::InvalidProofType(msg) => {
                write!(f, "Invalid proof type: {}", msg)
            }
            ProofEngineError::InvalidHeaderFormat(msg) => {
                write!(f, "Invalid header format: {}", msg)
            }
            ProofEngineError::InvalidPayload(msg) => {
                write!(f, "Invalid payload: {}", msg)
            }
            ProofEngineError::ProofGenerationUnavailable(msg) => {
                write!(f, "Proof generation unavailable: {}", msg)
            }
            ProofEngineError::HttpClientError(err) => {
                write!(f, "HTTP request failed: {}", err)
            }
            ProofEngineError::JsonRpcError { code, message } => {
                write!(f, "JSON-RPC error (code {}): {}", code, message)
            }
            ProofEngineError::SerdeError(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
            ProofEngineError::SszError(err) => {
                write!(f, "SSZ error: {}", err)
            }
            ProofEngineError::SseError(msg) => {
                write!(f, "SSE stream error: {}", msg)
            }
            ProofEngineError::ForkNotSupported(fork) => {
                write!(f, "Fork not supported: {}", fork)
            }
            ProofEngineError::ProofTypeNotSupported(proof_type) => {
                write!(f, "Proof type {} not supported", proof_type)
            }
            ProofEngineError::Timeout => {
                write!(f, "Proof engine request timed out")
            }
            ProofEngineError::EngineUnavailable => {
                write!(f, "Proof engine is unavailable")
            }
            ProofEngineError::StateError(state_error) => {
                write!(f, "State error: {:?}", state_error)
            }
        }
    }
}

impl fmt::Display for ProofEngineStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofEngineStateError::BlockHashNotFoundForRequestRoot {
                request_root,
                block_hash,
            } => write!(
                f,
                "Block hash {:?} not found for request root {:?}",
                block_hash, request_root
            ),
            ProofEngineStateError::ProofRequestRootNotSeen(request_root) => write!(
                f,
                "Proof request root {:?} has not been seen in a beacon block",
                request_root
            ),
            ProofEngineStateError::BufferedRequestNotFound(request_root) => {
                write!(f, "Buffered request with root {:?} not found", request_root)
            }
            ProofEngineStateError::BlockNumberNotFound(block_hash) => {
                write!(f, "Block number not found for block hash {:?}", block_hash)
            }
        }
    }
}

impl From<serde_json::Error> for ProofEngineError {
    fn from(e: serde_json::Error) -> Self {
        ProofEngineError::SerdeError(e)
    }
}

impl From<ssz_types::Error> for ProofEngineError {
    fn from(e: ssz_types::Error) -> Self {
        ProofEngineError::SszError(e)
    }
}

impl From<reqwest::Error> for ProofEngineError {
    fn from(e: reqwest::Error) -> Self {
        ProofEngineError::HttpClientError(e.into())
    }
}

impl From<PrettyReqwestError> for ProofEngineError {
    fn from(e: PrettyReqwestError) -> Self {
        ProofEngineError::HttpClientError(e)
    }
}

impl From<ProofEngineStateError> for ProofEngineError {
    fn from(e: ProofEngineStateError) -> Self {
        ProofEngineError::StateError(e)
    }
}

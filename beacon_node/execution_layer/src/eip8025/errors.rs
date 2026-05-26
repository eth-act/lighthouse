use pretty_reqwest_error::PrettyReqwestError;
use std::fmt;

#[derive(Debug)]
pub enum ProofEngineError {
    InvalidProofType(String),
    InvalidHeaderFormat(String),
    InvalidPayload(String),
    ProofGenerationUnavailable(String),
    HttpClientError(PrettyReqwestError),
    JsonRpcError { code: i64, message: String },
    SerdeError(serde_json::Error),
    SszError(ssz_types::Error),
    SseError(String),
    ForkNotSupported(String),
    ProofTypeNotSupported(u8),
    Timeout,
    EngineUnavailable,
}

impl ProofEngineError {
    pub fn rpc_error_code(&self) -> Option<i64> {
        match self {
            ProofEngineError::JsonRpcError { code, .. } => Some(*code),
            _ => None,
        }
    }

    pub fn is_not_supported(&self) -> bool {
        matches!(self, ProofEngineError::ProofTypeNotSupported(_))
    }
}

pub mod error_codes {
    pub const INVALID_HEADER_FORMAT: i64 = -39002;
    pub const INVALID_PAYLOAD: i64 = -39003;
    pub const PROOF_GENERATION_UNAVAILABLE: i64 = -39004;
}

impl fmt::Display for ProofEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofEngineError::InvalidProofType(msg) => write!(f, "invalid proof type: {msg}"),
            ProofEngineError::InvalidHeaderFormat(msg) => {
                write!(f, "invalid header format: {msg}")
            }
            ProofEngineError::InvalidPayload(msg) => write!(f, "invalid payload: {msg}"),
            ProofEngineError::ProofGenerationUnavailable(msg) => {
                write!(f, "proof generation unavailable: {msg}")
            }
            ProofEngineError::HttpClientError(err) => write!(f, "HTTP request failed: {err}"),
            ProofEngineError::JsonRpcError { code, message } => {
                write!(f, "JSON-RPC error ({code}): {message}")
            }
            ProofEngineError::SerdeError(err) => write!(f, "serialization error: {err}"),
            ProofEngineError::SszError(err) => write!(f, "SSZ error: {err}"),
            ProofEngineError::SseError(msg) => write!(f, "SSE error: {msg}"),
            ProofEngineError::ForkNotSupported(fork) => write!(f, "fork not supported: {fork}"),
            ProofEngineError::ProofTypeNotSupported(proof_type) => {
                write!(f, "proof type {proof_type} not supported")
            }
            ProofEngineError::Timeout => write!(f, "proof engine request timed out"),
            ProofEngineError::EngineUnavailable => write!(f, "proof engine is unavailable"),
        }
    }
}

impl std::error::Error for ProofEngineError {}

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

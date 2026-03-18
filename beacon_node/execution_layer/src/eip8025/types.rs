//! API types for EIP-8025 proof engine communication.
//!
//! This module contains the SSE event types broadcast by the proof engine.

use super::errors::ProofEngineError;
use types::Hash256;

/// SSE event types broadcast by the proof engine.
#[derive(Debug, Clone, PartialEq)]
pub enum ProofEvent {
    /// A proof completed successfully.
    ProofComplete(ProofComplete),
    /// A proof failed.
    ProofFailure(ProofFailure),
    /// Witness fetch timed out.
    WitnessTimeout(ProofEventInfo),
    /// Proof generation timed out.
    ProofTimeout(ProofEventInfo),
}

/// Payload for a successful proof event.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct ProofComplete {
    pub new_payload_request_root: Hash256,
    pub proof_type: u8,
}

/// Payload for a failed proof event.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct ProofFailure {
    pub new_payload_request_root: Hash256,
    pub proof_type: u8,
    pub error: String,
}

/// Common info for timeout events.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct ProofEventInfo {
    pub new_payload_request_root: Hash256,
    pub proof_type: u8,
}

/// SSE event name + JSON data pair used to construct a [`ProofEvent`].
pub struct SseEventParts<'a>(pub &'a str, pub &'a str);

impl<'a> TryFrom<SseEventParts<'a>> for ProofEvent {
    type Error = ProofEngineError;

    fn try_from(parts: SseEventParts<'a>) -> Result<Self, Self::Error> {
        let SseEventParts(name, data) = parts;
        match name {
            "proof_complete" => Ok(Self::ProofComplete(
                serde_json::from_str(data).map_err(ProofEngineError::SerdeError)?,
            )),
            "proof_failure" => Ok(Self::ProofFailure(
                serde_json::from_str(data).map_err(ProofEngineError::SerdeError)?,
            )),
            "witness_timeout" => Ok(Self::WitnessTimeout(
                serde_json::from_str(data).map_err(ProofEngineError::SerdeError)?,
            )),
            "proof_timeout" => Ok(Self::ProofTimeout(
                serde_json::from_str(data).map_err(ProofEngineError::SerdeError)?,
            )),
            other => Err(ProofEngineError::SseError(format!(
                "unknown SSE event type: {other}"
            ))),
        }
    }
}

impl ProofEvent {
    /// Returns the `new_payload_request_root` from the event.
    pub fn new_payload_request_root(&self) -> Hash256 {
        match self {
            Self::ProofComplete(inner) => inner.new_payload_request_root,
            Self::ProofFailure(inner) => inner.new_payload_request_root,
            Self::WitnessTimeout(inner) => inner.new_payload_request_root,
            Self::ProofTimeout(inner) => inner.new_payload_request_root,
        }
    }

    /// Returns the proof type from the event.
    pub fn proof_type(&self) -> u8 {
        match self {
            Self::ProofComplete(inner) => inner.proof_type,
            Self::ProofFailure(inner) => inner.proof_type,
            Self::WitnessTimeout(inner) => inner.proof_type,
            Self::ProofTimeout(inner) => inner.proof_type,
        }
    }
}

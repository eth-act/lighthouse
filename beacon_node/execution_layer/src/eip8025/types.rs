//! API types for EIP-8025 proof engine communication.
//!
//! This module contains:
//! - [`ProofType`]: an independent string enum that mirrors the
//!   proof node API's `ProofType` exactly.
//! - SSE event types broadcast by the proof engine.
//!
//! ## ProofType encoding
//!
//! EIP-8025 uses `u8` for `ProofType` in SSZ containers (consensus layer).
//! The proof node API uses kebab-case string identifiers
//! (`"reth-sp1"`, `"ethrex-risc0"`, etc.) in HTTP query params, URL paths,
//! and SSE event payloads.
//!
//! [`ProofType`] bridges this gap: the [`HttpProofNodeClient`] converts
//! between `u8` (internal) and string (wire) at the HTTP boundary.

use super::errors::ProofEngineError;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::str::FromStr;
use types::Hash256;

// ─── ProofType ─────────────────────────────────────────────────────────────

/// Proof type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
#[repr(u8)]
pub enum ProofType {
    EthrexRisc0 = 0,
    EthrexSP1 = 1,
    EthrexZisk = 2,
    RethOpenVM = 3,
    RethRisc0 = 4,
    RethSP1 = 5,
    RethZisk = 6,
}

impl ProofType {
    /// Canonical string representation, matching exactly.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EthrexRisc0 => "ethrex-risc0",
            Self::EthrexSP1 => "ethrex-sp1",
            Self::EthrexZisk => "ethrex-zisk",
            Self::RethOpenVM => "reth-openvm",
            Self::RethRisc0 => "reth-risc0",
            Self::RethSP1 => "reth-sp1",
            Self::RethZisk => "reth-zisk",
        }
    }

    /// Convert from EIP-8025 `u8` proof type to a string identifier.
    ///
    /// The mapping follows the order defined in the `ProofType` enum.
    pub fn from_u8(value: u8) -> Result<Self, ProofEngineError> {
        match value {
            0 => Ok(Self::EthrexRisc0),
            1 => Ok(Self::EthrexSP1),
            2 => Ok(Self::EthrexZisk),
            3 => Ok(Self::RethOpenVM),
            4 => Ok(Self::RethRisc0),
            5 => Ok(Self::RethSP1),
            6 => Ok(Self::RethZisk),
            _ => Err(ProofEngineError::InvalidProofType(format!(
                "no mapping for proof type {value}"
            ))),
        }
    }

    /// Convert back to EIP-8025 `u8` proof type.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// All known proof type variants.
    pub fn all() -> &'static [ProofType] {
        &[
            Self::EthrexRisc0,
            Self::EthrexSP1,
            Self::EthrexZisk,
            Self::RethOpenVM,
            Self::RethRisc0,
            Self::RethSP1,
            Self::RethZisk,
        ]
    }
}

impl FromStr for ProofType {
    type Err = ProofEngineError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ethrex-risc0" => Ok(Self::EthrexRisc0),
            "ethrex-sp1" => Ok(Self::EthrexSP1),
            "ethrex-zisk" => Ok(Self::EthrexZisk),
            "reth-openvm" => Ok(Self::RethOpenVM),
            "reth-risc0" => Ok(Self::RethRisc0),
            "reth-sp1" => Ok(Self::RethSP1),
            "reth-zisk" => Ok(Self::RethZisk),
            _ => Err(ProofEngineError::InvalidProofType(format!(
                "unknown proof type: {s}"
            ))),
        }
    }
}

impl fmt::Display for ProofType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<ProofType> for String {
    fn from(pt: ProofType) -> Self {
        pt.as_str().to_string()
    }
}

impl TryFrom<String> for ProofType {
    type Error = ProofEngineError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

// ─── ProofTypes ─────────────────────────────────────────────────────────────

/// ProofTypes defines the support proof types.
///
/// This type allows us to implement `Default` with reasonable defaults.
///
/// The default is `[EthrexRisc0, EthrexSP1, EthrexZisk, RethOpenVM]` (wire
/// values 0–3), matching the `--proof-types` CLI flag default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTypes(pub Vec<ProofType>);

impl Default for ProofTypes {
    fn default() -> Self {
        Self(vec![
            ProofType::EthrexRisc0,
            ProofType::EthrexSP1,
            ProofType::EthrexZisk,
            ProofType::RethOpenVM,
        ])
    }
}

impl std::ops::Deref for ProofTypes {
    type Target = Vec<ProofType>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<ProofType>> for ProofTypes {
    fn from(v: Vec<ProofType>) -> Self {
        Self(v)
    }
}

// ─── SSE Event Types ────────────────────────────────────────────────────────

/// SSE event types broadcast by the proof engine.
#[derive(Debug, Clone, PartialEq)]
pub enum ProofEvent {
    /// A proof completed successfully.
    ProofComplete(ProofComplete),
    /// A proof failed (includes timeouts, now encoded in [`FailureReason`]).
    ProofFailure(ProofFailure),
}

/// Payload for a successful proof event.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ProofComplete {
    pub new_payload_request_root: Hash256,
    #[serde(deserialize_with = "deserialize_proof_type")]
    pub proof_type: u8,
}

/// Payload for a failed proof event.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ProofFailure {
    pub new_payload_request_root: Hash256,
    #[serde(deserialize_with = "deserialize_proof_type")]
    pub proof_type: u8,
    /// Structured reason for the failure.
    pub reason: FailureReason,
    /// Human-readable error message with details about the failure.
    pub error: String,
}

/// Failure reason of a proof request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    /// The execution witness could not be fetched within the configured timeout.
    WitnessTimeout,
    /// Proof generation did not complete within the configured timeout.
    ProvingTimeout,
    /// A general error occurred during proving.
    ProvingError,
}

/// Deserialize `proof_type` from either a string (`"reth-sp1"`) or a
/// numeric value (`0`). This allows Lighthouse to consume SSE events from both
/// servers (string format) and test mocks (numeric format).
fn deserialize_proof_type<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ProofTypeValue {
        Number(u8),
        String(String),
    }

    match ProofTypeValue::deserialize(deserializer)? {
        ProofTypeValue::Number(n) => Ok(n),
        ProofTypeValue::String(s) => {
            // Try parsing as string identifier first.
            if let Ok(pt) = s.parse::<ProofType>() {
                return Ok(pt.to_u8());
            }
            // Fall back to parsing as numeric string (e.g. "0").
            s.parse::<u8>().map_err(serde::de::Error::custom)
        }
    }
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
        }
    }

    /// Returns the proof type from the event.
    pub fn proof_type(&self) -> u8 {
        match self {
            Self::ProofComplete(inner) => inner.proof_type,
            Self::ProofFailure(inner) => inner.proof_type,
        }
    }
}

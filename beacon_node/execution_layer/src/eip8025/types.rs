//! API types for EIP-8025 proof engine communication.
//!
//! This module contains:
//! - [`ZkBoostProofType`]: an independent string enum that mirrors the zkBoost
//!   proof node API's `ProofType` exactly, without importing zkBoost types.
//! - SSE event types broadcast by the proof engine.
//!
//! ## ProofType encoding
//!
//! EIP-8025 uses `u8` for `ProofType` in SSZ containers (consensus layer).
//! The zkBoost proof node API uses kebab-case string identifiers
//! (`"reth-sp1"`, `"ethrex-risc0"`, etc.) in HTTP query params, URL paths,
//! and SSE event payloads.
//!
//! [`ZkBoostProofType`] bridges this gap: the [`HttpProofNodeClient`] converts
//! between `u8` (internal) and string (wire) at the HTTP boundary.

use super::errors::ProofEngineError;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::str::FromStr;
use types::Hash256;

// ─── ZkBoostProofType ───────────────────────────────────────────────────────

/// Proof type identifiers matching the zkBoost proof node API exactly.
///
/// This is an **independent** mirror of zkBoost's `ProofType` enum — it does
/// not import or depend on zkBoost crates. The string representations match
/// zkBoost's canonical format so that Lighthouse's HTTP client speaks the
/// exact same wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum ZkBoostProofType {
    EthrexRisc0,
    EthrexSP1,
    EthrexZisk,
    RethOpenVM,
    RethRisc0,
    RethSP1,
    RethZisk,
}

impl ZkBoostProofType {
    /// Canonical string representation, matching zkBoost exactly.
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

    /// Convert from EIP-8025 `u8` proof type to zkBoost string identifier.
    ///
    /// The mapping follows the order defined in the zkBoost `ProofType` enum.
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
                "no zkBoost mapping for proof type {value}"
            ))),
        }
    }

    /// Convert back to EIP-8025 `u8` proof type.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::EthrexRisc0 => 0,
            Self::EthrexSP1 => 1,
            Self::EthrexZisk => 2,
            Self::RethOpenVM => 3,
            Self::RethRisc0 => 4,
            Self::RethSP1 => 5,
            Self::RethZisk => 6,
        }
    }

    /// All known proof type variants.
    pub fn all() -> &'static [ZkBoostProofType] {
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

impl FromStr for ZkBoostProofType {
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
                "unknown zkBoost proof type: {s}"
            ))),
        }
    }
}

impl fmt::Display for ZkBoostProofType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<ZkBoostProofType> for String {
    fn from(pt: ZkBoostProofType) -> Self {
        pt.as_str().to_string()
    }
}

impl TryFrom<String> for ZkBoostProofType {
    type Error = ProofEngineError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

// ─── SSE Event Types ────────────────────────────────────────────────────────

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
    pub error: String,
}

/// Common info for timeout events.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ProofEventInfo {
    pub new_payload_request_root: Hash256,
    #[serde(deserialize_with = "deserialize_proof_type")]
    pub proof_type: u8,
}

/// Deserialize `proof_type` from either a zkBoost string (`"reth-sp1"`) or a
/// numeric value (`0`). This allows Lighthouse to consume SSE events from both
/// zkBoost servers (string format) and test mocks (numeric format).
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
            // Try parsing as zkBoost string identifier first.
            if let Ok(pt) = s.parse::<ZkBoostProofType>() {
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

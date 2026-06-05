use super::errors::ProofEngineError;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::str::FromStr;
use types::Hash256;

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

    pub fn to_u8(self) -> u8 {
        self as u8
    }

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
            numeric => numeric.parse::<u8>().map_or_else(
                |_| {
                    Err(ProofEngineError::InvalidProofType(format!(
                        "unknown proof type: {s}"
                    )))
                },
                Self::from_u8,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ProofType;

    #[test]
    fn proof_type_parses_string_names() {
        assert_eq!(
            "reth-zisk"
                .parse::<ProofType>()
                .expect("known proof type should parse"),
            ProofType::RethZisk
        );
    }

    #[test]
    fn proof_type_parses_numeric_ids() {
        assert_eq!(
            "6".parse::<ProofType>()
                .expect("known numeric proof type should parse"),
            ProofType::RethZisk
        );
    }

    #[test]
    fn proof_type_rejects_unknown_names() {
        let error = "not-a-proof-type"
            .parse::<ProofType>()
            .expect_err("unknown proof type should be rejected");
        assert!(
            error.to_string().contains("unknown proof type"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn proof_type_rejects_unknown_numeric_ids() {
        let error = "7"
            .parse::<ProofType>()
            .expect_err("unknown numeric proof type should be rejected");
        assert!(
            error.to_string().contains("no mapping for proof type 7"),
            "unexpected error: {error}"
        );
    }
}

impl fmt::Display for ProofType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<ProofType> for String {
    fn from(proof_type: ProofType) -> Self {
        proof_type.as_str().to_string()
    }
}

impl TryFrom<String> for ProofType {
    type Error = ProofEngineError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

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
    fn from(proof_types: Vec<ProofType>) -> Self {
        Self(proof_types)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProofEvent {
    ProofComplete(ProofComplete),
    ProofFailure(ProofFailure),
}

impl ProofEvent {
    pub fn new_payload_request_root(&self) -> Hash256 {
        match self {
            Self::ProofComplete(complete) => complete.new_payload_request_root,
            Self::ProofFailure(failure) => failure.new_payload_request_root,
        }
    }

    pub fn proof_type(&self) -> u8 {
        match self {
            Self::ProofComplete(complete) => complete.proof_type,
            Self::ProofFailure(failure) => failure.proof_type,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ProofComplete {
    pub new_payload_request_root: Hash256,
    #[serde(deserialize_with = "deserialize_proof_type")]
    pub proof_type: u8,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ProofFailure {
    pub new_payload_request_root: Hash256,
    #[serde(deserialize_with = "deserialize_proof_type")]
    pub proof_type: u8,
    pub reason: FailureReason,
    pub error: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    WitnessTimeout,
    ProvingTimeout,
    ProvingError,
    InternalError,
    #[serde(other)]
    Unknown,
}

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
            if let Ok(proof_type) = s.parse::<ProofType>() {
                return Ok(proof_type.to_u8());
            }
            s.parse::<u8>().map_err(serde::de::Error::custom)
        }
    }
}

pub struct SseEventParts<'a>(pub &'a str, pub &'a str);

impl<'a> TryFrom<SseEventParts<'a>> for ProofEvent {
    type Error = ProofEngineError;

    fn try_from(parts: SseEventParts<'a>) -> Result<Self, Self::Error> {
        let SseEventParts(name, data) = parts;
        match name {
            "proof_complete" => Ok(Self::ProofComplete(serde_json::from_str(data)?)),
            "proof_failure" => Ok(Self::ProofFailure(serde_json::from_str(data)?)),
            other => Err(ProofEngineError::SseError(format!(
                "unknown SSE event type: {other}"
            ))),
        }
    }
}

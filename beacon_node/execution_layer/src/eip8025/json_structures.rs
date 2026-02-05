//! JSON structures for EIP-8025 Engine API communication.
//!
//! These types are used for JSON-RPC serialization/deserialization with the execution engine.

use crate::eip8025::ProofEngineError;
use serde::{Deserialize, Serialize};
use strum::EnumString;
use types::execution::eip8025::{ProofData, ProofStatus};
use types::{Hash256, ProofGenId};

// TODO: Consider if this type is necessary or if we can use existing ProofInput type.
/// JSON representation of PublicInput for Engine API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonPublicInputV1 {
    /// The tree hash root of the NewPayloadRequest
    pub new_payload_request_root: Hash256,
}

/// JSON representation of ExecutionProof for Engine API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonExecutionProofV1 {
    /// The proof data (hex encoded)
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub proof_data: ProofData,
    /// The type of proof
    #[serde(with = "serde_utils::quoted_u64")]
    pub proof_type: u64,
    /// Public input linking the proof to a specific payload request
    pub public_input: JsonPublicInputV1,
}

/// JSON representation of ProofStatus for Engine API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonProofStatusV1 {
    /// The status: "VALID", "INVALID", "ACCEPTED", or "NOT_SUPPORTED"
    pub status: JsonProofStatusV1Status,
    /// Optional error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, EnumString)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum JsonProofStatusV1Status {
    Valid,
    Invalid,
    Accepted,
    NotSupported,
}

/// JSON representation of ProofAttributes for proof requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonProofAttributesV1 {
    /// List of proof types to generate
    pub proof_types: Vec<u64>,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransparentJsonProofGenId(#[serde(with = "serde_utils::bytes_8_hex")] pub ProofGenId);

impl From<TransparentJsonProofGenId> for ProofGenId {
    fn from(json: TransparentJsonProofGenId) -> Self {
        json.0
    }
}

impl From<types::execution::eip8025::PublicInput> for JsonPublicInputV1 {
    fn from(input: types::execution::eip8025::PublicInput) -> Self {
        JsonPublicInputV1 {
            new_payload_request_root: input.new_payload_request_root,
        }
    }
}

impl From<types::execution::eip8025::ExecutionProof> for JsonExecutionProofV1 {
    fn from(proof: types::execution::eip8025::ExecutionProof) -> Self {
        JsonExecutionProofV1 {
            proof_data: proof.proof_data,
            proof_type: proof.proof_type as u64,
            public_input: proof.public_input.into(),
        }
    }
}

impl From<JsonProofStatusV1> for ProofStatus {
    fn from(j: JsonProofStatusV1) -> Self {
        // Use this verbose deconstruction pattern to ensure no field is left unused.
        let JsonProofStatusV1 { status, .. } = j;

        status.into()
    }
}

impl From<JsonProofStatusV1Status> for ProofStatus {
    fn from(status: JsonProofStatusV1Status) -> Self {
        match status {
            JsonProofStatusV1Status::Valid => ProofStatus::Valid,
            JsonProofStatusV1Status::Invalid => ProofStatus::Invalid,
            JsonProofStatusV1Status::Accepted => ProofStatus::Accepted,
            JsonProofStatusV1Status::NotSupported => ProofStatus::NotSupported,
        }
    }
}

impl From<types::execution::eip8025::ProofAttributes> for JsonProofAttributesV1 {
    fn from(attrs: types::execution::eip8025::ProofAttributes) -> Self {
        JsonProofAttributesV1 {
            proof_types: attrs.proof_types.into_iter().map(|t| t as u64).collect(),
        }
    }
}

impl TryFrom<JsonProofAttributesV1> for types::execution::eip8025::ProofAttributes {
    type Error = ProofEngineError;

    fn try_from(json: JsonProofAttributesV1) -> Result<Self, Self::Error> {
        Ok(types::execution::eip8025::ProofAttributes {
            proof_types: json
                .proof_types
                .into_iter()
                .map(|t| {
                    t.try_into()
                        .map_err(|_| ProofEngineError::InvalidProofType(t.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

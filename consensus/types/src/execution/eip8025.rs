//! EIP-8025: Optional Execution Proofs
//!
//! This module contains types for the EIP-8025 optional execution proofs feature.
//! See: https://eips.ethereum.org/EIPS/eip-8025

use crate::core::{Hash256, SignedRoot};
use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;

/// Maximum proof size: 300 KiB (307200 bytes)
///
/// Product of U75 * U4096
pub type MaxProofSize = typenum::Prod<typenum::U75, typenum::U4096>;

/// Proof data type
///
/// VariableList of bytes with max length [`MaxProofSize`]`
pub type ProofData = VariableList<u8, MaxProofSize>;

/// Maximum execution proofs per payload
pub type MaxExecutionProofsPerPayload = typenum::U4;

/// Proof generation identifier (8 bytes)
pub type ProofGenId = [u8; 8];

/// Proof type identifier
pub type ProofType = u8;

/// List of execution proofs per payload
pub type ExecutionProofList = VariableList<SignedExecutionProof, MaxExecutionProofsPerPayload>;

/// Domain type for execution proof signatures (0x0D000000)
pub const DOMAIN_EXECUTION_PROOF: [u8; 4] = [0x0D, 0x00, 0x00, 0x00];

/// Minimum required execution proofs for payload verification
pub const MIN_REQUIRED_EXECUTION_PROOFS: usize = 1;

/// Public input of an [`ExecutionProof`].
///
/// Contains the tree hash root of the new payload request that the proof is associated with.
#[derive(
    Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct PublicInput {
    /// The tree hash root of the NewPayloadRequest associated with the proof.
    pub new_payload_request_root: Hash256,
}

/// The type of an execution proof.
///
/// Contains the proof data, type, and public input that links it to a specific new payload request.
#[derive(
    Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct ExecutionProof {
    /// The proof data.
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub proof_data: ProofData,
    /// The type of proof.
    pub proof_type: ProofType,
    /// Public input linking the proof to a specific new payload request.
    pub public_input: PublicInput,
}

impl SignedRoot for ExecutionProof {}

/// A signed execution proof from a validator.
///
/// Contains the execution proof, the validator's index, and their BLS signature.
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct SignedExecutionProof {
    /// The execution proof message
    pub message: ExecutionProof,
    /// Index of the validator who signed this proof
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    /// BLS signature over the execution proof
    pub signature: SignatureBytes,
}

/// Proof attributes for requesting proof generation.
///
/// Specifies which types of proofs should be generated for a payload.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofAttributes {
    /// List of proof types to generate
    pub proof_types: Vec<ProofType>,
}

// =============================================================================
// Status Types
// =============================================================================

/// Status returned from proof verification operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofStatus {
    /// The proof is valid.
    Valid,
    /// The proof/header verification failed.
    Invalid,
    /// The proof is valid but does not change the canonical head.
    Accepted,
    /// The proof type is not supported by this client.
    NotSupported,
    /// The request root that the proof is associated with is not yet known.
    Syncing,
}

impl ProofStatus {
    /// Returns true if the status indicates successful verification.
    pub fn is_valid(&self) -> bool {
        matches!(self, ProofStatus::Valid)
    }

    /// Returns true if the status indicates the node is still syncing proofs.
    pub fn is_syncing(&self) -> bool {
        matches!(self, ProofStatus::Syncing)
    }

    /// Returns true if the status indicates the node has accepted the proof.
    pub fn is_accepted(&self) -> bool {
        matches!(self, ProofStatus::Accepted)
    }
}

impl std::fmt::Display for ProofStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProofStatus::Valid => {
                write!(f, "VALID")
            }
            ProofStatus::Invalid => write!(f, "INVALID"),
            ProofStatus::Accepted => write!(f, "ACCEPTED"),
            ProofStatus::NotSupported => write!(f, "NOT_SUPPORTED"),
            ProofStatus::Syncing => write!(f, "SYNCING"),
        }
    }
}

/// A generated proof with its tracking ID.
///
/// Used when receiving proofs from the proof engine via the beacon API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedProof {
    /// The proof generation ID for tracking
    #[serde(with = "serde_utils::bytes_8_hex")]
    pub proof_gen_id: ProofGenId,
    /// The generated execution proof
    pub execution_proof: ExecutionProof,
}

// =============================================================================
// Utility Implementations
// =============================================================================

impl ExecutionProof {
    /// Returns true if the proof data is empty.
    pub fn is_empty(&self) -> bool {
        self.proof_data.is_empty()
    }

    /// Returns the size of the proof data in bytes.
    pub fn proof_size(&self) -> usize {
        self.proof_data.len()
    }
}

impl SignedExecutionProof {
    /// Returns a reference to the underlying execution proof.
    pub fn proof(&self) -> &ExecutionProof {
        &self.message
    }

    /// Returns the new payload request root this proof validates.
    pub fn request_root(&self) -> Hash256 {
        self.message.public_input.new_payload_request_root
    }

    /// Returns the proof type.
    pub fn proof_type(&self) -> ProofType {
        self.message.proof_type
    }

    /// Returns the validator index that signed this proof.
    pub fn validator_index(&self) -> u64 {
        self.validator_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};

    #[test]
    fn public_input_round_trip() {
        let input = PublicInput {
            new_payload_request_root: Hash256::repeat_byte(0xab),
        };
        let encoded = input.as_ssz_bytes();
        let decoded = PublicInput::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(input, decoded);
    }

    #[test]
    fn execution_proof_round_trip() {
        let proof = ExecutionProof {
            proof_data: VariableList::new(vec![1u8, 2, 3, 4]).unwrap(),
            proof_type: 1,
            public_input: PublicInput {
                new_payload_request_root: Hash256::repeat_byte(0xcd),
            },
        };
        let encoded = proof.as_ssz_bytes();
        let decoded = ExecutionProof::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn signed_execution_proof_round_trip() {
        let signed_proof = SignedExecutionProof {
            message: ExecutionProof {
                proof_data: VariableList::new(vec![5u8, 6, 7, 8]).unwrap(),
                proof_type: 2,
                public_input: PublicInput {
                    new_payload_request_root: Hash256::repeat_byte(0xef),
                },
            },
            validator_index: 42,
            signature: SignatureBytes::empty(),
        };
        let encoded = signed_proof.as_ssz_bytes();
        let decoded = SignedExecutionProof::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(signed_proof, decoded);
    }

    #[test]
    fn execution_proof_is_empty() {
        let empty_proof = ExecutionProof {
            proof_data: VariableList::new(vec![]).unwrap(),
            proof_type: 1,
            public_input: PublicInput {
                new_payload_request_root: Hash256::ZERO,
            },
        };
        assert!(empty_proof.is_empty());

        let non_empty_proof = ExecutionProof {
            proof_data: VariableList::new(vec![1u8, 2, 3]).unwrap(),
            proof_type: 1,
            public_input: PublicInput {
                new_payload_request_root: Hash256::ZERO,
            },
        };
        assert!(!non_empty_proof.is_empty());
    }

    #[test]
    fn execution_proof_size() {
        let proof = ExecutionProof {
            proof_data: VariableList::new(vec![1u8, 2, 3, 4, 5]).unwrap(),
            proof_type: 1,
            public_input: PublicInput {
                new_payload_request_root: Hash256::ZERO,
            },
        };
        assert_eq!(proof.proof_size(), 5);

        let empty_proof = ExecutionProof::default();
        assert_eq!(empty_proof.proof_size(), 0);
    }

    #[test]
    fn signed_execution_proof_accessors() {
        let request_root = Hash256::repeat_byte(0xab);
        let proof_type = 42u8;
        let validator_index = 123u64;

        let signed_proof = SignedExecutionProof {
            message: ExecutionProof {
                proof_data: VariableList::new(vec![1u8, 2, 3]).unwrap(),
                proof_type,
                public_input: PublicInput {
                    new_payload_request_root: request_root,
                },
            },
            validator_index,
            signature: SignatureBytes::empty(),
        };

        assert_eq!(signed_proof.request_root(), request_root);
        assert_eq!(signed_proof.proof_type(), proof_type);
        assert_eq!(signed_proof.validator_index(), validator_index);
        assert_eq!(signed_proof.proof().proof_type, proof_type);
    }

    #[test]
    fn proof_status_is_valid() {
        assert!(ProofStatus::Valid.is_valid());
        assert!(!ProofStatus::Invalid.is_valid());
        assert!(!ProofStatus::Accepted.is_valid());
        assert!(!ProofStatus::NotSupported.is_valid());
    }

    #[test]
    fn proof_status_is_syncing() {
        assert!(ProofStatus::Syncing.is_syncing());
        assert!(!ProofStatus::Accepted.is_syncing());
        assert!(!ProofStatus::Valid.is_syncing());
        assert!(!ProofStatus::Invalid.is_syncing());
        assert!(!ProofStatus::NotSupported.is_syncing());
    }

    #[test]
    fn generated_proof_json_round_trip() {
        let proof = GeneratedProof {
            proof_gen_id: [1, 2, 3, 4, 5, 6, 7, 8],
            execution_proof: ExecutionProof {
                proof_data: VariableList::new(vec![0xaa, 0xbb, 0xcc]).unwrap(),
                proof_type: 1,
                public_input: PublicInput {
                    new_payload_request_root: Hash256::repeat_byte(0xde),
                },
            },
        };

        let json = serde_json::to_string(&proof).unwrap();
        let decoded: GeneratedProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn proof_attributes_default() {
        let attrs = ProofAttributes::default();
        assert!(attrs.proof_types.is_empty());

        let attrs_with_types = ProofAttributes {
            proof_types: vec![1, 2, 3],
        };
        assert_eq!(attrs_with_types.proof_types.len(), 3);
    }
}

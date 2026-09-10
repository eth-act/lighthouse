use crate::{ForkName, Hash256, SignedRoot};
use bls::Signature;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

/// SSZ bound for `proof_data`: 4 MiB (4,194,304 bytes).
pub type MaxProofSize = typenum::U4194304;

/// EIP-8025 `MAX_EXECUTION_PROOFS_PER_PAYLOAD`: distinct proof types per payload.
pub type MaxExecutionProofsPerPayload = typenum::U4;

/// Schema identifier for the Amsterdam stateless execution input, revision 1.
const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501;

/// Opaque proof bytes, bounded by EIP-8025 `MAX_PROOF_SIZE`.
pub type ProofData = VariableList<u8, MaxProofSize>;

/// Identifier for an immutable proof-system, guest-program, and version tuple.
pub type ProofType = u8;

/// Proof types supported by the current EIP-8025 specification.
const SUPPORTED_PROOF_TYPES: [ProofType; 3] = [1, 2, 3];

/// Return whether `proof_type` is assigned by the current EIP-8025 specification.
pub fn is_supported_proof_type(proof_type: ProofType) -> bool {
    SUPPORTED_PROOF_TYPES.contains(&proof_type)
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1, 1))]
pub struct PublicInput {
    pub new_payload_request_root: Hash256,
    pub successful_validation: bool,
    #[serde(with = "serde_utils::quoted_u64")]
    pub chain_id: u64,
    pub schema_id: u16,
}

/// An execution proof and the proof-system public input used to verify it.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ExecutionProof {
    pub proof_data: ProofData,
    pub proof_type: ProofType,
    pub public_input: PublicInput,
}

impl ExecutionProof {
    /// Construct an execution proof from proof data and public input values.
    pub fn new(
        proof_data: ProofData,
        proof_type: ProofType,
        new_payload_request_root: Hash256,
        chain_id: u64,
    ) -> Self {
        Self {
            proof_data,
            proof_type,
            public_input: PublicInput {
                new_payload_request_root,
                successful_validation: true,
                chain_id,
                schema_id: STATELESS_INPUT_SCHEMA_ID,
            },
        }
    }
}

/// Gossip envelope binding opaque proof bytes to a beacon block.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ExecutionProofEnvelope {
    pub proof_data: ProofData,
    #[serde(with = "serde_utils::quoted_u8")]
    pub proof_type: ProofType,
    pub beacon_block_root: Hash256,
}

impl SignedRoot for ExecutionProofEnvelope {}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct SignedExecutionProofEnvelope {
    pub message: ExecutionProofEnvelope,
    #[serde(with = "serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub signature: Signature,
}

impl SignedExecutionProofEnvelope {
    pub fn beacon_block_root(&self) -> Hash256 {
        self.message.beacon_block_root
    }

    pub fn proof_type(&self) -> ProofType {
        self.message.proof_type
    }
}

/// Signed execution proof envelopes for one payload, as exchanged over the Beacon API.
pub type SignedExecutionProofEnvelopes =
    VariableList<SignedExecutionProofEnvelope, MaxExecutionProofsPerPayload>;

#[cfg(test)]
mod tests {
    use super::*;
    use fixed_bytes::FixedBytesExtended;
    use ssz::{Decode as _, Encode as _};
    use typenum::Unsigned;

    ssz_and_tree_hash_tests!(SignedExecutionProofEnvelope);

    fn signed_envelope(proof_type: ProofType) -> SignedExecutionProofEnvelope {
        SignedExecutionProofEnvelope {
            message: ExecutionProofEnvelope {
                proof_data: ProofData::new(vec![1]).expect("valid proof data"),
                proof_type,
                beacon_block_root: Hash256::zero(),
            },
            validator_index: 7,
            signature: Signature::empty(),
        }
    }

    #[test]
    fn signed_envelope_json_quotes_integers() {
        let envelope = signed_envelope(2);

        let json = serde_json::to_value(&envelope).expect("serializes");
        assert_eq!(json["message"]["proof_type"], "2");
        assert_eq!(json["validator_index"], "7");

        let decoded: SignedExecutionProofEnvelope =
            serde_json::from_value(json).expect("deserializes");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn signed_envelopes_enforce_per_payload_bound() {
        let max = MaxExecutionProofsPerPayload::USIZE;
        assert!(SignedExecutionProofEnvelopes::new(vec![signed_envelope(1); max]).is_ok());
        assert!(SignedExecutionProofEnvelopes::new(vec![signed_envelope(1); max + 1]).is_err());
    }

    #[test]
    fn supported_proof_types_match_spec() {
        assert_eq!(SUPPORTED_PROOF_TYPES, [1, 2, 3]);
        assert!(
            SUPPORTED_PROOF_TYPES
                .iter()
                .all(|proof_type| is_supported_proof_type(*proof_type))
        );
        assert!(!is_supported_proof_type(0));
        assert!(!is_supported_proof_type(4));
    }

    #[test]
    fn proof_data_and_signed_envelope_enforce_size_bound() {
        let max_proof_size = MaxProofSize::USIZE;

        assert!(ProofData::new(vec![0; max_proof_size + 1]).is_err());

        let proof_data = ProofData::new(vec![0; max_proof_size]).expect("valid proof data");
        let envelope = SignedExecutionProofEnvelope {
            message: ExecutionProofEnvelope {
                proof_data,
                proof_type: SUPPORTED_PROOF_TYPES[0],
                beacon_block_root: Hash256::zero(),
            },
            validator_index: 0,
            signature: Signature::empty(),
        };

        let mut bytes = envelope.as_ssz_bytes();
        bytes.push(0);

        assert!(SignedExecutionProofEnvelope::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    fn execution_proof_constructor_uses_proof_and_public_input_context() {
        let proof_data = ProofData::new(vec![1, 2, 3]).expect("valid proof data");
        let proof_type = SUPPORTED_PROOF_TYPES[0];
        let new_payload_request_root = Hash256::repeat_byte(0x22);

        let proof =
            ExecutionProof::new(proof_data.clone(), proof_type, new_payload_request_root, 1);

        assert_eq!(proof.proof_data, proof_data);
        assert_eq!(proof.proof_type, proof_type);
        assert_eq!(
            proof.public_input,
            PublicInput {
                new_payload_request_root,
                successful_validation: true,
                chain_id: 1,
                schema_id: STATELESS_INPUT_SCHEMA_ID,
            }
        );
    }
}

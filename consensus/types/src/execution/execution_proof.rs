use crate::{ForkName, Hash256, SignedRoot};
use bls::Signature;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use ssz::{Decode as SszDecode, DecodeError, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use strum::VariantArray;
use tree_hash::{PackedEncoding, TreeHash as TreeHashTrait, TreeHashType};
use tree_hash_derive::TreeHash;

/// SSZ bound for `proof_data`: 4 MiB (4,194,304 bytes).
pub type MaxProofSize = typenum::U4194304;

/// EIP-8025 `MAX_EXECUTION_PROOFS_PER_PAYLOAD`: distinct proof types per payload.
pub type MaxExecutionProofsPerPayload = typenum::U4;

/// Schema identifier for the Amsterdam stateless execution input, revision 1.
const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501;

/// Opaque proof bytes, bounded by EIP-8025 `MAX_PROOF_SIZE`.
pub type ProofData = VariableList<u8, MaxProofSize>;

/// Proof system that verifies an execution proof.
///
/// Each assigned [`ProofType`] names exactly one of these, so it is derived from the proof type
/// rather than configured alongside it.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZkvmKind {
    /// OpenVM.
    Openvm,
    /// SP1.
    Sp1,
    /// Zisk.
    Zisk,
}

/// Identifier for an immutable proof-system, guest-program, and version tuple.
///
/// The discriminants are the assigned EIP-8025 wire encodings and are serialized as a `u8`. The
/// assignments are provisional while EIP-8025 is under development.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, VariantArray)]
#[repr(u8)]
pub enum ProofType {
    /// reth stateless validator proven on OpenVM.
    RethOpenvm = 1,
    /// reth stateless validator proven on SP1.
    RethSp1 = 2,
    /// reth stateless validator proven on Zisk.
    RethZisk = 3,
}

impl ProofType {
    /// Every proof type assigned by the current EIP-8025 specification.
    pub const fn all() -> &'static [Self] {
        Self::VARIANTS
    }

    /// The proof system this proof type is verified with.
    pub const fn zkvm(self) -> ZkvmKind {
        match self {
            Self::RethOpenvm => ZkvmKind::Openvm,
            Self::RethSp1 => ZkvmKind::Sp1,
            Self::RethZisk => ZkvmKind::Zisk,
        }
    }

    /// The assigned EIP-8025 wire encoding.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ProofType {
    /// The unassigned encoding that was rejected.
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::RethOpenvm),
            2 => Ok(Self::RethSp1),
            3 => Ok(Self::RethZisk),
            unassigned => Err(unassigned),
        }
    }
}

impl std::fmt::Display for ProofType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_u8())
    }
}

// `ssz(enum_behaviour = "tag")` cannot be used here: it encodes the variant *index*, not the
// assigned discriminant, and rejects explicit selectors, so proof types would go on the wire as
// 0, 1, 2 instead of 1, 2, 3.
impl SszEncode for ProofType {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        1
    }

    fn ssz_bytes_len(&self) -> usize {
        1
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.to_u8().ssz_append(buf);
    }
}

impl SszDecode for ProofType {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        1
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::try_from(u8::from_ssz_bytes(bytes)?).map_err(|unassigned| {
            DecodeError::BytesInvalid(format!("unassigned EIP-8025 proof type: {unassigned}"))
        })
    }
}

impl TreeHashTrait for ProofType {
    fn tree_hash_type() -> TreeHashType {
        u8::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        self.to_u8().tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        u8::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Hash256 {
        self.to_u8().tree_hash_root()
    }
}

impl Serialize for ProofType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for ProofType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(u8::deserialize(deserializer)?)
            .map_err(|unassigned| D::Error::custom(format!("unassigned proof type {unassigned}")))
    }
}

/// Serialize a [`ProofType`] as a quoted decimal string, as the Beacon API requires.
pub mod quoted_proof_type {
    use super::ProofType;
    use serde::{Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(value: &ProofType, serializer: S) -> Result<S::Ok, S::Error> {
        serde_utils::quoted_u8::serialize(&value.to_u8(), serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<ProofType, D::Error> {
        let value: u8 = serde_utils::quoted_u8::deserialize(deserializer)?;
        ProofType::try_from(value)
            .map_err(|unassigned| D::Error::custom(format!("unassigned proof type {unassigned}")))
    }
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
    #[serde(with = "quoted_proof_type")]
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
    use tree_hash::TreeHash as _;
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
        let envelope = signed_envelope(ProofType::RethSp1);

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
        let envelope = signed_envelope(ProofType::RethOpenvm);
        assert!(SignedExecutionProofEnvelopes::new(vec![envelope.clone(); max]).is_ok());
        assert!(SignedExecutionProofEnvelopes::new(vec![envelope; max + 1]).is_err());
    }

    #[test]
    fn assigned_proof_types_match_spec() {
        assert_eq!(
            ProofType::all(),
            [
                ProofType::RethOpenvm,
                ProofType::RethSp1,
                ProofType::RethZisk
            ]
        );

        // The discriminants are the wire encoding, so `all()` and the assignments must agree.
        for (index, proof_type) in ProofType::all().iter().enumerate() {
            let encoding = u8::try_from(index + 1).expect("index within bound");
            assert_eq!(proof_type.to_u8(), encoding);
            assert_eq!(ProofType::try_from(encoding), Ok(*proof_type));
        }

        for unassigned in [0, 4, u8::MAX] {
            assert_eq!(ProofType::try_from(unassigned), Err(unassigned));
        }
    }

    #[test]
    fn envelope_with_unassigned_proof_type_does_not_decode() {
        // EIP-8025 gossip validation says "[REJECT] The proof type is supported". That rule is
        // enforced here, by the codec, so an unassigned proof type never reaches validation.
        let envelope = signed_envelope(ProofType::RethSp1);
        let encoded = envelope.as_ssz_bytes();
        let offset = encoded
            .windows(1)
            .position(|byte| byte == [ProofType::RethSp1.to_u8()])
            .expect("the proof type byte is present");

        for unassigned in [0u8, 4, u8::MAX] {
            let mut corrupted = encoded.clone();
            corrupted[offset] = unassigned;
            assert!(
                SignedExecutionProofEnvelope::from_ssz_bytes(&corrupted).is_err(),
                "decoded an envelope carrying unassigned proof type {unassigned}"
            );
        }

        // The untouched encoding still decodes, so the corruption above is the only difference.
        assert_eq!(
            SignedExecutionProofEnvelope::from_ssz_bytes(&encoded).expect("valid envelope decodes"),
            envelope
        );
    }

    #[test]
    fn every_proof_type_names_its_proof_system() {
        assert_eq!(ProofType::RethOpenvm.zkvm(), ZkvmKind::Openvm);
        assert_eq!(ProofType::RethSp1.zkvm(), ZkvmKind::Sp1);
        assert_eq!(ProofType::RethZisk.zkvm(), ZkvmKind::Zisk);
    }

    #[test]
    fn proof_type_ssz_round_trips_as_its_assigned_encoding() {
        for proof_type in ProofType::all() {
            let bytes = proof_type.as_ssz_bytes();
            assert_eq!(bytes, [proof_type.to_u8()]);
            assert_eq!(
                ProofType::from_ssz_bytes(&bytes).expect("assigned encoding decodes"),
                *proof_type
            );
        }

        // Unassigned encodings are rejected by the codec, and the tree hash matches the `u8`.
        for unassigned in [0u8, 4, u8::MAX] {
            assert!(ProofType::from_ssz_bytes(&[unassigned]).is_err());
        }
        assert_eq!(
            ProofType::RethSp1.tree_hash_root(),
            ProofType::RethSp1.to_u8().tree_hash_root()
        );
    }

    #[test]
    fn proof_data_and_signed_envelope_enforce_size_bound() {
        let max_proof_size = MaxProofSize::USIZE;

        assert!(ProofData::new(vec![0; max_proof_size + 1]).is_err());

        let proof_data = ProofData::new(vec![0; max_proof_size]).expect("valid proof data");
        let envelope = SignedExecutionProofEnvelope {
            message: ExecutionProofEnvelope {
                proof_data,
                proof_type: ProofType::RethOpenvm,
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
        let proof_type = ProofType::RethOpenvm;
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

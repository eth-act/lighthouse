use crate::execution::{ExecutionPayloadGloas, ExecutionRequestsGloas};
use crate::{EthSpec, ForkName, Hash256, SignedRoot, VersionedHash};
use bls::Signature;
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use tree_hash_derive::TreeHash;

/// SSZ bound for `proof_data`: 4 MiB (4,194,304 bytes).
pub type MaxProofSize = typenum::U4194304;

/// Schema identifier for the Amsterdam stateless execution input, revision 1.
pub const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501;

/// Opaque proof bytes, bounded by EIP-8025 `MAX_PROOF_SIZE`.
pub type ProofData = VariableList<u8, MaxProofSize>;

/// Identifier for an immutable proof-system, guest-program, and version tuple.
pub type ProofType = u8;

/// Proof types supported by the current EIP-8025 specification.
pub const SUPPORTED_PROOF_TYPES: [ProofType; 3] = [1, 2, 3];

/// Return whether `proof_type` is assigned by the current EIP-8025 specification.
pub fn is_supported_proof_type(proof_type: ProofType) -> bool {
    SUPPORTED_PROOF_TYPES.contains(&proof_type)
}

/// SSZ representation of the Gloas `engine_newPayload` request committed by a proof.
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec")]
#[context_deserialize(ForkName)]
#[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 1, 1, 1))]
pub struct SSZNewPayloadRequest<E: EthSpec> {
    pub execution_payload: ExecutionPayloadGloas<E>,
    pub versioned_hashes: VariableList<VersionedHash, <E as EthSpec>::MaxBlobCommitmentsPerBlock>,
    pub parent_beacon_block_root: Hash256,
    pub execution_requests: ExecutionRequestsGloas<E>,
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

/// Gossip envelope binding opaque proof bytes to a beacon block.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct ExecutionProofEnvelope {
    pub proof_data: ProofData,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;
    use fixed_bytes::FixedBytesExtended;
    use ssz::{Decode as _, Encode as _};
    use typenum::Unsigned;

    mod new_payload_request {
        use super::*;

        ssz_and_tree_hash_tests!(SSZNewPayloadRequest<MainnetEthSpec>);
    }

    ssz_and_tree_hash_tests!(SignedExecutionProofEnvelope);

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
}

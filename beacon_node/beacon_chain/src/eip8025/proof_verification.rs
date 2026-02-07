//! EIP-8025 Proof Verification
//!
//! This module implements the proof verification logic for EIP-8025 optional execution proofs.
//! It provides:
//! - BLS signature verification for validator signatures
//! - Validator index validation against the BeaconState
//! - TODO: integration into proof engine for end-to-end verification

use crate::BeaconChainError;
use execution_layer::eip8025::ProofEngineError;
use std::fmt;
use tree_hash::TreeHash;
use types::{ChainSpec, Domain, EthSpec, ForkName, Hash256, SignedExecutionProof, SigningData};

/// Errors that can occur during execution proof verification.
#[derive(Debug)]
pub enum ExecutionProofError {
    /// The BLS signature is invalid.
    InvalidSignature,
    /// The proof data is empty.
    EmptyProofData,
    /// The validator index is out of range.
    InvalidValidatorIndex,
    /// Failed to decompress the validator's public key.
    InvalidValidatorPubkey,
    /// Failed to decompress the signature.
    InvalidSignatureFormat,
    /// The fork does not support EIP-8025.
    UnsupportedFork,
    /// Failed to retrieve beacon state.
    StateError(String),
    /// No execution layer configured.
    NoExecutionLayer,
    /// The request root referenced by the proof is not known.
    UnknownRequestRoot(Hash256),
    /// The was an error in the proof engine during verification.
    ProofEngineError(ProofEngineError),
}

impl fmt::Display for ExecutionProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionProofError::InvalidSignature => {
                write!(f, "Invalid BLS signature")
            }
            ExecutionProofError::EmptyProofData => {
                write!(f, "Proof data is empty")
            }
            ExecutionProofError::InvalidValidatorIndex => {
                write!(f, "Validator index out of range")
            }
            ExecutionProofError::InvalidValidatorPubkey => {
                write!(f, "Invalid validator public key format")
            }
            ExecutionProofError::InvalidSignatureFormat => {
                write!(f, "Invalid signature format")
            }
            ExecutionProofError::UnsupportedFork => {
                write!(f, "Fork does not support EIP-8025")
            }
            ExecutionProofError::StateError(msg) => {
                write!(f, "Beacon state error: {}", msg)
            }
            ExecutionProofError::NoExecutionLayer => {
                write!(f, "No execution layer configured")
            }
            ExecutionProofError::UnknownRequestRoot(root) => {
                write!(
                    f,
                    "Unknown request root {:?}. Block may not be imported yet or was already finalized.",
                    root
                )
            }
            ExecutionProofError::ProofEngineError(engine_error) => {
                write!(f, "Proof engine error: {:?}", engine_error)
            }
        }
    }
}

impl std::error::Error for ExecutionProofError {}

/// Compute the signing root for an execution proof message.
///
/// This function is public for use by the validator client when signing proofs.
pub fn compute_signing_root(message: &types::ExecutionProof, domain: Hash256) -> Hash256 {
    SigningData {
        object_root: message.tree_hash_root(),
        domain,
    }
    .tree_hash_root()
}

/// Compute the domain for execution proof signing.
///
/// This function is public for use by the validator client when signing proofs.
pub fn compute_execution_proof_domain(
    fork_name: ForkName,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Hash256 {
    let fork_version = spec.fork_version_for_name(fork_name);
    spec.compute_domain(
        Domain::ExecutionProof,
        fork_version,
        genesis_validators_root,
    )
}

// TODO: migrate into an impl on BeaconChain
/// Verify a validator's BLS signature over an execution proof.
///
/// This function:
/// 1. Checks that the fork supports EIP-8025
/// 2. Checks that proof data is not empty (max proof size should be enforced by ssz deserialization)
/// 3. Verifies the BLS signature over the proof message using the validator's pubkey
///
/// # Arguments
///
/// * `signed_proof` - The signed execution proof to verify
/// * `validator_pubkey` - The public key of the validator at the specified index
/// * `fork_name` - The current fork name
/// * `genesis_validators_root` - The genesis validators root for domain computation
/// * `spec` - The chain specification
///
/// # Returns
///
/// `Ok(())` if the proof is valid, otherwise an `ExecutionProofError`.
pub fn verify_signed_execution_proof_signature<E: EthSpec>(
    signed_proof: &SignedExecutionProof,
    validator_pubkey: &bls::PublicKeyBytes,
    fork_name: ForkName,
    genesis_validators_root: Hash256,
    spec: &ChainSpec,
) -> Result<(), BeaconChainError> {
    // Check fork support
    if !fork_name.eip8025_enabled() {
        Err(ExecutionProofError::UnsupportedFork)?;
    }

    // Check proof data is not empty
    if signed_proof.message.proof_data.is_empty() {
        Err(ExecutionProofError::EmptyProofData)?;
    }

    // Decompress the validator's public key
    let pubkey = validator_pubkey
        .decompress()
        .map_err(|_| ExecutionProofError::InvalidValidatorPubkey)?;

    // Decompress the signature using bls::SignatureBytes::decompress()
    let signature = signed_proof
        .signature
        .decompress()
        .map_err(|_| ExecutionProofError::InvalidSignatureFormat)?;

    // Get the domain for execution proof signing
    let domain = compute_execution_proof_domain(fork_name, genesis_validators_root, spec);

    // Compute the signing root
    let signing_root = compute_signing_root(&signed_proof.message, domain);

    // Verify the signature
    if !signature.verify(&pubkey, signing_root) {
        Err(ExecutionProofError::InvalidSignature)?;
    }

    Ok(())
}

impl From<ProofEngineError> for BeaconChainError {
    fn from(engine_error: ProofEngineError) -> Self {
        BeaconChainError::ExecutionProofError(ExecutionProofError::ProofEngineError(engine_error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BeaconChainError;
    use bls::{Keypair, SignatureBytes};
    use ssz_types::VariableList;
    use types::{ExecutionProof, MainnetEthSpec, PublicInput};

    fn get_fulu_spec() -> ChainSpec {
        ForkName::Fulu.make_genesis_spec(MainnetEthSpec::default_spec())
    }

    fn create_test_proof(proof_data: Vec<u8>) -> ExecutionProof {
        ExecutionProof {
            proof_data: VariableList::new(proof_data).unwrap(),
            proof_type: 1,
            public_input: PublicInput {
                new_payload_request_root: Hash256::repeat_byte(0xab),
            },
        }
    }

    fn sign_proof(
        proof: &ExecutionProof,
        keypair: &Keypair,
        fork_name: ForkName,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedExecutionProof {
        let domain = compute_execution_proof_domain(fork_name, genesis_validators_root, spec);
        let signing_root = compute_signing_root(proof, domain);
        let signature = keypair.sk.sign(signing_root);

        // Convert signature to bls::SignatureBytes
        let sig_bytes = signature.serialize();
        let signature_vec: SignatureBytes = SignatureBytes::deserialize(&sig_bytes).unwrap();

        SignedExecutionProof {
            message: proof.clone(),
            validator_index: 0,
            signature: signature_vec,
        }
    }

    #[test]
    fn test_verify_valid_signature() {
        let keypair = Keypair::random();
        let spec = get_fulu_spec();
        let genesis_validators_root = Hash256::repeat_byte(0xcd);
        let proof = create_test_proof(vec![1, 2, 3, 4]);

        let signed = sign_proof(
            &proof,
            &keypair,
            ForkName::Fulu,
            genesis_validators_root,
            &spec,
        );

        let result = verify_signed_execution_proof_signature::<MainnetEthSpec>(
            &signed,
            &keypair.pk.compress(),
            ForkName::Fulu,
            genesis_validators_root,
            &spec,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let keypair = Keypair::random();
        let wrong_keypair = Keypair::random();
        let spec = get_fulu_spec();
        let genesis_validators_root = Hash256::repeat_byte(0xcd);
        let proof = create_test_proof(vec![1, 2, 3, 4]);

        // Sign with one keypair, verify with another
        let signed = sign_proof(
            &proof,
            &keypair,
            ForkName::Fulu,
            genesis_validators_root,
            &spec,
        );

        let result = verify_signed_execution_proof_signature::<MainnetEthSpec>(
            &signed,
            &wrong_keypair.pk.compress(),
            ForkName::Fulu,
            genesis_validators_root,
            &spec,
        );

        assert!(matches!(
            result,
            Err(BeaconChainError::ExecutionProofError(
                ExecutionProofError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn test_verify_empty_proof_data() {
        let keypair = Keypair::random();
        let spec = get_fulu_spec();
        let genesis_validators_root = Hash256::repeat_byte(0xcd);
        let proof = create_test_proof(vec![]); // Empty proof data

        let signed = sign_proof(
            &proof,
            &keypair,
            ForkName::Fulu,
            genesis_validators_root,
            &spec,
        );

        let result = verify_signed_execution_proof_signature::<MainnetEthSpec>(
            &signed,
            &keypair.pk.compress(),
            ForkName::Fulu,
            genesis_validators_root,
            &spec,
        );

        assert!(matches!(
            result,
            Err(BeaconChainError::ExecutionProofError(
                ExecutionProofError::EmptyProofData
            ))
        ));
    }

    #[test]
    fn test_verify_unsupported_fork() {
        let keypair = Keypair::random();
        let spec = MainnetEthSpec::default_spec();
        let genesis_validators_root = Hash256::repeat_byte(0xcd);
        let proof = create_test_proof(vec![1, 2, 3, 4]);

        // Use Electra spec (pre-Fulu, EIP-8025 not enabled)
        let electra_spec = ForkName::Electra.make_genesis_spec(spec.clone());
        let signed = sign_proof(
            &proof,
            &keypair,
            ForkName::Electra,
            genesis_validators_root,
            &electra_spec,
        );

        let result = verify_signed_execution_proof_signature::<MainnetEthSpec>(
            &signed,
            &keypair.pk.compress(),
            ForkName::Electra, // Pre-Fulu fork
            genesis_validators_root,
            &electra_spec,
        );

        assert!(matches!(
            result,
            Err(BeaconChainError::ExecutionProofError(
                ExecutionProofError::UnsupportedFork
            ))
        ));
    }

    #[test]
    fn test_verify_invalid_pubkey_format() {
        let keypair = Keypair::random();
        let spec = get_fulu_spec();
        let genesis_validators_root = Hash256::repeat_byte(0xcd);
        let proof = create_test_proof(vec![1, 2, 3, 4]);

        let signed = sign_proof(
            &proof,
            &keypair,
            ForkName::Fulu,
            genesis_validators_root,
            &spec,
        );

        // Create invalid pubkey bytes (all zeros is not a valid point on the curve)
        let invalid_pubkey = bls::PublicKeyBytes::empty();

        let result = verify_signed_execution_proof_signature::<MainnetEthSpec>(
            &signed,
            &invalid_pubkey,
            ForkName::Fulu,
            genesis_validators_root,
            &spec,
        );

        assert!(matches!(
            result,
            Err(BeaconChainError::ExecutionProofError(
                ExecutionProofError::InvalidValidatorPubkey
            ))
        ));
    }

    #[test]
    fn test_verify_invalid_signature_format() {
        let keypair = Keypair::random();
        let spec = get_fulu_spec();
        let genesis_validators_root = Hash256::repeat_byte(0xcd);
        let proof = create_test_proof(vec![1, 2, 3, 4]);

        // Create a signed proof with invalid signature bytes.
        // BLS signatures are G2 points. Bytes 0xff repeated are not a valid
        // compressed G2 point representation because they fail deserialization.
        let invalid_signature = SignatureBytes::deserialize(&[0xff; 96]).unwrap();
        let signed = SignedExecutionProof {
            message: proof,
            validator_index: 0,
            signature: invalid_signature,
        };

        let result = verify_signed_execution_proof_signature::<MainnetEthSpec>(
            &signed,
            &keypair.pk.compress(),
            ForkName::Fulu,
            genesis_validators_root,
            &spec,
        );

        assert!(matches!(
            result,
            Err(BeaconChainError::ExecutionProofError(
                ExecutionProofError::InvalidSignatureFormat
            ))
        ));
    }

    #[test]
    fn test_compute_signing_root_deterministic() {
        let proof = create_test_proof(vec![1, 2, 3, 4]);
        let domain = Hash256::repeat_byte(0xaa);

        let root1 = compute_signing_root(&proof, domain);
        let root2 = compute_signing_root(&proof, domain);

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_compute_signing_root_different_inputs() {
        let proof1 = create_test_proof(vec![1, 2, 3, 4]);
        let proof2 = create_test_proof(vec![5, 6, 7, 8]);
        let domain = Hash256::repeat_byte(0xaa);

        let root1 = compute_signing_root(&proof1, domain);
        let root2 = compute_signing_root(&proof2, domain);

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_compute_signing_root_different_domains() {
        let proof = create_test_proof(vec![1, 2, 3, 4]);
        let domain1 = Hash256::repeat_byte(0xaa);
        let domain2 = Hash256::repeat_byte(0xbb);

        let root1 = compute_signing_root(&proof, domain1);
        let root2 = compute_signing_root(&proof, domain2);

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_compute_execution_proof_domain() {
        let spec = get_fulu_spec();
        let genesis_validators_root = Hash256::repeat_byte(0xcd);

        let domain1 =
            compute_execution_proof_domain(ForkName::Fulu, genesis_validators_root, &spec);

        // Domain should be deterministic
        let domain2 =
            compute_execution_proof_domain(ForkName::Fulu, genesis_validators_root, &spec);
        assert_eq!(domain1, domain2);

        // Different genesis_validators_root should produce different domain
        let different_root = Hash256::repeat_byte(0xef);
        let domain3 = compute_execution_proof_domain(ForkName::Fulu, different_root, &spec);
        assert_ne!(domain1, domain3);
    }

    #[test]
    fn test_verify_with_different_genesis_validators_root() {
        let keypair = Keypair::random();
        let spec = get_fulu_spec();
        let genesis_validators_root = Hash256::repeat_byte(0xcd);
        let different_root = Hash256::repeat_byte(0xef);
        let proof = create_test_proof(vec![1, 2, 3, 4]);

        // Sign with one genesis_validators_root
        let signed = sign_proof(
            &proof,
            &keypair,
            ForkName::Fulu,
            genesis_validators_root,
            &spec,
        );

        // Verify with different genesis_validators_root
        let result = verify_signed_execution_proof_signature::<MainnetEthSpec>(
            &signed,
            &keypair.pk.compress(),
            ForkName::Fulu,
            different_root,
            &spec,
        );

        // Should fail because domain computation uses genesis_validators_root
        assert!(matches!(
            result,
            Err(BeaconChainError::ExecutionProofError(
                ExecutionProofError::InvalidSignature
            ))
        ));
    }
}

//! In-process EIP-8025 proof verification using ERE.

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
#[cfg(feature = "ere-verifier")]
use std::collections::HashMap;
use std::{collections::HashSet, str::FromStr, sync::Arc};
#[cfg(feature = "ere-verifier")]
use tree_hash::TreeHash;
use types::execution::{ExecutionProof, ProofType, is_supported_proof_type};

#[derive(Debug)]
pub enum ProofEngineError {
    EreVerifierUnavailable,
    InvalidProgramVk { proof_type: ProofType, status: i32 },
    UnconfiguredProofType(ProofType),
    Verifier { proof_type: ProofType, status: i32 },
}

/// Outcome of proof verification. `Invalid` means the artifact does not verify; it says nothing
/// about the validity of the payload it claims to prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerificationOutcome {
    Valid,
    Invalid,
}

/// Interface used by the beacon chain to verify reconstructed execution proofs.
pub trait ProofEngineT: Send + Sync + 'static {
    fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError>;
}

/// zkVM verifier supported by the ERE v0.18.0 C API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZkvmKind {
    Openvm,
    Sp1,
    Zisk,
}

impl ZkvmKind {
    #[cfg(feature = "ere-verifier")]
    const fn ere_discriminant(self) -> u32 {
        match self {
            Self::Openvm => 0,
            Self::Sp1 => 1,
            Self::Zisk => 2,
        }
    }
}

/// Configuration for the verifier assigned to an EIP-8025 proof type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProofConfig {
    pub proof_type: ProofType,
    #[serde(rename = "zkvm")]
    pub zkvm_kind: ZkvmKind,
    #[serde(with = "hex_bytes")]
    pub program_vk: Vec<u8>,
}

impl Default for ExecutionProofConfig {
    /// Built-in verifier configuration for the reth SP1 stateless-validator guest v0.1.0-rc.2 in
    /// `eth-act/ere-guests` at commit `dd6ac1a43fc14a34e0dc764937ba64f4b0237885`.
    /// The proof-type assignment is provisional while EIP-8025 is under development.
    fn default() -> Self {
        Self {
            proof_type: 2,
            zkvm_kind: ZkvmKind::Sp1,
            program_vk: hex::decode(DEFAULT_RETH_SP1_PROGRAM_VK)
                .expect("embedded ERE program verification key is valid hex"),
        }
    }
}

/// Configuration for the in-process EIP-8025 proof engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofEngineConfig {
    execution_proofs: Vec<ExecutionProofConfig>,
}

impl ProofEngineConfig {
    pub fn new(execution_proofs: Vec<ExecutionProofConfig>) -> Result<Self, String> {
        if execution_proofs.is_empty() {
            return Err("`execution_proofs` must contain at least one entry".to_string());
        }

        let mut proof_types = HashSet::with_capacity(execution_proofs.len());

        for config in &execution_proofs {
            if !is_supported_proof_type(config.proof_type) {
                return Err(format!("unsupported proof type `{}`", config.proof_type));
            }
            if !proof_types.insert(config.proof_type) {
                return Err(format!(
                    "duplicate configuration for proof type `{}`",
                    config.proof_type
                ));
            }
            if config.program_vk.is_empty() {
                return Err(format!(
                    "empty program verification key for proof type `{}`",
                    config.proof_type
                ));
            }
        }

        Ok(Self { execution_proofs })
    }

    pub fn execution_proofs(&self) -> &[ExecutionProofConfig] {
        &self.execution_proofs
    }
}

impl<'de> Deserialize<'de> for ProofEngineConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Config {
            execution_proofs: Vec<ExecutionProofConfig>,
        }

        let config = Config::deserialize(deserializer)?;
        Self::new(config.execution_proofs).map_err(D::Error::custom)
    }
}

impl FromStr for ProofEngineConfig {
    type Err = serde_json::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(value)
    }
}

/// Cloneable handle to an execution-proof verifier.
#[derive(Clone)]
pub struct ProofEngine {
    inner: Arc<dyn ProofEngineT>,
}

impl ProofEngine {
    /// Wrap an execution-proof verifier in a shared handle.
    pub fn new(engine: impl ProofEngineT) -> Self {
        Self {
            inner: Arc::new(engine),
        }
    }

    /// Construct the production proof engine from its configuration.
    pub fn from_config(config: ProofEngineConfig) -> Result<Self, ProofEngineError> {
        EreProofEngine::from_config(config).map(Self::new)
    }

    pub fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        self.inner.verify_execution_proof(proof)
    }
}

/// Production proof-engine implementation backed by ERE's statically linked C verifier library.
struct EreProofEngine {
    #[cfg(feature = "ere-verifier")]
    verifiers: HashMap<ProofType, ere::Verifier>,
}

impl EreProofEngine {
    fn from_config(config: ProofEngineConfig) -> Result<Self, ProofEngineError> {
        #[cfg(feature = "ere-verifier")]
        {
            let mut verifiers = HashMap::with_capacity(config.execution_proofs.len());

            for config in config.execution_proofs {
                let verifier =
                    ere::Verifier::new(config.zkvm_kind, &config.program_vk).map_err(|status| {
                        ProofEngineError::InvalidProgramVk {
                            proof_type: config.proof_type,
                            status,
                        }
                    })?;
                verifiers.insert(config.proof_type, verifier);
            }

            Ok(Self { verifiers })
        }

        #[cfg(not(feature = "ere-verifier"))]
        {
            let _ = config;
            Err(ProofEngineError::EreVerifierUnavailable)
        }
    }
}

impl ProofEngineT for EreProofEngine {
    fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        #[cfg(feature = "ere-verifier")]
        {
            let verifier = self
                .verifiers
                .get(&proof.proof_type)
                .ok_or(ProofEngineError::UnconfiguredProofType(proof.proof_type))?;
            let expected_public_values = proof.public_input.tree_hash_root();
            verify_with_ere(
                verifier,
                proof.proof_type,
                proof.proof_data.as_ref(),
                expected_public_values.as_slice(),
            )
        }

        #[cfg(not(feature = "ere-verifier"))]
        {
            let _ = proof;
            Err(ProofEngineError::EreVerifierUnavailable)
        }
    }
}

/// Deterministic proof engine used by beacon-chain tests.
#[derive(Debug, Default)]
pub struct MockProofEngine {
    valid_proof_data: HashSet<Vec<u8>>,
}

impl MockProofEngine {
    pub fn new(valid_proof_data: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            valid_proof_data: valid_proof_data.into_iter().collect(),
        }
    }
}

impl ProofEngineT for MockProofEngine {
    fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        Ok(
            if self.valid_proof_data.contains(proof.proof_data.as_ref()) {
                ProofVerificationOutcome::Valid
            } else {
                ProofVerificationOutcome::Invalid
            },
        )
    }
}

#[cfg(feature = "ere-verifier")]
fn verify_with_ere(
    verifier: &ere::Verifier,
    proof_type: ProofType,
    encoded_proof: &[u8],
    expected_public_values: &[u8],
) -> Result<ProofVerificationOutcome, ProofEngineError> {
    let public_values = match verifier.verify(encoded_proof) {
        Ok(public_values) => public_values,
        Err(ere::ERE_ERR_DECODE_PROOF | ere::ERE_ERR_VERIFY) => {
            return Ok(ProofVerificationOutcome::Invalid);
        }
        Err(status) => return Err(ProofEngineError::Verifier { proof_type, status }),
    };

    Ok(
        if matches_public_values(&public_values, expected_public_values) {
            ProofVerificationOutcome::Valid
        } else {
            ProofVerificationOutcome::Invalid
        },
    )
}

// OpenVM and Zisk may zero-pad the guest's public-value buffer.
#[cfg(any(test, feature = "ere-verifier"))]
fn matches_public_values(actual: &[u8], expected: &[u8]) -> bool {
    actual
        .split_at_checked(expected.len())
        .is_some_and(|(value, padding)| value == expected && padding.iter().all(|byte| *byte == 0))
}

#[cfg(feature = "ere-verifier")]
mod ere {
    use super::ZkvmKind;
    use std::{ptr::NonNull, slice};

    pub const ERE_OK: i32 = 0;
    pub const ERE_ERR_DECODE_PROOF: i32 = 4;
    pub const ERE_ERR_VERIFY: i32 = 5;
    const ERE_ERR_INTERNAL: i32 = 6;

    #[repr(C)]
    struct EreVerifier {
        _private: [u8; 0],
    }

    unsafe extern "C" {
        fn ere_verifier_new(
            zkvm_kind: u32,
            encoded_program_vk_ptr: *const u8,
            encoded_program_vk_len: usize,
            output: *mut *mut EreVerifier,
        ) -> i32;
        fn ere_verifier_verify(
            handle: *const EreVerifier,
            encoded_proof_ptr: *const u8,
            encoded_proof_len: usize,
            public_values_ptr: *mut *mut u8,
            public_values_len: *mut usize,
        ) -> i32;
        fn ere_verifier_free(handle: *mut EreVerifier);
        fn ere_bytes_free(ptr: *mut u8, len: usize);
    }

    pub struct Verifier(NonNull<EreVerifier>);

    // ERE's Rust verifier trait requires Send + Sync, and the C handle only exposes shared
    // verification plus exclusive destruction after the last Arc is dropped.
    unsafe impl Send for Verifier {}
    unsafe impl Sync for Verifier {}

    impl Verifier {
        pub fn new(zkvm_kind: ZkvmKind, encoded_program_vk: &[u8]) -> Result<Self, i32> {
            let mut output = std::ptr::null_mut();
            // SAFETY: the input slice is readable for its length and `output` is writable.
            let status = unsafe {
                ere_verifier_new(
                    zkvm_kind.ere_discriminant(),
                    encoded_program_vk.as_ptr(),
                    encoded_program_vk.len(),
                    &mut output,
                )
            };
            if status != ERE_OK {
                return Err(status);
            }
            NonNull::new(output).map(Self).ok_or(ERE_ERR_INTERNAL)
        }

        pub fn verify(&self, encoded_proof: &[u8]) -> Result<Vec<u8>, i32> {
            let mut output = std::ptr::null_mut();
            let mut output_len = 0;
            // SAFETY: the handle is live, the proof slice is readable for its length, and both
            // output pointers are writable.
            let status = unsafe {
                ere_verifier_verify(
                    self.0.as_ptr(),
                    encoded_proof.as_ptr(),
                    encoded_proof.len(),
                    &mut output,
                    &mut output_len,
                )
            };
            if status != ERE_OK {
                if !output.is_null() {
                    // SAFETY: ERE initialized this output allocation and reports its length.
                    unsafe { ere_bytes_free(output, output_len) };
                }
                return Err(status);
            }
            if output.is_null() {
                return (output_len == 0).then(Vec::new).ok_or(ERE_ERR_INTERNAL);
            }

            // SAFETY: ERE returned a readable allocation of exactly `output_len` bytes.
            let public_values = unsafe { slice::from_raw_parts(output, output_len) }.to_vec();
            // SAFETY: this is the exact pointer/length pair returned above and is freed once.
            unsafe { ere_bytes_free(output, output_len) };
            Ok(public_values)
        }
    }

    impl Drop for Verifier {
        fn drop(&mut self) {
            // SAFETY: the handle is live, uniquely owned by this value, and dropped once.
            unsafe { ere_verifier_free(self.0.as_ptr()) };
        }
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let encoded = value
            .strip_prefix("0x")
            .ok_or_else(|| D::Error::custom("program_vk must be 0x-prefixed hex"))?;
        let bytes = hex::decode(encoded)
            .map_err(|error| D::Error::custom(format!("invalid program_vk hex: {error}")))?;
        if bytes.is_empty() {
            return Err(D::Error::custom("program_vk must not be empty"));
        }
        Ok(bytes)
    }
}

// Program verification key from reth SP1 stateless-validator guest v0.1.0-rc.2.
const DEFAULT_RETH_SP1_PROGRAM_VK: &str =
    "00cf96ecee478c118cba3ac169054a25d7cb2d06df2d2dcb4bd9ab62dd47ef56";

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Hash256, execution::ProofData};

    #[test]
    fn parses_and_serializes_json_config() {
        let json = format!(
            r#"{{"execution_proofs":[{{"proof_type":2,"zkvm":"sp1","program_vk":"0x{}"}}]}}"#,
            DEFAULT_RETH_SP1_PROGRAM_VK
        );
        let config: ProofEngineConfig = json.parse().expect("valid JSON configuration");

        assert_eq!(config.execution_proofs().len(), 1);
        assert_eq!(config.execution_proofs()[0].proof_type, 2);
        assert_eq!(config.execution_proofs()[0].zkvm_kind, ZkvmKind::Sp1);
        assert_eq!(
            config.execution_proofs()[0].program_vk,
            hex::decode(DEFAULT_RETH_SP1_PROGRAM_VK).expect("valid embedded key")
        );
        assert_eq!(
            serde_json::from_str::<ProofEngineConfig>(
                &serde_json::to_string(&config).expect("serialize configuration")
            )
            .expect("deserialize configuration"),
            config
        );
    }

    #[test]
    fn rejects_invalid_json_fields() {
        for json in [
            r#"{"execution_proofs":[{"proof_type":2,"zkvm":"unknown","program_vk":"0x00"}]}"#,
            r#"{"execution_proofs":[{"proof_type":2,"zkvm":"sp1","program_vk":"00"}]}"#,
            r#"{"execution_proofs":[{"proof_type":2,"zkvm":"sp1","program_vk":"0x0g"}]}"#,
            r#"{"execution_proofs":[{"proof_type":2,"zkvm":"sp1","program_vk":"0x"}]}"#,
        ] {
            assert!(
                json.parse::<ProofEngineConfig>().is_err(),
                "accepted {json}"
            );
        }
    }

    #[test]
    fn proof_engine_config_rejects_unsupported_and_duplicate_proof_types() {
        let empty = ProofEngineConfig::new(vec![]);
        assert_eq!(
            empty.unwrap_err(),
            "`execution_proofs` must contain at least one entry"
        );

        let unsupported = ProofEngineConfig::new(vec![ExecutionProofConfig {
            proof_type: 0,
            ..ExecutionProofConfig::default()
        }]);
        assert_eq!(unsupported.unwrap_err(), "unsupported proof type `0`");

        let execution_proof = ExecutionProofConfig::default();
        let duplicate = ProofEngineConfig::new(vec![execution_proof.clone(), execution_proof]);
        assert_eq!(
            duplicate.unwrap_err(),
            "duplicate configuration for proof type `2`"
        );
    }

    #[test]
    fn default_config_matches_ere_guests_reth_v0_1_0_rc_2() {
        let config = ExecutionProofConfig::default();
        assert_eq!(
            (config.proof_type, config.zkvm_kind, config.program_vk.len()),
            (2, ZkvmKind::Sp1, 32)
        );
        assert_eq!(hex::encode(config.program_vk), DEFAULT_RETH_SP1_PROGRAM_VK);
    }

    #[cfg(not(feature = "ere-verifier"))]
    #[test]
    fn production_verifier_requires_ere_feature() {
        let config = ProofEngineConfig::new(vec![ExecutionProofConfig::default()])
            .expect("default configurations are valid");
        assert!(matches!(
            ProofEngine::from_config(config),
            Err(ProofEngineError::EreVerifierUnavailable)
        ));
    }

    #[cfg(feature = "ere-verifier")]
    #[test]
    fn default_config_initializes_ere_verifier() {
        let config = ProofEngineConfig::new(vec![ExecutionProofConfig::default()])
            .expect("default configurations are valid");
        ProofEngine::from_config(config)
            .expect("ERE accepts the embedded program verification key");
    }

    #[cfg(feature = "ere-verifier")]
    #[test]
    fn malformed_ere_proof_is_invalid() {
        let config = ProofEngineConfig::new(vec![ExecutionProofConfig::default()])
            .expect("SP1 configuration is valid");
        let proof_engine = ProofEngine::from_config(config).expect("SP1 verifier initializes");
        let proof = ExecutionProof::new(
            ProofData::new(vec![0xff]).expect("proof data within bound"),
            2,
            Hash256::default(),
            1,
        );

        assert_eq!(
            proof_engine
                .verify_execution_proof(&proof)
                .expect("ERE reports a verification outcome"),
            ProofVerificationOutcome::Invalid
        );
    }

    #[test]
    fn public_values_must_match_with_only_zero_padding() {
        assert!(matches_public_values(&[1, 2, 3], &[1, 2, 3]));
        assert!(matches_public_values(&[1, 2, 3, 0, 0], &[1, 2, 3]));
        assert!(!matches_public_values(&[1, 2], &[1, 2, 3]));
        assert!(!matches_public_values(&[1, 2, 4], &[1, 2, 3]));
        assert!(!matches_public_values(&[1, 2, 3, 0, 1], &[1, 2, 3]));
    }

    #[test]
    fn mock_proof_engine_matches_configured_proof_data() {
        let valid_data = vec![1, 2, 3];
        let proof_engine = ProofEngine::new(MockProofEngine::new([valid_data.clone()]));
        let proof = |proof_data| {
            ExecutionProof::new(
                ProofData::new(proof_data).expect("proof data within bound"),
                2,
                Hash256::default(),
                1,
            )
        };

        assert_eq!(
            proof_engine
                .verify_execution_proof(&proof(valid_data))
                .expect("mock verification succeeds"),
            ProofVerificationOutcome::Valid
        );
        assert_eq!(
            proof_engine
                .verify_execution_proof(&proof(vec![9]))
                .expect("mock verification succeeds"),
            ProofVerificationOutcome::Invalid
        );
    }
}

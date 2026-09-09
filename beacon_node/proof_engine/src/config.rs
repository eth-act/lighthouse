//! Configuration for mapping EIP-8025 proof types to ERE zkVM verifiers.

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::{collections::HashSet, str::FromStr};
use types::execution::{ProofType, is_supported_proof_type};

// Program verification keys from reth stateless-validator guest v0.1.0-rc.2.
const DEFAULT_RETH_OPENVM_PROGRAM_VK: &str = concat!(
    "001242647100d986f257006692793600fac3cc7600dd1f982800d7efb7340086f7837100fb65952b06030619068000a2",
    "c21b53000a2fee4f0036169c2800aaaa8d6c0087fbce5b00328dc26f009fe7de5a004686562400e77e894500a128f20f",
    "00674f7c2400b38df01800309c530900a487cf0400725bac510051af497500e4abff6e00a58ac939000775b41a001a76",
    "e84100c5e8944400c94e8e1600330e6b39001cacbc5a00ca47cd51001b418e02000fe02a480009a32070002554164500",
    "d7069403007d07bf3000290ccf21008726523b00e5fd1112003d03bd4c001c6831680016a3fe4200ad7ec6300028529e",
    "3c005710de1700349b6a77004b13962f00cff00054001483f65100ab05ce6b0034174b6000bc041c0900a9b5a11a00b2",
    "6f160300615de46100935f922800d39e4a2700596ea87000ca5764770023df7b57000b1ee85e004c456d61000bdad13b",
    "003de28a5f008584cc2a00033ab1020025f59e4a00c3a9f64a00b8ef166500",
);
const DEFAULT_RETH_SP1_PROGRAM_VK: &str =
    "00cf96ecee478c118cba3ac169054a25d7cb2d06df2d2dcb4bd9ab62dd47ef56";
const DEFAULT_RETH_ZISK_PROGRAM_VK: &str =
    "271ffd2449e1ca3ad8b63f18e0786a9d8267ae478bb5fb7a2dc55ef00cdfb968";

/// Configuration for the in-process EIP-8025 proof engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofEngineConfig {
    execution_proofs: Vec<ExecutionProofConfig>,
}

impl ProofEngineConfig {
    /// Validate and construct a non-empty configuration with unique, supported proof types.
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

    /// Return the configured proof-type/verifier mappings.
    pub fn execution_proofs(&self) -> &[ExecutionProofConfig] {
        &self.execution_proofs
    }
}

impl Default for ProofEngineConfig {
    /// Built-in verifier configuration for the reth stateless-validator guest v0.1.0-rc.2 in
    /// `eth-act/ere-guests` at commit `dd6ac1a43fc14a34e0dc764937ba64f4b0237885`.
    /// The proof-type assignments are provisional while EIP-8025 is under development.
    fn default() -> Self {
        Self::new(vec![
            ExecutionProofConfig {
                proof_type: 1,
                zkvm_kind: ZkvmKind::Openvm,
                program_vk: hex::decode(DEFAULT_RETH_OPENVM_PROGRAM_VK)
                    .expect("embedded OpenVM program verification key is valid hex"),
            },
            ExecutionProofConfig {
                proof_type: 2,
                zkvm_kind: ZkvmKind::Sp1,
                program_vk: hex::decode(DEFAULT_RETH_SP1_PROGRAM_VK)
                    .expect("embedded SP1 program verification key is valid hex"),
            },
            ExecutionProofConfig {
                proof_type: 3,
                zkvm_kind: ZkvmKind::Zisk,
                program_vk: hex::decode(DEFAULT_RETH_ZISK_PROGRAM_VK)
                    .expect("embedded Zisk program verification key is valid hex"),
            },
        ])
        .expect("built-in proof engine configuration is valid")
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

/// Configuration for the verifier assigned to an EIP-8025 proof type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProofConfig {
    /// EIP-8025 proof type handled by this verifier.
    pub proof_type: ProofType,
    /// zkVM used to decode and verify proofs of this type.
    #[serde(rename = "zkvm")]
    pub zkvm_kind: ZkvmKind,
    /// ERE-encoded program verification key.
    #[serde(with = "serde_utils::hex_vec")]
    pub program_vk: Vec<u8>,
}

/// zkVM verifier supported by the ERE v0.18.0 C API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZkvmKind {
    /// OpenVM.
    Openvm,
    /// SP1.
    Sp1,
    /// Zisk.
    Zisk,
}

#[cfg(test)]
mod tests {
    use super::*;

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
            zkvm_kind: ZkvmKind::Sp1,
            program_vk: vec![0],
        }]);
        assert_eq!(unsupported.unwrap_err(), "unsupported proof type `0`");

        let execution_proof = ProofEngineConfig::default().execution_proofs()[0].clone();
        let duplicate = ProofEngineConfig::new(vec![execution_proof.clone(), execution_proof]);
        assert_eq!(
            duplicate.unwrap_err(),
            "duplicate configuration for proof type `1`"
        );
    }

    #[test]
    fn default_config_matches_all_ere_guests_reth_v0_1_0_rc_2_verifiers() {
        let config = ProofEngineConfig::default();
        let expected = [
            (1, ZkvmKind::Openvm, DEFAULT_RETH_OPENVM_PROGRAM_VK),
            (2, ZkvmKind::Sp1, DEFAULT_RETH_SP1_PROGRAM_VK),
            (3, ZkvmKind::Zisk, DEFAULT_RETH_ZISK_PROGRAM_VK),
        ];

        assert_eq!(config.execution_proofs().len(), expected.len());
        for (config, (proof_type, zkvm_kind, program_vk)) in
            config.execution_proofs().iter().zip(expected)
        {
            assert_eq!(
                (config.proof_type, config.zkvm_kind),
                (proof_type, zkvm_kind)
            );
            assert_eq!(hex::encode(&config.program_vk), program_vk);
        }
    }
}

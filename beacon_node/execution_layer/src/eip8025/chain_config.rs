//! EIP-8025 chain-config wire types for the external proof engine.
//!
//! The proof-request and proof-verification bodies carry a [`ChainConfig`] describing the block's
//! activated execution fork.

use core::cmp::Reverse;

use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode as SszDecode, Encode as SszEncode};
use ssz_types::VariableList;
use ssz_types::typenum::U1;
use types::{ChainSpec, Epoch};

/// Execution fork identifier, encoded as a `u64` discriminant.
///
/// Only the forks a consensus client can resolve are listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u64)]
pub enum ProtocolFork {
    Paris = 14,
    Shanghai = 15,
    Cancun = 16,
    Prague = 17,
    Osaka = 18,
    Bpo1 = 19,
    Bpo2 = 20,
    // Skipping Bpo3, Bpo4 and Bpo5 which will be removed in next spec release.
    Amsterdam = 24,
}

impl ProtocolFork {
    /// Returns the `u64` discriminant used on the wire.
    pub fn as_u64(self) -> u64 {
        self as u64
    }

    /// Builds a fork from its wire discriminant, if recognised.
    pub fn from_u64(value: u64) -> Option<Self> {
        Some(match value {
            14 => Self::Paris,
            15 => Self::Shanghai,
            16 => Self::Cancun,
            17 => Self::Prague,
            18 => Self::Osaka,
            19 => Self::Bpo1,
            20 => Self::Bpo2,
            24 => Self::Amsterdam,
            _ => return None,
        })
    }
}

impl Encode for ProtocolFork {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        8
    }

    fn ssz_bytes_len(&self) -> usize {
        8
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.as_u64().ssz_append(buf)
    }
}

impl Decode for ProtocolFork {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        8
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let value = u64::from_ssz_bytes(bytes)?;
        Self::from_u64(value)
            .ok_or_else(|| DecodeError::BytesInvalid(format!("unknown ProtocolFork {value}")))
    }
}

/// Blob schedule for a fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SszEncode, SszDecode)]
pub struct BlobSchedule {
    pub target: u64,
    pub max: u64,
    pub base_fee_update_fraction: u64,
}

/// Activation of a fork, after the merge it is always activated by timestamp.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct ForkActivation {
    pub block_number: VariableList<u64, U1>,
    pub timestamp: VariableList<u64, U1>,
}

impl ForkActivation {
    /// Builds an activation from a timestamp.
    pub fn at_timestamp(timestamp: u64) -> Self {
        Self {
            block_number: VariableList::empty(),
            timestamp: VariableList::new(vec![timestamp]).expect("at most one element"),
        }
    }
}

/// A resolved fork with its activation and optional blob schedule.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct ForkConfig {
    pub fork: ProtocolFork,
    pub activation: ForkActivation,
    pub blob_schedule: VariableList<BlobSchedule, U1>,
}

impl ForkConfig {
    /// Builds a fork config from a fork, its activation, and an optional blob schedule.
    pub fn new(
        fork: ProtocolFork,
        activation: ForkActivation,
        blob_schedule: Option<BlobSchedule>,
    ) -> Self {
        Self {
            fork,
            activation,
            blob_schedule: VariableList::new(blob_schedule.into_iter().collect())
                .expect("at most one element"),
        }
    }
}

/// Chain configuration sent to the external proof engine alongside a payload.
#[derive(Debug, Clone, PartialEq, Eq, SszEncode, SszDecode)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub active_fork: ForkConfig,
}

impl ChainConfig {
    /// Builds a [`ChainConfig`] for a fork activated at `timestamp`.
    fn new(chain_id: u64, fork: ProtocolFork, timestamp: u64, blob_max: Option<u64>) -> Self {
        Self {
            chain_id,
            active_fork: ForkConfig::new(
                fork,
                ForkActivation::at_timestamp(timestamp),
                blob_max.map(|max| BlobSchedule {
                    max,
                    // `target` and `base_fee_update_fraction` left `0` to be filled
                    //  by proof node. Eventually `BlobSchedule` will be removed.
                    target: 0,
                    base_fee_update_fraction: 0,
                }),
            ),
        }
    }
}

/// The chain configs for every execution fork the proof engine can resolve, sorted by activation
/// timestamp.
#[derive(Debug, Clone)]
pub struct ChainConfigSchedule {
    chain_configs: Vec<ChainConfig>,
}

impl ChainConfigSchedule {
    /// Builds the schedule from the consensus spec, genesis time, and slots per epoch.
    pub fn new(spec: &ChainSpec, genesis_time: u64, slots_per_epoch: u64) -> Self {
        let epoch_seconds = spec.seconds_per_slot.saturating_mul(slots_per_epoch);
        let activation = |epoch: Epoch| {
            genesis_time.saturating_add(epoch.as_u64().saturating_mul(epoch_seconds))
        };
        let chain_id = spec.deposit_chain_id;

        let mut chain_configs = Vec::new();

        for (epoch, fork) in [
            (spec.bellatrix_fork_epoch, ProtocolFork::Paris),
            (spec.capella_fork_epoch, ProtocolFork::Shanghai),
            (spec.deneb_fork_epoch, ProtocolFork::Cancun),
            (spec.electra_fork_epoch, ProtocolFork::Prague),
            (spec.fulu_fork_epoch, ProtocolFork::Osaka),
            (spec.gloas_fork_epoch, ProtocolFork::Amsterdam),
        ] {
            // A fork left at the far-future sentinel is not scheduled.
            if let Some(epoch) = epoch.filter(|epoch| *epoch != spec.far_future_epoch) {
                let timestamp = activation(epoch);
                let blob_max =
                    (fork >= ProtocolFork::Cancun).then(|| spec.max_blobs_per_block(epoch));
                chain_configs.push(ChainConfig::new(chain_id, fork, timestamp, blob_max));
            }
        }

        for (index, param) in spec.blob_schedule().into_iter().rev().enumerate() {
            if let Some(fork) = bpo_fork(index) {
                let timestamp = activation(param.epoch);
                chain_configs.push(ChainConfig::new(
                    chain_id,
                    fork,
                    timestamp,
                    Some(param.max_blobs_per_block),
                ));
            }
        }

        // Sort by activation timestamp in descending order.
        chain_configs.sort_by_key(|config| {
            Reverse((
                activation_timestamp(config),
                config.active_fork.fork.as_u64(),
            ))
        });

        Self { chain_configs }
    }

    /// Resolves the chain config active at `timestamp`, or `None` before the first scheduled fork.
    pub fn resolve(&self, timestamp: u64) -> Option<ChainConfig> {
        self.chain_configs
            .iter()
            .find(|config| activation_timestamp(config) <= timestamp)
            .cloned()
    }
}

/// The activation timestamp a chain config was built for.
fn activation_timestamp(config: &ChainConfig) -> u64 {
    config
        .active_fork
        .activation
        .timestamp
        .first()
        .copied()
        .expect("always activated by timestamp")
}

/// Maps a zero-based blob-schedule index to its BPO fork.
fn bpo_fork(index: usize) -> Option<ProtocolFork> {
    match index {
        0 => Some(ProtocolFork::Bpo1),
        1 => Some(ProtocolFork::Bpo2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scheduled_spec() -> ChainSpec {
        let mut spec = ChainSpec::mainnet();
        spec.gloas_fork_epoch = Some(spec.blob_schedule().as_vec()[0].epoch + 1);
        spec
    }

    #[test]
    fn protocol_fork_ssz() {
        for fork in [
            ProtocolFork::Paris,
            ProtocolFork::Shanghai,
            ProtocolFork::Cancun,
            ProtocolFork::Prague,
            ProtocolFork::Osaka,
            ProtocolFork::Bpo1,
            ProtocolFork::Bpo2,
            ProtocolFork::Amsterdam,
        ] {
            let bytes = fork.as_ssz_bytes();
            assert_eq!(bytes, fork.as_u64().to_le_bytes());
            assert_eq!(ProtocolFork::from_ssz_bytes(&bytes).unwrap(), fork);
        }
        assert!(ProtocolFork::from_ssz_bytes(&99u64.to_le_bytes()).is_err());
    }

    #[test]
    fn chain_config_ssz_round_trip() {
        let config = ChainConfig {
            chain_id: 1,
            active_fork: ForkConfig::new(
                ProtocolFork::Cancun,
                ForkActivation::at_timestamp(1000),
                Some(BlobSchedule {
                    target: 0,
                    max: 6,
                    base_fee_update_fraction: 0,
                }),
            ),
        };
        assert_eq!(
            ChainConfig::from_ssz_bytes(&config.as_ssz_bytes()).unwrap(),
            config
        );
    }

    #[test]
    fn resolves_active_fork_by_timestamp() {
        let spec = scheduled_spec();
        let schedule = ChainConfigSchedule::new(&spec, 0, 32);
        let epoch_seconds = 12 * 32;

        let forks = [
            (ProtocolFork::Paris, spec.bellatrix_fork_epoch.unwrap()),
            (ProtocolFork::Shanghai, spec.capella_fork_epoch.unwrap()),
            (ProtocolFork::Cancun, spec.deneb_fork_epoch.unwrap()),
            (ProtocolFork::Prague, spec.electra_fork_epoch.unwrap()),
            (ProtocolFork::Osaka, spec.fulu_fork_epoch.unwrap()),
            (ProtocolFork::Bpo1, spec.blob_schedule().as_vec()[1].epoch),
            (ProtocolFork::Bpo2, spec.blob_schedule().as_vec()[0].epoch),
            (ProtocolFork::Amsterdam, spec.gloas_fork_epoch.unwrap()),
        ];

        for (idx, (fork, epoch)) in forks.into_iter().enumerate() {
            let timestamp = epoch.as_u64() * epoch_seconds;
            if idx == 0 {
                assert!(schedule.resolve(timestamp - 1).is_none());
            } else {
                assert_eq!(
                    schedule.resolve(timestamp - 1).unwrap().active_fork.fork,
                    forks[idx - 1].0
                );
            }

            let config = schedule.resolve(timestamp).unwrap();
            assert_eq!(config.chain_id, 1);
            assert_eq!(config.active_fork.fork, fork);
            assert_eq!(
                config.active_fork.activation.timestamp.first().copied(),
                Some(timestamp)
            );

            let carries_blobs = fork >= ProtocolFork::Cancun;
            let blob = config.active_fork.blob_schedule.first();
            assert_eq!(blob.is_some(), carries_blobs);
            if carries_blobs {
                assert_eq!(blob.unwrap().max, spec.max_blobs_per_block(epoch));
            }
        }
    }

    #[test]
    fn skips_far_future_unscheduled_forks() {
        // A fork at the far-future sentinel (a config's "not scheduled") must not overflow the
        // activation timestamp when building the schedule, and must never resolve.
        let mut spec = ChainSpec::mainnet();
        spec.gloas_fork_epoch = Some(spec.far_future_epoch);
        let schedule = ChainConfigSchedule::new(&spec, 0, 32);
        assert_ne!(
            schedule.resolve(u64::MAX).unwrap().active_fork.fork,
            ProtocolFork::Amsterdam
        );
    }

    #[test]
    fn resolves_higher_fork_on_shared_timestamp() {
        // Two forks activating at the same epoch, hence the same timestamp, resolve to the
        // higher-discriminant fork, matching the descending (timestamp, fork) sort.
        let mut spec = ChainSpec::mainnet();
        let shared = Epoch::new(5);
        spec.electra_fork_epoch = Some(shared);
        spec.fulu_fork_epoch = Some(shared);
        let schedule = ChainConfigSchedule::new(&spec, 0, 32);
        let timestamp = shared.as_u64() * 12 * 32;
        assert_eq!(
            schedule.resolve(timestamp).unwrap().active_fork.fork,
            ProtocolFork::Osaka
        );
    }
}

//! Test network builder for creating local beacon node networks.
//!
//! Provides a builder pattern for setting up test networks with beacon nodes,
//! validator clients, and execution nodes. Used by simulator tests like
//! `basic_sim` and `proof_service_sim`.

pub use crate::basic_sim::SUGGESTED_FEE_RECIPIENT;
pub use crate::local_network::{LocalNetwork, LocalNetworkParams, NodeType};
pub use environment::LoggerConfig;
pub use environment::test_utils::TestEnvironment;
pub use execution_layer::test_utils::MockClientEvent;
pub use logging::build_workspace_filter;
pub use node_test_rig::ApiTopic;
pub use node_test_rig::{
    ClientConfig, MockExecutionConfig, ValidatorFiles, environment::EnvironmentBuilder,
    testing_validator_config,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::path::PathBuf;
pub use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};
pub use types::{Address, ChainSpec, Epoch, EthSpec, MinimalEthSpec};

mod builder;
pub use builder::TestNetworkFixtureBuilder;

pub struct TestNetworkFixture<E: EthSpec = MinimalEthSpec> {
    pub env: TestEnvironment<E>,
    pub network: LocalNetwork<E>,
    pub config: TestConfig,
}

pub struct TestConfig {
    pub client: ClientConfig,
    pub execution: MockExecutionConfig,
}

impl TestNetworkFixture {
    pub fn builder() -> TestNetworkFixtureBuilder {
        TestNetworkFixtureBuilder::default()
    }

    /// Mark all payloads as valid on execution nodes.
    pub fn payloads_valid(&mut self) {
        self.network
            .execution_nodes
            .write()
            .iter()
            .for_each(|node| {
                node.server.all_payloads_valid();
            });
    }

    /// Wait for the network to reach genesis by sleeping until the genesis time.
    pub async fn wait_for_genesis(&self) -> anyhow::Result<()> {
        let duration_to_genesis = self
            .network
            .duration_to_genesis()
            .await
            .map_err(anyhow::Error::msg)?;
        tokio::time::sleep(duration_to_genesis).await;
        Ok(())
    }
}

// Ignore this for now because it conflicts with the `proof_engine` testing crate.
// We should migrate to defaulting to unused ports assigned by the OS instead of hardcoding ports.
#[tokio::test]
#[ignore]
async fn test_network_fixture_build() -> anyhow::Result<()> {
    let mut fixture = TestNetworkFixtureBuilder::default()
        .map_network_params(|params| {
            params.genesis_delay = 20;
        })
        .map_spec(|spec| {
            spec.seconds_per_slot = 1;
            spec.slot_duration_ms = 1000;
            spec.min_genesis_time = 0;
            spec.altair_fork_epoch = Some(Epoch::new(0));
            spec.bellatrix_fork_epoch = Some(Epoch::new(0));
            spec.capella_fork_epoch = Some(Epoch::new(0));
            spec.deneb_fork_epoch = Some(Epoch::new(0));
            spec.electra_fork_epoch = Some(Epoch::new(0));
            spec.fulu_fork_epoch = Some(Epoch::new(2));
        })
        .build()
        .await?;
    fixture.payloads_valid();

    fixture.wait_for_genesis().await?;

    tokio::time::sleep(std::time::Duration::from_secs(60)).await;

    Ok(())
}

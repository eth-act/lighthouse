//! [`ProofEngineTestRig`] — a thin wrapper over [`TestNetworkFixture`] for EIP-8025 tests.
//!
//! Provides a clean API for building standard proof engine test topologies and asserting
//! on mock proof engine events, insulating individual tests from `LocalNetwork` internals.

use anyhow::anyhow;
use simulator::test_utils::{
    BeaconNodeHttpClient, Epoch, EventStream, InternalBeaconNodeEvent, LocalNetworkParams,
    NodeType, TestNetworkFixture, TestNetworkFixtureBuilder,
};
use types::MinimalEthSpec;

pub use simulator::test_utils::MockEventStream;

pub type E = MinimalEthSpec;

/// Test harness for EIP-8025 proof engine integration tests.
pub struct ProofEngineTestRig {
    pub fixture: TestNetworkFixture<E>,
}

impl ProofEngineTestRig {
    /// Wrap a fixture directly.
    pub fn new(fixture: TestNetworkFixture<E>) -> Self {
        Self { fixture }
    }

    /// Standard topology: 1 vanilla node + 1 proof generator + 1 proof verifier.
    /// All forks activate at genesis, 1-second slots.
    pub async fn standard() -> anyhow::Result<Self> {
        Ok(Self::new(base_builder().build().await?))
    }

    /// Sync topology: 1 vanilla node + 1 proof generator, no verifier, 1 delayed node slot.
    /// Used for testing late-joining proof verifier sync recovery.
    pub async fn sync_topology() -> anyhow::Result<Self> {
        Ok(Self::new(
            base_builder()
                .map_spec(|spec| {
                    // Collapse all columns onto a single subnet so the small network can cover them.
                    spec.data_column_sidecar_subnet_count = 1;
                    spec.number_of_custody_groups = 8;
                })
                .map_network_params(|params| {
                    params.proof_verifier_nodes = 0;
                    params.delayed_nodes = 1;
                })
                .build()
                .await?,
        ))
    }

    /// Multi-generator topology: 1 vanilla node + 2 proof generators + 1 proof verifier.
    /// Used for testing that each generator is independently wired.
    pub async fn multi_generator() -> anyhow::Result<Self> {
        Ok(Self::new(
            base_builder()
                .map_network_params(|params| {
                    params.proof_generator_nodes = 2;
                })
                .build()
                .await?,
        ))
    }

    /// Subscribe to the nth proof generator node's event stream (0-indexed).
    pub fn proof_generator_events(&self, n: usize) -> anyhow::Result<MockEventStream> {
        let idx = self.fixture.config.network_params.node_count + n;
        self.fixture
            .network
            .node_subscribe_client_events(idx)
            .map(MockEventStream::from)
            .ok_or_else(|| anyhow!("no proof generator at index {n}"))
    }

    /// Subscribe to the nth proof verifier node's event stream (0-indexed).
    pub fn proof_verifier_events(&self, n: usize) -> anyhow::Result<MockEventStream> {
        let params = &self.fixture.config.network_params;
        let idx = params.node_count + params.proof_generator_nodes + n;
        self.fixture
            .network
            .node_subscribe_client_events(idx)
            .map(MockEventStream::from)
            .ok_or_else(|| anyhow!("no proof verifier at index {n}"))
    }

    /// Subscribe to the internal event bus for the nth default node (0-indexed).
    pub fn default_node_chain_events(
        &self,
        n: usize,
    ) -> anyhow::Result<EventStream<InternalBeaconNodeEvent>> {
        self.fixture
            .network
            .node_subscribe_internal_events(n)
            .map(EventStream::from)
            .ok_or_else(|| anyhow!("no default node at index {n}"))
    }

    /// Subscribe to the internal event bus for the nth proof generator node (0-indexed).
    pub fn proof_generator_chain_events(
        &self,
        n: usize,
    ) -> anyhow::Result<EventStream<InternalBeaconNodeEvent>> {
        let idx = self.fixture.config.network_params.node_count + n;
        self.fixture
            .network
            .node_subscribe_internal_events(idx)
            .map(EventStream::from)
            .ok_or_else(|| anyhow!("no proof generator at index {n}"))
    }

    /// Subscribe to the internal event bus for the nth proof verifier node (0-indexed).
    pub fn proof_verifier_chain_events(
        &self,
        n: usize,
    ) -> anyhow::Result<EventStream<InternalBeaconNodeEvent>> {
        let params = &self.fixture.config.network_params;
        let idx = params.node_count + params.proof_generator_nodes + n;
        self.fixture
            .network
            .node_subscribe_internal_events(idx)
            .map(EventStream::from)
            .ok_or_else(|| anyhow!("no proof verifier at index {n}"))
    }

    /// Return HTTP clients for all beacon nodes in the network.
    pub fn remote_nodes(&self) -> anyhow::Result<Vec<BeaconNodeHttpClient>> {
        self.fixture
            .network
            .remote_nodes()
            .map_err(anyhow::Error::msg)
    }

    /// Return an HTTP client for the nth default node (0-indexed).
    pub fn default_node(&self, n: usize) -> anyhow::Result<BeaconNodeHttpClient> {
        let idx = n;
        self.fixture
            .network
            .remote_node(idx)
            .ok_or_else(|| anyhow!("no default node at index {n}"))
    }

    /// Return an HTTP client for the nth proof generator node (0-indexed).
    pub fn proof_generator_node(&self, n: usize) -> anyhow::Result<BeaconNodeHttpClient> {
        let idx = self.fixture.config.network_params.node_count + n;
        self.fixture
            .network
            .remote_node(idx)
            .ok_or_else(|| anyhow!("no proof generator node at index {n}"))
    }

    /// Return an HTTP client for the nth proof verifier node (0-indexed).
    pub fn proof_verifier_node(&self, n: usize) -> anyhow::Result<BeaconNodeHttpClient> {
        let params = &self.fixture.config.network_params;
        let idx = params.node_count + params.proof_generator_nodes + n;
        self.fixture
            .network
            .remote_node(idx)
            .ok_or_else(|| anyhow!("no proof verifier node at index {n}"))
    }

    /// Add a proof verifier node dynamically and return its mock and internal event streams.
    pub async fn add_proof_verifier_and_subscribe(
        &self,
    ) -> anyhow::Result<(MockEventStream, EventStream<InternalBeaconNodeEvent>)> {
        let client_config = self.fixture.config.client.clone();
        let exec_config = self.fixture.config.execution.clone();

        // Await the node start so we know its index in beacon_nodes before subscribing.
        // Spawning + sleeping is unreliable on slow CI runners where node startup takes
        // longer than the fixed sleep duration.
        self.fixture
            .network
            .add_beacon_node(client_config, exec_config, NodeType::ProofVerifier)
            .await
            .map_err(anyhow::Error::msg)?;

        // The new verifier is the last beacon node; subscribe to both event streams.
        let idx = self
            .fixture
            .network
            .beacon_nodes
            .read()
            .len()
            .saturating_sub(1);
        let mock = self
            .fixture
            .network
            .node_subscribe_client_events(idx)
            .map(MockEventStream::from)
            .ok_or_else(|| anyhow!("newly added verifier node has no mock event stream"))?;
        let chain = self
            .fixture
            .network
            .node_subscribe_internal_events(idx)
            .map(EventStream::from)
            .ok_or_else(|| anyhow!("newly added verifier node has no beacon chain"))?;
        Ok((mock, chain))
    }

    /// Builder escape hatch for custom topologies.
    pub fn builder() -> TestNetworkFixtureBuilder {
        base_builder()
    }
}

/// Base builder shared by all standard topologies.
fn base_builder() -> TestNetworkFixtureBuilder {
    TestNetworkFixture::builder()
        .map_spec(|spec| {
            spec.seconds_per_slot = 1;
            spec.slot_duration_ms = 1000;
            spec.min_genesis_time = 0;
            spec.altair_fork_epoch = Some(Epoch::new(0));
            spec.bellatrix_fork_epoch = Some(Epoch::new(0));
            spec.capella_fork_epoch = Some(Epoch::new(0));
            spec.deneb_fork_epoch = Some(Epoch::new(0));
            spec.electra_fork_epoch = Some(Epoch::new(0));
            spec.fulu_fork_epoch = Some(Epoch::new(0));
        })
        .with_network_params(LocalNetworkParams {
            validator_count: 4,
            node_count: 1,
            proposer_nodes: 0,
            extra_nodes: 0,
            proof_generator_nodes: 1,
            proof_verifier_nodes: 1,
            delayed_nodes: 0,
            genesis_delay: 40,
        })
        // Disable the activation delay so proof sync fires immediately after the node
        // becomes head-synced. The default (10 slots) is intended for production to let
        // the beacon processor drain, but in CI each slot can take several seconds,
        // causing the countdown to exhaust the test timeout.
        .map_client_config(|config| {
            config.network.proof_sync_activation_slots = 0;
        })
}

//! Topology and lifecycle of the proof test network.

use crate::{E, NodeChain};
use node_test_rig::{
    ClientConfig, ValidatorFiles,
    environment::{EnvironmentBuilder, RuntimeContext},
    eth2::BeaconNodeHttpClient,
    testing_validator_config,
};
use proof_engine::{ProofEngine, test_utils::MockProofEngine};
use simulator::local_network::{LocalNetwork, LocalNetworkParams};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::info;
use tracing_subscriber::EnvFilter;
use types::{Address, ChainSpec, Epoch};

/// Fee recipient configured for every validator client, as in the simulator.
const FEE_RECIPIENT: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// Node log filter used when `RUST_LOG` is unset.
const DEFAULT_LOG_FILTER: &str = "warn,execution_proof_network_tests=info";

/// Serialises networks within one process: every node binds the simulator's fixed ports.
static NETWORK_LOCK: Mutex<()> = Mutex::new(());

/// Configuration of one beacon node in the network.
#[derive(Debug, Clone)]
pub struct NodeSpec {
    /// Proof data accepted by this node's mock proof engine. `None` starts the node without a
    /// proof engine: it neither verifies proofs nor subscribes to the `execution_proof` topic.
    pub valid_proof_data: Option<Vec<Vec<u8>>>,
    /// Whether a validator client is attached to this node.
    pub validators: bool,
}

impl NodeSpec {
    /// A node without a proof engine.
    pub fn plain() -> Self {
        Self {
            valid_proof_data: None,
            validators: false,
        }
    }

    /// A node whose mock proof engine accepts exactly `valid_proof_data`.
    pub fn verifier(valid_proof_data: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            valid_proof_data: Some(valid_proof_data.into_iter().collect()),
            validators: false,
        }
    }

    /// Attach a validator client to this node.
    pub fn with_validators(mut self) -> Self {
        self.validators = true;
        self
    }

    fn has_proof_engine(&self) -> bool {
        self.valid_proof_data.is_some()
    }
}

/// Network-wide parameters.
#[derive(Debug, Clone)]
pub struct ProofNetworkConfig {
    /// Nodes to start, in index order. The first node is the boot node.
    pub nodes: Vec<NodeSpec>,
    /// Genesis validators, split evenly across the nodes with `validators` set.
    pub validator_count: usize,
    pub slot_duration_ms: u64,
    /// Seconds between network start and genesis; must cover node and validator startup.
    pub genesis_delay_secs: u64,
    /// All earlier forks activate at genesis. Execution proofs exist from Gloas onwards.
    pub gloas_fork_epoch: u64,
    /// Node log filter, overridden by `RUST_LOG`.
    pub log_filter: String,
}

impl ProofNetworkConfig {
    /// Defaults tuned for release builds: 2-second slots, Gloas at genesis and a genesis delay
    /// long enough to start the nodes and validators. Gloas genesis needs a validator in every
    /// slot's beacon committee (the payload timeliness committee is drawn from it), so the
    /// validator count stays at two per minimal-spec slot.
    pub fn new(nodes: Vec<NodeSpec>) -> Self {
        Self {
            nodes,
            validator_count: 16,
            slot_duration_ms: 2000,
            genesis_delay_secs: 30,
            gloas_fork_epoch: 0,
            log_filter: DEFAULT_LOG_FILTER.to_string(),
        }
    }
}

/// A running network of beacon nodes with per-node proof engines.
pub struct ProofNetwork {
    pub(crate) network: LocalNetwork<E>,
    nodes: Vec<NodeSpec>,
    spec: Arc<ChainSpec>,
}

impl ProofNetwork {
    /// Start the network, run `test` on the environment's runtime, then tear everything down.
    ///
    /// Follows the simulator lifecycle: one multi-threaded tokio runtime per network, nodes
    /// added through [`LocalNetwork`], and the runtime shut down once the test returns. Networks
    /// are serialised process-wide because nodes bind fixed ports.
    pub fn run<F, Fut>(config: ProofNetworkConfig, test: F) -> Result<(), String>
    where
        F: FnOnce(ProofNetwork) -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        let _serial = NETWORK_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        init_tracing(&config.log_filter);

        let mut env = EnvironmentBuilder::minimal()
            .multi_threaded_tokio_runtime()?
            .build()?;
        let spec = Arc::new(chain_spec(&env.eth2_config.spec, &config));
        env.eth2_config.spec = spec.clone();
        let context = env.core_context();

        let result = env.runtime().block_on(async {
            let network = Self::build(config, spec, context).await?;
            test(network).await
        });

        env.fire_signal();
        env.shutdown_on_idle();
        result
    }

    async fn build(
        config: ProofNetworkConfig,
        spec: Arc<ChainSpec>,
        context: RuntimeContext<E>,
    ) -> Result<Self, String> {
        let ProofNetworkConfig {
            nodes,
            validator_count,
            genesis_delay_secs,
            ..
        } = config;
        if nodes.is_empty() {
            return Err("a proof network needs at least one node".to_string());
        }

        let params = LocalNetworkParams {
            validator_count,
            node_count: nodes.len(),
            proposer_nodes: 0,
            extra_nodes: 0,
            genesis_delay: genesis_delay_secs,
        };
        let (network, base_config, execution_config) =
            LocalNetwork::create_local_network(None, None, params, context.clone()).await?;

        for (index, node) in nodes.iter().enumerate() {
            let mut client_config = base_config.clone();
            configure_proof_engine(&mut client_config, node);
            info!(
                node = index,
                proof_engine = node.has_proof_engine(),
                validators = node.validators,
                "Starting beacon node"
            );
            network
                .add_beacon_node(client_config, execution_config.clone(), false)
                .await?;
        }

        let validator_nodes: Vec<usize> = nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.validators)
            .map(|(index, _)| index)
            .collect();
        for (position, node_index) in validator_nodes.iter().enumerate() {
            let per_node = validator_count / validator_nodes.len();
            let start = position * per_node;
            let end = if position + 1 == validator_nodes.len() {
                validator_count
            } else {
                start + per_node
            };
            let indices: Vec<usize> = (start..end).collect();
            info!(node = node_index, validators = ?indices, "Starting validator client");
            let files = context
                .executor
                .spawn_blocking_handle(
                    move || ValidatorFiles::with_keystores(&indices),
                    "validator_keystore_generation",
                )
                .ok_or("runtime is shutting down")?
                .await
                .map_err(|e| format!("keystore generation panicked: {e:?}"))??;
            let mut validator_config = testing_validator_config();
            validator_config.validator_store.fee_recipient = Some(Address::from(FEE_RECIPIENT));
            network
                .add_validator_client(validator_config, *node_index, files)
                .await?;
        }

        // The mock execution layers are infallible.
        network
            .execution_nodes
            .read()
            .iter()
            .for_each(|node| node.server.all_payloads_valid());

        Ok(Self {
            network,
            nodes,
            spec,
        })
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn node_spec(&self, node: usize) -> Result<&NodeSpec, String> {
        self.nodes.get(node).ok_or(format!("no node {node}"))
    }

    pub fn spec(&self) -> &ChainSpec {
        &self.spec
    }

    pub fn slot_duration(&self) -> Duration {
        self.spec.get_slot_duration()
    }

    /// The underlying simulator network, for scenarios the harness does not cover.
    pub fn local_network(&self) -> &LocalNetwork<E> {
        &self.network
    }

    /// The beacon chain of node `node`.
    pub fn chain(&self, node: usize) -> Result<NodeChain, String> {
        self.network
            .beacon_nodes
            .read()
            .get(node)
            .ok_or(format!("no node {node}"))?
            .client
            .beacon_chain()
            .ok_or(format!("node {node} has no beacon chain"))
    }

    /// An HTTP client for node `node`'s Beacon API.
    pub fn remote_node(&self, node: usize) -> Result<BeaconNodeHttpClient, String> {
        self.network
            .beacon_nodes
            .read()
            .get(node)
            .ok_or(format!("no node {node}"))?
            .remote_node()
    }

    /// Sleep until genesis. Returns immediately if genesis has passed.
    pub async fn wait_for_genesis(&self) -> Result<(), String> {
        match self.network.duration_to_genesis().await {
            Ok(duration) => {
                info!(seconds = duration.as_secs(), "Waiting for genesis");
                tokio::time::sleep(duration).await;
            }
            Err(reason) => info!(reason, "Genesis has already passed"),
        }
        Ok(())
    }
}

fn configure_proof_engine(client_config: &mut ClientConfig, node: &NodeSpec) {
    if let Some(valid_proof_data) = &node.valid_proof_data {
        client_config.proof_engine_override = Some(ProofEngine::new(MockProofEngine::new(
            valid_proof_data.iter().cloned(),
        )));
        client_config.network.enable_execution_proof = true;
    }
}

fn chain_spec(base: &ChainSpec, config: &ProofNetworkConfig) -> ChainSpec {
    let mut spec = base
        .clone()
        .set_slot_duration_ms::<E>(config.slot_duration_ms);
    spec.genesis_delay = config.genesis_delay_secs;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = config.validator_count as u64;
    let genesis = Some(Epoch::new(0));
    spec.altair_fork_epoch = genesis;
    spec.bellatrix_fork_epoch = genesis;
    spec.capella_fork_epoch = genesis;
    spec.deneb_fork_epoch = genesis;
    spec.electra_fork_epoch = genesis;
    spec.fulu_fork_epoch = genesis;
    spec.gloas_fork_epoch = Some(Epoch::new(config.gloas_fork_epoch));
    spec
}

fn init_tracing(default_filter: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

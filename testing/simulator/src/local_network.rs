use crate::checks::epoch_delay;
use beacon_chain::custody_context::NodeCustodyType;
use kzg::trusted_setup::get_trusted_setup;
use lighthouse_network::types::Enr;
use node_test_rig::{
    ClientConfig, ClientGenesis, LocalBeaconNode, LocalExecutionNode, LocalValidatorClient,
    MockExecutionConfig, ValidatorConfig, ValidatorFiles,
    environment::RuntimeContext,
    eth2::{BeaconNodeHttpClient, types::StateId},
    testing_client_config,
};
use node_test_rig::{LocalProofEngine, MockProofEngineConfig};
use parking_lot::RwLock;
use sensitive_url::SensitiveUrl;
use std::{
    net::Ipv4Addr,
    ops::Deref,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use task_executor::TaskExecutor;
use tempfile::tempdir;
use types::{ChainSpec, Epoch, EthSpec};
use validator_http_api::{Config as ValidatorHttpConfig, PK_FILENAME};

pub const TERMINAL_BLOCK: u64 = 0;

#[derive(Debug, Copy, Clone)]
pub enum NodeType {
    Default,
    Proposer,
    ProofVerifier,
    ProofGenerator,
}

impl NodeType {
    /// Returns true if this node is a proposer node.
    pub fn is_proposer(&self) -> bool {
        matches!(self, NodeType::Proposer)
    }

    /// Returns true if this node is a proof verifier node.
    pub fn is_proof_verifier(&self) -> bool {
        matches!(self, NodeType::ProofVerifier)
    }

    /// Returns true if this node is a proof generator node.
    pub fn is_proof_generator(&self) -> bool {
        matches!(self, NodeType::ProofGenerator)
    }

    /// Returns true if this node requires a proof node.
    pub fn requires_proof_node(&self) -> bool {
        matches!(self, NodeType::ProofVerifier | NodeType::ProofGenerator)
    }

    /// Returns true if this node requires an execution node.
    pub fn requires_execution_node(&self) -> bool {
        matches!(
            self,
            NodeType::Default | NodeType::Proposer | NodeType::ProofGenerator
        )
    }
}

#[derive(Debug, Clone)]
pub struct LocalNetworkParams {
    pub validator_count: usize,
    pub node_count: usize,
    pub proposer_nodes: usize,
    pub proof_generator_nodes: usize,
    pub proof_verifier_nodes: usize,
    pub extra_nodes: usize,
    pub genesis_delay: u64,
}

impl LocalNetworkParams {
    pub fn node_type(&self, node_idx: usize) -> NodeType {
        if node_idx < self.node_count {
            NodeType::Default
        } else if node_idx < self.node_count + self.proposer_nodes {
            NodeType::Proposer
        } else if node_idx < self.node_count + self.proposer_nodes + self.proof_generator_nodes {
            NodeType::ProofGenerator
        } else if node_idx
            < self.node_count
                + self.proposer_nodes
                + self.proof_generator_nodes
                + self.proof_verifier_nodes
        {
            NodeType::ProofVerifier
        } else {
            panic!("Invalid node index: {}", node_idx);
        }
    }
}

fn default_client_config(network_params: LocalNetworkParams, genesis_time: u64) -> ClientConfig {
    let mut beacon_config = testing_client_config();

    beacon_config.genesis = ClientGenesis::InteropMerge {
        validator_count: network_params.validator_count,
        genesis_time,
    };
    beacon_config.network.target_peers = network_params.node_count
        + network_params.proposer_nodes
        + network_params.proof_generator_nodes
        + network_params.proof_verifier_nodes
        + network_params.extra_nodes
        - 1;
    beacon_config.network.enr_address = (Some(Ipv4Addr::LOCALHOST), None);
    beacon_config.network.enable_light_client_server = true;
    beacon_config.network.discv5_config.enable_packet_filter = false;
    beacon_config.chain.enable_light_client_server = true;
    beacon_config.chain.optimistic_finalized_sync = false;
    beacon_config.trusted_setup = get_trusted_setup();
    beacon_config.chain.node_custody_type = NodeCustodyType::Supernode;

    beacon_config
}

fn default_mock_execution_config<E: EthSpec>(
    spec: &ChainSpec,
    genesis_time: u64,
) -> MockExecutionConfig {
    let mut mock_execution_config = MockExecutionConfig::default();

    if let Some(capella_fork_epoch) = spec.capella_fork_epoch {
        mock_execution_config.shanghai_time = Some(
            genesis_time
                + spec.seconds_per_slot * E::slots_per_epoch() * capella_fork_epoch.as_u64(),
        )
    }
    if let Some(deneb_fork_epoch) = spec.deneb_fork_epoch {
        mock_execution_config.cancun_time = Some(
            genesis_time + spec.seconds_per_slot * E::slots_per_epoch() * deneb_fork_epoch.as_u64(),
        )
    }
    if let Some(electra_fork_epoch) = spec.electra_fork_epoch {
        mock_execution_config.prague_time = Some(
            genesis_time
                + spec.seconds_per_slot * E::slots_per_epoch() * electra_fork_epoch.as_u64(),
        )
    }
    if let Some(fulu_fork_epoch) = spec.fulu_fork_epoch {
        mock_execution_config.osaka_time = Some(
            genesis_time + spec.seconds_per_slot * E::slots_per_epoch() * fulu_fork_epoch.as_u64(),
        )
    }

    mock_execution_config
}

/// Helper struct to reduce `Arc` usage.
pub struct Inner<E: EthSpec> {
    pub context: RuntimeContext<E>,
    pub beacon_nodes: RwLock<Vec<LocalBeaconNode<E>>>,
    pub proposer_nodes: RwLock<Vec<LocalBeaconNode<E>>>,
    pub validator_clients: RwLock<Vec<LocalValidatorClient<E>>>,
    pub execution_nodes: RwLock<Vec<LocalExecutionNode<E>>>,
    pub proof_engines: RwLock<Vec<node_test_rig::LocalProofEngine<E>>>,
}

/// Represents a set of interconnected `LocalBeaconNode` and `LocalValidatorClient`.
///
/// Provides functions to allow adding new beacon nodes and validators.
pub struct LocalNetwork<E: EthSpec> {
    inner: Arc<Inner<E>>,
}

impl<E: EthSpec> Clone for LocalNetwork<E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<E: EthSpec> Deref for LocalNetwork<E> {
    type Target = Inner<E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<E: EthSpec> LocalNetwork<E> {
    pub async fn create_local_network(
        client_config: Option<ClientConfig>,
        mock_execution_config: Option<MockExecutionConfig>,
        network_params: LocalNetworkParams,
        context: RuntimeContext<E>,
    ) -> Result<(LocalNetwork<E>, ClientConfig, MockExecutionConfig), String> {
        let genesis_time: u64 = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "should get system time")?
            + Duration::from_secs(network_params.genesis_delay))
        .as_secs();

        let beacon_config = if let Some(config) = client_config {
            config
        } else {
            default_client_config(network_params, genesis_time)
        };

        let execution_config = if let Some(config) = mock_execution_config {
            config
        } else {
            default_mock_execution_config::<E>(&context.eth2_config().spec, genesis_time)
        };

        let network = Self {
            inner: Arc::new(Inner {
                context,
                beacon_nodes: RwLock::new(vec![]),
                proposer_nodes: RwLock::new(vec![]),
                execution_nodes: RwLock::new(vec![]),
                validator_clients: RwLock::new(vec![]),
                proof_engines: RwLock::new(vec![]),
            }),
        };

        Ok((network, beacon_config, execution_config))
    }

    /// Returns the `TaskExecutor` used by this `LocalNetwork`.
    pub fn executor(&self) -> &TaskExecutor {
        &self.context.executor
    }

    /// Returns the number of beacon nodes in the network.
    ///
    /// Note: does not count nodes that are external to this `LocalNetwork` that may have connected
    /// (e.g., another Lighthouse process on the same machine.)
    pub fn beacon_node_count(&self) -> usize {
        self.beacon_nodes.read().len()
    }

    /// Returns the number of proposer nodes in the network.
    ///
    /// Note: does not count nodes that are external to this `LocalNetwork` that may have connected
    /// (e.g., another Lighthouse process on the same machine.)
    pub fn proposer_node_count(&self) -> usize {
        self.proposer_nodes.read().len()
    }

    /// Returns the number of proof engines in the network.
    pub fn proof_engine_count(&self) -> usize {
        self.proof_engines.read().len()
    }

    /// Returns the number of validator clients in the network.
    ///
    /// Note: does not count nodes that are external to this `LocalNetwork` that may have connected
    /// (e.g., another Lighthouse process on the same machine.)
    pub fn validator_client_count(&self) -> usize {
        self.validator_clients.read().len()
    }

    async fn construct_boot_node(
        &self,
        mut beacon_config: ClientConfig,
        mock_execution_config: MockExecutionConfig,
    ) -> Result<(LocalBeaconNode<E>, LocalExecutionNode<E>), String> {
        beacon_config.network.discv5_config.table_filter = |_| true;

        // The boot node is a full data-availability node and should custody all columns from
        // genesis. Setting Supernode ensures cgc = number_of_custody_groups from startup so
        // no validator-registration-triggered cgc jump occurs. Without this, the first proposer
        // preparation call from the validator client causes cgc to increase from
        // spec.custody_requirement → number_of_custody_groups, which stamps
        // earliest_available_slot = current_slot and prevents late-joining nodes from syncing
        // from epoch 0.
        beacon_config.chain.node_custody_type = NodeCustodyType::Supernode;

        let execution_node = LocalExecutionNode::new(self.context.clone(), mock_execution_config);

        beacon_config.execution_layer = Some(execution_layer::Config {
            execution_endpoint: Some(SensitiveUrl::parse(&execution_node.server.url()).unwrap()),
            default_datadir: execution_node.datadir.path().to_path_buf(),
            secret_file: Some(execution_node.datadir.path().join("jwt.hex")),
            ..Default::default()
        });

        let beacon_node = LocalBeaconNode::production(self.context.clone(), beacon_config).await?;

        Ok((beacon_node, execution_node))
    }

    async fn construct_beacon_node(
        &self,
        mut beacon_config: ClientConfig,
        mock_execution_config: MockExecutionConfig,
        node_type: NodeType,
    ) -> Result<
        (
            LocalBeaconNode<E>,
            Option<LocalExecutionNode<E>>,
            Option<LocalProofEngine<E>>,
        ),
        String,
    > {
        beacon_config.network.discv5_config.table_filter = |_| true;
        beacon_config.network.proposer_only = node_type.is_proposer();

        let execution_node = if node_type.requires_execution_node() {
            let execution_node =
                LocalExecutionNode::new(self.context.clone(), mock_execution_config);

            // Pair the beacon node and execution node.
            beacon_config.execution_layer = Some(execution_layer::Config {
                execution_endpoint: Some(
                    SensitiveUrl::parse(&execution_node.server.url()).unwrap(),
                ),
                default_datadir: execution_node.datadir.path().to_path_buf(),
                secret_file: Some(execution_node.datadir.path().join("jwt.hex")),
                ..Default::default()
            });
            Some(execution_node)
        } else {
            beacon_config.execution_layer = None;
            None
        };

        let proof_node = if node_type.requires_proof_node() {
            let config = MockProofEngineConfig::default();
            let proof_engine = LocalProofEngine::new(self.context.clone(), config).await;
            if let Some(exeuction_layer) = beacon_config.execution_layer.as_mut() {
                exeuction_layer.proof_engine_endpoint = Some(proof_engine.server.url().clone());
            } else {
                beacon_config.execution_layer = Some(execution_layer::Config {
                    proof_engine_endpoint: Some(proof_engine.server.url().clone()),
                    ..Default::default()
                });
            }
            // Subscribe to the execution_proof gossip topic for nodes with a proof engine.
            beacon_config.network.enable_execution_proof = true;
            Some(proof_engine)
        } else {
            None
        };

        if node_type.is_proof_verifier() {
            beacon_config.chain.optimistic_finalized_sync = true;
            beacon_config.network.boot_nodes_enr.push(self.proof_generator_enr().ok_or_else(|| {
                "Proof verifier node requires a proof generator node to connect to, but no proof generator node found in the network".to_string()
            })?);
        }

        // Construct beacon node using the config,
        let beacon_node = LocalBeaconNode::production(self.context.clone(), beacon_config).await?;

        Ok((beacon_node, execution_node, proof_node))
    }

    pub fn proof_generator_enr(&self) -> Option<Enr> {
        self.beacon_nodes
            .read()
            .last()
            .and_then(|bn| bn.client.enr())
    }

    /// Returns the boot node's ENR once it has a valid (non-zero) TCP port, or an error if
    /// the port isn't populated within 10 seconds.
    async fn boot_node_enr(&self) -> Result<Option<Enr>, String> {
        // If there are no beacon nodes yet, the network hasn't started — return None immediately.
        if self.beacon_nodes.read().is_empty() {
            return Ok(None);
        }

        for _ in 0..100 {
            if let Some(enr) = self
                .beacon_nodes
                .read()
                .first()
                .and_then(|bn| bn.client.enr())
                .filter(|e| e.tcp4().is_some_and(|p| p != 0))
            {
                return Ok(Some(enr));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("Boot node ENR did not get a valid TCP port within 10 seconds".to_string())
    }

    /// Adds a beacon node to the network, connecting to the 0'th beacon node via ENR.
    pub async fn add_beacon_node(
        &self,
        mut beacon_config: ClientConfig,
        mock_execution_config: MockExecutionConfig,
        node_type: NodeType,
    ) -> Result<(), String> {
        let (beacon_node, execution_node, proof_node) =
            if let Some(boot_node) = self.boot_node_enr().await? {
                // Network already exists. The boot node ENR has a valid TCP port; use it to
                // bootstrap the new node.
                beacon_config.network.boot_nodes_enr.push(boot_node);
                self.construct_beacon_node(beacon_config, mock_execution_config, node_type)
                    .await?
            } else {
                // Network does not exist. We construct a boot node.
                let (bn, en) = self
                    .construct_boot_node(beacon_config, mock_execution_config)
                    .await?;
                (bn, Some(en), None)
            };

        // Add nodes to the network.
        if let Some(execution_node) = execution_node {
            self.execution_nodes.write().push(execution_node);
        }
        if let Some(proof_node) = proof_node {
            self.proof_engines.write().push(proof_node);
        }
        match node_type {
            NodeType::Proposer => self.proposer_nodes.write().push(beacon_node),
            _ => self.beacon_nodes.write().push(beacon_node),
        }

        Ok(())
    }

    // Add a new node with a delay. This node will not have validators and is only used to test
    // sync.
    pub async fn add_beacon_node_with_delay(
        &self,
        beacon_config: ClientConfig,
        mock_execution_config: MockExecutionConfig,
        wait_until_epoch: u64,
        slot_duration: Duration,
        slots_per_epoch: u64,
    ) -> Result<(), String> {
        epoch_delay(Epoch::new(wait_until_epoch), slot_duration, slots_per_epoch).await;

        self.add_beacon_node(beacon_config, mock_execution_config, NodeType::Default)
            .await?;

        Ok(())
    }

    /// Adds a validator client to the network, connecting it to the beacon node with index
    /// `beacon_node`.
    pub async fn add_validator_client(
        &self,
        mut validator_config: ValidatorConfig,
        beacon_node: usize,
        validator_files: ValidatorFiles,
        node_type: NodeType,
    ) -> Result<(), String> {
        let context = self.context.clone();
        let socket_addr = {
            let read_lock = self.beacon_nodes.read();
            let beacon_node = read_lock
                .get(beacon_node)
                .ok_or_else(|| format!("No beacon node for index {}", beacon_node))?;
            beacon_node
                .client
                .http_api_listen_addr()
                .expect("Must have http started")
        };
        // If there is a proposer node for the same index, we will use that for proposing
        let proposer_socket_addr = {
            let read_lock = self.proposer_nodes.read();
            read_lock.get(beacon_node).map(|proposer_node| {
                proposer_node
                    .client
                    .http_api_listen_addr()
                    .expect("Must have http started")
            })
        };

        let beacon_node = SensitiveUrl::parse(
            format!("http://{}:{}", socket_addr.ip(), socket_addr.port()).as_str(),
        )
        .unwrap();
        validator_config.beacon_nodes = vec![beacon_node];

        // If this is a proof generator node, we will set the proof engine endpoint to the first proof engine in the network.
        if node_type.is_proof_generator() {
            let proof_engine_url = self
                .proof_engines
                .read()
                .first()
                .map(|proof_engine| proof_engine.server.url())
                // use expect here to fail fast if the network has been instantiated incorrectly
                // even though we wrap in Some(..) again in the line below.
                .expect("Proof generator node must exist if validator is a proof generator");
            validator_config.proof_engine_endpoint = Some(proof_engine_url);
            let token_path = tempdir().unwrap().path().join(PK_FILENAME);
            validator_config.http_api = ValidatorHttpConfig {
                enabled: true,
                listen_addr: Ipv4Addr::LOCALHOST.into(),
                listen_port: 0, // use random port
                allow_origin: None,
                allow_keystore_export: true,
                store_passwords_in_secrets_dir: false,
                http_token_path: token_path,
                bn_long_timeouts: false,
            };
        };

        // If we have a proposer node established, use it.
        if let Some(proposer_socket_addr) = proposer_socket_addr {
            let url = SensitiveUrl::parse(
                format!(
                    "http://{}:{}",
                    proposer_socket_addr.ip(),
                    proposer_socket_addr.port()
                )
                .as_str(),
            )
            .unwrap();
            validator_config.proposer_nodes = vec![url];
        }

        let validator_client = LocalValidatorClient::production_with_insecure_keypairs(
            context,
            validator_config,
            validator_files,
        )
        .await?;

        // Set the callback url on the proof engine if this is a proof generator node.
        if node_type.is_proof_generator() {
            let validator_http_client = validator_client
                .http_client()?
                .expect("HTTP client should be available for proof generator node");
            self.proof_engines
                .write()
                .first_mut()
                .unwrap()
                .set_validator_client(validator_http_client);
        }

        self.validator_clients.write().push(validator_client);
        Ok(())
    }

    pub async fn add_validator_client_with_fallbacks(
        &self,
        mut validator_config: ValidatorConfig,
        beacon_nodes: Vec<usize>,
        validator_files: ValidatorFiles,
    ) -> Result<(), String> {
        let context = self.context.clone();
        let mut beacon_node_urls = vec![];
        for beacon_node in beacon_nodes {
            let socket_addr = {
                let read_lock = self.beacon_nodes.read();
                let beacon_node = read_lock
                    .get(beacon_node)
                    .ok_or_else(|| format!("No beacon node for index {}", beacon_node))?;
                beacon_node
                    .client
                    .http_api_listen_addr()
                    .expect("Must have http started")
            };
            let beacon_node_url = SensitiveUrl::parse(
                format!("http://{}:{}", socket_addr.ip(), socket_addr.port()).as_str(),
            )
            .unwrap();
            beacon_node_urls.push(beacon_node_url);
        }

        validator_config.beacon_nodes = beacon_node_urls;

        let validator_client = LocalValidatorClient::production_with_insecure_keypairs(
            context,
            validator_config,
            validator_files,
        )
        .await?;
        self.validator_clients.write().push(validator_client);
        Ok(())
    }

    /// For all beacon nodes in `Self`, return a HTTP client to access each nodes HTTP API.
    pub fn remote_nodes(&self) -> Result<Vec<BeaconNodeHttpClient>, String> {
        let beacon_nodes = self.beacon_nodes.read();
        let proposer_nodes = self.proposer_nodes.read();

        beacon_nodes
            .iter()
            .chain(proposer_nodes.iter())
            .map(|beacon_node| beacon_node.remote_node())
            .collect()
    }

    /// Return current epoch of bootnode.
    pub async fn _bootnode_epoch(&self) -> Result<Epoch, String> {
        let nodes = self.remote_nodes().expect("Failed to get remote nodes");
        let bootnode = nodes.first().expect("Should contain bootnode");
        bootnode
            .get_beacon_states_finality_checkpoints(StateId::Head)
            .await
            .map_err(|e| format!("Cannot get head: {:?}", e))
            .map(|body| body.unwrap().data.finalized.epoch)
    }

    pub async fn duration_to_genesis(&self) -> Result<Duration, &'static str> {
        let nodes = self.remote_nodes().expect("Failed to get remote nodes");
        let bootnode = nodes.first().expect("Should contain bootnode");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let genesis_time = Duration::from_secs(
            bootnode
                .get_beacon_genesis()
                .await
                .unwrap()
                .data
                .genesis_time,
        );
        genesis_time.checked_sub(now).ok_or(
            "The genesis time has already passed since all nodes started. The node startup time \
            may have regressed, and the current `GENESIS_DELAY` is no longer sufficient.",
        )
    }
}

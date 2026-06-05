use crate::local_network::NodeType;

use super::*;

type ClientConfigTransform = Box<dyn FnOnce(&mut ClientConfig) + Send + 'static>;
type SpecTransform = Box<dyn FnOnce(&mut ChainSpec) + Send + 'static>;

/// Builder for creating test networks with configurable parameters.
pub struct TestNetworkFixtureBuilder<E: EthSpec = MinimalEthSpec> {
    env: EnvironmentBuilder<E>,
    network_params: LocalNetworkParams,
    logger_config: LoggerConfig,
    disable_stdout: bool,
    client_config_transform: Option<ClientConfigTransform>,
    spec_transform: Option<SpecTransform>,
}

impl Default for TestNetworkFixtureBuilder {
    fn default() -> Self {
        Self {
            env: EnvironmentBuilder::minimal(),
            network_params: LocalNetworkParams {
                validator_count: 4,
                node_count: 2,
                proposer_nodes: 0,
                proof_generator_nodes: 0,
                proof_verifier_nodes: 0,
                extra_nodes: 0,
                delayed_nodes: 0,
                genesis_delay: 38,
            },
            logger_config: LoggerConfig::default(),
            disable_stdout: false,
            client_config_transform: None,
            spec_transform: None,
        }
    }
}

impl<E: EthSpec> TestNetworkFixtureBuilder<E> {
    /// Set the `EnvironmentBuilder` to use for the network.
    pub fn with_env(mut self, env: EnvironmentBuilder<E>) -> Self {
        self.env = env;
        self
    }

    /// Apply an arbitrary modification to the `EnvironmentBuilder` used for the network.
    pub fn map_env(mut self, f: impl FnOnce(&mut EnvironmentBuilder<E>)) -> Self {
        f(&mut self.env);
        self
    }

    /// Apply an arbitrary modification to the `ChainSpec` used for the network.
    pub fn map_spec(mut self, f: impl FnOnce(&mut ChainSpec) + Send + 'static) -> Self {
        self.spec_transform = Some(match self.spec_transform.take() {
            None => Box::new(f),
            Some(prev) => Box::new(move |spec| {
                prev(spec);
                f(spec);
            }),
        });
        self
    }

    /// Set the log level.
    pub fn with_log_level(mut self, level: LevelFilter) -> Self {
        self.logger_config.debug_level = level;
        self.logger_config.logfile_debug_level = level;
        self
    }

    /// Set the log directory.
    pub fn with_log_dir(mut self, log_dir: PathBuf) -> Self {
        self.logger_config.path = Some(log_dir);
        self
    }

    /// Apply an arbitrary modification to the `LoggerConfig` used for the network.
    pub fn map_logger_config(mut self, f: impl FnOnce(&mut LoggerConfig)) -> Self {
        f(&mut self.logger_config);
        self
    }

    /// Set the network params.
    pub fn with_network_params(mut self, network_params: LocalNetworkParams) -> Self {
        self.network_params = network_params;
        self
    }

    /// Apply an arbitrary modification to the `LocalNetworkParams` used for the network.
    pub fn map_network_params(mut self, f: impl FnOnce(&mut LocalNetworkParams)) -> Self {
        f(&mut self.network_params);
        self
    }

    /// Apply an arbitrary modification to the `ClientConfig` used for all beacon nodes.
    ///
    /// Multiple calls are composed in order: the first registered transform runs first.
    pub fn map_client_config(mut self, f: impl FnOnce(&mut ClientConfig) + Send + 'static) -> Self {
        self.client_config_transform = Some(match self.client_config_transform.take() {
            None => Box::new(f),
            Some(prev) => Box::new(move |config| {
                prev(config);
                f(config);
            }),
        });
        self
    }

    /// Build the test network fixture with the specified configuration.
    pub async fn build(self) -> anyhow::Result<TestNetworkFixture<E>> {
        info!(target: "simulator", "Building test network fixture");

        // initialize the network
        let (env, network_params, network, beacon_config, mock_execution_config) =
            self.init_network().await?;

        // Initialize beacon nodes
        Self::init_beacon_nodes(
            &network,
            &network_params,
            &beacon_config,
            &mock_execution_config,
        )
        .await?;

        // Initialize validator clients
        Self::init_validators(&network, &network_params).await?;

        Ok(TestNetworkFixture {
            env,
            network,
            config: TestConfig {
                client: beacon_config,
                execution: mock_execution_config,
                network_params,
            },
        })
    }

    async fn init_validators(
        network: &LocalNetwork<E>,
        network_params: &LocalNetworkParams,
    ) -> anyhow::Result<()> {
        info!(target: "simulator", "Building validator clients for {} validators", network_params.validator_count);
        let network_params = network_params.clone();
        let task_executor = network.executor();

        // Generate validator keystores in parallel to speed up setup time
        let validator_files = task_executor
            .spawn_blocking_handle(
                move || -> anyhow::Result<Vec<ValidatorFiles>> {
                    let num_beacon_nodes =
                        network_params.node_count + network_params.proof_generator_nodes;
                    let validators_per_node = network_params.validator_count / num_beacon_nodes;

                    (0..num_beacon_nodes)
                        .into_par_iter()
                        .map(|i| -> anyhow::Result<ValidatorFiles> {
                            info!(target: "simulator",
                                "Generating keystores for validator {} of {}",
                                i + 1,
                                num_beacon_nodes
                            );

                            let indices = (i * validators_per_node..(i + 1) * validators_per_node)
                                .collect::<Vec<_>>();

                            ValidatorFiles::with_keystores(&indices).map_err(anyhow::Error::msg)
                        })
                        .collect::<anyhow::Result<Vec<_>>>()
                },
                "validator_keystore_generation",
            )
            .ok_or_else(|| anyhow::anyhow!("Failed to spawn blocking task"))?
            .await??;

        for (i, files) in validator_files.into_iter().enumerate() {
            let network = network.clone();
            let network_params = network_params.clone();

            task_executor.spawn(
                async move {
                    let mut validator_config = testing_validator_config();
                    validator_config.validator_store.fee_recipient =
                        Some(Into::<Address>::into(SUGGESTED_FEE_RECIPIENT));

                    // Enable broadcast on every 2nd node.
                    // TODO: do we need this?
                    if i % 4 == 0 {
                        validator_config.broadcast_topics = ApiTopic::all();
                        let beacon_nodes = vec![i, (i + 1) % network_params.node_count];
                        network
                            .add_validator_client_with_fallbacks(
                                validator_config,
                                beacon_nodes,
                                files,
                            )
                            .await
                    } else {
                        let node_type = network_params.node_type(i);
                        network
                            .add_validator_client(validator_config, i, files, node_type)
                            .await
                    }
                    .expect("should add validator");
                },
                "validator_client_setup",
            )
        }

        Ok(())
    }

    async fn init_beacon_nodes(
        network: &LocalNetwork<E>,
        network_params: &LocalNetworkParams,
        beacon_config: &ClientConfig,
        mock_execution_config: &MockExecutionConfig,
    ) -> anyhow::Result<()> {
        // Build the full list of (NodeType, count) pairs, then spawn all nodes concurrently.
        let node_types = [
            (NodeType::Default, network_params.node_count),
            (NodeType::Proposer, network_params.proposer_nodes),
            (
                NodeType::ProofGenerator,
                network_params.proof_generator_nodes,
            ),
            (NodeType::ProofVerifier, network_params.proof_verifier_nodes),
        ];

        let total: usize = node_types.iter().map(|(_, n)| n).sum();
        info!(target: "simulator", "Spawning {total} beacon nodes");

        for (node_type, count) in node_types {
            for _ in 0..count {
                network
                    .add_beacon_node(
                        beacon_config.clone(),
                        mock_execution_config.clone(),
                        node_type,
                    )
                    .await
                    .map_err(anyhow::Error::msg)?;
            }
        }

        Ok(())
    }

    /// Initialize the network environment and create the local network instance.
    async fn init_network(
        self,
    ) -> anyhow::Result<(
        TestEnvironment<E>,
        LocalNetworkParams,
        LocalNetwork<E>,
        ClientConfig,
        MockExecutionConfig,
    )> {
        info!(target: "simulator", "Initializing test network environment and local network");
        let Self {
            env,
            network_params,
            logger_config,
            disable_stdout,
            client_config_transform,
            spec_transform,
        } = self;

        // Initialize logging
        info!(target: "simulator", "Initializing logging with config: {:?}", logger_config);

        let file_mode = if logger_config.is_restricted {
            0o600
        } else {
            0o644
        };
        let (env, stdout_logging_layer, file_logging_layer, _see_logging_layer) =
            env.init_tracing(logger_config.clone(), "lighthouse", file_mode);

        //TODO: optionally add discv5 logging layer for network tests
        // Instantiate logging layers
        let filters = build_workspace_filter().expect("should build workspace filter");
        let mut layers = vec![];

        if let Some(layer) = (!disable_stdout).then(|| {
            stdout_logging_layer
                .with_filter(logger_config.debug_level)
                .with_filter(filters.clone())
                .boxed()
        }) {
            layers.push(layer);
        }
        if let Some(file_logging_layer) = file_logging_layer {
            layers.push(
                file_logging_layer
                    .with_filter(logger_config.logfile_debug_level)
                    .with_filter(filters.clone())
                    .boxed(),
            );
        }
        // Initialize the subscriber with the configured layers
        tracing_subscriber::registry().with(layers).try_init()?;

        // Instantiate the environment.
        let mut env = env.build_test_environment().map_err(anyhow::Error::msg)?;

        let mut spec = (*env.eth2_config.spec).clone();
        spec.genesis_delay = network_params.genesis_delay;
        spec.min_genesis_active_validator_count = network_params.validator_count as u64;
        if let Some(transform) = spec_transform {
            transform(&mut spec);
        }
        env.eth2_config.spec = std::sync::Arc::new(spec);

        // Instantiate the local network
        info!(target: "simulator", "Initializing local network with params: {:?}", network_params);
        let (network, mut beacon_config, mock_execution_config) =
            Box::pin(LocalNetwork::create_local_network(
                None,
                None,
                network_params.clone(),
                env.core_context(),
            ))
            .await
            .map_err(anyhow::Error::msg)?;

        if let Some(transform) = client_config_transform {
            transform(&mut beacon_config);
        }

        Ok((
            env,
            network_params,
            network,
            beacon_config,
            mock_execution_config,
        ))
    }
}

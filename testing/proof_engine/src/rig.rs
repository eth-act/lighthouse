//! [`ProofEngineTestRig`] — a thin wrapper over [`TestNetworkFixture`] for EIP-8025 tests.
//!
//! Provides a clean API for building standard proof engine test topologies and asserting
//! on mock proof engine events, insulating individual tests from `LocalNetwork` internals.

use anyhow::anyhow;
use beacon_chain::WhenSlotSkipped;
use beacon_chain::eip8025::{compute_execution_proof_domain, compute_signing_root};
use execution_layer::NewPayloadRequest;
use execution_layer::test_utils::MockClientEvent;
use simulator::test_utils::{
    BeaconNodeHttpClient, Epoch, EventStream, InternalBeaconNodeEvent, LocalNetworkParams,
    NodeType, TestNetworkFixture, TestNetworkFixtureBuilder,
};
use types::test_utils::generate_deterministic_keypair;
use types::{
    EthSpec, ExecutionProof, Hash256, MinimalEthSpec, ProofData, PublicInput, SignedExecutionProof,
    Slot,
};

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

    /// Return the most recent canonical execution payload request in the current
    /// finalized-to-head window for the selected proof generator.
    pub async fn latest_generator_payload_request(
        &self,
        generator_index: usize,
    ) -> anyhow::Result<(Hash256, Slot, Hash256)> {
        let idx = self.fixture.config.network_params.node_count + generator_index;
        let chain = self
            .fixture
            .network
            .beacon_nodes
            .read()
            .get(idx)
            .and_then(|node| node.client.beacon_chain())
            .ok_or_else(|| anyhow!("no proof generator chain at index {generator_index}"))?;

        let head = chain.canonical_head.cached_head();
        let start_slot = head
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch());
        let end_slot = head.head_slot();

        for slot in (start_slot.as_u64()..=end_slot.as_u64()).rev() {
            let slot = Slot::new(slot);
            let Some(block_root) = chain
                .block_root_at_slot(slot, WhenSlotSkipped::None)
                .map_err(|error| anyhow!("{error:?}"))?
            else {
                continue;
            };
            let Some(block) = chain
                .get_block(&block_root)
                .await
                .map_err(|error| anyhow!("{error:?}"))?
            else {
                continue;
            };
            let request = NewPayloadRequest::try_from(block.message())
                .map_err(|error| anyhow!("{error:?}"))?;
            return Ok((block_root, slot, request.request_root()));
        }

        Err(anyhow!(
            "no canonical execution payload request in finalized-to-head window"
        ))
    }

    /// Store a valid proof on the selected generator without publishing it through gossip.
    pub fn observe_valid_generator_proof(
        &self,
        generator_index: usize,
        block_root: Hash256,
        proof: &SignedExecutionProof,
    ) -> anyhow::Result<()> {
        let idx = self.fixture.config.network_params.node_count + generator_index;
        let chain = self
            .fixture
            .network
            .beacon_nodes
            .read()
            .get(idx)
            .and_then(|node| node.client.beacon_chain())
            .ok_or_else(|| anyhow!("no proof generator chain at index {generator_index}"))?;

        let observation = chain
            .observe_valid_execution_proof(proof, Some(block_root))
            .map_err(|error| anyhow!("{error:?}"))?;
        anyhow::ensure!(
            observation.block_root == Some(block_root),
            "proof was not associated with the expected block root"
        );
        Ok(())
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

    /// Wait for a proof request from the selected generator, sign a matching proof, submit it to
    /// that generator's beacon node HTTP API, and return the signed proof.
    pub async fn sign_and_submit_next_generator_proof(
        &self,
        generator_index: usize,
        events: &mut MockEventStream,
    ) -> anyhow::Result<SignedExecutionProof> {
        let request = events
            .expect_proof_requests(1, std::time::Duration::from_secs(60))
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("expected one proof request event"))?;

        let MockClientEvent::ProofRequested {
            root,
            proof_attributes,
            ..
        } = request
        else {
            return Err(anyhow!("unexpected mock proof event"));
        };
        let proof_type = proof_attributes
            .proof_types
            .first()
            .copied()
            .ok_or_else(|| anyhow!("proof request did not include any proof types"))?;

        let proof = self.sign_execution_proof(root, proof_type, 0)?;
        self.proof_generator_node(generator_index)?
            .post_beacon_pool_execution_proofs(std::slice::from_ref(&proof))
            .await
            .map_err(|error| anyhow!("{error:?}"))?;
        Ok(proof)
    }

    pub fn sign_execution_proof(
        &self,
        request_root: Hash256,
        proof_type: u8,
        validator_index: u64,
    ) -> anyhow::Result<SignedExecutionProof> {
        let chain = self
            .fixture
            .network
            .beacon_nodes
            .read()
            .first()
            .and_then(|node| node.client.beacon_chain())
            .ok_or_else(|| anyhow!("network has no beacon chain"))?;
        let fork_name = chain.spec.fork_name_at_slot::<E>(Slot::new(0));
        let keypair = generate_deterministic_keypair(validator_index as usize);
        let proof = ExecutionProof {
            proof_data: ProofData::new(vec![0xDE, 0xAD, 0xBE, 0xEF])?,
            proof_type,
            public_input: PublicInput {
                new_payload_request_root: request_root,
            },
        };
        let domain =
            compute_execution_proof_domain(fork_name, chain.genesis_validators_root, &chain.spec);
        let signing_root = compute_signing_root(&proof, domain);

        Ok(SignedExecutionProof {
            message: proof,
            validator_index,
            signature: keypair.sk.sign(signing_root).into(),
        })
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
            *spec = spec.clone().set_slot_duration_ms::<MinimalEthSpec>(1000);
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
}

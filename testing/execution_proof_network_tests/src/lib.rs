//! Deterministic multi-node integration tests for EIP-8025 execution proofs.
//!
//! [`ProofNetwork`] starts a local network of production beacon nodes through the simulator's
//! [`LocalNetwork`](simulator::LocalNetwork) and lets a test:
//!
//! - choose the topology: per node, whether it runs an execution layer, a proof engine or both,
//!   which proof bytes its engine accepts, and whether it carries validators ([`NodeSpec`]);
//! - inject a deterministic [`MockProofEngine`](proof_engine::test_utils::MockProofEngine) per
//!   node through `ProofEngineConfig::with_engine` (behind the `proof_engine/test-utils`
//!   feature), so valid and invalid proof data are chosen per scenario instead of by a zkVM
//!   verifier;
//! - build and sign proof envelopes with the deterministic interop validator keys, and submit
//!   them through a node's Beacon API or inject them onto gossip unverified
//!   ([`ProofNetwork::submit_execution_proof`], [`ProofNetwork::publish_execution_proof`]);
//! - generate proofs on the network with a proving execution layer
//!   ([`ProvingExecutionLayer`], attached with [`NodeSpec::proving`]): a proxy in front of a
//!   node's mock execution layer that proves every payload `engine_newPayload` validates and
//!   posts the proofs to that node's Beacon API;
//! - observe verification, caching, storage, payload import and Beacon API retrieval on every
//!   node ([`ProofStatus`], [`ProofNetwork::retrieved_proof_types`]), with bounded waits that
//!   report a per-node snapshot on timeout ([`ProofNetwork::wait_for`]).
//!
//! Nodes with an execution layer run the mock execution layer and mark all payloads valid, so
//! the tests exercise the consensus-layer proof pipeline: gossip validation, the proof engine,
//! the pending payload cache, fork choice and the `execution_proofs` Beacon API endpoints.
//!
//! ## Node modes
//!
//! - Execution-layer nodes ([`NodeSpec::plain`]) import payloads once executed and ignore
//!   proofs. They carry the validators.
//! - Verifiers ([`NodeSpec::verifier`]) also import at once, but verify, cache and serve proofs.
//! - Proof-only nodes ([`NodeSpec::proof_only`]) have no execution layer and hold every payload
//!   until two proof types verify. Without a prover they stop at the first full block; with
//!   proving execution layers on the network they follow the chain.
//!
//! ## Pending integration points
//!
//! - **RPC retrieval.** Proofs are not requested from peers by range or by root yet. A
//!   proof-only node that joins late therefore cannot catch up on proofs it missed; that
//!   scenario waits for the integration.
//!
//! ## Running
//!
//! Each test starts real beacon nodes on the simulator's fixed ports, so tests run one at a time
//! (enforced in-process by a lock, and by `--test-threads 1` under nextest) and are ignored in
//! debug builds:
//!
//! ```bash
//! cargo nextest run -p execution_proof_network_tests --release --test-threads 1
//! ```
//!
//! Set `RUST_LOG` to change the default `warn` node log level.

mod network;
mod observe;
mod prover;
mod proving_execution_layer;
#[cfg(test)]
mod tests;

pub use network::{NodeSpec, ProofNetwork, ProofNetworkConfig};
pub use observe::ProofStatus;
pub use proving_execution_layer::{ProvenPayload, ProverSpec, ProvingExecutionLayer};

use beacon_chain::{
    BeaconChain, builder::Witness, slot_clock::SystemTimeSlotClock,
    store::database::interface::BeaconNodeBackend,
};
use std::sync::Arc;
use types::MinimalEthSpec;

pub type E = MinimalEthSpec;

/// Beacon chain types of a production beacon node started by the harness.
pub type NodeTypes = Witness<SystemTimeSlotClock, E, BeaconNodeBackend, BeaconNodeBackend>;

/// Shared handle to a node's beacon chain.
pub type NodeChain = Arc<BeaconChain<NodeTypes>>;

//! Deterministic multi-node integration tests for EIP-8025 execution proofs.
//!
//! [`ProofNetwork`] starts a local network of production beacon nodes through the simulator's
//! [`LocalNetwork`](simulator::LocalNetwork) and lets a test:
//!
//! - choose the topology: which nodes run a proof engine, which proof bytes each engine accepts,
//!   and which nodes carry validators ([`NodeSpec`]);
//! - inject a deterministic [`MockProofEngine`](proof_engine::test_utils::MockProofEngine) per
//!   node through `ClientConfig::proof_engine_override`, so valid and invalid proof data are
//!   chosen per scenario instead of by a zkVM verifier;
//! - build and sign proof envelopes with the deterministic interop validator keys, submit them
//!   through a node (gossip verification, caching, then publication) or inject them onto gossip
//!   unverified ([`ProofNetwork::submit_execution_proof`],
//!   [`ProofNetwork::publish_execution_proof`]);
//! - observe verification, storage, propagation and payload import on every node through the
//!   beacon chain's caches ([`ProofStatus`]), with bounded waits that report a per-node snapshot
//!   on timeout ([`ProofNetwork::wait_for`]).
//!
//! Every node runs the mock execution layer and marks all payloads valid, so the tests exercise
//! the consensus-layer proof pipeline: gossip validation, the proof engine, the pending payload
//! cache and fork choice.
//!
//! ## Pending integration points
//!
//! These belong to parallel tasks and are documented here instead of being reimplemented:
//!
//! - **Beacon API submission and retrieval.** [`ProofNetwork::submit_execution_proof`] performs
//!   the verify, cache and publish sequence in-process because no HTTP endpoint exists yet. Once
//!   the Beacon API endpoints land, the adapter should call them and [`ProofStatus`] should gain
//!   an HTTP retrieval check.
//! - **RPC retrieval.** Proofs are not requested from peers by range or by root yet, so
//!   late-joining node scenarios wait for that integration.
//! - **Execution-layer-optional nodes.** Proof-only nodes without an execution layer need the
//!   pending EL-optional interfaces before they can be expressed as a [`NodeSpec`].
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
#[cfg(test)]
mod tests;

pub use network::{NodeSpec, ProofNetwork, ProofNetworkConfig};
pub use observe::ProofStatus;

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

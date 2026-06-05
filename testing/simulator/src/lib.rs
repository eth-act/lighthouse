//! This crate provides various simulations that create both beacon nodes and validator clients,
//! each with `v` validators.
//!
//! When a simulation runs, there are checks made to ensure that all components are operating
//! as expected. If any of these checks fail, the simulation will exit immediately.
//!
//! ## Future works
//!
//! Presently all the beacon nodes and validator clients all log to stdout. Additionally, the
//! simulation uses `println` to communicate some info. It might be nice if the nodes logged to
//! easy-to-find files and stdout only contained info from the simulation.
//!
pub mod basic_sim;
pub mod checks;
pub mod cli;
pub mod fallback_sim;
pub mod local_network;
pub mod retry;

pub use local_network::LocalNetwork;
pub use types::MinimalEthSpec;

pub type E = MinimalEthSpec;

#[cfg(feature = "test-utils")]
pub mod test_utils;

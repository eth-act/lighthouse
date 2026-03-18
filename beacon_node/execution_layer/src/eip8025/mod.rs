//! EIP-8025: Optional Execution Proofs
//!
//! This module provides the execution layer integration for EIP-8025 optional proofs.
//! It includes:
//! - ProofEngine trait for abstracting proof engine communication
//! - ProofNodeClient for low-level HTTP transport (REST+SSZ+SSE)
//! - HttpProofEngine combining transport with proof state management
//! - SSE event types for proof completion streaming

pub mod errors;
pub mod persisted_state;
pub mod proof_engine;
pub mod proof_node_client;
pub mod state;

pub use errors::ProofEngineError;
pub use persisted_state::{PersistedProofEngineState, PROOF_ENGINE_DB_KEY};
pub use proof_engine::{
    HttpProofEngine, ProofComplete, ProofEngine, ProofEvent, ProofEventInfo, ProofFailure,
};
pub use proof_node_client::{ProofNodeClient, ProofRequestResponse, PROOF_ENGINE_TIMEOUT};

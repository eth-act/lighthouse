//! EIP-8025: Optional Execution Proofs
//!
//! This module provides the execution layer integration for EIP-8025 optional proofs.
//! It includes:
//! - HttpProofEngine combining transport with proof state management
//! - ProofNodeClient trait for low-level transport abstraction (REST+SSZ+SSE)
//! - HttpProofNodeClient for production HTTP transport
//! - SSE event types for proof completion streaming

pub mod errors;
pub mod persisted_state;
pub mod proof_engine;
pub mod proof_node_client;
pub mod state;
#[cfg(test)]
mod tests;
pub mod types;

pub use errors::ProofEngineError;
pub use persisted_state::{PROOF_ENGINE_DB_KEY, PersistedProofEngineState};
pub use proof_engine::HttpProofEngine;
pub use proof_node_client::{
    HttpProofNodeClient, PROOF_ENGINE_TIMEOUT, ProofNodeClient, ProofRequestResponse,
};
pub use types::{ProofComplete, ProofEvent, ProofEventInfo, ProofFailure, SseEventParts};

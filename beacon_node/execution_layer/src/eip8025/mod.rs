//! EIP-8025: Optional Execution Proofs
//!
//! This module provides the execution layer integration for EIP-8025 optional proofs.
//! It includes:
//! - Engine API methods for proof verification and generation
//! - ProofEngine trait for abstracting proof engine communication
//! - JSON structures for Engine API serialization

pub mod errors;
pub mod json_structures;
pub mod persisted_state;
pub mod proof_engine;
pub mod state;

pub use errors::ProofEngineError;
pub use json_structures::*;
pub use persisted_state::{PROOF_ENGINE_DB_KEY, PersistedProofEngineState};
pub use proof_engine::{
    ENGINE_REQUEST_PROOFS_V1, ENGINE_VERIFY_EXECUTION_PROOF_V1,
    ENGINE_VERIFY_NEW_PAYLOAD_REQUEST_HEADER_V1, HttpProofEngine, PROOF_ENGINE_TIMEOUT,
    ProofEngine,
};

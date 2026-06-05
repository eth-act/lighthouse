//! EIP-8025 optional execution proof-engine transport.
//!
//! This module intentionally does not act as an execution engine and does not gate fork choice.
//! It provides HTTP helpers for requesting and verifying proofs. Beacon-chain code records proof
//! status separately and only applies proof-backed payload promotion when explicitly configured.

pub mod errors;
pub mod proof_engine;
pub mod proof_node_client;
pub mod types;

pub use errors::ProofEngineError;
pub use proof_engine::HttpProofEngine;
pub use proof_node_client::{
    HttpProofNodeClient, PROOF_ENGINE_TIMEOUT, ProofNodeClient, ProofRequestResponse,
};
pub use types::{FailureReason, ProofComplete, ProofEvent, ProofFailure, ProofType, SseEventParts};

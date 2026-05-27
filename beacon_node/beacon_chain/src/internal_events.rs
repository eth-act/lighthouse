//! Internal event bus for execution-proof integration tests.

use std::sync::Arc;
use types::execution::eip8025::{ProofByRootIdentifier, ProofStatus, SignedExecutionProof};
use types::{Hash256, Slot};

pub const INTERNAL_EVENT_CHANNEL_CAPACITY: usize = 16_384;

#[derive(Debug, Clone)]
pub enum InternalBeaconNodeEvent {
    GossipExecutionProof(Arc<SignedExecutionProof>),
    RpcExecutionProof(Arc<SignedExecutionProof>),
    OutboundExecutionProofsByRange {
        start_slot: Slot,
        count: u64,
    },
    OutboundExecutionProofsByRoot {
        identifiers: Vec<ProofByRootIdentifier>,
    },
    ExecutionProofVerified {
        request_root: Hash256,
        status: ProofStatus,
        block: Option<(Hash256, Slot)>,
    },
    ExecutionProofVerificationFailed {
        request_root: Hash256,
        error: String,
    },
}

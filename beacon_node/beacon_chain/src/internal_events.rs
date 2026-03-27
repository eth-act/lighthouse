//! Internal event bus for `BeaconChain`.
//!
//! Variants wrap the actual message and result types that already flow through the node —
//! no new summary types are introduced.  The channel is lazily initialised on the first call to
//! [`BeaconChain::subscribe_internal_events`], so there is zero overhead in production runs where
//! no subscriber is ever registered.

use std::sync::Arc;
use types::execution::eip8025::{ProofStatus, SignedExecutionProof};
use types::{Hash256, Slot};

/// Event emitted on the per-node internal event bus.
///
/// Each variant wraps the real message or result type that is already present at the emission
/// site, so tests can inspect the full payload without lossy conversion.
#[derive(Debug, Clone)]
pub enum InternalBeaconNodeEvent {
    /// A `SignedExecutionProof` arrived via gossip, before dedup/verification.
    GossipExecutionProof(Arc<SignedExecutionProof>),
    /// A `SignedExecutionProof` arrived via RPC sync, before dedup/verification.
    RpcExecutionProof(Arc<SignedExecutionProof>),
    /// An outbound `ExecutionProofsByRange` RPC request was sent to a peer.
    OutboundExecutionProofsByRange { start_slot: Slot, count: u64 },
    /// An outbound `ExecutionProofsByRoot` RPC request was sent to a peer.
    OutboundExecutionProofsByRoot { block_root: Hash256 },
    /// `verify_execution_proof` completed; carries the status and, when the block is known,
    /// its root and slot.
    ExecutionProofVerified {
        request_root: Hash256,
        status: ProofStatus,
        block: Option<(Hash256, Slot)>,
    },
    /// `verify_execution_proof` returned an error.
    ExecutionProofVerificationFailed {
        request_root: Hash256,
        error: String,
    },
}

use super::{ActiveRequestItems, LookupVerifyError};
use lighthouse_network::rpc::methods::ExecutionProofsByRangeRequest;
use std::sync::Arc;
use types::ExecutionProof;

/// Accumulates results of an execution_proofs_by_range request. Only returns items after receiving
/// the stream termination.
pub struct ExecutionProofsByRangeRequestItems {
    request: ExecutionProofsByRangeRequest,
    items: Vec<Arc<ExecutionProof>>,
}

impl ExecutionProofsByRangeRequestItems {
    pub fn new(request: ExecutionProofsByRangeRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl ActiveRequestItems for ExecutionProofsByRangeRequestItems {
    type Item = Arc<ExecutionProof>;

    fn add(&mut self, proof: Self::Item) -> Result<bool, LookupVerifyError> {
        // TODO(zkproofs): Add proper validation
        // For now, just check the slot is within the requested range
        if proof.slot < self.request.start_slot
            || proof.slot >= self.request.start_slot + self.request.count
        {
            return Err(LookupVerifyError::UnrequestedSlot(proof.slot));
        }

        // Check for duplicate proofs
        if self.items.iter().any(|existing| {
            existing.slot == proof.slot && existing.proof_id == proof.proof_id
        }) {
            return Err(LookupVerifyError::DuplicatedProofIDs(proof.proof_id));
        }

        self.items.push(proof);

        // We can't know exactly how many proofs to expect, so we never return true here.
        // The stream termination will signal completion.
        Ok(false)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}

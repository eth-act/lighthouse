use super::{ActiveRequestItems, LookupVerifyError};
use lighthouse_network::rpc::methods::ExecutionProofsByRangeRequest;
use std::sync::Arc;
use types::{ExecutionProof, Slot};

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
        let proof_slot = proof.slot;

        // Verify the proof is within the requested slot range
        if proof_slot < Slot::new(self.request.start_slot)
            || proof_slot >= Slot::new(self.request.start_slot + self.request.count)
        {
            return Err(LookupVerifyError::UnrequestedSlot(proof_slot));
        }

        // Check for duplicate proofs (same slot and proof_id)
        if self
            .items
            .iter()
            .any(|existing| existing.slot == proof_slot && existing.proof_id == proof.proof_id)
        {
            return Err(LookupVerifyError::DuplicatedProofIDs(proof.proof_id));
        }

        self.items.push(proof);

        // We don't know exactly how many proofs to expect (depends on block content),
        // so we never return true here - rely on stream termination
        Ok(false)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}

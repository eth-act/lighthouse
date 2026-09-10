use std::sync::Arc;

use execution_layer::{NewPayloadRequest, NewPayloadRequestGloas};
use fork_choice::PayloadVerificationStatus;
use ssz_types::VariableList;
use state_processing::per_block_processing::deneb::kzg_commitment_to_versioned_hash;
use tracing::warn;
use types::{BeaconStateError, SignedBeaconBlock, SignedExecutionPayloadEnvelope};

use crate::{
    BeaconChain, BeaconChainTypes, NotifyExecutionLayer, PayloadVerificationError,
    execution_payload::notify_new_payload, payload_envelope_verification::EnvelopeError,
};

/// Used to await the result of executing payload with a remote EE.
pub struct PayloadNotifier<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
    block: Arc<SignedBeaconBlock<T::EthSpec>>,
    payload_verification_status: Option<PayloadVerificationStatus>,
}

impl<T: BeaconChainTypes> PayloadNotifier<T> {
    pub fn new(
        chain: Arc<BeaconChain<T>>,
        envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<Self, EnvelopeError> {
        let payload_verification_status = {
            let payload_message = &envelope.message;

            match notify_execution_layer {
                NotifyExecutionLayer::No if chain.config.optimistic_finalized_sync => {
                    let new_payload_request = Self::build_new_payload_request(&envelope, &block)?;
                    // TODO(gloas): check and test RLP block hash calculation post-Gloas
                    if let Err(e) = new_payload_request.perform_optimistic_sync_verifications() {
                        warn!(
                            block_number = ?payload_message.payload.block_number,
                            info = "you can silence this warning with --disable-optimistic-finalized-sync",
                            error = ?e,
                            "Falling back to slow block hash verification"
                        );
                        None
                    } else {
                        Some(PayloadVerificationStatus::Optimistic)
                    }
                }
                _ => None,
            }
        };

        // A proof-only node has no engine to execute the payload against. There is no engine
        // verdict to wait on, and the envelope only reaches import once
        // `REQUIRED_EXECUTION_PROOFS` proofs have verified it, so the question the engine would
        // answer does not apply.
        //
        // This must not be `Optimistic`: Gloas does not support optimistic import, and
        // `into_executed_payload_envelope` rejects an optimistic envelope outright, which would
        // stop a proof-only node importing any payload at all.
        let payload_verification_status = payload_verification_status.or_else(|| {
            chain
                .execution_layer
                .is_none()
                .then_some(PayloadVerificationStatus::Irrelevant)
        });

        Ok(Self {
            chain,
            envelope,
            block,
            payload_verification_status,
        })
    }

    pub async fn notify_new_payload(
        self,
    ) -> Result<PayloadVerificationStatus, PayloadVerificationError> {
        if let Some(precomputed_status) = self.payload_verification_status {
            Ok(precomputed_status)
        } else {
            let parent_root = self.block.message().parent_root();
            let request = Self::build_new_payload_request(&self.envelope, &self.block)?;
            notify_new_payload(&self.chain, self.envelope.slot(), parent_root, request).await
        }
    }

    fn build_new_payload_request<'a>(
        envelope: &'a SignedExecutionPayloadEnvelope<T::EthSpec>,
        block: &'a SignedBeaconBlock<T::EthSpec>,
    ) -> Result<NewPayloadRequest<'a, T::EthSpec>, PayloadVerificationError> {
        let bid = &block
            .message()
            .body()
            .signed_execution_payload_bid()
            .map_err(|e| PayloadVerificationError::BeaconChainError(Box::new(e.into())))?
            .message;

        let versioned_hashes = VariableList::new(
            bid.blob_kzg_commitments
                .iter()
                .map(kzg_commitment_to_versioned_hash)
                .collect(),
        )
        .map_err(BeaconStateError::from)?;

        Ok(NewPayloadRequest::Gloas(NewPayloadRequestGloas {
            execution_payload: &envelope.message.payload,
            versioned_hashes,
            parent_beacon_block_root: envelope.message.parent_beacon_block_root,
            execution_requests: &envelope.message.execution_requests,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::BeaconChainHarness;
    use bls::Signature;
    use proof_engine::{ProofEngine, test_utils::MockProofEngine};
    use types::execution::ExecutionPayloadEnvelope;
    use types::{BeaconBlock, EthSpec, ForkName, MinimalEthSpec};

    type E = MinimalEthSpec;

    /// A proof-only node has no engine to ask, so the notifier must decide the status itself.
    /// Reaching `notify_new_payload` would fail: that helper requires an execution layer.
    ///
    /// The status must not be optimistic. `into_executed_payload_envelope` rejects an optimistic
    /// envelope with `OptimisticSyncNotSupported`, so an optimistic status here would stop a
    /// proof-only node importing any payload.
    #[tokio::test]
    async fn proof_only_node_precomputes_a_non_optimistic_status() {
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .proof_engine(Some(ProofEngine::new(MockProofEngine::default())))
            .build();
        let chain = harness.chain.clone();

        let envelope = Arc::new(SignedExecutionPayloadEnvelope::<E> {
            message: ExecutionPayloadEnvelope {
                beacon_block_root: chain.genesis_block_root,
                ..ExecutionPayloadEnvelope::empty()
            },
            signature: Signature::empty(),
        });
        let block = Arc::new(SignedBeaconBlock::from_block(
            BeaconBlock::empty(&spec),
            Signature::empty(),
        ));

        let notifier = PayloadNotifier::new(
            chain,
            envelope,
            block,
            // `Yes` is what the gossip path uses, and is the case that would otherwise consult
            // the engine.
            NotifyExecutionLayer::Yes,
        )
        .expect("the notifier is constructed");

        assert_eq!(
            notifier.payload_verification_status,
            Some(PayloadVerificationStatus::Irrelevant),
            "a proof-only node must not defer to an engine it does not have"
        );
        assert!(
            !notifier
                .payload_verification_status
                .expect("status is precomputed")
                .is_optimistic(),
            "an optimistic status would be rejected at import"
        );
    }

    /// An execution-layer node still defers to its engine.
    #[tokio::test]
    async fn execution_layer_node_defers_to_the_engine() {
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();
        let chain = harness.chain.clone();

        let envelope = Arc::new(SignedExecutionPayloadEnvelope::<E> {
            message: ExecutionPayloadEnvelope {
                beacon_block_root: chain.genesis_block_root,
                ..ExecutionPayloadEnvelope::empty()
            },
            signature: Signature::empty(),
        });
        let block = Arc::new(SignedBeaconBlock::from_block(
            BeaconBlock::empty(&spec),
            Signature::empty(),
        ));

        let notifier = PayloadNotifier::new(chain, envelope, block, NotifyExecutionLayer::Yes)
            .expect("the notifier is constructed");

        assert_eq!(
            notifier.payload_verification_status, None,
            "an engine-backed node leaves the status for the engine to decide"
        );
    }
}

//! Building, signing and submitting execution proof envelopes.

use crate::{E, ProofNetwork};
use beacon_chain::AvailabilityProcessingStatus;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use std::sync::Arc;
use types::{
    Domain, Hash256, SignedRoot,
    execution::{ExecutionProofEnvelope, ProofData, ProofType, SignedExecutionProofEnvelope},
    test_utils::generate_deterministic_keypair,
};

impl ProofNetwork {
    /// Build and sign a proof envelope for `block_root` with the deterministic interop key of
    /// `validator_index`. The signing domain follows the block's slot as seen by `node`.
    pub fn signed_execution_proof(
        &self,
        node: usize,
        block_root: Hash256,
        proof_type: ProofType,
        proof_data: Vec<u8>,
        validator_index: u64,
    ) -> Result<Arc<SignedExecutionProofEnvelope>, String> {
        let chain = self.chain(node)?;
        let block_slot = chain
            .canonical_head
            .fork_choice_read_lock()
            .get_block(&block_root)
            .ok_or(format!("node {node} does not know block {block_root:?}"))?
            .slot;
        let message = ExecutionProofEnvelope {
            proof_data: ProofData::new(proof_data)
                .map_err(|e| format!("proof data exceeds the size bound: {e:?}"))?,
            proof_type,
            beacon_block_root: block_root,
        };
        let fork_name = chain.spec.fork_name_at_slot::<E>(block_slot);
        let domain = chain.spec.compute_domain(
            Domain::ExecutionProof,
            chain.spec.fork_version_for_name(fork_name),
            chain.genesis_validators_root,
        );
        let signature = generate_deterministic_keypair(validator_index as usize)
            .sk
            .sign(message.signing_root(domain));
        Ok(Arc::new(SignedExecutionProofEnvelope {
            message,
            validator_index,
            signature,
        }))
    }

    /// Submit a proof through node `from`: verify it for gossip, cache it (importing the payload
    /// envelope if the proof completed the requirement), then publish it to peers.
    ///
    /// This is the sequence the pending Beacon API submission endpoint will expose. A local
    /// rejection is returned as an error carrying the gossip verification error and nothing is
    /// published.
    pub async fn submit_execution_proof(
        &self,
        from: usize,
        proof: Arc<SignedExecutionProofEnvelope>,
    ) -> Result<AvailabilityProcessingStatus, String> {
        let chain = self.chain(from)?;
        let verified = chain
            .verify_execution_proof_for_gossip(proof.clone())
            .await
            .map_err(|e| format!("node {from} rejected the proof locally: {e:?}"))?;
        let status = chain
            .check_execution_proof_availability_and_import(verified)
            .await
            .map_err(|e| format!("node {from} could not cache the proof: {e:?}"))?;
        self.publish_execution_proof(from, proof)?;
        Ok(status)
    }

    /// Publish a proof on gossip from node `from` without verifying it locally, as a faulty or
    /// malicious peer would.
    pub fn publish_execution_proof(
        &self,
        from: usize,
        proof: Arc<SignedExecutionProofEnvelope>,
    ) -> Result<(), String> {
        let senders = self
            .network
            .beacon_nodes
            .read()
            .get(from)
            .ok_or(format!("no node {from}"))?
            .client
            .network_senders()
            .ok_or(format!("node {from} has no network service"))?;
        senders
            .network_send()
            .send(NetworkMessage::Publish {
                messages: vec![PubsubMessage::ExecutionProof(proof)],
            })
            .map_err(|e| format!("node {from} network channel closed: {e}"))
    }
}

//! Building, signing and submitting execution proof envelopes.

use crate::{E, ProofNetwork};
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use std::sync::Arc;
use types::{
    Domain, Hash256, SignedRoot,
    execution::{
        ExecutionProofEnvelope, ProofData, ProofType, SignedExecutionProofEnvelope,
        SignedExecutionProofEnvelopes,
    },
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

    /// Submit a proof through node `from`'s Beacon API (`POST /eth/v1/beacon/execution_proofs`).
    ///
    /// The node verifies the proof as gossip would, publishes it to peers, caches it and imports
    /// the payload envelope if the proof completed the requirement. A rejection comes back as an
    /// error carrying the node's indexed failure message, and nothing is published.
    pub async fn submit_execution_proof(
        &self,
        from: usize,
        proof: Arc<SignedExecutionProofEnvelope>,
    ) -> Result<(), String> {
        let proofs = SignedExecutionProofEnvelopes::new(vec![proof.as_ref().clone()])
            .map_err(|e| format!("cannot build a proof list: {e:?}"))?;
        self.remote_node(from)?
            .post_beacon_execution_proofs(&proofs)
            .await
            .map_err(|e| format!("node {from} rejected the proof: {e:?}"))
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

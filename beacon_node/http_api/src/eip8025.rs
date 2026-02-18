//! EIP-8025: Optional Execution Proofs - HTTP API Endpoints
//!
//! This module provides HTTP API endpoints for:
//! - GET `/eth/v1/beacon/proofs/execution_proofs/{block_id}` - Retrieve execution proofs for a block
//! - POST `/eth/v1/beacon/execution_proofs` - Submit pre-signed execution proofs

use crate::block_id::BlockId;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use execution_layer::eip8025::ProofEngine;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, warn};
use types::SignedExecutionProof;
use warp::Reply;
use warp::http::Response;
use warp::hyper::Body;
use warp_utils::reject::{custom_bad_request, custom_server_error};

/// Response for GET /eth/v1/beacon/proofs/execution_proofs/{block_id}
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionProofsResponse {
    pub execution_optimistic: bool,
    pub finalized: bool,
    pub data: Vec<SignedExecutionProof>,
}

/// Request body for POST /eth/v1/beacon/execution_proofs
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitExecutionProofsRequest {
    /// Pre-signed execution proofs from validators
    pub proofs: Vec<SignedExecutionProof>,
}

/// Get execution proofs for a given block.
///
/// Returns execution proofs from the ProofEngine for the block's execution payload.
/// This endpoint requires `--proof-engine-endpoint` to be configured.
pub fn get_execution_proofs<T: BeaconChainTypes>(
    block_id: BlockId,
    chain: Arc<BeaconChain<T>>,
) -> Result<ExecutionProofsResponse, warp::Rejection> {
    // Get the execution layer's proof engine — presence is the only gate.
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or_else(|| custom_server_error("Execution layer not available".to_string()))?;

    let proof_engine = execution_layer
        .proof_engine()
        .ok_or_else(|| custom_bad_request(
            "Proof engine not configured. Start with --proof-engine-endpoint to enable EIP-8025.".to_string(),
        ))?;

    // Get the block to retrieve its execution payload root
    let (block_root, execution_optimistic, finalized) = block_id.root(&chain)?;

    // Get proofs from the proof engine
    let request_root = chain
        .store
        .get_request_root_by_block_root(&block_root)
        .ok_or(custom_server_error("request block is unknown".to_string()))?;
    let proofs = proof_engine.get_proofs_by_root(&request_root);

    debug!(
        block_root = ?block_root,
        num_proofs = proofs.len(),
        "Retrieved execution proofs for block"
    );

    Ok(ExecutionProofsResponse {
        execution_optimistic,
        finalized,
        data: proofs,
    })
}

/// Submit signed execution proofs.
///
/// This endpoint is used by validator clients to submit execution proofs that have been
/// signed by a validator. The proofs will be verified, stored in the ProofEngine, and
/// gossiped to the network.
pub async fn submit_execution_proofs<T: BeaconChainTypes>(
    request: SubmitExecutionProofsRequest,
    chain: Arc<BeaconChain<T>>,
    network_send: UnboundedSender<NetworkMessage<T::EthSpec>>,
) -> Result<Response<Body>, warp::Rejection> {
    // TODO: should we add a verify: bool to verify_execution_proof to allow skipping verification checks from this endpoint if we trust the source?

    // Require proof engine to be configured — presence is the only gate.
    if chain
        .execution_layer
        .as_ref()
        .and_then(|el| el.proof_engine())
        .is_none()
    {
        return Err(custom_bad_request(
            "Proof engine not configured. Start with --proof-engine-endpoint to enable EIP-8025."
                .to_string(),
        ));
    }

    if request.proofs.is_empty() {
        return Err(custom_bad_request("No proofs provided".to_string()));
    }

    // Process each signed proof
    for signed_proof in request.proofs {
        let request_root = signed_proof.request_root();
        let proof_type = signed_proof.proof_type();
        let validator_index = signed_proof.validator_index();

        debug!(
            ?request_root,
            proof_type, validator_index, "Processing submitted signed execution proof"
        );

        // Verify proof (BLS signature + execution engine + fork choice update)
        if let Err(e) = chain.verify_execution_proof(signed_proof.clone()).await {
            warn!(
                error = ?e,
                ?request_root,
                proof_type,
                validator_index,
                "Signed proof validation failed"
            );
            return Err(custom_bad_request(format!(
                "Proof validation failed: {e:?}"
            )));
        }

        // Gossip publish the signed proof
        if let Err(e) = network_send.send(NetworkMessage::Publish {
            messages: vec![PubsubMessage::ExecutionProof(Box::new(signed_proof))],
        }) {
            warn!(
                error = ?e,
                ?request_root,
                proof_type,
                "Failed to gossip signed proof"
            );
        }

        debug!(
            ?request_root,
            proof_type, validator_index, "Signed execution proof verified, stored, and gossiped"
        );
    }

    Ok(warp::reply().into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_proofs_response_serialization() {
        let response = ExecutionProofsResponse {
            execution_optimistic: false,
            finalized: true,
            data: vec![],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("execution_optimistic"));
        assert!(json.contains("finalized"));
        assert!(json.contains("data"));
    }
}

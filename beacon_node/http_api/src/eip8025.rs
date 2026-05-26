//! EIP-8025: Optional Execution Proofs - HTTP API Endpoints
//!
//! This module provides HTTP API endpoints for:
//! - GET `/eth/v1/beacon/execution_proofs/{block_id}` - Retrieve execution proofs for a block
//! - POST `/eth/v1/beacon/execution_proofs` - Submit pre-signed execution proofs

use crate::block_id::BlockId;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::{NetworkGlobals, PubsubMessage};
use network::NetworkMessage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, warn};
use types::{ProofStatus, SignedExecutionProof};
use warp::Reply;
use warp::http::Response;
use warp::hyper::Body;
use warp_utils::reject::{custom_bad_request, custom_not_implemented, custom_server_error};

/// Response for GET /eth/v1/beacon/execution_proofs/{block_id}
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

    let proof_engine = execution_layer.proof_engine().ok_or_else(|| {
        custom_not_implemented(
            "Proof engine not configured. Start with --proof-engine-endpoint to enable EIP-8025."
                .to_string(),
        )
    })?;

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
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
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
        return Err(custom_not_implemented(
            "Proof engine not configured. Start with --proof-engine-endpoint to enable EIP-8025."
                .to_string(),
        ));
    }

    if request.proofs.is_empty() {
        return Err(custom_bad_request("No proofs provided".to_string()));
    }

    // Process each signed proof
    for signed_proof in request.proofs {
        let signed_proof = Arc::new(signed_proof);
        let request_root = signed_proof.request_root();
        let proof_type = signed_proof.proof_type();
        let validator_index = signed_proof.validator_index();

        debug!(
            ?request_root,
            proof_type, validator_index, "Processing submitted signed execution proof"
        );

        let validator_pubkey = chain
            .validator_pubkey_bytes(validator_index as usize)
            .map_err(|e| custom_bad_request(format!("Pubkey lookup failed: {e:?}")))?
            .ok_or_else(|| custom_bad_request("Unknown validator index".to_string()))?;

        // Verify proof (BLS signature + execution engine + fork choice update)
        let (status, verified_block) = chain
            .verify_execution_proof(signed_proof.clone(), validator_pubkey)
            .await
            .map_err(|e| {
                warn!(
                    error = ?e,
                    ?request_root,
                    proof_type,
                    validator_index,
                    "Signed proof validation failed"
                );
                custom_bad_request(format!("Proof validation failed: {e:?}"))
            })?;

        // Update local execution proof status watermark if the proof was fully valid.
        if status.is_valid()
            && let Some((block_root, slot)) = verified_block
        {
            let mut local_status = network_globals.local_execution_proof_status();
            local_status.slot = slot.as_u64();
            local_status.block_root = block_root;
            network_globals.set_local_execution_proof_status(local_status);
        };

        // Only propagate proofs the execution engine accepted as valid or tentatively accepted.
        // Invalid, Syncing, and NotSupported proofs must not be gossiped.
        match status {
            ProofStatus::Valid | ProofStatus::Accepted => {
                if let Err(e) = network_send.send(NetworkMessage::Publish {
                    messages: vec![PubsubMessage::ExecutionProof(signed_proof)],
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
                    proof_type, validator_index, "Signed execution proof verified and gossiped"
                );
            }
            ProofStatus::Invalid => {
                return Err(custom_bad_request(format!(
                    "Proof {request_root:?} is invalid"
                )));
            }
            ProofStatus::Syncing => {
                debug!(
                    ?request_root,
                    proof_type,
                    validator_index,
                    "Proof skipped: node is still syncing the associated block"
                );
            }
            ProofStatus::NotSupported => {
                debug!(
                    ?request_root,
                    proof_type,
                    validator_index,
                    "Proof skipped: proof type not supported by local engine"
                );
            }
        }
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

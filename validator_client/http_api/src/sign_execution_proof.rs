//! EIP-8025: Execution proof signing for validator client.
//!
//! This module provides functionality for validators to sign execution proofs
//! for optional execution verification.

use bls::{PublicKey, PublicKeyBytes};
use eth2::types::GenericResponse;
use lighthouse_validator_store::LighthouseValidatorStore;
use slot_clock::SlotClock;
use std::sync::Arc;
use tracing::info;
use types::{Epoch, EthSpec, ExecutionProof, SignedExecutionProof};

/// Request body for signing an execution proof.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct SignExecutionProofRequest {
    /// The execution proof to sign
    pub execution_proof: ExecutionProof,
    /// The epoch for signing context (optional, defaults to current epoch)
    #[serde(default)]
    pub epoch: Option<Epoch>,
}

/// Signs an execution proof using the specified validator's key.
pub async fn sign_execution_proof<T: 'static + SlotClock + Clone, E: EthSpec>(
    pubkey: PublicKey,
    request: SignExecutionProofRequest,
    validator_store: Arc<LighthouseValidatorStore<T, E>>,
    slot_clock: T,
) -> Result<GenericResponse<SignedExecutionProof>, warp::Rejection> {
    let epoch = match request.epoch {
        Some(epoch) => epoch,
        None => get_current_epoch::<T, E>(slot_clock).ok_or_else(|| {
            warp_utils::reject::custom_server_error("Unable to determine current epoch".to_string())
        })?,
    };

    let pubkey_bytes = PublicKeyBytes::from(pubkey.clone());
    if !validator_store.has_validator(&pubkey_bytes) {
        return Err(warp_utils::reject::custom_not_found(format!(
            "{} is disabled or not managed by this validator client",
            pubkey_bytes.as_hex_string()
        )));
    }

    info!(
        validator = pubkey_bytes.as_hex_string(),
        %epoch,
        proof_type = request.execution_proof.proof_type,
        "Signing execution proof"
    );

    let signed_execution_proof = validator_store
        .sign_execution_proof(pubkey_bytes, request.execution_proof, epoch)
        .await
        .map_err(|e| {
            warp_utils::reject::custom_server_error(format!(
                "Failed to sign execution proof: {:?}",
                e
            ))
        })?;

    Ok(GenericResponse::from(signed_execution_proof))
}

/// Calculates the current epoch from the genesis time and current time.
fn get_current_epoch<T: 'static + SlotClock + Clone, E: EthSpec>(slot_clock: T) -> Option<Epoch> {
    slot_clock.now().map(|s| s.epoch(E::slots_per_epoch()))
}

//! Low-level HTTP client for the proof engine REST+SSZ+SSE API.
//!
//! Handles all network I/O: SSZ serialization, HTTP transport, and SSE streams.
//! No proof state management — that stays in [`super::proof_engine::HttpProofEngine`].

use super::errors::ProofEngineError;
use crate::NewPayloadRequestFulu;
use bytes::Bytes;
use futures::stream::Stream;
use reqwest::Client;
use reqwest_eventsource::{Event, EventSource};
use sensitive_url::SensitiveUrl;
use ssz::Encode;
use ssz_derive::Encode as SszEncode;
use ssz_types::VariableList;
use std::pin::Pin;
use std::time::Duration;
use tokio_stream::StreamExt;

use super::proof_engine::ProofEvent;
use types::execution::eip8025::{ProofAttributes, ProofStatus};
use types::{EthSpec, ExecutionPayloadFulu, ExecutionRequests, Hash256, VersionedHash};

/// Default timeout for proof engine requests (1 second per spec).
pub const PROOF_ENGINE_TIMEOUT: Duration = Duration::from_secs(1);

// ─── Private SSZ Helper ─────────────────────────────────────────────────────

/// SSZ-encodable owned representation of a Fulu NewPayloadRequest.
///
/// Used to serialize the request body when sending to the proof engine.
/// Field order matches the zkboost `NewPayloadRequest` Fulu variant.
#[derive(SszEncode)]
struct SszNewPayloadRequestFulu<E: EthSpec> {
    execution_payload: ExecutionPayloadFulu<E>,
    versioned_hashes: VariableList<VersionedHash, E::MaxBlobCommitmentsPerBlock>,
    parent_beacon_block_root: Hash256,
    execution_requests: ExecutionRequests<E>,
}

impl<'a, E: EthSpec> From<&NewPayloadRequestFulu<'a, E>> for SszNewPayloadRequestFulu<E> {
    fn from(req: &NewPayloadRequestFulu<'a, E>) -> Self {
        Self {
            execution_payload: req.execution_payload.clone(),
            versioned_hashes: req.versioned_hashes.clone(),
            parent_beacon_block_root: req.parent_beacon_block_root,
            execution_requests: req.execution_requests.clone(),
        }
    }
}

// ─── Private REST API Response Types ─────────────────────────────────────────

/// Response for `POST /v1/execution_proof_requests`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProofRequestResponse {
    pub new_payload_request_root: Hash256,
}

/// Response for `POST /v1/execution_proof_verifications`.
#[derive(Debug, Clone, serde::Deserialize)]
struct ProofVerificationResponse {
    status: ProofVerificationStatus,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ProofVerificationStatus {
    Valid,
    Invalid,
}

// ─── ProofNodeClient ─────────────────────────────────────────────────────────

/// Low-level HTTP client for the proof engine REST+SSZ+SSE API.
///
/// Handles all network I/O — SSZ serialization, HTTP transport, SSE streams.
/// No proof state management; that stays in `HttpProofEngine`.
pub struct ProofNodeClient {
    client: Client,
    url: SensitiveUrl,
}

impl ProofNodeClient {
    /// Create a new proof node client.
    pub fn new(url: SensitiveUrl, timeout: Option<Duration>) -> Self {
        let client = Client::builder()
            .timeout(timeout.unwrap_or(PROOF_ENGINE_TIMEOUT))
            .build()
            .expect("Failed to build HTTP client");

        Self { client, url }
    }

    /// Request proof generation from the proof engine.
    ///
    /// `POST /v1/execution_proof_requests?proof_types=0,1,2`
    /// Body: SSZ-encoded NewPayloadRequest
    /// Returns the `new_payload_request_root` identifying this request.
    pub async fn request_proofs<E: EthSpec>(
        &self,
        new_payload_request_fulu: NewPayloadRequestFulu<'_, E>,
        proof_attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError> {
        let mut url = self.url.expose_full().clone();
        url.set_path("/v1/execution_proof_requests");

        let proof_types_str = proof_attributes
            .proof_types
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(",");
        url.set_query(Some(&format!("proof_types={proof_types_str}")));

        let ssz_body = SszNewPayloadRequestFulu::from(&new_payload_request_fulu);

        let response: ProofRequestResponse = self
            .client
            .post(url)
            .header("content-type", "application/octet-stream")
            .body(ssz_body.as_ssz_bytes())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(response.new_payload_request_root)
    }

    /// Verify a proof via the proof engine REST API.
    ///
    /// `POST /v1/execution_proof_verifications?new_payload_request_root=...&proof_type=...`
    /// Body: raw proof bytes
    pub async fn verify_proof(
        &self,
        new_payload_request_root: Hash256,
        proof_type: u8,
        proof_data: &[u8],
    ) -> Result<ProofStatus, ProofEngineError> {
        let mut url = self.url.expose_full().clone();
        url.set_path("/v1/execution_proof_verifications");
        url.set_query(Some(&format!(
            "new_payload_request_root={new_payload_request_root}&proof_type={proof_type}"
        )));

        let response: ProofVerificationResponse = self
            .client
            .post(url)
            .header("content-type", "application/octet-stream")
            .body(proof_data.to_vec())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        match response.status {
            ProofVerificationStatus::Valid => Ok(ProofStatus::Valid),
            ProofVerificationStatus::Invalid => Ok(ProofStatus::Invalid),
        }
    }

    /// Download a completed execution proof by proof type.
    ///
    /// `GET /v1/execution_proofs/{root}/{proof_type}`
    pub async fn get_proof(
        &self,
        new_payload_request_root: Hash256,
        proof_type: u8,
    ) -> Result<Bytes, ProofEngineError> {
        let mut url = self.url.expose_full().clone();
        url.set_path(&format!(
            "/v1/execution_proofs/{new_payload_request_root}/{proof_type}"
        ));

        let response = self.client.get(url).send().await?.error_for_status()?;

        Ok(response.bytes().await?)
    }

    /// Subscribe to SSE proof events from the proof engine.
    ///
    /// Opens `GET /v1/execution_proof_requests` as an SSE stream.
    /// When `filter_root` is provided, only events for that root are received.
    pub fn subscribe_proof_events(
        &self,
        filter_root: Option<Hash256>,
    ) -> Pin<Box<dyn Stream<Item = Result<ProofEvent, ProofEngineError>> + Send + '_>> {
        let client = self.client.clone();
        let base_url = self.url.expose_full().clone();

        Box::pin(async_stream::try_stream! {
            let mut url = base_url;
            url.set_path("/v1/execution_proof_requests");
            if let Some(root) = filter_root {
                url.set_query(Some(&format!("new_payload_request_root={root}")));
            }

            let builder = client.get(url);
            let mut es = EventSource::new(builder)
                .map_err(|e| ProofEngineError::SseError(
                    format!("failed to create event source: {e}")
                ))?;

            while let Some(event) = es.next().await {
                match event {
                    Ok(Event::Open) => {}
                    Ok(Event::Message(message)) => {
                        yield ProofEvent::try_from_parts(&message.event, &message.data)?;
                    }
                    Err(error) => {
                        es.close();
                        Err(ProofEngineError::SseError(error.to_string()))?;
                    }
                }
            }
        })
    }
}

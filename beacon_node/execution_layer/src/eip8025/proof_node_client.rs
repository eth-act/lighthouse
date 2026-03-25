//! Proof node client trait and HTTP implementation for EIP-8025.
//!
//! [`ProofNodeClient`] abstracts over the transport used to communicate with the
//! proof engine. [`HttpProofNodeClient`] is the production implementation.

use super::errors::ProofEngineError;
use bytes::Bytes;
use futures::stream::Stream;
use reqwest::Client;
use reqwest_eventsource::{Event, EventSource};
use sensitive_url::SensitiveUrl;
use std::pin::Pin;
use std::time::Duration;
use tokio_stream::StreamExt;

use super::types::{ProofEvent, ProofType, SseEventParts};
use types::Hash256;
use types::execution::eip8025::{ProofAttributes, ProofStatus};

/// Default timeout for proof engine requests (1 second per spec).
pub const PROOF_ENGINE_TIMEOUT: Duration = Duration::from_secs(1);

const PATH_PROOF_REQUESTS: &str = "/v1/execution_proof_requests";
const PATH_PROOF_VERIFICATIONS: &str = "/v1/execution_proof_verifications";
const PATH_PROOFS: &str = "/v1/execution_proofs";

const QUERY_PROOF_TYPES: &str = "proof_types";
const QUERY_NEW_PAYLOAD_REQUEST_ROOT: &str = "new_payload_request_root";
const QUERY_PROOF_TYPE: &str = "proof_type";

const HEADER_CONTENT_TYPE: &str = "content-type";
const HEADER_VALUE_SSZ: &str = "application/octet-stream";

// ─── ProofNodeClient Trait ───────────────────────────────────────────────────

/// Transport abstraction for communicating with a proof engine.
///
/// The SSZ encoding of the payload is done by the caller ([`HttpProofEngine`])
/// before invoking [`request_proofs`], so implementations receive raw bytes and
/// do not need to be generic over [`EthSpec`].
///
/// [`HttpProofEngine`]: super::proof_engine::HttpProofEngine
/// [`request_proofs`]: ProofNodeClient::request_proofs
/// [`EthSpec`]: types::EthSpec
#[async_trait::async_trait]
pub trait ProofNodeClient: Send + Sync {
    /// Submit an SSZ-encoded `NewPayloadRequest` to the proof engine.
    ///
    /// Returns the `new_payload_request_root` assigned by the proof engine.
    async fn request_proofs(
        &self,
        ssz_body: Vec<u8>,
        proof_attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError>;

    /// Verify a single proof via the proof engine.
    async fn verify_proof(
        &self,
        root: Hash256,
        proof_type: u8,
        proof_data: &[u8],
    ) -> Result<ProofStatus, ProofEngineError>;

    /// Download a completed proof by root and proof type.
    async fn get_proof(&self, root: Hash256, proof_type: u8) -> Result<Bytes, ProofEngineError>;

    /// Subscribe to SSE proof events from the proof engine.
    ///
    /// When `filter_root` is provided, only events for that root are yielded.
    fn subscribe_proof_events(
        &self,
        filter_root: Option<Hash256>,
    ) -> Pin<Box<dyn Stream<Item = Result<ProofEvent, ProofEngineError>> + Send + '_>>;

    /// Subscribe to method-invocation events emitted by a mock client.
    ///
    /// Returns `None` for production clients; overridden in [`MockProofNodeClient`] to
    /// expose its internal broadcast channel for test assertions.
    ///
    /// [`MockProofNodeClient`]: crate::test_utils::MockProofNodeClient
    fn subscribe_client_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<crate::test_utils::MockClientEvent>> {
        None
    }
}

// ─── REST API Response Types ─────────────────────────────────────────────────

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

// ─── HttpProofNodeClient ─────────────────────────────────────────────────────

/// HTTP implementation of [`ProofNodeClient`].
///
/// Handles all network I/O — SSZ body transport, HTTP requests, SSE streams.
/// No proof state management; that stays in [`HttpProofEngine`].
///
/// [`HttpProofEngine`]: super::proof_engine::HttpProofEngine
pub struct HttpProofNodeClient {
    client: Client,
    url: SensitiveUrl,
    timeout: Duration,
}

impl HttpProofNodeClient {
    /// Create a new HTTP proof node client.
    pub fn new(url: SensitiveUrl, timeout: Option<Duration>) -> Self {
        let client = Client::builder()
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            url,
            timeout: timeout.unwrap_or(PROOF_ENGINE_TIMEOUT),
        }
    }

    /// Build a URL from the base URL and a path.
    fn url(&self, path: &str) -> reqwest::Url {
        let mut url = self.url.expose_full().clone();
        url.set_path(path);
        url
    }
}

#[async_trait::async_trait]
impl ProofNodeClient for HttpProofNodeClient {
    /// `POST /v1/execution_proof_requests?proof_types=reth-sp1,ethrex-risc0`
    ///
    /// Converts EIP-8025 `u8` proof types to string identifiers for the wire
    /// format.
    async fn request_proofs(
        &self,
        ssz_body: Vec<u8>,
        proof_attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError> {
        // Convert u8 proof types to string identifiers.
        // proof node expects: `proof_types=reth-sp1,ethrex-risc0`
        let proof_types_csv = proof_attributes
            .proof_types
            .iter()
            .map(|t| ProofType::from_u8(*t).map(|pt| pt.as_str().to_string()))
            .collect::<Result<Vec<_>, _>>()?
            .join(",");

        let response: ProofRequestResponse = self
            .client
            .post(self.url(PATH_PROOF_REQUESTS))
            .query(&[(QUERY_PROOF_TYPES, &proof_types_csv)])
            .header(HEADER_CONTENT_TYPE, HEADER_VALUE_SSZ)
            .body(ssz_body)
            .timeout(self.timeout)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(response.new_payload_request_root)
    }

    /// `POST /v1/execution_proof_verifications?new_payload_request_root=...&proof_type=reth-sp1`
    ///
    /// Converts the `u8` proof type to a string identifier for the query param.
    async fn verify_proof(
        &self,
        root: Hash256,
        proof_type: u8,
        proof_data: &[u8],
    ) -> Result<ProofStatus, ProofEngineError> {
        let proof_type_str = ProofType::from_u8(proof_type)?;
        let response: ProofVerificationResponse = self
            .client
            .post(self.url(PATH_PROOF_VERIFICATIONS))
            .query(&[
                (QUERY_NEW_PAYLOAD_REQUEST_ROOT, &root.to_string()),
                (QUERY_PROOF_TYPE, &proof_type_str.to_string()),
            ])
            .header(HEADER_CONTENT_TYPE, HEADER_VALUE_SSZ)
            .body(proof_data.to_vec())
            .timeout(self.timeout)
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

    /// `GET /v1/execution_proofs/{root}/{proof_type}`
    ///
    /// Uses string identifier in the URL path (e.g. `/reth-sp1`).
    async fn get_proof(&self, root: Hash256, proof_type: u8) -> Result<Bytes, ProofEngineError> {
        let proof_type_str = ProofType::from_u8(proof_type)?;
        Ok(self
            .client
            .get(self.url(&format!("{PATH_PROOFS}/{root}/{proof_type_str}")))
            .timeout(self.timeout)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?)
    }

    /// Opens `GET /v1/execution_proof_requests` as an SSE stream.
    fn subscribe_proof_events(
        &self,
        filter_root: Option<Hash256>,
    ) -> Pin<Box<dyn Stream<Item = Result<ProofEvent, ProofEngineError>> + Send + '_>> {
        let client = self.client.clone();
        let url = self.url(PATH_PROOF_REQUESTS);

        Box::pin(async_stream::try_stream! {
            let builder = if let Some(root) = filter_root {
                client.get(url).query(&[(QUERY_NEW_PAYLOAD_REQUEST_ROOT, &root.to_string())])
            } else {
                client.get(url)
            };
            let mut es = EventSource::new(builder)
                .map_err(|e| ProofEngineError::SseError(
                    format!("failed to create event source: {e}")
                ))?;

            while let Some(event) = es.next().await {
                match event {
                    Ok(Event::Open) => {}
                    Ok(Event::Message(message)) => {
                        yield ProofEvent::try_from(SseEventParts(&message.event, &message.data))?;
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

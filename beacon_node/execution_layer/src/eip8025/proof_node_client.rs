use super::errors::ProofEngineError;
use super::types::{ProofEvent, ProofType, SseEventParts};
use bytes::Bytes;
use futures::stream::Stream;
use reqwest::Client;
use reqwest_eventsource::{Event, EventSource};
use sensitive_url::SensitiveUrl;
use std::pin::Pin;
use std::time::Duration;
use tokio_stream::StreamExt;
use types::Hash256;
use types::execution::eip8025::{ProofAttributes, ProofStatus};

pub const PROOF_ENGINE_TIMEOUT: Duration = Duration::from_secs(1);

const PATH_PROOF_REQUESTS: &str = "/v1/execution_proof_requests";
const PATH_PROOF_VERIFICATIONS: &str = "/v1/execution_proof_verifications";
const PATH_PROOFS: &str = "/v1/execution_proofs";

const QUERY_PROOF_TYPES: &str = "proof_types";
const QUERY_NEW_PAYLOAD_REQUEST_ROOT: &str = "new_payload_request_root";
const QUERY_PROOF_TYPE: &str = "proof_type";

const HEADER_CONTENT_TYPE: &str = "content-type";
const HEADER_VALUE_SSZ: &str = "application/octet-stream";

#[async_trait::async_trait]
pub trait ProofNodeClient: Send + Sync {
    async fn request_proofs(
        &self,
        ssz_body: Vec<u8>,
        proof_attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError>;

    async fn verify_proof(
        &self,
        root: Hash256,
        proof_type: u8,
        proof_data: &[u8],
    ) -> Result<ProofStatus, ProofEngineError>;

    async fn get_proof(&self, root: Hash256, proof_type: u8) -> Result<Bytes, ProofEngineError>;

    fn subscribe_proof_events(
        &self,
        filter_root: Option<Hash256>,
    ) -> Pin<Box<dyn Stream<Item = Result<ProofEvent, ProofEngineError>> + Send + '_>>;
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProofRequestResponse {
    pub new_payload_request_root: Hash256,
}

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

pub struct HttpProofNodeClient {
    client: Client,
    url: SensitiveUrl,
    timeout: Duration,
}

impl HttpProofNodeClient {
    pub fn new(url: SensitiveUrl, timeout: Option<Duration>) -> Self {
        let client = Client::builder()
            .build()
            .expect("failed to build proof-engine HTTP client");

        Self {
            client,
            url,
            timeout: timeout.unwrap_or(PROOF_ENGINE_TIMEOUT),
        }
    }

    fn url(&self, path: &str) -> reqwest::Url {
        let mut url = self.url.expose_full().clone();
        url.set_path(path);
        url
    }
}

#[async_trait::async_trait]
impl ProofNodeClient for HttpProofNodeClient {
    async fn request_proofs(
        &self,
        ssz_body: Vec<u8>,
        proof_attributes: ProofAttributes,
    ) -> Result<Hash256, ProofEngineError> {
        let proof_types_csv = proof_attributes
            .proof_types
            .iter()
            .map(|proof_type| ProofType::from_u8(*proof_type).map(|pt| pt.as_str().to_string()))
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

    async fn verify_proof(
        &self,
        root: Hash256,
        proof_type: u8,
        proof_data: &[u8],
    ) -> Result<ProofStatus, ProofEngineError> {
        let proof_type = ProofType::from_u8(proof_type)?;
        let response: ProofVerificationResponse = self
            .client
            .post(self.url(PATH_PROOF_VERIFICATIONS))
            .query(&[
                (QUERY_NEW_PAYLOAD_REQUEST_ROOT, &root.to_string()),
                (QUERY_PROOF_TYPE, &proof_type.to_string()),
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

    async fn get_proof(&self, root: Hash256, proof_type: u8) -> Result<Bytes, ProofEngineError> {
        let proof_type = ProofType::from_u8(proof_type)?;
        Ok(self
            .client
            .get(self.url(&format!("{PATH_PROOFS}/{root}/{proof_type}")))
            .timeout(self.timeout)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?)
    }

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
            let mut events = EventSource::new(builder)
                .map_err(|e| ProofEngineError::SseError(
                    format!("failed to create proof-engine event source: {e}")
                ))?;

            while let Some(event) = events.next().await {
                match event {
                    Ok(Event::Open) => {}
                    Ok(Event::Message(message)) => {
                        yield ProofEvent::try_from(SseEventParts(&message.event, &message.data))?;
                    }
                    Err(error) => {
                        events.close();
                        Err(ProofEngineError::SseError(error.to_string()))?;
                    }
                }
            }
        })
    }
}

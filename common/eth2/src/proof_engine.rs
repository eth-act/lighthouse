//! HTTP JSON-RPC client for EIP-8025 proof engine interaction.
//!
//! This module provides an HTTP client for communicating with external proof engines
//! that implement the `engine_requestProofsV1` JSON-RPC method for EIP-8025.

use reqwest::Client;
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use serde_json::json;
use types::Hash256;

/// HTTP client for proof engine JSON-RPC communication
#[derive(Clone)]
pub struct ProofEngineHttpClient {
    url: SensitiveUrl,
    client: Client,
}

/// Unique identifier for a proof generation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofGenId(pub String);

impl std::fmt::Display for ProofGenId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// JSON-RPC response from proof engine
#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    result: ProofGenId,
}

impl ProofEngineHttpClient {
    /// Create a new proof engine HTTP client
    pub fn new(url: SensitiveUrl) -> Self {
        Self {
            url,
            client: Client::new(),
        }
    }

    /// Request async proof generation for a block
    ///
    /// The proof engine will generate proofs asynchronously and callback to the
    /// validator client's HTTP API when ready.
    ///
    /// # Arguments
    ///
    /// * `block_root` - The block root to generate proofs for
    /// * `callback_url` - The validator client HTTP API URL for callbacks
    ///
    /// # Returns
    ///
    /// A unique `ProofGenId` that identifies this proof generation request
    pub async fn request_proofs_for_block(
        &self,
        block_root: Hash256,
        callback_url: String,
    ) -> Result<ProofGenId, String> {
        let response = self
            .client
            .post(self.url.expose_full().clone())
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "engine_requestProofsV1",
                "params": [{
                    "block_root": block_root,
                    "callback_url": callback_url,
                }],
                "id": 1
            }))
            .send()
            .await
            .map_err(|e| format!("Failed to send request to proof engine: {}", e))?;

        if !response.status().is_success() {
            return Err(format!(
                "Proof engine returned error status: {}",
                response.status()
            ));
        }

        let json_response: JsonRpcResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse proof engine response: {}", e))?;

        Ok(json_response.result)
    }
}

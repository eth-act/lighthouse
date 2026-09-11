//! A proving execution layer: a JSON-RPC proxy in front of a node's mock execution layer that
//! turns every valid `engine_newPayload` into execution proofs.
//!
//! Every engine call is forwarded unchanged. When `engine_newPayload*` returns `VALID`, the
//! proxy resolves the beacon block that carries the payload through the node's Beacon API
//! (headers by parent root, matched on the bid's block hash), signs one proof envelope per
//! configured `(proof_type, proof_data)` pair with a deterministic interop validator key, and
//! posts them to `POST /eth/v1/beacon/execution_proofs`. This is the shape of a prover that
//! sits beside an execution client; here the proofs are mock bytes chosen by the scenario.

use crate::E;
use node_test_rig::eth2::{BeaconNodeHttpClient, types::BlockId};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};
use types::{
    ChainSpec, Domain, ExecutionBlockHash, Hash256, SignedRoot, Slot,
    execution::{
        ExecutionProofEnvelope, ProofData, ProofType, SignedExecutionProofEnvelope,
        SignedExecutionProofEnvelopes,
    },
    test_utils::generate_deterministic_keypair,
};
use warp::{Filter, http::StatusCode};

/// How the middleware proves each payload.
#[derive(Debug, Clone)]
pub struct ProverSpec {
    /// One proof per pair, submitted together for every valid payload.
    pub proofs: Vec<(ProofType, Vec<u8>)>,
    /// Validator whose deterministic interop key signs the envelopes.
    pub validator_index: u64,
}

/// A payload the middleware proved, in submission order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenPayload {
    pub block_root: Hash256,
    pub block_hash: ExecutionBlockHash,
    pub slot: Slot,
    pub proof_types: Vec<ProofType>,
}

/// How long the prover waits for the beacon node to expose the block carrying a payload.
const BLOCK_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
const BLOCK_LOOKUP_INTERVAL: Duration = Duration::from_millis(250);

struct Inner {
    upstream: String,
    client: reqwest::Client,
    spec: Arc<ChainSpec>,
    prover: ProverSpec,
    /// The beacon node's API, set once the node has started.
    target: RwLock<Option<BeaconNodeHttpClient>>,
    proven: Mutex<Vec<ProvenPayload>>,
}

/// Handle to a running proving execution layer.
pub struct ProvingExecutionLayer {
    pub listen_addr: SocketAddr,
    inner: Arc<Inner>,
    _shutdown: oneshot::Sender<()>,
}

impl ProvingExecutionLayer {
    /// Start the proxy on `listen_port`, forwarding to the mock execution layer at `upstream`.
    pub fn start(
        handle: &tokio::runtime::Handle,
        listen_port: u16,
        upstream: String,
        spec: Arc<ChainSpec>,
        prover: ProverSpec,
    ) -> Result<Self, String> {
        let inner = Arc::new(Inner {
            upstream,
            client: reqwest::Client::new(),
            spec,
            prover,
            target: RwLock::new(None),
            proven: Mutex::new(Vec::new()),
        });
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let routes = warp::post()
            .and(warp::header::optional::<String>("authorization"))
            .and(warp::body::json())
            .then({
                let inner = inner.clone();
                move |authorization: Option<String>, request: serde_json::Value| {
                    let inner = inner.clone();
                    async move { inner.forward(authorization, request).await }
                }
            });

        // Bind like the mock execution client does: a non-blocking std listener handed to tokio.
        let std_listener =
            std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], listen_port))).map_err(
                |e| format!("cannot bind proving execution layer on {listen_port}: {e}"),
            )?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| format!("cannot configure proving execution layer socket: {e}"))?;
        let _runtime = handle.enter();
        let listener = tokio::net::TcpListener::from_std(std_listener)
            .map_err(|e| format!("cannot register proving execution layer socket: {e}"))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|e| format!("cannot read proving execution layer address: {e}"))?;
        let server = warp::serve(routes)
            .incoming(listener)
            .graceful(async {
                let _ = shutdown_rx.await;
            })
            .run();
        handle.spawn(server);
        info!(%listen_addr, upstream = %inner.upstream, "Started proving execution layer");

        Ok(Self {
            listen_addr,
            inner,
            _shutdown: shutdown_tx,
        })
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.listen_addr)
    }

    /// Point the prover at the beacon node that receives its proofs.
    pub fn set_target(&self, target: BeaconNodeHttpClient) {
        *self.inner.target.write().expect("target lock poisoned") = Some(target);
    }

    /// Payloads proved so far, in submission order.
    pub fn proven_payloads(&self) -> Vec<ProvenPayload> {
        self.inner
            .proven
            .lock()
            .expect("proven lock poisoned")
            .clone()
    }
}

impl Inner {
    async fn forward(
        self: Arc<Self>,
        authorization: Option<String>,
        request: serde_json::Value,
    ) -> warp::reply::WithStatus<warp::reply::Json> {
        let mut upstream = self.client.post(&self.upstream).json(&request);
        if let Some(authorization) = authorization {
            upstream = upstream.header("authorization", authorization);
        }
        let (status, response) = match upstream.send().await {
            Ok(response) => {
                let status = response.status();
                match response.json::<serde_json::Value>().await {
                    Ok(body) => (status, body),
                    Err(e) => {
                        warn!(error = %e, "Proving execution layer got a non-JSON upstream reply");
                        (status, serde_json::Value::Null)
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Proving execution layer could not reach the mock execution layer");
                (reqwest::StatusCode::BAD_GATEWAY, serde_json::Value::Null)
            }
        };

        if let Some(payload) = new_valid_payload(&request, &response) {
            tokio::spawn(self.clone().prove(payload));
        }

        warp::reply::with_status(
            warp::reply::json(&response),
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        )
    }

    async fn prove(self: Arc<Self>, payload: NewPayload) {
        if let Err(error) = self.try_prove(&payload).await {
            warn!(
                block_hash = ?payload.block_hash,
                parent_beacon_block_root = ?payload.parent_beacon_block_root,
                error,
                "Proving execution layer could not prove a payload"
            );
        }
    }

    async fn try_prove(&self, payload: &NewPayload) -> Result<(), String> {
        let target = self
            .target
            .read()
            .expect("target lock poisoned")
            .clone()
            .ok_or("no beacon node attached to the proving execution layer yet")?;

        let (block_root, slot) = self.find_block(&target, payload).await?;
        let genesis_validators_root = target
            .get_beacon_genesis()
            .await
            .map_err(|e| format!("genesis lookup failed: {e:?}"))?
            .data
            .genesis_validators_root;
        let fork_name = self.spec.fork_name_at_slot::<E>(slot);
        let domain = self.spec.compute_domain(
            Domain::ExecutionProof,
            self.spec.fork_version_for_name(fork_name),
            genesis_validators_root,
        );
        let keypair = generate_deterministic_keypair(self.prover.validator_index as usize);

        let mut envelopes = Vec::with_capacity(self.prover.proofs.len());
        for (proof_type, proof_data) in &self.prover.proofs {
            let message = ExecutionProofEnvelope {
                proof_data: ProofData::new(proof_data.clone())
                    .map_err(|e| format!("proof data exceeds the size bound: {e:?}"))?,
                proof_type: *proof_type,
                beacon_block_root: block_root,
            };
            let signature = keypair.sk.sign(message.signing_root(domain));
            envelopes.push(SignedExecutionProofEnvelope {
                message,
                validator_index: self.prover.validator_index,
                signature,
            });
        }
        let proofs = SignedExecutionProofEnvelopes::new(envelopes)
            .map_err(|e| format!("too many proofs per payload: {e:?}"))?;
        target
            .post_beacon_execution_proofs(&proofs)
            .await
            .map_err(|e| format!("proof submission failed: {e:?}"))?;

        let proof_types = self.prover.proofs.iter().map(|(t, _)| *t).collect();
        info!(?block_root, %slot, ?proof_types, "Proving execution layer submitted proofs");
        self.proven
            .lock()
            .expect("proven lock poisoned")
            .push(ProvenPayload {
                block_root,
                block_hash: payload.block_hash,
                slot,
                proof_types,
            });
        Ok(())
    }

    /// Find the beacon block whose bid commits to `payload.block_hash`: a child of
    /// `payload.parent_beacon_block_root` in the node's view.
    async fn find_block(
        &self,
        target: &BeaconNodeHttpClient,
        payload: &NewPayload,
    ) -> Result<(Hash256, Slot), String> {
        let deadline = tokio::time::Instant::now() + BLOCK_LOOKUP_TIMEOUT;
        loop {
            let headers = target
                .get_beacon_headers(None, Some(payload.parent_beacon_block_root))
                .await
                .map_err(|e| format!("header lookup failed: {e:?}"))?
                .map(|response| response.data)
                .unwrap_or_default();
            for header in headers {
                let block = target
                    .get_beacon_blocks::<E>(BlockId::Root(header.root))
                    .await
                    .map_err(|e| format!("block lookup failed: {e:?}"))?;
                let Some(block) = block else { continue };
                let bid_hash = block
                    .data()
                    .message()
                    .body()
                    .signed_execution_payload_bid()
                    .map(|bid| bid.message.block_hash)
                    .map_err(|e| format!("block {:?} has no bid: {e:?}", header.root))?;
                if bid_hash == payload.block_hash {
                    return Ok((header.root, header.header.message.slot));
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "no block with bid hash {:?} below parent {:?} within {BLOCK_LOOKUP_TIMEOUT:?}",
                    payload.block_hash, payload.parent_beacon_block_root
                ));
            }
            tokio::time::sleep(BLOCK_LOOKUP_INTERVAL).await;
        }
    }
}

/// What the prover needs from a valid `engine_newPayload` exchange.
struct NewPayload {
    block_hash: ExecutionBlockHash,
    parent_beacon_block_root: Hash256,
}

/// Extract the payload from a JSON-RPC `engine_newPayload*` request whose response is `VALID`.
fn new_valid_payload(
    request: &serde_json::Value,
    response: &serde_json::Value,
) -> Option<NewPayload> {
    let method = request.get("method")?.as_str()?;
    if !method.starts_with("engine_newPayload") {
        return None;
    }
    if response.pointer("/result/status")?.as_str()? != "VALID" {
        debug!(method, "Proving execution layer skips a non-valid payload");
        return None;
    }
    let params = request.get("params")?.as_array()?;
    let block_hash = serde_json::from_value(params.first()?.get("blockHash")?.clone()).ok()?;
    let parent_beacon_block_root = serde_json::from_value(params.get(2)?.clone()).ok()?;
    Some(NewPayload {
        block_hash,
        parent_beacon_block_root,
    })
}

//! Per-node observation of proofs, payloads and peers, with bounded waits.

use crate::ProofNetwork;
use std::time::{Duration, Instant};
use types::{Hash256, Slot, execution::ProofType};

const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// What one node knows about a block and the proofs of one type for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStatus {
    pub node: usize,
    /// The block is in fork choice.
    pub block_known: bool,
    /// A valid proof of the requested type was verified for the block.
    pub valid_proof_verified: bool,
    /// Proof types held in the pending payload cache for the block.
    pub cached_proof_types: Vec<ProofType>,
    /// The executed payload envelope sits in the pending payload cache, waiting for proofs or
    /// data columns before it can be imported.
    pub envelope_pending: bool,
    /// The payload envelope is persisted in the store.
    pub envelope_stored: bool,
    /// Fork choice marks the block's payload as received.
    pub payload_received: bool,
    pub head_slot: Slot,
}

impl ProofNetwork {
    /// Snapshot node `node`'s view of `block_root` and proofs of `proof_type` for it.
    pub fn proof_status(
        &self,
        node: usize,
        block_root: Hash256,
        proof_type: ProofType,
    ) -> Result<ProofStatus, String> {
        let chain = self.chain(node)?;
        let (block_slot, payload_received) = {
            let fork_choice = chain.canonical_head.fork_choice_read_lock();
            (
                fork_choice.get_block(&block_root).map(|block| block.slot),
                fork_choice.is_payload_received(&block_root),
            )
        };
        let valid_proof_verified = block_slot.is_some_and(|slot| {
            chain
                .observed_execution_proofs
                .read()
                .has_valid_proof(block_root, proof_type, slot)
                .unwrap_or(false)
        });
        Ok(ProofStatus {
            node,
            block_known: block_slot.is_some(),
            valid_proof_verified,
            cached_proof_types: chain
                .pending_payload_cache
                .cached_execution_proof_types(&block_root)
                .unwrap_or_default(),
            envelope_pending: chain
                .pending_payload_cache
                .get_executed_payload_envelope(&block_root)
                .is_some(),
            envelope_stored: chain
                .store
                .payload_envelope_exists(&block_root)
                .map_err(|e| format!("node {node} store error: {e:?}"))?,
            payload_received,
            head_slot: chain.canonical_head.cached_head().head_slot(),
        })
    }

    /// [`Self::proof_status`] for every node.
    pub fn proof_statuses(
        &self,
        block_root: Hash256,
        proof_type: ProofType,
    ) -> Result<Vec<ProofStatus>, String> {
        (0..self.node_count())
            .map(|node| self.proof_status(node, block_root, proof_type))
            .collect()
    }

    pub fn head_block_root(&self, node: usize) -> Result<Hash256, String> {
        Ok(self
            .chain(node)?
            .canonical_head
            .cached_head()
            .head_block_root())
    }

    /// Node `node`'s score for node `peer`, or `None` if they are not connected.
    pub fn peer_score(&self, node: usize, peer: usize) -> Result<Option<f64>, String> {
        let beacon_nodes = self.network.beacon_nodes.read();
        let globals = |index: usize| {
            beacon_nodes
                .get(index)
                .ok_or(format!("no node {index}"))?
                .client
                .network_globals()
                .ok_or(format!("node {index} has no network service"))
        };
        let peer_id = globals(peer)?.local_peer_id();
        Ok(globals(node)?
            .peers
            .read()
            .peer_info(&peer_id)
            .map(|info| info.score().score()))
    }

    /// One line per node: head, payload status of the head, finality and peer count.
    pub fn describe(&self) -> String {
        let mut lines = Vec::with_capacity(self.node_count());
        for node in 0..self.node_count() {
            let line = match self.chain(node) {
                Ok(chain) => {
                    let head = chain.canonical_head.cached_head();
                    let head_root = head.head_block_root();
                    let payload_received = chain
                        .canonical_head
                        .fork_choice_read_lock()
                        .is_payload_received(&head_root);
                    let peers = self
                        .network
                        .beacon_nodes
                        .read()
                        .get(node)
                        .and_then(|node| node.client.network_globals())
                        .map(|globals| globals.connected_peers())
                        .unwrap_or_default();
                    format!(
                        "node {node}: head slot {} root {head_root:?} payload_received={payload_received} \
                         finalized epoch {} peers {peers} proof_engine={}",
                        head.head_slot(),
                        head.finalized_checkpoint().epoch,
                        self.node_spec(node)
                            .map(|spec| spec.valid_proof_data.is_some())
                            .unwrap_or(false),
                    )
                }
                Err(e) => format!("node {node}: {e}"),
            };
            lines.push(line);
        }
        lines.join("\n")
    }

    /// Poll `condition` until it holds or `timeout` elapses. The timeout error names `what` and
    /// includes [`Self::describe`].
    pub async fn wait_for<F>(
        &self,
        what: &str,
        timeout: Duration,
        mut condition: F,
    ) -> Result<(), String>
    where
        F: FnMut(&Self) -> Result<bool, String>,
    {
        let start = Instant::now();
        loop {
            if condition(self)? {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                return Err(format!(
                    "timed out after {timeout:?} waiting for {what}\n{}",
                    self.describe()
                ));
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Wait until node `node`'s head reaches `slot`, returning the head block root.
    pub async fn wait_for_head_slot(
        &self,
        node: usize,
        slot: Slot,
        timeout: Duration,
    ) -> Result<Hash256, String> {
        self.wait_for(
            &format!("node {node} head to reach slot {slot}"),
            timeout,
            |net| Ok(net.chain(node)?.canonical_head.cached_head().head_slot() >= slot),
        )
        .await?;
        self.head_block_root(node)
    }

    /// Wait until node `node`'s head block has an executed payload envelope waiting in the pending
    /// payload cache, returning that block's root.
    ///
    /// A node with a proof engine stops at the first full block: it executes the envelope but
    /// cannot import it without proofs, and every later block builds on that payload. This is
    /// the block scenarios should submit proofs for.
    pub async fn wait_for_pending_payload(
        &self,
        node: usize,
        timeout: Duration,
    ) -> Result<Hash256, String> {
        self.wait_for(
            &format!("node {node} to hold a payload envelope pending proofs"),
            timeout,
            |net| {
                let head_root = net.head_block_root(node)?;
                let status = net.proof_status(node, head_root, 0)?;
                Ok(status.envelope_pending && !status.payload_received)
            },
        )
        .await?;
        self.head_block_root(node)
    }

    /// Wait until every node in `nodes` is connected to at least `min_peers` peers.
    pub async fn wait_for_peers(
        &self,
        nodes: &[usize],
        min_peers: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        self.wait_for(
            &format!("nodes {nodes:?} to have {min_peers} peers"),
            timeout,
            |net| {
                let beacon_nodes = net.network.beacon_nodes.read();
                nodes.iter().try_fold(true, |all, node| {
                    let peers = beacon_nodes
                        .get(*node)
                        .ok_or(format!("no node {node}"))?
                        .client
                        .network_globals()
                        .map(|globals| globals.connected_peers())
                        .unwrap_or_default();
                    Ok(all && peers >= min_peers)
                })
            },
        )
        .await
    }

    /// Wait until every node in `nodes` has verified a valid proof of `proof_type` for
    /// `block_root`. The timeout error includes each node's [`ProofStatus`].
    pub async fn wait_for_valid_proof(
        &self,
        nodes: &[usize],
        block_root: Hash256,
        proof_type: ProofType,
        timeout: Duration,
    ) -> Result<(), String> {
        self.wait_for_statuses(
            &format!("nodes {nodes:?} to verify a type {proof_type} proof for {block_root:?}"),
            nodes,
            block_root,
            proof_type,
            timeout,
            |status| status.valid_proof_verified,
        )
        .await
    }

    /// Wait until every node in `nodes` has imported the payload of `block_root`.
    pub async fn wait_for_payload_received(
        &self,
        nodes: &[usize],
        block_root: Hash256,
        timeout: Duration,
    ) -> Result<(), String> {
        self.wait_for_statuses(
            &format!("nodes {nodes:?} to receive the payload of {block_root:?}"),
            nodes,
            block_root,
            0,
            timeout,
            |status| status.payload_received,
        )
        .await
    }

    async fn wait_for_statuses(
        &self,
        what: &str,
        nodes: &[usize],
        block_root: Hash256,
        proof_type: ProofType,
        timeout: Duration,
        satisfied: impl Fn(&ProofStatus) -> bool,
    ) -> Result<(), String> {
        self.wait_for(what, timeout, |net| {
            nodes.iter().try_fold(true, |all, node| {
                Ok(all && satisfied(&net.proof_status(*node, block_root, proof_type)?))
            })
        })
        .await
        .map_err(|e| format!("{e}\n{}", self.format_statuses(block_root, proof_type)))
    }

    /// [`Self::proof_statuses`] rendered one node per line.
    pub fn format_statuses(&self, block_root: Hash256, proof_type: ProofType) -> String {
        match self.proof_statuses(block_root, proof_type) {
            Ok(statuses) => statuses
                .iter()
                .map(|status| format!("{status:?}"))
                .collect::<Vec<_>>()
                .join("\n"),
            Err(e) => e,
        }
    }
}

//! Assertion helpers for [`MockClientEvent`] broadcast streams.
//!
//! [`MockEventStream`] wraps a `broadcast::Receiver<MockClientEvent>` and provides
//! ergonomic methods for collecting and asserting on events in integration tests,
//! eliminating the `timeout + loop + counter` boilerplate.

use super::MockClientEvent;
use std::time::Duration;
use tokio::sync::broadcast;

/// Error type for [`MockEventStream`] assertions.
#[derive(Debug)]
pub struct MockStreamError(String);

impl std::fmt::Display for MockStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for MockStreamError {}

/// Wraps a `broadcast::Receiver<MockClientEvent>` with assertion helpers.
pub struct MockEventStream {
    rx: broadcast::Receiver<MockClientEvent>,
}

impl From<broadcast::Receiver<MockClientEvent>> for MockEventStream {
    fn from(rx: broadcast::Receiver<MockClientEvent>) -> Self {
        Self { rx }
    }
}

impl MockEventStream {
    /// Collect `n` events matching `predicate` within `timeout`, or return an error.
    pub async fn collect_n(
        &mut self,
        n: usize,
        predicate: impl Fn(&MockClientEvent) -> bool,
        timeout: Duration,
    ) -> Result<Vec<MockClientEvent>, MockStreamError> {
        tokio::time::timeout(timeout, async {
            let mut collected = Vec::with_capacity(n);
            loop {
                match self.rx.recv().await {
                    Ok(event) if predicate(&event) => {
                        collected.push(event);
                        if collected.len() >= n {
                            return Ok(collected);
                        }
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(MockStreamError(format!(
                            "event stream lagged, skipped {skipped} events"
                        )));
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(MockStreamError(format!(
                            "event stream closed before collecting {n} events (got {})",
                            collected.len()
                        )));
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            MockStreamError(format!(
                "timed out after {timeout:?} waiting for {n} events"
            ))
        })?
    }

    /// Expect at least `n` `ProofRequested` events within `timeout`.
    pub async fn expect_proof_requests(
        &mut self,
        n: usize,
        timeout: Duration,
    ) -> Result<Vec<MockClientEvent>, MockStreamError> {
        self.collect_n(
            n,
            |e| matches!(e, MockClientEvent::ProofRequested { .. }),
            timeout,
        )
        .await
    }

    /// Expect at least `n` `ProofVerified` events within `timeout`.
    pub async fn expect_proof_verified(
        &mut self,
        n: usize,
        timeout: Duration,
    ) -> Result<Vec<MockClientEvent>, MockStreamError> {
        self.collect_n(
            n,
            |e| matches!(e, MockClientEvent::ProofVerified { .. }),
            timeout,
        )
        .await
    }

    /// Expect at least `n` `ProofFetched` events within `timeout`.
    pub async fn expect_proof_fetched(
        &mut self,
        n: usize,
        timeout: Duration,
    ) -> Result<Vec<MockClientEvent>, MockStreamError> {
        self.collect_n(
            n,
            |e| matches!(e, MockClientEvent::ProofFetched { .. }),
            timeout,
        )
        .await
    }
}

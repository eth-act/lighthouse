//! Generic event stream wrapper for broadcast channels.
//!
//! [`EventStream`] wraps a `broadcast::Receiver<E>` and provides ergonomic timeout-based
//! collection helpers used across simulator integration tests.

use std::time::Duration;
use tokio::sync::broadcast;

/// Wraps a `broadcast::Receiver<E>` with assertion helpers.
pub struct EventStream<E: Clone> {
    rx: broadcast::Receiver<E>,
}

impl<E: Clone> From<broadcast::Receiver<E>> for EventStream<E> {
    fn from(rx: broadcast::Receiver<E>) -> Self {
        Self { rx }
    }
}

impl<E: Clone + Send + 'static> EventStream<E> {
    /// Collect `n` events matching `predicate` within `timeout`, or return an error.
    pub async fn collect_n(
        &mut self,
        n: usize,
        predicate: impl Fn(&E) -> bool,
        timeout: Duration,
    ) -> anyhow::Result<Vec<E>> {
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
                        return Err(anyhow::anyhow!(
                            "event stream lagged, skipped {skipped} events"
                        ));
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(anyhow::anyhow!(
                            "event stream closed before collecting {n} events (got {})",
                            collected.len()
                        ));
                    }
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("timed out after {timeout:?} waiting for {n} events"))?
    }
}

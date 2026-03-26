//! Integration tests for the EIP-8025 proof engine, using [`ProofEngineTestRig`].

mod rig;
pub use rig::ProofEngineTestRig;

#[cfg(test)]
mod test {
    use std::time::Duration;

    use futures::try_join;
    use simulator::test_utils::{Epoch, StateId};

    use super::ProofEngineTestRig;

    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_proof_engine_basic() -> anyhow::Result<()> {
        let mut rig = ProofEngineTestRig::standard().await?;
        rig.fixture.payloads_valid();
        rig.fixture.wait_for_genesis().await?;

        let mut events = rig.proof_generator_events(0)?;
        events
            .expect_proof_requests(1, Duration::from_secs(30))
            .await?;
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_proof_engine_sync() -> anyhow::Result<()> {
        let mut rig = ProofEngineTestRig::sync_topology().await?;
        rig.fixture.payloads_valid();
        rig.fixture.wait_for_genesis().await?;

        // Let the proof generator accumulate some proofs before the verifier joins.
        tokio::time::sleep(Duration::from_secs(30)).await;

        // Add a proof verifier and subscribe to its events.
        let mut events = rig.add_proof_verifier_and_subscribe().await?;

        // The verifier should sync historical proofs and issue verification calls.
        events
            .expect_proof_verified(1, Duration::from_secs(60))
            .await?;

        Ok(())
    }

    /// Assert that the proof verifier actually receives and validates gossip proofs from the
    /// generator — not just that the generator issued a request.
    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_proof_verifier_receives_proofs() -> anyhow::Result<()> {
        let mut rig = ProofEngineTestRig::standard().await?;
        rig.fixture.payloads_valid();
        rig.fixture.wait_for_genesis().await?;

        let mut verifier_events = rig.proof_verifier_events(0)?;
        verifier_events
            .expect_proof_verified(1, Duration::from_secs(60))
            .await?;

        Ok(())
    }

    /// Assert that two independent proof generators each receive proof requests, validating that
    /// mock registration and event wiring is per-node and not shared.
    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_multi_generator_proof_requests() -> anyhow::Result<()> {
        let mut rig = ProofEngineTestRig::multi_generator().await?;
        rig.fixture.payloads_valid();
        rig.fixture.wait_for_genesis().await?;

        let mut gen0 = rig.proof_generator_events(0)?;
        let mut gen1 = rig.proof_generator_events(1)?;

        // Both generators should receive proof requests independently.
        try_join!(
            gen0.expect_proof_requests(1, Duration::from_secs(30)),
            gen1.expect_proof_requests(1, Duration::from_secs(30)),
        )?;

        Ok(())
    }

    /// Assert that the network reaches finality (epoch ≥ 2) while the proof engine is running.
    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_network_finalizes_with_proofs() -> anyhow::Result<()> {
        let mut rig = ProofEngineTestRig::standard().await?;
        rig.fixture.payloads_valid();
        rig.fixture.wait_for_genesis().await?;

        // MinimalEthSpec: 8 slots/epoch. Finality of epoch 2 requires epochs 3-4 to elapse.
        // 4 epochs * 8 slots * 1s = 32s minimum; use 45s for margin.
        tokio::time::sleep(Duration::from_secs(45)).await;

        // Check finality on the default node and the proof generator independently.
        for node in [rig.default_node(0)?, rig.proof_generator_node(0)?] {
            let checkpoint = node
                .get_beacon_states_finality_checkpoints(StateId::Head)
                .await
                .map_err(|e| anyhow::anyhow!("{e:?}"))?
                .ok_or_else(|| anyhow::anyhow!("no finality checkpoint response"))?
                .data
                .finalized;
            assert!(
                checkpoint.epoch >= Epoch::new(2),
                "expected finality at epoch ≥ 2, got {}",
                checkpoint.epoch
            );
        }

        Ok(())
    }
}

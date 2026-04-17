//! Integration tests for the EIP-8025 proof engine, using [`ProofEngineTestRig`].

mod rig;
pub use rig::ProofEngineTestRig;

#[cfg(test)]
mod test {
    use std::time::Duration;

    use futures::{TryFutureExt, try_join};
    use simulator::test_utils::{Epoch, InternalBeaconNodeEvent, StateId};

    use super::ProofEngineTestRig;

    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_proof_engine_basic() -> anyhow::Result<()> {
        let mut rig = ProofEngineTestRig::standard().await?;
        rig.fixture.payloads_valid();
        rig.fixture.wait_for_genesis().await?;

        // Subscribe to both execution-layer events (proof requested by the mock engine) and
        // chain-level events (gossip proof received and verified by the beacon chain).
        let mut gen_events = rig.proof_generator_events(0)?;
        let mut verifier_chain = rig.proof_verifier_chain_events(0)?;

        // The proof generator must receive at least one proof request from the EL.
        gen_events
            .expect_proof_requests(1, Duration::from_secs(30))
            .await?;

        // The verifier must receive the gossip proof and verify it on-chain.
        verifier_chain
            .collect_n(
                1,
                |e| matches!(e, InternalBeaconNodeEvent::GossipExecutionProof(_)),
                Duration::from_secs(60),
            )
            .await?;
        verifier_chain
            .collect_n(
                1,
                |e| matches!(e, InternalBeaconNodeEvent::ExecutionProofVerified { .. }),
                Duration::from_secs(30),
            )
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

        // Add a proof verifier and subscribe to both its mock and internal event streams.
        let (mut mock_events, mut verifier_chain) = rig.add_proof_verifier_and_subscribe().await?;

        // The late-joining verifier must issue at least one outbound RPC proof request to
        // catch up with proofs it missed while offline.
        verifier_chain
            .collect_n(
                1,
                |e| {
                    matches!(
                        e,
                        InternalBeaconNodeEvent::OutboundExecutionProofsByRange { .. }
                            | InternalBeaconNodeEvent::OutboundExecutionProofsByRoot { .. }
                    )
                },
                Duration::from_secs(120),
            )
            .await?;

        // An execution proof must arrive via RPC and be verified on-chain, concurrently with
        // the mock engine confirming it was processed.
        try_join!(
            verifier_chain.collect_n(
                1,
                |e| matches!(e, InternalBeaconNodeEvent::RpcExecutionProof(_)),
                Duration::from_secs(60),
            ),
            mock_events
                .expect_proof_verified(1, Duration::from_secs(60))
                .map_err(anyhow::Error::from),
        )?;

        verifier_chain
            .collect_n(
                1,
                |e| matches!(e, InternalBeaconNodeEvent::ExecutionProofVerified { .. }),
                Duration::from_secs(30),
            )
            .await?;

        Ok(())
    }

    /// Assert that the proof verifier receives gossip proofs from the generator and that the
    /// full pipeline — gossip arrival → chain verification — completes successfully.
    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_proof_verifier_receives_proofs() -> anyhow::Result<()> {
        let mut rig = ProofEngineTestRig::standard().await?;
        rig.fixture.payloads_valid();
        rig.fixture.wait_for_genesis().await?;

        // Subscribe to both streams before proofs start flowing so no events are missed.
        let mut mock_events = rig.proof_verifier_events(0)?;
        let mut chain_events = rig.proof_verifier_chain_events(0)?;

        // Mock engine confirms the proof was processed by the EL.
        mock_events
            .expect_proof_verified(1, Duration::from_secs(60))
            .await?;

        // Chain events confirm the full gossip pipeline: arrival then on-chain verification.
        // Events are buffered since subscription, so these complete immediately.
        chain_events
            .collect_n(
                1,
                |e| matches!(e, InternalBeaconNodeEvent::GossipExecutionProof(_)),
                Duration::from_secs(60),
            )
            .await?;
        chain_events
            .collect_n(
                1,
                |e| {
                    matches!(
                        e,
                        InternalBeaconNodeEvent::ExecutionProofVerified { status, .. }
                        if status.is_valid()
                    )
                },
                Duration::from_secs(30),
            )
            .await?;

        Ok(())
    }

    /// Assert that two independent proof generators each receive proof requests, and that the
    /// verifier receives gossip proofs from the network.
    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_multi_generator_proof_requests() -> anyhow::Result<()> {
        let mut rig = ProofEngineTestRig::multi_generator().await?;
        rig.fixture.payloads_valid();
        rig.fixture.wait_for_genesis().await?;

        let mut gen0 = rig.proof_generator_events(0)?;
        let mut gen1 = rig.proof_generator_events(1)?;
        let mut verifier_chain = rig.proof_verifier_chain_events(0)?;

        // Both generators must independently receive proof requests from their EL.
        try_join!(
            gen0.expect_proof_requests(1, Duration::from_secs(30)),
            gen1.expect_proof_requests(1, Duration::from_secs(30)),
        )?;

        // The verifier must receive at least one gossip proof from the network and verify it.
        verifier_chain
            .collect_n(
                1,
                |e| matches!(e, InternalBeaconNodeEvent::GossipExecutionProof(_)),
                Duration::from_secs(60),
            )
            .await?;
        verifier_chain
            .collect_n(
                1,
                |e| matches!(e, InternalBeaconNodeEvent::ExecutionProofVerified { .. }),
                Duration::from_secs(30),
            )
            .await?;

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

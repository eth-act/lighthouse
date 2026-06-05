//! Integration tests for the EIP-8025 proof engine, using [`ProofEngineTestRig`].

mod rig;
pub use rig::ProofEngineTestRig;

#[cfg(test)]
mod test {
    use std::time::Duration;

    use futures::try_join;
    use simulator::test_utils::{BeaconNodeHttpClient, Epoch, InternalBeaconNodeEvent, StateId};

    use super::ProofEngineTestRig;

    async fn wait_for_finalized_epoch(
        node: BeaconNodeHttpClient,
        min_epoch: Epoch,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(timeout, async move {
            loop {
                let checkpoint = node
                    .get_beacon_states_finality_checkpoints(StateId::Head)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?
                    .ok_or_else(|| anyhow::anyhow!("no finality checkpoint response"))?
                    .data
                    .finalized;
                if checkpoint.epoch >= min_epoch {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for finalized epoch {min_epoch}"))?
    }

    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_proof_engine_basic() -> anyhow::Result<()> {
        let mut rig = ProofEngineTestRig::standard().await?;
        rig.fixture.payloads_valid();
        rig.fixture.wait_for_genesis().await?;

        let mut gen_events = rig.proof_generator_events(0)?;
        let mut verifier_chain = rig.proof_verifier_chain_events(0)?;

        rig.sign_and_submit_next_generator_proof(0, &mut gen_events)
            .await?;

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

    /// Assert that the validator client's proof service requests completed proof bytes from the
    /// proof node, signs them, submits them to its beacon node, and that the proof reaches a
    /// verifier through the normal gossip/verification path.
    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_validator_client_proof_service_signs_and_submits_proofs() -> anyhow::Result<()> {
        let mut rig = ProofEngineTestRig::standard().await?;
        rig.fixture.payloads_valid();
        rig.fixture.wait_for_genesis().await?;

        let mut gen_events = rig.proof_generator_events(0)?;
        let mut verifier_chain = rig.proof_verifier_chain_events(0)?;

        gen_events
            .expect_proof_requests(1, Duration::from_secs(60))
            .await?;
        gen_events
            .expect_proof_fetched(1, Duration::from_secs(60))
            .await?;

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
                |e| {
                    matches!(
                        e,
                        InternalBeaconNodeEvent::ExecutionProofVerified { status, .. }
                        if status.is_valid() || status.is_accepted()
                    )
                },
                Duration::from_secs(30),
            )
            .await?;

        Ok(())
    }

    #[tokio::test]
    #[ignore = "late-joining verifier cannot reliably discover the proof-capable peer yet; \
                proof-sync peer selection needs rework"]
    async fn test_proof_engine_sync() -> anyhow::Result<()> {
        let mut rig = ProofEngineTestRig::sync_topology().await?;
        rig.fixture.payloads_valid();
        rig.fixture.wait_for_genesis().await?;

        wait_for_finalized_epoch(
            rig.proof_generator_node(0)?,
            Epoch::new(2),
            Duration::from_secs(90),
        )
        .await?;

        // Create a proof inside the generator's current finalized-to-head request window, then add
        // a verifier. The generator should see the verifier's proof-capable ENR and initiate the
        // proof-status exchange that lets the verifier request the missed proof by RPC.
        let (block_root, _slot, request_root) = rig.latest_generator_payload_request(0).await?;
        let proof = rig.sign_execution_proof(request_root, 0, 0)?;
        rig.observe_valid_generator_proof(0, block_root, &proof)?;
        let (_mock_events, mut verifier_chain) = rig.add_proof_verifier_and_subscribe().await?;

        // The late-joining verifier must issue at least one outbound RPC proof request for missing
        // proofs in its finalized-to-head window.
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

        // It must then receive proof data by RPC and verify it. `Accepted` means the proof content
        // is verified without flipping execution optimism, which is the default proof policy.
        verifier_chain
            .collect_n(
                1,
                |e| matches!(e, InternalBeaconNodeEvent::RpcExecutionProof(_)),
                Duration::from_secs(120),
            )
            .await?;
        verifier_chain
            .collect_n(
                1,
                |e| {
                    matches!(
                        e,
                        InternalBeaconNodeEvent::ExecutionProofVerified { status, .. }
                        if status.is_valid() || status.is_accepted()
                    )
                },
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
        let mut gen_events = rig.proof_generator_events(0)?;

        rig.sign_and_submit_next_generator_proof(0, &mut gen_events)
            .await?;

        // Mock engine confirms the received proof was verified by the verifier's EL.
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
                        // Quorum-based payload promotion is disabled in this network, so newly
                        // verified proofs surface as `Accepted` rather than `Valid`.
                        if status.is_valid() || status.is_accepted()
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

        // Both generators must independently receive proof requests from their EL. Submit the
        // first generator's proof once requested so the verifier also exercises gossip.
        let (_, _) = try_join!(
            rig.sign_and_submit_next_generator_proof(0, &mut gen0),
            async {
                gen1.expect_proof_requests(1, Duration::from_secs(60))
                    .await
                    .map_err(anyhow::Error::new)
            },
        )?;

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

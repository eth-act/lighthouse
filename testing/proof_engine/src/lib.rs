//! A test suite for the proof engine, using a local test network fixture.

#[cfg(test)]
mod test {
    use std::time::Duration;

    use simulator::test_utils::*;

    /// A base test network fixture builder for eip-8025 testing.
    ///
    /// This fixture has:
    /// - all forks up to and including fulu activate at genesis
    /// - all nodes configured with 1 second slots to speed up tests
    /// - a minimal genesis time to allow tests to start quickly
    ///
    /// - 1 vanilla beacon node
    /// - 1 proof generator node
    /// - 1 proof verifier node
    fn test_fixture_builder_base() -> TestNetworkFixtureBuilder {
        TestNetworkFixture::builder()
            .map_spec(|spec| {
                spec.seconds_per_slot = 1;
                spec.slot_duration_ms = 1000;
                spec.min_genesis_time = 0;
                spec.altair_fork_epoch = Some(Epoch::new(0));
                spec.bellatrix_fork_epoch = Some(Epoch::new(0));
                spec.capella_fork_epoch = Some(Epoch::new(0));
                spec.deneb_fork_epoch = Some(Epoch::new(0));
                spec.electra_fork_epoch = Some(Epoch::new(0));
                spec.fulu_fork_epoch = Some(Epoch::new(0));
            })
            .with_network_params(LocalNetworkParams {
                validator_count: 4,
                node_count: 1,
                proposer_nodes: 0,
                extra_nodes: 0,
                proof_generator_nodes: 1,
                proof_verifier_nodes: 1,
                genesis_delay: 60,
            })
    }

    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_proof_engine_basic() -> anyhow::Result<()> {
        let mut fixture = test_fixture_builder_base()
            .with_log_level(LevelFilter::DEBUG)
            .with_log_dir("proof-engine".into())
            .build()
            .await?;
        fixture.payloads_valid();
        fixture.wait_for_genesis().await?;

        // Verify continuous operation
        tokio::time::sleep(Duration::from_secs(60)).await;

        let requests = fixture
            .network
            .proof_engines
            .read()
            .first()
            .unwrap()
            .server
            .get_proof_requests();

        assert!(
            requests.len() >= 2,
            "Should have received multiple proof requests"
        );

        // TODO: Add more assertions after we extend test framework. For now just check logs to ensure correctness.

        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(debug_assertions, ignore = "too slow in debug mode")]
    async fn test_proof_engine_sync() -> anyhow::Result<()> {
        let mut fixture = test_fixture_builder_base()
            .map_spec(|spec| {
                // Collapse all columns onto a single subnet and reduce the total number of
                // custody groups so the small 2-node network can fully cover them.
                //
                // - data_column_sidecar_subnet_count = 1: all custody groups map to subnet 0,
                //   so any connected peer satisfies `good_peers_on_sampling_subnets()`.
                //
                // - number_of_custody_groups = 8: with validator_custody_requirement = 8 (the
                //   spec default), nodes with validators always get cgc = min(max(units, 8), 8)
                //   = 8 = full custody of all groups. This avoids the "too many columns, not
                //   enough peers" problem that occurs with the default 128 groups across 2 nodes.
                //   Note: do NOT also set custody_requirement = 128; that shrinks the valid cgc
                //   range to 128..=128 and causes the joining node to ban existing peers whose
                //   validator-derived cgc is 8.
                spec.data_column_sidecar_subnet_count = 1;
                spec.number_of_custody_groups = 8;
            })
            .map_network_params(|params| {
                params.proof_verifier_nodes = 0;
            })
            .with_log_level(LevelFilter::DEBUG)
            .with_log_dir("proof-engine-sync".into())
            .build()
            .await?;
        fixture.payloads_valid();
        fixture.wait_for_genesis().await?;

        tokio::time::sleep(Duration::from_secs(60)).await;

        // Now lets add a new proof verifier node and observe the sync behaviour.
        let net = fixture.network.clone();
        info!(target: "simulator", "Adding 1 proof verifier beacon nodes to the network");
        fixture.network.executor().spawn(
            async move {
                net.add_beacon_node(
                    fixture.config.client.clone(),
                    fixture.config.execution.clone(),
                    NodeType::ProofVerifier,
                )
                .await
                .map_err(anyhow::Error::msg)
                .expect("should not error");
            },
            "add_proof_verifier",
        );

        tokio::time::sleep(Duration::from_secs(60)).await;

        Ok(())
    }
}

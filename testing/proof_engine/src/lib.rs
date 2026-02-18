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
                genesis_delay: 20,
            })
    }

    #[tokio::test]
    async fn test_proof_engine_basic() -> anyhow::Result<()> {
        let mut fixture = test_fixture_builder_base().build().await?;
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
}

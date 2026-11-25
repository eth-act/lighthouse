//! Cross-reference Lighthouse's Gloas payload request against the execution-specs schema.
//!
//! The vectors are SSZ-encoded `NewPayloadRequestGloas` values generated with
//! [ere-guests v0.20.0](https://github.com/eth-act/ere-guests/tree/d8682fa53fd960c42ca0ac1eefccda0d80fe59e0),
//! which implements the execution-specs `tests-zkevm@v21.0.7` stateless schema, and the expected
//! roots come from that crate's `HashTreeRoot`.

use execution_layer::NewPayloadRequestGloas;
use ssz::{Decode, Encode};
use ssz_types::VariableList;
use std::str::FromStr;
use tree_hash::TreeHash;
use types::{EthSpec, ExecutionPayloadGloas, ExecutionRequestsGloas, Hash256, MainnetEthSpec};

/// Owned decoding view for the independently generated execution-specs fixtures.
#[derive(ssz_derive::Decode)]
struct GloasRequestFixture {
    execution_payload: ExecutionPayloadGloas<MainnetEthSpec>,
    versioned_hashes:
        VariableList<Hash256, <MainnetEthSpec as EthSpec>::MaxBlobCommitmentsPerBlock>,
    parent_beacon_block_root: Hash256,
    execution_requests: ExecutionRequestsGloas<MainnetEthSpec>,
}

#[test]
fn gloas_request_matches_execution_specs_ssz_and_tree_hash() {
    // Cover a real block plus empty and populated progressive lists, including builder requests.
    let fixtures: &[(&[u8], &str)] = &[
        (
            include_bytes!("fixtures/new_payload_gloas/block_93354.ssz"),
            "ae5c1a4a1808f07a248132e44180babaa796b5499b78509b96392cd7709f814e",
        ),
        (
            include_bytes!("fixtures/new_payload_gloas/populated.ssz"),
            "a48929ca29922378df229e0a337dd79cfc4de0b07609da1d60dd1c1a9e43fa20",
        ),
        (
            include_bytes!("fixtures/new_payload_gloas/empty_lists.ssz"),
            "d3413c36bd28bf1185e4240249c602d9a316acc194d85c9928f23e7f4e5ac9a5",
        ),
    ];
    for &(bytes, expected_root) in fixtures {
        let fixture = GloasRequestFixture::from_ssz_bytes(bytes).expect("valid guest fixture");
        let request = NewPayloadRequestGloas {
            execution_payload: &fixture.execution_payload,
            versioned_hashes: fixture.versioned_hashes,
            parent_beacon_block_root: fixture.parent_beacon_block_root,
            execution_requests: &fixture.execution_requests,
        };
        assert_eq!(request.as_ssz_bytes(), bytes);
        assert_eq!(
            request.tree_hash_root(),
            Hash256::from_str(expected_root).expect("valid fixture root"),
            "execution-specs root {expected_root}",
        );
    }
}

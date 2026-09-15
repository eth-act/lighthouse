//! Cross-reference Lighthouse's Gloas payload request against the execution-specs schema.
//!
//! The vectors are SSZ-encoded `NewPayloadRequestGloas` values generated with
//! [ere-guests v0.17.0](https://github.com/eth-act/ere-guests/tree/0bfcdd9f318774761de8b8c13dcebf425673285f),
//! which implements the execution-specs `tests-zkevm@v0.8.4` stateless schema, and the expected
//! roots come from that crate's `HashTreeRoot`.

use execution_layer::NewPayloadRequestGloas;
use ssz::{Decode, Encode};
use ssz_types::ProgressiveVariableList;
use std::str::FromStr;
use tree_hash::TreeHash;
use types::{ExecutionPayloadGloas, ExecutionRequestsGloas, Hash256, MainnetEthSpec};

/// Owned decoding view for the independently generated execution-specs fixtures.
#[derive(ssz_derive::Decode)]
struct GloasRequestFixture {
    execution_payload: ExecutionPayloadGloas<MainnetEthSpec>,
    versioned_hashes: ProgressiveVariableList<Hash256>,
    parent_beacon_block_root: Hash256,
    execution_requests: ExecutionRequestsGloas<MainnetEthSpec>,
}

#[test]
fn gloas_request_matches_execution_specs_ssz_and_tree_hash() {
    // Cover a real block plus empty and populated progressive lists, including builder requests.
    let fixtures: &[(&[u8], &str)] = &[
        (
            include_bytes!("fixtures/new_payload_gloas/block_93354.ssz"),
            "8c3a890206a189727e151767653f846ccddbd269eb29fb0a2f97371f23a481c6",
        ),
        (
            include_bytes!("fixtures/new_payload_gloas/populated.ssz"),
            "1e3a96403f54a092c167d2fc3493bb0127dbe1258491a3bd2486206d6cf1324a",
        ),
        (
            include_bytes!("fixtures/new_payload_gloas/empty_lists.ssz"),
            "57a969c82f7f9ae4290a3f5170a255f4e62a1c5ddc4edc5d1d131087fa118e23",
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

//! EIP-8025 execution proof endpoints: `POST /eth/v1/beacon/execution_proofs` and
//! `GET /eth/v1/beacon/execution_proofs/{block_id}`.
//!
//! The chain is Gloas from genesis with a mock proof engine that accepts exactly
//! `VALID_PROOF_DATA`, so proof validity is decided by the proof bytes alone.
use beacon_chain::custody_context::NodeCustodyType;
use bls::Signature;
use eth2::{CONTENT_TYPE_HEADER, Error, SSZ_CONTENT_TYPE_HEADER, types::BlockId};
use futures::FutureExt;
use http_api::test_utils::InteractiveTester;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use proof_engine::{ProofEngine, test_utils::MockProofEngine};
use reqwest::StatusCode;
use types::execution::{
    ExecutionProofEnvelope, ProofData, ProofType, SignedExecutionProofEnvelope,
    SignedExecutionProofEnvelopes,
};
use types::{Domain, EthSpec, ForkName, Hash256, MinimalEthSpec, SignedRoot, Slot};

type E = MinimalEthSpec;

const VALIDATOR_COUNT: usize = 32;
const VALID_PROOF_DATA: [u8; 4] = [0xab, 0xcd, 0xef, 0x01];

struct ProofTester {
    tester: InteractiveTester<E>,
    /// Head block: its payload envelope is stored and its bid is in the pending payload cache.
    block_root: Hash256,
    block_slot: Slot,
}

impl ProofTester {
    async fn new(proof_engine: Option<ProofEngine>) -> Self {
        let spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
        let tester = InteractiveTester::<E>::new_with_initializer_and_mutator(
            Some(spec),
            VALIDATOR_COUNT,
            Some(Box::new(move |builder| {
                builder
                    .deterministic_keypairs(VALIDATOR_COUNT)
                    .fresh_ephemeral_store()
                    .proof_engine(proof_engine)
            })),
            None,
            Default::default(),
            false,
            NodeCustodyType::Fullnode,
        )
        .await;

        let block_root = tester.harness.extend_slots(2).await;
        let block_slot = tester
            .harness
            .chain
            .canonical_head
            .cached_head()
            .head_slot();
        assert!(
            tester
                .harness
                .chain
                .store
                .get_payload_envelope(&block_root)
                .unwrap()
                .is_some(),
            "precondition: the head payload envelope is stored"
        );

        Self {
            tester,
            block_root,
            block_slot,
        }
    }

    fn mock_proof_engine() -> ProofEngine {
        ProofEngine::new(MockProofEngine::new([VALID_PROOF_DATA.to_vec()]))
    }

    /// A proof for the head block, signed by `validator_index`.
    fn proof(
        &self,
        proof_type: ProofType,
        proof_data: &[u8],
        validator_index: u64,
    ) -> SignedExecutionProofEnvelope {
        self.proof_for_block(self.block_root, proof_type, proof_data, validator_index)
    }

    fn proof_for_block(
        &self,
        beacon_block_root: Hash256,
        proof_type: ProofType,
        proof_data: &[u8],
        validator_index: u64,
    ) -> SignedExecutionProofEnvelope {
        let chain = &self.tester.harness.chain;
        let message = ExecutionProofEnvelope {
            proof_data: ProofData::new(proof_data.to_vec()).unwrap(),
            proof_type,
            beacon_block_root,
        };
        let fork_name = chain.spec.fork_name_at_slot::<E>(self.block_slot);
        let domain = chain.spec.compute_domain(
            Domain::ExecutionProof,
            chain.spec.fork_version_for_name(fork_name),
            chain.genesis_validators_root,
        );
        let signature = self.tester.harness.validator_keypairs[validator_index as usize]
            .sk
            .sign(message.signing_root(domain));
        SignedExecutionProofEnvelope {
            message,
            validator_index,
            signature,
        }
    }

    /// Drain the execution proofs published to the network channel.
    fn published_proofs(&mut self) -> Vec<SignedExecutionProofEnvelope> {
        let mut proofs = vec![];
        while let Some(message) = self
            .tester
            .network_rx
            .network_recv
            .recv()
            .now_or_never()
            .flatten()
        {
            if let NetworkMessage::Publish { messages } = message {
                proofs.extend(messages.into_iter().filter_map(|message| match message {
                    PubsubMessage::ExecutionProof(proof) => Some(proof.as_ref().clone()),
                    _ => None,
                }));
            }
        }
        proofs
    }
}

fn list(proofs: Vec<SignedExecutionProofEnvelope>) -> SignedExecutionProofEnvelopes {
    SignedExecutionProofEnvelopes::new(proofs).unwrap()
}

/// Assert an indexed `400` naming exactly `expected` `(index, error substring)` failures.
fn assert_rejected(result: Result<(), Error>, expected: &[(u64, &str)]) {
    match result {
        Err(Error::ServerIndexedMessage(message)) => {
            assert_eq!(message.code, StatusCode::BAD_REQUEST.as_u16());
            assert_eq!(message.failures.len(), expected.len(), "{message:?}");
            for (failure, (index, error)) in message.failures.iter().zip(expected) {
                assert_eq!(failure.index, *index, "{message:?}");
                assert!(failure.message.contains(error), "{message:?}");
            }
        }
        other => panic!("expected an indexed 400, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execution_proofs_require_proof_engine() {
    let tester = ProofTester::new(None).await;
    let client = &tester.tester.client;

    match client
        .get_beacon_execution_proofs(BlockId::Root(tester.block_root))
        .await
    {
        Err(Error::ServerMessage(message)) => {
            assert_eq!(message.code, StatusCode::NOT_IMPLEMENTED.as_u16());
            assert!(message.message.contains("--proof-engine"), "{message:?}");
        }
        other => panic!("expected a 501, got {other:?}"),
    }

    let err = client
        .get_beacon_execution_proofs_ssz(BlockId::Head)
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::NOT_IMPLEMENTED));

    let proof = tester.proof(1, &VALID_PROOF_DATA, 0);
    let err = client
        .post_beacon_execution_proofs(&list(vec![proof]))
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::NOT_IMPLEMENTED));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_and_get_execution_proofs() {
    let mut tester = ProofTester::new(Some(ProofTester::mock_proof_engine())).await;
    let client = tester.tester.client.clone();
    let block_root = tester.block_root;

    // A known block without proofs yields an empty list, not a 404.
    let response = client
        .get_beacon_execution_proofs(BlockId::Root(block_root))
        .await
        .unwrap()
        .expect("known block");
    assert!(response.data.is_empty());
    assert_eq!(response.execution_optimistic, Some(false));
    assert_eq!(response.finalized, Some(false));
    assert!(
        client
            .get_beacon_execution_proofs_ssz(BlockId::Root(block_root))
            .await
            .unwrap()
            .expect("known block")
            .is_empty()
    );

    // An unknown block is a 404.
    assert!(
        client
            .get_beacon_execution_proofs(BlockId::Root(Hash256::repeat_byte(0xab)))
            .await
            .unwrap()
            .is_none()
    );

    let proof_1 = tester.proof(1, &VALID_PROOF_DATA, 0);
    let proof_2 = tester.proof(2, &VALID_PROOF_DATA, 1);
    tester.published_proofs();

    client
        .post_beacon_execution_proofs(&list(vec![proof_1.clone()]))
        .await
        .unwrap();
    assert_eq!(tester.published_proofs(), vec![proof_1.clone()]);

    client
        .post_beacon_execution_proofs_ssz(&list(vec![proof_2.clone()]))
        .await
        .unwrap();
    assert_eq!(tester.published_proofs(), vec![proof_2.clone()]);

    // Resubmitting a published proof (fallback beacon nodes do this) succeeds silently.
    client
        .post_beacon_execution_proofs(&list(vec![proof_1.clone()]))
        .await
        .unwrap();
    // So does another prover's proof for a type that is already proven.
    client
        .post_beacon_execution_proofs(&list(vec![tester.proof(1, &VALID_PROOF_DATA, 2)]))
        .await
        .unwrap();
    assert!(tester.published_proofs().is_empty());

    // Retrieval returns the cached proofs by proof type, for every block id form.
    let expected = list(vec![proof_1, proof_2]);
    for block_id in [
        BlockId::Root(block_root),
        BlockId::Head,
        BlockId::Slot(tester.block_slot),
    ] {
        let response = client
            .get_beacon_execution_proofs(block_id)
            .await
            .unwrap()
            .expect("known block");
        assert_eq!(response.data, expected, "{block_id:?}");
        assert_eq!(response.execution_optimistic, Some(false));
        assert_eq!(response.finalized, Some(false));
        assert_eq!(
            client
                .get_beacon_execution_proofs_ssz(block_id)
                .await
                .unwrap()
                .expect("known block"),
            expected,
            "{block_id:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_execution_proofs_rejections() {
    let mut tester = ProofTester::new(Some(ProofTester::mock_proof_engine())).await;
    let client = tester.tester.client.clone();
    tester.published_proofs();

    let err = client
        .post_beacon_execution_proofs(&list(vec![]))
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::BAD_REQUEST));

    // The proof engine rejects the proof bytes.
    assert_rejected(
        client
            .post_beacon_execution_proofs(&list(vec![tester.proof(3, &[0xff], 2)]))
            .await,
        &[(0, "InvalidProof")],
    );
    // The same prover retrying with a different proof for the same block and type is ignored
    // by gossip, so the submitter is told.
    assert_rejected(
        client
            .post_beacon_execution_proofs(&list(vec![tester.proof(3, &VALID_PROOF_DATA, 2)]))
            .await,
        &[(0, "DuplicateFromValidator")],
    );
    assert_rejected(
        client
            .post_beacon_execution_proofs(&list(vec![tester.proof(0, &VALID_PROOF_DATA, 3)]))
            .await,
        &[(0, "UnsupportedProofType")],
    );
    let mut forged = tester.proof(3, &VALID_PROOF_DATA, 4);
    forged.signature = Signature::empty();
    assert_rejected(
        client
            .post_beacon_execution_proofs(&list(vec![forged]))
            .await,
        &[(0, "InvalidSignature")],
    );
    let unknown_block = Hash256::repeat_byte(0xcd);
    assert_rejected(
        client
            .post_beacon_execution_proofs(&list(vec![tester.proof_for_block(
                unknown_block,
                3,
                &VALID_PROOF_DATA,
                5,
            )]))
            .await,
        &[(0, "UnknownBlockRoot")],
    );
    assert!(tester.published_proofs().is_empty());
    assert!(
        client
            .get_beacon_execution_proofs(BlockId::Root(tester.block_root))
            .await
            .unwrap()
            .expect("known block")
            .data
            .is_empty()
    );

    // Failures are reported by index; the valid proof in the batch is still published.
    let valid = tester.proof(3, &VALID_PROOF_DATA, 6);
    assert_rejected(
        client
            .post_beacon_execution_proofs(&list(vec![tester.proof(3, &[0xee], 7), valid.clone()]))
            .await,
        &[(0, "InvalidProof")],
    );
    assert_eq!(tester.published_proofs(), vec![valid.clone()]);
    assert_eq!(
        client
            .get_beacon_execution_proofs(BlockId::Root(tester.block_root))
            .await
            .unwrap()
            .expect("known block")
            .data,
        list(vec![valid])
    );

    // Malformed bodies are 400s: bad SSZ and a JSON list over the per-payload bound.
    let url = client.post_beacon_execution_proofs_path().unwrap();
    let response = reqwest::Client::new()
        .post(url.clone())
        .header(CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER)
        .body(vec![1, 2, 3])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let too_many = (0..5)
        .map(|i| tester.proof(1, &VALID_PROOF_DATA, 10 + i))
        .collect::<Vec<_>>();
    let response = reqwest::Client::new()
        .post(url)
        .json(&too_many)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(tester.published_proofs().is_empty());
}

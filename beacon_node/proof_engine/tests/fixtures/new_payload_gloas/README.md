# Gloas stateless request fixtures

These are SSZ-encoded `NewPayloadRequestGloas` values generated with
[ere-guests v0.20.0](https://github.com/eth-act/ere-guests/tree/d8682fa53fd960c42ca0ac1eefccda0d80fe59e0),
which implements the execution-specs `tests-zkevm@v21.0.7` stateless schema.
The expected roots in the test come from that crate's `HashTreeRoot` implementation.

| Fixture | Coverage |
| --- | --- |
| `block_93354.ssz` | Request extracted from zkboost's Amsterdam stateless-input fixture for glamsterdam-devnet-8 block 93354. |
| `populated.ssz` | Same payload metadata, with five versioned hashes, two transactions (33 and 65 bytes), one withdrawal, a 129-byte access list, and one request of each of the five execution-request types. |
| `empty_lists.ssz` | Same payload metadata with empty versioned hashes, transactions, withdrawals, access list, and execution-request lists. |

The tests decode these bytes using Lighthouse types, then compare the native request's
SSZ serialization and tree hash against the guest encoding and root. No guest dependency
is needed to run them.

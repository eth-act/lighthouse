## Summary
Add ExecutionProofStatus RPC type and request/response protocol for P2P proof synchronization (EIP-8025).

## Changes
- ExecutionProofStatus RPC type with SSZ encoding
- Request/response protocol integration
- ProofSync state machine implementation
- Network integration

## CI Status
- [x] Format check: PASS
- [x] Lint check: PASS (with fixes to pre-existing base branch issues)
- [x] Network tests: PASS (167 tests passed)

## Testing
All 167 tests pass:
- 72 lighthouse_network unit tests
- 84 network sync tests
- 17 proof_sync module tests
- 11 proof_verification tests (EIP-8025)

## Related
- EIP-8025: Optional Execution Proofs
- Target: feat/eip8025 branch (eth-act/lighthouse fork)

## Checklist
- [x] Code follows Lighthouse patterns
- [x] Tests added and passing
- [x] Clippy clean (no warnings)
- [x] CI checks pass

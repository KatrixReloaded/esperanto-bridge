# Implementation status

The four worker tracks provide a local foundation for a private-to-private Monero ↔ Ethereum bridge. They do not yet form a runnable end-to-end bridge. No shared-network contracts or AWS resources have been deployed.

## Implemented components

| Area | Implemented | Validation boundary |
| --- | --- | --- |
| Contracts | cwXMR with 12 decimals; immutable Bridge mint authority; per-mint Nitro verification and proof-populated vault directory; deposit replay protection; confidential redemption inputs; eligible-vault snapshot; first valid claim; assignee settlement; cancellation of unassigned requests | Local Hardhat/FHEVM mocks. No genuine bridge-bound Nitro proof or live Zama round trip |
| Core | Domain types, recipient-bound intents, input and liquidity reservations, exact signed transaction journal, encrypted PostgreSQL records, replay and transition checks | Local state tests and disposable PostgreSQL race/restart tests |
| Monero | Wallet keys, subaddresses, address validation and canonical destination encoding, private deposit IDs, scan primitives, chain-policy boundary, reservation-bound offline signing | Real upstream scan fixture and synthetic signing inputs; no broadcast or consensus verification |
| Zama | Enclave-local SDK sidecar, scoped and width-bound decryption, one-proof redemption encryption, ABI binding and EIP-712 Mint/Claim/Settle signatures | Local SDK protocol mocks, TypeScript checks and cross-language signature vectors |
| Nitro | Runtime identity, NSM attestation binding, TLS identity, attested-recipient KMS recovery, encrypted identity backup, enclave packaging and operator scripts | Native checks only until an actual EIF is built and run on Nitro |

`contracts/INTERFACES.md` defines the shared protocol. Withdrawal destinations use three encrypted 256-bit words containing a canonical 96-byte address encoding. Eligible vaults receive access to the request ciphertexts; only a positivity bit is publicly decrypted for claim admission. Ethereum addresses, request timing, selected vaults and claims remain public. This is confidential value and destination handling, not complete Ethereum metadata anonymity.

The sidecar's only current server Ethereum RPC client is configured for enclave-local Nym SOCKS with remote DNS and no direct fallback; live mixnet and Nitro egress validation are pending. Ethereum transaction submission and event watching are not implemented. Monero authenticated chain access is also unimplemented and has not been routed through Nym. Zama relayer/gateway and KMS HTTPS are separate transports. The operator-side `verify-peer.mjs` is outside this server routing.

## Required before an end-to-end demonstration

1. **Validate the real Nitro image and recovery path.** Build the EIF, record reproducible non-debug measurements, exercise first proven mint, fresh identity discovery and restart on hardware, verify peer TLS against an independently trusted Ethereum state, and test KMS recipient enforcement. Local tests cannot establish these properties.
2. **Complete and approve Automata per-mint verification.** Pin the deployed verifier, its mutable configuration and governance assumptions. Generate a fresh proof containing this bridge's keys, complete canonical mint request and domain. The historical upstream fixture only tests schema decoding. Shared-network deployment remains disabled.
3. **Implement authenticated chain inputs.** Supply Monero consensus/canonicality and Ethereum finalized-state sources. A daemon response, decrypted output, TLS connection or matching block hash alone does not establish consensus. Add durable duplicate-output handling, change classification, fee and decoy verification, and deposit eligibility.
4. **Wire the bridge operations.** Connect encrypted PostgreSQL over enclave-terminated authenticated TLS, SDK encryption/decryption, per-request Nitro proving, transaction submission and receipt reconciliation. Implement deposit issuance/observation/mint and redemption observation/reservation/claim/payment/settlement. The runtime exposes identity, health and a separate discovery-only attestation route; no public mint-attestation or signing route.
5. **Resolve exclusive spending and rollback recovery.** Define and test a rollback-resistant fencing mechanism before enabling Monero broadcasts. PostgreSQL locks and encrypted backups do not stop hostile clones. Preserve exact signed bytes across uncertain outcomes; do not introduce timeout-based reassignment of an assigned payment.
6. **Resolve recovery governance.** Restrictive KMS policy prevents the ordinary parent role from wrapping a host-chosen data key or decrypting an enclave data key. A policy administrator can alter those restrictions. Independently operated AWS accounts therefore do not yet meet a malicious-operator custody model. Establish a recovery trust model and provenance/freshness guarantees before making that claim.
7. **Validate real Zama behavior and lifecycle.** Exercise encryption, vault decryption ACLs, actual-result accounting and settlement on the intended network from inside Nitro. Define late deposits during draining, stranded-vault liquidity, recovery and fees. Then demonstrate restart and two independent vaults on Monero stagenet and Ethereum Sepolia.

The frontend remains a later adaptation of the existing `web/`. Arkiv, threshold custody, automatic liquidity transfers and multi-TEE platform support are out of this implementation batch.

## Test interpretation

The pre-correction baseline on 2026-11-06 passed: 35 Rust tests with the PostgreSQL integration enabled, 17 contract tests, 15 sidecar tests, four native TLS/transport/policy tests, TypeScript checking, Rust formatting, and shell/Python syntax checks. The Nitro worker also passed CloudFormation lint. All results concern the local foundation; no live-network or Nitro-hardware result is included.

The per-mint correction passed 17 contract tests (including a shared Rust/ethers digest vector), 37 Rust test cases and four native TLS/transport/policy checks. The PostgreSQL integration branch was not exercised in this correction run because `CWXMR_TEST_DATABASE_URL` was unset; the prior integrated baseline above covered it. Shared-network gates remain disabled.

Local contract tests use FHEVM mocks, not production cryptography. The sidecar tests mock SDK/network behavior. Monero signing fixtures are deliberately not broadcastable. PostgreSQL tests require `CWXMR_TEST_DATABASE_URL`; a test run without it skips database integration. Nitro packaging and AWS policies require hardware and live-service validation. Dependency advisories in the reused npm graphs remain unresolved and must be assessed before a release.

No test result in this repository authorizes real-fund custody. Current fail-closed gates are part of the implementation, not evidence that the missing integration has succeeded.

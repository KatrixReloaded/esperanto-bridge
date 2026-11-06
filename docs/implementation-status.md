# Implementation status

The four worker tracks provide a local foundation for a private-to-private Monero ↔ Ethereum bridge. They do not yet form a runnable end-to-end bridge. The user deployed the Sepolia contracts; no AWS resources have been provisioned. AWS rental is postponed until local work is complete. The user explicitly approved trusted Monero and Ethereum nodes for the stagenet-only PoC; that assumption must not be described as independent consensus verification.

Sepolia deployment (chain 11155111), checked through PublicNode on 2026-11-06:

| Contract | Address |
| --- | --- |
| Automata Nitro verifier | `0x61997FD1eC0BcdCEFA5Dfe714B69558293E60822` |
| Nitro adapter | `0x9A93576c438c7dbF293572D369d41515F84fAc2D` |
| Bridge | `0x1C833095c0cd2d50e08dF0031052A865f026C319` |
| cwXMR | `0xfB60968c57CcE889C9A9E5f912C88Da75aeA23c6` |
| VaultRegistry | `0xF83171035445b01B0F70f71Dc2aff923f681D279` |

The adapter reports a valid pinned configuration. This is not proof of a successful live mint; reviewed PCR approval, fresh Nitro evidence, proof generation and real FHE execution remain pending. Registration and renewal are not part of the protocol.

## Implemented components

| Area | Implemented | Validation boundary |
| --- | --- | --- |
| Contracts | cwXMR with 12 decimals; immutable Bridge mint authority; per-mint Nitro verification and proof-populated vault directory; deposit replay protection; confidential redemption inputs; eligible-vault snapshot; first valid claim; assignee settlement; cancellation of unassigned requests | Local Hardhat/FHEVM mocks. No genuine bridge-bound Nitro proof or live Zama round trip |
| Core | Domain types, recipient-bound intents, input and liquidity reservations, exact signed transaction journal, encrypted PostgreSQL records, replay and transition checks | Local state tests and disposable PostgreSQL race/restart tests |
| Monero | Wallet keys, subaddresses, address validation and canonical destination encoding, private deposit IDs, scan primitives, chain-policy boundary, reservation-bound offline signing | Real upstream scan fixture and synthetic signing inputs; no broadcast or consensus verification |
| Zama | Enclave-local SDK sidecar, scoped and width-bound decryption, one-proof redemption encryption, ABI binding and EIP-712 Mint/Claim/Settle signatures | Local SDK protocol mocks, TypeScript checks and cross-language signature vectors |
| Nitro | Runtime identity, NSM attestation binding, TLS identity, attested-recipient KMS recovery, encrypted identity backup, enclave packaging and operator scripts | Native checks only until an actual EIF is built and run on Nitro |

`contracts/INTERFACES.md` defines the shared protocol. Withdrawal destinations use three encrypted 256-bit words containing a canonical 96-byte address encoding. Eligible vaults receive access to the request ciphertexts; only a positivity bit is publicly decrypted for claim admission. Ethereum addresses, request timing, selected vaults and claims remain public. This is confidential value and destination handling, not complete Ethereum metadata anonymity.

The sidecar's server Ethereum RPC client uses enclave-local Nym SOCKS with remote DNS and no direct fallback. It implements bounded reads, exact journaled transaction submission and receipt reconciliation. A trusted-node stagenet adapter scans Monero blocks through the same Nym listener; the watcher persists deposit intents, private wallet outputs and scan progress in encrypted PostgreSQL over authenticated TLS. Neither adapter independently verifies consensus. Native local Nym probes successfully read Monero stagenet and Sepolia. PublicNode was rejected by the tested Nym exit; the explicitly configured `https://1rpc.io/sepolia` worked. Zama relayer/gateway and KMS HTTPS remain separate transports. The operator-side `verify-peer.mjs` is outside this server routing.

The amd64 Linux SDK container loaded the real Zama SDK and completed encryption-key warmup with its local SOCKS socket forwarded to a temporary native Nym client. An earlier warmup failed, so this is not evidence of reliable startup. Rust and Nym container builds are still in progress. No EIF execution has occurred.

## Required before an end-to-end demonstration

1. **Validate the real Nitro image and recovery path.** Build the EIF, record reproducible non-debug measurements, exercise first proven mint, fresh identity discovery and restart on hardware, verify peer TLS against an independently trusted Ethereum state, and test KMS recipient enforcement. Local tests cannot establish these properties.
2. **Validate Automata per-mint verification.** The verifier and adapter are deployed and pinned. Generate a fresh proof containing this bridge's keys, complete canonical mint request and domain. The historical upstream fixture only tests schema decoding; actual Nitro proof verification remains pending.
3. **Validate trusted stagenet chain inputs.** The user explicitly approved configured Monero and Ethereum nodes for this PoC. Test the integrated maturity, duplicate-output, reorg and receipt checks. A daemon response, TLS connection or matching block hash does not establish independent consensus; independent verification remains outside this PoC.
4. **Finish bridge scheduling and client verification.** The mint driver now connects eligibility, FHE encryption, NSM evidence, public proof candidates, exact-call simulation, durable signing, submission and actual-result reconciliation. Wire it and the in-progress withdrawal controller into one serialized runtime loop, with bounded retries and recovery tests. Verify the enclave before issuing a client deposit address; a directory entry populated by the first mint cannot bootstrap that first deposit. The runtime exposes identity, health and discovery-only attestation; public deposit actions remain disabled.
5. **Exercise the explicit payout assumption.** The user approved one trusted operator, one active vault process and no database rollback for stagenet only. The withdrawal controller is being implemented under that policy; mainnet payouts remain disabled. PostgreSQL locks and encrypted backups do not stop hostile clones. Preserve exact signed bytes across uncertain outcomes; never introduce timeout-based reassignment of an assigned payment. Hostile-clone protection is a later requirement, not a property of this PoC.
6. **Resolve recovery governance.** Restrictive KMS policy prevents the ordinary parent role from wrapping a host-chosen data key or decrypting an enclave data key. A policy administrator can alter those restrictions. Independently operated AWS accounts therefore do not yet meet a malicious-operator custody model. Establish a recovery trust model and provenance/freshness guarantees before making that claim.
7. **Validate the real round trip.** Exercise encryption, vault decryption ACLs, actual-result accounting and settlement from inside Nitro. Demonstrate a stagenet deposit → confidential Sepolia mint → stagenet withdrawal, then restart recovery. Multiple active vaults, draining and hostile-operator custody require additional work beyond the approved single-process PoC.

The reused `web/` is adapted to XMR, 12 decimals, current Bridge redemption inputs and deposit intents. Its 85 local tests and production build passed. Live actions remain disabled pending verified enclave bootstrap and integration. Arkiv, threshold custody, automatic liquidity transfers and multi-TEE platform support are out of this implementation batch.

## Test interpretation

The pre-correction baseline on 2026-11-06 passed: 35 Rust tests with the PostgreSQL integration enabled, 17 contract tests, 15 sidecar tests, four native TLS/transport/policy tests, TypeScript checking, Rust formatting, and shell/Python syntax checks. The Nitro worker also passed CloudFormation lint. All results concern the local foundation; no live-network or Nitro-hardware result is included.

The per-mint correction passed 17 contract tests (including a shared Rust/ethers digest vector), 37 Rust test cases and four native TLS/transport/policy checks. The PostgreSQL integration branch was not exercised in this correction run because `CWXMR_TEST_DATABASE_URL` was unset; the prior integrated baseline above covered it. Shared-network gates remain disabled.

Local contract tests use FHEVM mocks, not production cryptography. The sidecar tests mock SDK/network behavior. Monero signing fixtures are deliberately not broadcastable. PostgreSQL tests require `CWXMR_TEST_DATABASE_URL`; a test run without it skips database integration. Nitro packaging and AWS policies require hardware and live-service validation. Dependency advisories in the reused npm graphs remain unresolved and must be assessed before a release.

No test result in this repository authorizes real-fund custody. Current fail-closed gates are part of the implementation, not evidence that the missing integration has succeeded.

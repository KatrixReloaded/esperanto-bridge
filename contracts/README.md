# cwXMR contracts

Contracts-first local foundation. No shared-network deployment or genuine bridge-bound Nitro verification is claimed.

Use Node 22 or 24 and `npm ci`, then `npm test` (Hardhat's supported FHEVM mock, local chain only). `npm run export-abi` compiles and writes consumer ABIs. `npm run check-deployment -- deployment.example.json` deliberately fails: shared-network release policy has no approved deployments and sample pins are incomplete.

Read [INTERFACES.md](INTERFACES.md) for canonical bytes, EIP-712 signatures, events, ACL policy, actual-result accounting and integration limits. The Bridge constructor creates its immutable token and registry. Governance may approve/revoke PCR policy and suspend/revoke vaults but cannot mint or restore an identity without fresh valid evidence. Suspended identities are intentionally fail-closed and cannot self-reactivate.

Tests cover authenticated field binding, stale/debug/PCR/replay rejection, policy/expiry changes, ciphertext domains, actual-zero results, uint64 capacity including pending burns, exact one-time unassigned refunds, vault ACLs for 3×euint256 destination, first valid claim and assignee-only settlement. Only a positivity bit is public; the claim checks a Zama KMS decryption signature proof. These tests do not exercise real FHE cryptography or real attestation proofs.

The historical Automata Pico proof fixture is copied from the pinned upstream `contracts/test/assets/inputs.json` under Apache-2.0 solely to test decoding of its actual journal schema. Pico is unsupported by this adapter, and this fixture lacks bridge-bound keys/nonce. It is not an enrollment fixture. The pinned upstream ABI is vendored unchanged. Upstream verifier governance, root/program configuration and proof verifier implementation remain trust boundaries; inspect proxies and mutable verifier state before release.

Runtime configuration checks are read-only and hash-pinned. No deploy script is supplied until release evidence is approved. Test verifier constructors reject every chain except 31337. Shared-network policy rejects mocks, bypass flags and missing reviewed real Nitro/Zama round-trip evidence. An empty release list is a deliberate deployment gate, not an unsupported success result.

Dependency versions match the existing tested Zama integration: Solidity 0.8.28, FHE Solidity 0.11.1, FHEVM Hardhat plugin/mock-utils 0.4.2, OpenZeppelin confidential-contracts 0.5.3/contracts 5.6.1, relayer SDK 0.4.1. The pinned npm dependency tree reports advisories; SDK 0.4.1 is deprecated upstream. Upgrades and production-network compatibility require a separate tested release, not an unreviewed audit-fix version change.

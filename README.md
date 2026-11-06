# cwXMR bridge

Monero stagenet ↔ confidential cwXMR on Ethereum Sepolia, with independent AWS Nitro vaults and Automata Nitro attestation.

The contracts are deployed on Sepolia; the backend is a locally tested foundation and does not yet form an end-to-end bridge. The [implementation status](docs/implementation-status.md) distinguishes working components from remaining integration gates. The [architecture plan](docs/cwxmr-bridge-plan.md) describes the target behavior. AWS provisioning is postponed until local integration and packaging checks are complete.

## Layout

- `contracts/`: confidential token, Nitro verification adapter, vault registry and bridge state transitions.
- `service/crates/core/`: domain state, encrypted persistence and recovery rules.
- `service/crates/monero/`: Monero wallet and chain adapter.
- `service/crates/zama/`: Ethereum and confidential-input integration.
- `service/crates/watcher/`: Nitro runtime and reconciliation entry points.
- `sidecar/`: enclave-local Zama SDK process, shared with the Rust confidential client.
- `infra/`, `enclave/`, `scripts/nitro/`: operator infrastructure and enclave tooling.

## Development boundaries

Keep code minimal and modular. Traits belong at meaningful storage, signing, chain and transport boundaries. Share domain types; keep authoritative transitions in one place. Test failure behavior and invariants rather than reproducing implementation details.

PostgreSQL stores encrypted application state. It does not establish chain finality, prevent hostile snapshot rollback, or make cloned enclave execution safe. Ethereum arbitrates withdrawal assignment; encrypted journals preserve exact signed transactions for recovery. Missing payment evidence never authorizes a refund or a second payment.

Local tests and mock attestations do not establish Nitro security. Before a shared-network demonstration, validate a production EIF, authenticated Automata proof outputs, enclave-only Zama processing, restricted KMS recovery and safe payout fencing on actual AWS hardware.

No Arkiv integration, threshold custody, automatic ambiguous-payment reassignment or frontend implementation is included in this development batch.

## Local checks

Use Node 22 or 24 for the contract tooling. These tests use local fixtures and FHEVM mocks; they do not require AWS or funds.

```sh
cd contracts
npm ci
npm test
cd ../sidecar
npm ci
npm run check
npm test
cd ../service
cargo test --workspace
```

Set `CWXMR_TEST_DATABASE_URL` to a disposable PostgreSQL database before running Rust tests to exercise encrypted persistence, concurrent reservations and restart behavior. That integration test is skipped when the variable is absent.

For native TLS checks and the future Linux/AWS setup, follow the [Nitro operator runbook](docs/operators.md). Enclave image builds and hardware verification are still pending.

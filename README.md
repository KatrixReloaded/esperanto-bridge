# cwXMR bridge

Monero stagenet ↔ confidential cwXMR on Ethereum Sepolia, with independent AWS Nitro vaults and Automata Nitro attestation.

This repository is under implementation. It is not a deployed bridge and must not hold real funds. The [architecture plan](docs/cwxmr-bridge-plan.md) describes the target behavior; runnable checks and remaining integration gates are recorded below as components land.

## Layout

- `contracts/`: confidential token, Nitro verification adapter, vault registry and bridge state transitions.
- `service/crates/core/`: domain state, encrypted persistence and recovery rules.
- `service/crates/monero/`: Monero wallet and chain adapter.
- `service/crates/zama/`: Ethereum and confidential-input integration.
- `service/crates/watcher/`: Nitro runtime and reconciliation entry points.
- `infra/`, `enclave/`, `scripts/nitro/`: operator infrastructure and enclave tooling.

## Development boundaries

Keep code minimal and modular. Traits belong at meaningful storage, signing, chain and transport boundaries. Share domain types; keep authoritative transitions in one place. Test failure behavior and invariants rather than reproducing implementation details.

PostgreSQL stores encrypted application state. It does not establish chain finality, prevent hostile snapshot rollback, or make cloned enclave execution safe. Ethereum arbitrates withdrawal assignment; encrypted journals preserve exact signed transactions for recovery. Missing payment evidence never authorizes a refund or a second payment.

Local tests and mock attestations do not establish Nitro security. Before a shared-network demonstration, validate a production EIF, authenticated Automata proof outputs, enclave-only Zama processing, restricted KMS recovery and safe payout fencing on actual AWS hardware.

No Arkiv integration, threshold custody, automatic ambiguous-payment reassignment or frontend implementation is included in this development batch.

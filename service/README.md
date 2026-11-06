# Backend foundation

The four crates separate application state (`zz-core`), Monero wallet operations (`zz-monero`), confidential Ethereum operations (`zz-zama`) and the Nitro runtime (`zz-watcher`). See the [implementation status](../docs/implementation-status.md) for deployment gates and the [contract interface](../contracts/INTERFACES.md) for canonical wire formats.

Core stores vault records encrypted with XChaCha20-Poly1305 using an injected `DataKeySource`. PostgreSQL transactions serialize cooperative updates; ciphertext, database locks and KMS recovery do not prevent hostile rollback or cloned enclaves. Initialize a new vault explicitly. A missing row is a recovery error, never permission to generate a replacement wallet. Runtime PostgreSQL connections terminate authenticated TLS inside the enclave using an image-pinned CA and hostname.

Payout reservations bind exact input IDs, amount and fee headroom. The journal preserves exact signed transaction bytes and EVM nonces across retries. Broadcast authorization fails closed until rollback-resistant fencing is implemented. An ambiguous payment never authorizes a refund, reassignment or a newly signed payment.

The Monero crate derives and validates addresses, scans blocks, evaluates chain-policy evidence through an `AuthenticatedChain` boundary, encodes the Bridge's 96-byte destination format and signs offline transactions. The separate `TrustedStagenet` adapter obtains bounded daemon observations through Nym; the watcher persists scan progress and deposit eligibility. This is the explicitly approved stagenet trust assumption, not independent consensus verification. Live payout orchestration remains under integration. See its [limitations](crates/monero/README.md).

The Zama crate calls the SDK process in `../sidecar`, validates scoped decryption sessions and signs Bridge Mint, Claim and Settle authorizations. Redemption encryption submits one `uint64` amount and three `uint256` destination words with one proof. Decryption sessions bind result width and validate its range. The SDK and plaintext processing belong inside the enclave. Its Ethereum transport submits journaled bytes and reads receipts through Nym using explicitly trusted Sepolia RPC observations, not independent finality verification.

The watcher supplies Nitro identity and attestation, encrypted identity recovery, KMS attested-recipient handling and a TLS endpoint. Its mint driver connects deposit eligibility, FHE encryption, NSM evidence, the untrusted parent proof service, complete-call simulation, durable signing and finalized actual-result reconciliation. Runtime scheduling is still being integrated. A submitted mint blocks new work until reconciled; automatic replacement transactions are not allowed. Public deposit routes remain disabled pending client enclave verification and integration checks. It exposes no public signing oracle. Actual AWS execution and the complete bridge loop remain unverified.

## Tests

Run `cargo test --workspace`. Set `CWXMR_TEST_DATABASE_URL` to a disposable PostgreSQL database to exercise storage race and restart tests; these are skipped without that variable. Run `npm ci`, `npm run check` and `npm test` in `../sidecar` for the SDK protocol tests. Neither test suite establishes hardware attestation or network consensus.

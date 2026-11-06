# Backend foundation

The four crates separate application state (`zz-core`), Monero wallet operations (`zz-monero`), confidential Ethereum operations (`zz-zama`) and the Nitro runtime (`zz-watcher`). See the [implementation status](../docs/implementation-status.md) for deployment gates and the [contract interface](../contracts/INTERFACES.md) for canonical wire formats.

Core stores vault records encrypted with XChaCha20-Poly1305 using an injected `DataKeySource`. PostgreSQL transactions serialize cooperative updates; ciphertext, database locks and KMS recovery do not prevent hostile rollback or cloned enclaves. Initialize a new vault explicitly. A missing row is a recovery error, never permission to generate a replacement wallet. Production PostgreSQL connections must terminate authenticated TLS inside the enclave; this connection is not yet wired into the runtime.

Payout reservations bind exact input IDs, amount and fee headroom. The journal preserves exact signed transaction bytes and EVM nonces across retries. Broadcast authorization fails closed until rollback-resistant fencing is implemented. An ambiguous payment never authorizes a refund, reassignment or a newly signed payment.

The Monero crate derives and validates addresses, scans fixture blocks, evaluates chain-policy evidence through an `AuthenticatedChain` boundary, encodes the Bridge's 96-byte destination format and signs offline transactions. It does not implement a trusted chain source, wallet synchronization or live payout orchestration. See its [limitations](crates/monero/README.md).

The Zama crate calls the SDK process in `../sidecar`, validates scoped decryption sessions and signs Bridge Mint, Claim and Settle authorizations. Redemption encryption submits one `uint64` amount and three `uint256` destination words with one proof. Decryption sessions bind result width and validate its range. The SDK and plaintext processing belong inside the enclave. There is no live Ethereum transaction sender or authenticated finality implementation yet.

The watcher supplies Nitro identity and attestation, encrypted identity recovery, KMS attested-recipient handling and a TLS endpoint. It deliberately exposes no mint, claim or payout operation. Actual AWS execution, enclave-local Zama network processing and the complete bridge loop remain unverified.

## Tests

Run `cargo test --workspace`. Set `CWXMR_TEST_DATABASE_URL` to a disposable PostgreSQL database to exercise storage race and restart tests; these are skipped without that variable. Run `npm ci`, `npm run check` and `npm test` in `../sidecar` for the SDK protocol tests. Neither test suite establishes hardware attestation or network consensus.

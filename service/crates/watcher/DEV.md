# Explicit unsafe host development runner

`zz-dev` is a separate binary, built only with `unsafe-test`. It runs without Nitro, NSM, AWS KMS or an attestation prover. **Its attestation is forged. The operator/host controls the mint key, Monero spend key, decrypt key and local storage key. Anyone able to use the unsafe verifier can forge evidence.** This is exclusively a stagenet/Sepolia plumbing test, with one trusted operator, one process, no database rollback and explicitly trusted nodes. Never reuse these keys, contracts or state in a protected deployment.

The normal `zz-watcher` remains Cargo's default binary. Its `prepare_mint` still calls real NSM and fails without it, even when `unsafe-test` is compiled. Shared preparation only produces a durable mint authorization; it never fabricates an NSM document. No normal startup path falls back to this runner.

## Local preparation

From the repository root:

```sh
cargo build --manifest-path service/Cargo.toml -p zz-watcher --bin zz-dev --features unsafe-test
mkdir -m 700 dev-state
./service/target/debug/zz-dev init dev-state/bundle.json
```

`init` creates a new 0600 file and refuses to overwrite an existing file. It prints public identity information only. The bundle contains **host-readable private Identity and Cipher data key**; filesystem permissions protect it only from other ordinary users, not the host administrator. Keep it outside Git and images; mount it as a private persistent volume. Copying/rolling back it together with the database invalidates the PoC's single-process/no-rollback assumption.

Copy `dev.example.json` to `dev-state/config.json`. Replace the eight `pins` fields using the **new** unsafe deployment's `contracts/artifacts/unsafe-test-pins.json` described in `docs/unsafe-test.md`. Supply the explicit trusted stagenet HTTPS daemon, wallet birth height, Registry/Bridge deployment scan height, reviewed fee commitment and limits. The example's placeholder values deliberately fail parsing. All amounts/fees use integer 12-decimal atomic units. `monero_birth_height` must precede all deposits to this identity; setting it to current height after a deposit loses the observation. Avoid genesis scanning for a newly created wallet by supplying its actual creation height.

Required local services in the same network namespace:

- Nym SOCKS listener `127.0.0.1:1080`.
- Real Zama/Ethereum sidecar `127.0.0.1:8788`, with Sepolia RPC via Nym.
- PostgreSQL on literal `127.0.0.1` (configured port/database/user); this development-only DB connection is plaintext loopback. Cipher encrypts the stored vault payload. Remote DB hosts/hostaddr overrides are rejected.

Create the encrypted DB record exactly once, then perform read-only deployment checks:

```sh
./service/target/debug/zz-dev init-db dev-state/config.json
./service/target/debug/zz-dev check dev-state/config.json
```

`init-db` never replaces an existing vault record. `check` verifies Sepolia, runtime hashes of Bridge/Registry/Adapter/verifier, all deployment links, `unsafeTestOnly()==true`, shared mock verifier/zkVerifier address, exact unsafe root/program/selector, approved policy 1 PCR tuple and token decimals 12. It sends no transaction. Failure does not select another verifier.

## Explicit later execution

**The following command can spend stagenet XMR and Sepolia ETH. It was not run during implementation.** It requires the user-approved new unsafe deployment, its PCR policy, funded signing identity, configured real SDK/Nym services and local DB first:

```sh
./service/target/debug/zz-dev run dev-state/config.json --send-stagenet
```

The explicit command and `mode: "UNSAFE_TEST_NO_NITRO"` are required; there is no automatic activation flag or fallback. The process holds the cooperative PostgreSQL payout session lease for the whole serialized worker, including mint work. A second cooperative process is rejected. Lease loss, reconciliation errors and worker panics close the deposit issuance gate. This is not malicious-clone fencing.

The worker scans confirmed Monero outputs, prepares real SDK ciphertext/input proof and a real mint signature, then constructs an ABI VerifierJournal with current trusted Sepolia timestamp, exact mint binding/nonce, public key, root and PCR0/1/2 fixed to 48 bytes of 11/22/33. Proof bytes are `0x54535431`; moduleId is `UNSAFE_TEST_NO_NITRO`. There is no COSE/NSM document and no claim of genuine attestation. Pins are rechecked before each action and again after expensive encryption before mint submission. Existing contract deposit-nullifier, signature, registry binding, PCR, time, FHE proof and actual-result rules still execute; only attestation cryptographic verification is deliberately absent.

For future faster stagenet demos, the example sets `demo_mint_confirmations: 3`: inclusion is confirmation one, so mint eligibility starts after two additional blocks. This explicit development option permits minting against ordinary outputs before they are spendable and increases reorg exposure. Canonical-block and additional timelock checks still apply. Omit it (or use `null`) to retain the original mint maturity policy; existing configs are unchanged. The separate `confirmations: 10` setting and Monero spendability checks continue to govern payouts. Fresh deposits cannot fund immediate withdrawals until unlocked; use already-unlocked vault liquidity for a faster return leg. Ethereum finality waits also remain. These settings take effect only when a newly built runner starts; do not change the active demo's policy mid-flight.

Mint and payout work is serialized. Submitted mint envelopes reconcile before another signer nonce is allocated. Existing claim/settlement envelopes and Monero transaction bytes are restored from the journal; an ambiguous submission is never replaced or automatically rebroadcast. A crash between journaling and socket submission may require manual reconciliation of those exact bytes. Expired authorizations, zero/unsupported redemption candidates, lost claim races and reverted transactions stop the worker for explicit operator review. No automatic refund/reassignment is provided. See `PAYOUTS.md` for the actual-burn/decryption, assignment, Monero inclusion/depth and settlement gates.

The loopback HTTP API exposes only:

```text
GET  http://127.0.0.1:8789/health
POST http://127.0.0.1:8789/v1/deposit-intents
     {"recipient":"0x<20 bytes>","nonce":"0x<32 random bytes>"}
GET  http://127.0.0.1:8789/v1/deposit-intents/0x<private intent ID>
```

It binds only 127.0.0.1, requires the exact loopback Host header, rejects browser Origin headers, does not enable CORS, and has no `/attestation`, `/mint`, `/sign` or redemption signing endpoint. Request IDs are private bearer data: do not put them in public logs. Busy scanning/signing returns 503. Health clearly reports `native_development:true`, `unsafe_test_only:true`, `mock_attestation:true`; issuance is enabled only once scanning catches up and while the worker runs.

Use local tools in the same namespace (`docker exec`, or an explicitly local host-network setup on Linux). Do not publish a reverse proxy. Normal web live mode remains gated and is not made to believe this host service is an attested enclave. User-signed redemption requests must target the **new unsafe Bridge**, using the existing real Zama encryption/client ABI. No public signing oracle is exposed.

## Linux container runner

The separate `enclave/Dockerfile.dev` builds only the explicitly unsafe runner. It requires a local `cwxmr-rust-build:local` builder image created from the `rust-build` target of `enclave/Dockerfile`; this local build cache is mutable and is not a reproducible release artifact. Build it from the same checked-out project and review the resulting image before use. The production image and its Nitro startup remain separate.

```sh
docker build --platform linux/amd64 --target rust-build -f enclave/Dockerfile -t cwxmr-rust-build:local .
docker build --platform linux/amd64 -f enclave/Dockerfile.dev -t cwxmr-unsafe-dev:local .
```

On Linux, `--network host` shares loopback with the required Nym, sidecar and PostgreSQL services; it does not provide container network isolation. Keep the state directory outside the build context and Git, and mount it at the paths used in the configuration. For example, with an absolute private directory mounted at `/state`, set `bundle` in `/state/config.json` to `/state/bundle.json`:

```sh
docker run --rm --network host -v /absolute/private/dev-state:/state cwxmr-unsafe-dev:local init /state/bundle.json
docker run --rm --network host -v /absolute/private/dev-state:/state cwxmr-unsafe-dev:local init-db /state/config.json
docker run --rm --network host -v /absolute/private/dev-state:/state cwxmr-unsafe-dev:local check /state/config.json
```

The later `run /state/config.json --send-stagenet` command can spend test funds and must use the same mount and host network. Host networking on Docker Desktop is different; this recipe targets Linux. The image does not start Nym, the sidecar or PostgreSQL for you.

## Validation and limits

Local tests cover bundle permissions/recovery/no overwrite, HTTP Host/Origin boundaries, exact journal binding/PCR/nonce/signature, normal NSM failure, and mock RPC pin rejection. The Rust-produced journal was independently decoded with ethers against the Solidity ABI. No actual deployment, broadcast, funded mint/payout or genuine online SDK decryption was performed. Tests with forged journal fixtures do not demonstrate attestation security. Mainnet is rejected; this runner cannot provide production custody guarantees.

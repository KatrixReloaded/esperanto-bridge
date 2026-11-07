# Request-bound Nitro proving

This operator tool prepares the exact `VaultRegistry.MintEvidence` and `Bridge.confidentialMint` calldata from a signed mint request and a real binary NSM document. It never signs or broadcasts an Ethereum transaction. It does not enable the runtime bridge actions or change any deployment/release gate. The public `/attestation?nonce=` endpoint returns discovery evidence, which this tool rejects: the internal, deposit-authorized mint NSM path must supply the document.

The selected upstream is [Automata revision 65c4a4233029ea3bbe16110a80731fcfd47cf300](https://github.com/automata-network/aws-nitro-enclave-attestation/tree/65c4a4233029ea3bbe16110a80731fcfd47cf300). Its concrete CLI is `nitro-attest-cli prove --report BINARY_COSE --sp1 --out OnchainProof.json`. `crates/prover/src/types.rs` defines `raw_proof.journal` as the ABI output, `onchain_proof` as selector-prefixed EVM proof bytes, `program_id.verifier_id` as the pinned program ID, `zktype="Succinct"`, and `proof_type="Verifier"`. Batch, Pico, empty/mock proofs and incompatible selectors are rejected. This tool currently supports SP1 only; the contract's RISC0 support is unchanged.

## Build the host CLI without changing the guest

The upstream CLI forces SP1 network proving even if `SP1_PROVER=cpu` was set. The reviewed [host-only patch](../scripts/nitro/automata-host-prover.patch) adds an explicit `--prover cpu|network` option, defaults to CPU, and refuses development proofs. It changes two CLI source files only. Preserve the checked-in guest ELFs and the lockfile; `REPRODUCIBLE_BUILD=prebuilt` is essential. The wrapper requires exactly this patch on the pinned commit plus an independently recorded CLI binary SHA256.

From the bridge repository, select an empty destination outside the bridge workspace:

```sh
BRIDGE_REPO="$PWD"
AUTOMATA_SOURCE=/absolute/path/to/automata-nitro-prover
git clone https://github.com/automata-network/aws-nitro-enclave-attestation "$AUTOMATA_SOURCE"
git -C "$AUTOMATA_SOURCE" checkout --detach 65c4a4233029ea3bbe16110a80731fcfd47cf300
git -C "$AUTOMATA_SOURCE" apply "$BRIDGE_REPO/scripts/nitro/automata-host-prover.patch"
cd "$AUTOMATA_SOURCE"
rustup toolchain install 1.91.1 --profile minimal
REPRODUCIBLE_BUILD=prebuilt CARGO_BUILD_JOBS=2 rustup run 1.91.1 cargo build --locked --release -p nitro-attest-cli --no-default-features --features sp1
shasum -a 256 target/release/nitro-attest-cli
```

The build downloads public Rust/git dependencies and the SP1 toolchain's required artifacts; it does not request a proof or require a proving wallet. The upstream workspace may resolve optional backend dependencies even for this SP1-only build. Prefix the resulting SHA256 with `0x` in the operator config. Source revision and binary checksum pins establish the operator's build identity; they are not a substitute for reproducible-build review.

CPU proving is a real SP1 mode, not a mock. The [v6.1.0 environment prover](https://github.com/succinctlabs/sp1/blob/v6.1.0/crates/sdk/src/blocking/env/mod.rs) supports CPU and the same Groth16 output path. Succinct lists minimums of 16+ CPU cores, 16GB+ RAM for Groth16 and 10GB+ disk; these are general minimums, not a measurement for this Nitro program. [Hardware requirements](https://docs.succinct.xyz/docs/sp1/getting-started/hardware-requirements)

This build uses SP1's [Docker gnark wrapper](https://github.com/succinctlabs/sp1/blob/v6.1.0/crates/recursion/gnark-ffi/src/ffi/docker.rs) for the final Groth16 step. Before obtaining fresh NSM evidence, prepare a running Docker daemon, the `ghcr.io/succinctlabs/sp1-gnark:v6.1.0` image and SP1 circuit artifacts, with sufficient memory assigned to Docker. The published image includes linux/arm64 and linux/amd64; native arm64 image download and `--help` execution passed, while actual wrapping remains untested. The tool checks `docker info` before beginning CPU proving; a passing check only establishes daemon availability. Docker became available during local validation, with about 7.65GiB assigned; that allocation is below the cited Groth16 minimum. The public `v6.1.0-groth16.tar.gz` circuit archive returned HTTP 200 and is 6,211,807,514 bytes compressed; it was not downloaded. Image index digest: `sha256:fd3e39f4995735567932b145580c70f87552dec0181f14a6898451a7ec5fa409`.

The available machine is arm64 with 16GiB RAM. A successful build does not establish that this program can prove here within the bridge's **600-second NSM freshness window**. The wrapper limits a proving attempt to 540 seconds and rechecks freshness afterward. A timeout or stale proof is an integration failure, not permission to relax the contract freshness policy. CPU proving remains unmeasured; the separate network diagnostic below completed within the window.

## Hardware diagnostic result (2026-11-07 IST)

A separate non-debug enclave on the Mumbai parent produced a fresh 4,601-byte NSM report using public dummy binding fields. The unchanged pinned Automata SP1 ELF executed 80,335,506 cycles / 65,679,938 prover gas. One Succinct Mainnet Groth16 request completed and verified locally in 82 seconds. The deployed Sepolia adapter `0x9A93576c438c7dbF293572D369d41515F84fAc2D` returned Success via `eth_call` at block 12079398, with an attestation age of 115 seconds. A corrupted proof reverted. The adapter-only gas estimate was 761,214; no Ethereum transaction was broadcast and no Ethereum gas was spent by this diagnostic.

Request ID: `0xda7aff81dc5638375a4e4d8506c9c2d2719db6dd7ecfb0e9435600f4b0b7cdbc`. The requester network balance decreased by **0.31510638574 PROVE** (0.3 base fee plus 65,679,938 PGU at 230,000,000 atomic PROVE/PGU), leaving 26.15150143737244681 PROVE. Its 0.0015 mainnet ETH remained unchanged. Final settlement status was still pending at the recorded balance check.

The isolated operator utility used SP1 SDK 6.1.0 with a local patch that enforces a 1 PROVE ceiling before signing and disables automatic paid request retries. Configured gas/price caps gave a 0.492 PROVE ceiling at the quoted base fee. A durable submission marker and request ID prevent accidental resubmission; polling resumes the same request. The requester key stayed on the operator's Mac. Public source, patch, manifest and evidence are saved under `artifacts/nitro/cost-probe/`; the proof and adapter results are in `paid-diagnostic-1/`.

This diagnostic did not use the production wrapper or authorize issuance. Its PCRs must not be approved as bridge measurements. The runtime-facing proof service now supports the bounded network driver below. A real mint-bound document and a successful Nitro mint remain hardware validation steps.

## Input protocol and commands

Install the declared tooling dependencies with Node 22/24:

```sh
npm ci --prefix contracts --ignore-scripts
node --test scripts/nitro/prove-mint.test.mjs
cp scripts/nitro/prover.example.json /secure/operator/prover.json
```

Fill every `null` pin from the independently reviewed deployment and measured PCR policy. Do not use sample addresses or hashes as authority. The config deliberately defaults to `"prover":"cpu"`, and passes no wallet credentials in that mode. The direct HTTPS Ethereum RPC in this config is **operator-only**, following the existing manual inspection workflow. A backend integration must use its reviewed Nym transport; do not route server traffic through this direct-provider path.

The request JSON is a reusable protocol for future enclave/runtime integration:

```json
{
  "schema": "cwxmr-mint-proof-request-v1",
  "domain": {"name":"CWXMRBridge","version":"1","chainId":11155111,"verifyingContract":"0x...Bridge"},
  "registry": "0x...Registry",
  "authorization": {
    "vaultId":"0x...32 bytes", "depositId":"0x...32 bytes", "recipient":"0x...address",
    "amountHandle":"0x...32 bytes", "inputProofHash":"0x...32 bytes", "nonce":"7", "deadline":"...Unix seconds"
  },
  "keys": {"decryptKey":"0x...address","tlsKeyHash":"0x...32 bytes","authKeyHash":"0x...32 bytes"},
  "policyVersion":"1",
  "publicKey":"0x...raw64 secp256k1",
  "inputProof":"0x...FHE input proof",
  "signature":"0x...65-byte EIP-712 signature"
}
```

Nonce, deadline and policy version are canonical decimal **strings**; chainId is a safe integer. The request contains no private keys or plaintext deposit amount. Supply the exact NSM COSE bytes separately, not JSON, a base64 string or discovery evidence. The signature must be generated inside the enclave only after independently verified deposit eligibility; this tool does not authorize deposits.

```sh
# Offline public-field/schema validation only; cryptographicallyVerified is explicitly false.
node scripts/nitro/prove-mint.mjs inspect /secure/operator/prover.json request.json attestation.report

# Real CPU attempt; requires the built CLI, a real mint-bound NSM report and valid live deployment pins.
node scripts/nitro/prove-mint.mjs prove --prover cpu /secure/operator/prover.json request.json attestation.report evidence.json

# Validate/assemble an existing upstream single-report proof, with no new proving request.
node scripts/nitro/prove-mint.mjs assemble /secure/operator/prover.json request.json attestation.report proof.json evidence.json
```

Before proving, the wrapper validates the request signature/domain/input proof hash, COSE structure and authenticated-field *claims*, expected PCR tuple and document freshness. This parsing is not independent AWS signature verification. It also checks live contract bytecode, adapter configuration, directory lifecycle/keys, approved PCR policy and replay state. The real prover validates the Nitro document; after proving, a read-only `eth_call` to the pinned adapter must succeed before a result is emitted. That call runs actual proof verification; certificate-cache writes are simulated, not persisted. RPC state is an independently trusted input, not a consensus proof.

The raw upstream artifact is retained as `evidence.json.automata.json`, even if final assembly rejects a stale proof. Successful output uses schema `cwxmr-mint-proof-result-v1`: original `request`, exact `evidence:{keys,policyVersion,output,proof}`, public report SHA256, `adapterVerifiedAt:{blockHash,blockNumber}`, unsigned `transaction:{to,data,value:"0"}` and `broadcast:false`. The report SHA256 is local provenance, not a field proven by the journal. Revalidate before submission: policy, nonce state, document freshness and FHE proof validity can change; adapter validation is not a simulation of the whole mint transaction. Output files are never overwritten.

## Untrusted parent proof service

The runtime-facing service is a separate, **candidate-only** path. It never constructs an Ethereum provider or calls `checkChain`; both RPC URLs must be `null`. It accepts CPU proving or the explicitly configured bounded network driver. The host handles public signed requests and NSM documents only. It cannot authorize a deposit or establish proof validity. The enclave must independently validate the exact returned `confidentialMint` calldata and simulate that complete call through its Nym transport before signing gas or submitting it. Candidate output must never be interpreted as the operator tool's adapter-verified result.

```sh
cp scripts/nitro/prover-service.example.json /secure/operator/prover-service.json
# Fill the public deployment/measurement pins and reviewed CLI source/binary identity.
node scripts/nitro/prover-server.mjs /secure/operator/prover-service.json
```

The listener binds only loopback, defaulting to `127.0.0.1:8789`; `CWXMR_PROVER_PORT` can select another unprivileged local port. The parent vsock forward exposes it to enclave-local port `8447`; do not expose the host listener publicly. `POST /prove` accepts `Content-Type: application/json` and exactly `{ "request": <cwxmr-mint-proof-request-v1>, "document": "<canonical base64 binary COSE>" }`. Request bodies are limited to 512KiB and decoded documents to 64KiB. One job runs at a time; concurrent requests receive 503. The total HTTP deadline is 550 seconds and the actual prover limit is at most 540 seconds. Cancellation terminates the prover process group; an already-started Docker wrapper may require operator cleanup after a timeout. No automatic paid fallback or retry exists.

Successful responses have exactly `{ "schema":"cwxmr-mint-proof-candidate-v1", "verification":"candidate_unverified", "transaction":{ "to":"0x...Bridge", "data":"0x...confidentialMint calldata", "value":"0" } }`. Request/proof shape, signature, binding and freshness checks run locally, but this response **does not attest cryptographic verification**. Errors are sanitized as `invalid_request` (400), `prover_busy` (503), `prover_timeout` (504), or `prover_failed` (502); no child stderr or credentials are returned. The reusable library exports `proveCandidate` and `assembleCandidate`; the latter only validates shape and encodes candidate calldata, and never starts proving or makes a network call.

## Optional network proving and validation boundary

Network mode uses [network-prover.rs](../scripts/nitro/network-prover.rs), built against the same pinned guest ELF and SP1 SDK 6.1.0. The [SDK patch](../scripts/nitro/sp1-single-request.patch) checks the actual base fee plus gas/price caps before signing and removes automatic paid submission retries. Each request is capped at **1 PROVE**; the current configured gas/price limits reserve less when the live base fee permits. This is an operator service, outside the custody enclave.

```sh
# Empty build directory; this command never reads a wallet or requests a proof.
bash scripts/nitro/build-network-prover.sh /absolute/automata-checkout /absolute/network-build
cp scripts/nitro/prover-service.network.example.json /secure/operator/network-prover.json
# Fill deployment/PCR pins, binary SHA256, walletFile and private stateDirectory.
# maxRequests is an explicit 1..10 attempt budget; the example starts with two.
CWXMR_ALLOW_PAID_PROVING=1 node scripts/nitro/prover-server.mjs /secure/operator/network-prover.json
```

Use Node 24.11.1; the CBOR tests fail under the currently installed Node 26. The wallet is a mode-600 `cast wallet new --json` file (direct array or structured envelope); its stored address must match its key. Keys stay inside the child process and never appear in arguments. Do not export `SP1_PRIVATE_KEY` for this driver. The server binds loopback; an SSH reverse forward may connect the parent to a service on the operator's Mac, keeping the requester key off EC2. Server chain RPC continues through enclave Nym; proof requests contain public signed mint/NSM data only.

For a Mac-hosted service, start it with the pinned Node 24 binary and keep the machine awake. In a second terminal, forward only the parent loopback listener:

```sh
CWXMR_ALLOW_PAID_PROVING=1 CWXMR_PROVER_PORT=18789 caffeinate -i /absolute/node24/bin/node \
  scripts/nitro/prover-server.mjs /secure/operator/network-prover.json
ssh -N -i /absolute/ec2-key.pem -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -R 127.0.0.1:8789:127.0.0.1:18789 ec2-user@PARENT_IP
```

The existing parent vsock forward on port 8447 connects to this loopback port. No public security-group rule for 8789 is needed. A disconnected tunnel makes proof requests fail closed; keep the service and its persistent journal when reconnecting. A GET to the forwarded port should return the service's JSON 404 without buying a proof. Do not use a real mint POST as a connectivity check.

The private state directory contains a durable slot for each attempted request, keyed by deployment/vault/deposit/nonce. Concurrent processes cannot exceed `maxRequests`. Failed and ambiguous attempts keep their slots, and a fresh NSM timestamp does not create a new charge for the same authorization. The child saves `started.json` before signing and `request.json` after acceptance. It never automatically resubmits. Preserve these records across restarts; deleting them resets the operator budget. To recover a known submitted request, use the driver's `resume REPORT JOB_DIR WALLET_JSON` command, which only polls that request or verifies the saved proof. A completed proof must still pass freshness and exact binding checks before it can become mint calldata.

The first actual bridge proof completed and verified locally in 62.52 seconds. A full operator-side Sepolia `eth_call` of its exact `confidentialMint` calldata succeeded, but no mint transaction was sent: the database relay's old 60-second idle limit dropped the enclave's cooperative lease during proving. Both database hops must outlive the 560-second enclave proof-request timeout, just like the proof transport. The corrected configuration uses 600 seconds and a regression check covers both hops. An expired authorization requires explicit measured recovery, not an automatic additional paid request.

The service's result remains `candidate_unverified`. The enclave checks the restored identity, cooperative database lease, deployed code/adapter links and its own approved nonzero PCR tuple before paying for a proof, rechecks pins afterward, validates and simulates the entire mint through Nym, and journals the exact signed transaction before submission. The caller stops on proof/mint errors for explicit reconciliation. No mainnet custody or hostile-clone safety is claimed.

Local tests exercise the shared Rust/ethers digest vector, synthetic COSE/OnchainProof schemas, rejection of the pinned upstream historical `samples/attestation_1.report`, input/domain/nonce/key substitutions, freshness/PCR/root/selector rejection, and CPU/network environment isolation. The public historical report is vendored under the existing Apache-2.0 `contracts/test/fixtures/AUTOMATA-LICENSE`; it has no valid bridge request binding and is not live evidence. Synthetic signatures and proof bytes are labeled test-only and cannot pass the real adapter. They are not a live Nitro/SP1 proof. The hardware diagnostic separately established real attestation proving and live adapter verification. Two real mint-bound NSM proofs have now verified within the freshness budget (62.52 and 46.29 seconds). The first attempt stopped on a lost database relay connection; the second submitted an Ethereum transaction that reverted under its 3 million gas limit. A third proof verified in 60.81 seconds; its mint transaction succeeded with 3,403,354 gas and finalized, and the enclave subsequently reported a positive decrypted mint result (`minted`). Evidence is under `artifacts/nitro/mint-recovery/`; the withdrawal leg remains unverified. The repaired preflight uses the signed transaction’s exact gas and fee limits; explicit reverted-mint recovery preserves its journal and requires a finalized failed receipt. See the operator runbook for current evidence and recovery constraints. Shared-network release gates remain unchanged.

Validation on 2026-11-06: ten proof-tool/service tests and 17 contract regressions passed. On the available arm64 machine, the patched pinned upstream passed `REPRODUCIBLE_BUILD=prebuilt CARGO_BUILD_JOBS=2 rustup run 1.91.1 cargo check --locked -p nitro-attest-cli --no-default-features --features sp1` after public dependency downloads (11m20s). This checks the host patch, SDK and prebuilt-ELF integration; it does not produce a release CLI executable, execute CPU/Groth16 proving, or prove that completion fits the 600-second window. The release build command above and actual proof timing remain operator validation steps. No private credentials, AWS resources or paid proving were used.

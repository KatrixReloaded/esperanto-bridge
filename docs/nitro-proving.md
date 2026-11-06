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

The available machine is arm64 with 16GiB RAM. A successful build does not establish that this program can prove here within the bridge's **600-second NSM freshness window**. The wrapper limits a proving attempt to 540 seconds and rechecks freshness afterward. A timeout or stale proof is an integration failure, not permission to relax the contract freshness policy. No expensive proof run or paid proving request was performed for this implementation.

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

## Optional network proving and validation boundary

Network proving is an explicit alternative, not a prerequisite for the CPU path. Select `--prover network` explicitly (or set the config to `"prover":"network"`) and provide the SP1 account key through `SP1_PRIVATE_KEY` (0x-prefixed raw32, never a CLI argument). The wrapper requires explicit `CWXMR_ALLOW_PAID_PROVING=1`. The upstream maps that credential to `NETWORK_PRIVATE_KEY`; `sp1RpcUrl` optionally configures its prover endpoint. The operator needs an account and sufficient proving funds with the selected provider. Do not set the paid opt-in until spending is authorized. On timeout, a submitted network job may still incur charges; inspect the account before retrying. This implementation made no paid call.

Local tests exercise the shared Rust/ethers digest vector, synthetic COSE/OnchainProof schemas, rejection of the pinned upstream historical `samples/attestation_1.report`, input/domain/nonce/key substitutions, freshness/PCR/root/selector rejection, and CPU/network environment isolation. The public historical report is vendored under the existing Apache-2.0 `contracts/test/fixtures/AUTOMATA-LICENSE`; it has no valid bridge request binding and is not live evidence. Synthetic signatures and proof bytes are labeled test-only and cannot pass the real adapter. They are not a live Nitro/SP1 proof. Required remaining evidence: an actual mint-bound NSM document, a complete real proof within the freshness budget, and successful verification against independently pinned live contracts. Shared-network release gates remain unchanged.

Validation on 2026-11-06: seven proof-tool tests and 17 contract regressions passed. On the available arm64 machine, the patched pinned upstream passed `REPRODUCIBLE_BUILD=prebuilt CARGO_BUILD_JOBS=2 rustup run 1.91.1 cargo check --locked -p nitro-attest-cli --no-default-features --features sp1` after public dependency downloads (11m20s). This checks the host patch, SDK and prebuilt-ELF integration; it does not produce a release CLI executable, execute CPU/Groth16 proving, or prove that completion fits the 600-second window. The release build command above and actual proof timing remain operator validation steps. No private credentials, AWS resources or paid proving were used.

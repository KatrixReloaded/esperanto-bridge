# Registry-pinned TLS for Nym browser requests

Source: `nymtech/nym` commit `a93dd70ac7983f25af3841b42e6ad71b07c571f3`, the release bump for mix-fetch3.0.1 and mix-tunnel0.3.1. npm did not supply gitHead metadata; this is the explicitly selected source revision, not a claim of bit-identical upstream npm provenance.

`nym.patch` adds `mixFetchPinned(url, init, origin, spkiSha256)` through the JS worker into Rust. `pinned-tls.rs` is copied into the Rust TLS module and is also compiled directly by native handshake tests. Ordinary Nym fetch retains its existing CA verifier. Pinned fetch uses fresh TLS1.3, the expected origin, a SHA256 DER SubjectPublicKeyInfo pin, certificate validity and actual TLS handshake signature verification. It never pools connections, resumes sessions, retries HTTP, follows redirects or sends early data. GET/POST bodies are bounded to4KiB; responses to64KiB. Public CA/SAN verification is intentionally replaced by the registry key authority. DNS/IP routing cannot replace key possession.

The browser independently retrieves that pin and current vault authorization from a fresh canonical finalized wallet RPC block before each private API request. Trusting the wallet RPC, the reviewed contract deployment, registry owner policy and measured enclave program remains necessary. This does not independently verify Ethereum consensus or replace per-mint Automata proof verification.

## Build

Prerequisites: Node26.12.1/npm11.21.1 (versions used for the checked-in artifacts), Git, Rust1.96.1 with `wasm32-unknown-unknown`, and wasm-bindgen0.2.122 in PATH. The build tools are pinned by package-lock.json. The script clones a new isolated source directory and uses Cargo.lock; it does not modify an existing checkout. Building needs several GB of temporary disk.

```sh
rustup toolchain install 1.96.1 --target wasm32-unknown-unknown
# Install wasm-bindgen-cli0.2.122 or use its versioned release archive.
./scripts/browser-nym/build.sh /absolute/path/to/new-build-directory
cd web
npm install --ignore-scripts
npm test
npm run build
```

The macOS ARM wasm-bindgen archive used was `wasm-bindgen-0.2.122-aarch64-apple-darwin.tar.gz` from the official0.2.122 GitHub release; SHA256 `36beadc86c5c02c511a152e8fc2c63850646887e97dc94ae04553640f839e808`. Other hosts need the matching platform tool. `web/vendor/SHA256SUMS` records shipped artifacts; rebuilding can differ due to build paths/toolchain output and requires updating both these hashes and npm lock integrity after review. No bit-for-bit reproducibility claim is made.

## Security tests

```sh
cd scripts/browser-nym/tls-tests
RUSTC="$(rustup which --toolchain 1.96.1 rustc)" \
RUSTDOC="$(rustup which --toolchain 1.96.1 rustdoc)" \
rustup run 1.96.1 cargo test --locked
```

Four actual rustls handshakes test correct pin success, wrong pin failure, expired certificate failure and a copied certificate with a forged CertificateVerify signature. Web tests cover finalized canonical authority reads, stale/wrong-chain/code/registry/lifecycle rejection, private-request refusal on authority failure and independent withdrawal readiness. Native tests exercise the exact verifier source but do not substitute for a live browser/Nym/enclave round trip.

Apache2.0 license text is included in each patched package. Existing upstream copyright notices remain in source.

## Read-only live browser check

Start `web/` with its reviewed public configuration, then run:

```sh
CWXMR_BROWSER=/absolute/path/to/chromium \
node scripts/browser-nym/check-browser.mjs http://127.0.0.1:5188
```

The script uses a fresh temporary browser profile, the real pinned Nym client, and real finalized Sepolia public RPC reads. It first checks that the actual App starts Nym without a wallet, then injects a real read-only RPC provider at the wallet boundary and runs the complete `liveApi.getInfo` path (contract discovery, decimals, vault eligibility and authenticated `/health`). It never signs or broadcasts and removes its own temporary profile on exit. It does not emulate a wallet balance or user signature. The separate public RPC requests are outside Nym, matching the frontend's explicitly trusted wallet-RPC boundary. Chromium successfully completed this check against the configured enclave ingress; withdrawal readiness was false during the deployment transition.

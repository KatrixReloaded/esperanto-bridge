#!/usr/bin/env bash
set -euo pipefail
# Build from a clean, separate checkout; never modifies an existing Nym checkout.
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
ROOT="$(cd -- "$HERE/../.." && pwd)"
BUILD_DIR="${1:?Usage: build.sh /absolute/new/build-directory}"
REV=a93dd70ac7983f25af3841b42e6ad71b07c571f3
case "$BUILD_DIR" in /*) ;; *) echo 'Build directory must be absolute' >&2; exit 1;; esac
if [ -e "$BUILD_DIR" ]; then echo 'Build directory must not exist' >&2; exit 1; fi
mkdir -p "$BUILD_DIR/tools"
cp "$HERE/package.json" "$HERE/package-lock.json" "$BUILD_DIR/tools/"
npm --prefix "$BUILD_DIR/tools" ci --ignore-scripts --legacy-peer-deps
git init "$BUILD_DIR/nym"
git -C "$BUILD_DIR/nym" remote add origin https://github.com/nymtech/nym.git
git -C "$BUILD_DIR/nym" fetch --depth 1 origin "$REV"
git -C "$BUILD_DIR/nym" checkout --detach FETCH_HEAD
git -C "$BUILD_DIR/nym" apply "$HERE/nym.patch"
mkdir -p "$BUILD_DIR/nym/wasm/smolmix/src/tls"
cp "$HERE/pinned-tls.rs" "$BUILD_DIR/nym/wasm/smolmix/src/tls/pinned.rs"
# Install this compiler/target first: rustup toolchain install 1.96.1 --target wasm32-unknown-unknown
export RUSTC="$(rustup which --toolchain 1.96.1 rustc)"
export RUSTDOC="$(rustup which --toolchain 1.96.1 rustdoc)"
cd "$BUILD_DIR/nym"
CARGO_BUILD_JOBS=2 rustup run 1.96.1 cargo build --locked -p nym-smolmix-wasm --target wasm32-unknown-unknown --release
# Supply wasm-bindgen 0.2.122 in PATH (matching the source Cargo.lock).
[ "$(wasm-bindgen --version)" = 'wasm-bindgen 0.2.122' ]
wasm-bindgen --target web --out-name smolmix_wasm --out-dir wasm/smolmix/pkg target/wasm32-unknown-unknown/release/nym_smolmix_wasm.wasm
node --input-type=module <<'JS'
import fs from 'node:fs';
fs.writeFileSync('wasm/smolmix/pkg/package.json', JSON.stringify({name:'@nymproject/smolmix-wasm',version:'0.1.0',type:'module',module:'smolmix_wasm.js',main:'smolmix_wasm.js',types:'smolmix_wasm.d.ts'}));
JS
ln -s "$BUILD_DIR/tools/node_modules" node_modules
mkdir -p "$BUILD_DIR/tools/node_modules/@nymproject"
ln -s "$BUILD_DIR/nym/wasm/smolmix/pkg" "$BUILD_DIR/tools/node_modules/@nymproject/smolmix-wasm"
ln -s "$BUILD_DIR/nym/sdk/typescript/packages/mix-tunnel" "$BUILD_DIR/tools/node_modules/@nymproject/mix-tunnel"
export PATH="$BUILD_DIR/tools/node_modules/.bin:$PATH"
cd sdk/typescript/packages/mix-tunnel
bash scripts/build.sh
cp "$BUILD_DIR/nym/LICENSES/Apache-2.0.txt" LICENSE
npm pack --ignore-scripts --pack-destination "$ROOT/web/vendor"
cd ../mix-fetch
tsc
cp "$BUILD_DIR/nym/LICENSES/Apache-2.0.txt" LICENSE
npm pack --ignore-scripts --pack-destination "$ROOT/web/vendor"

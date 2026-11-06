#!/usr/bin/env bash
# Build an operator executable; no wallet is read and no proof is requested.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: build-network-prover.sh AUTOMATA_CHECKOUT EMPTY_BUILD_DIR' >&2; exit 1; }
cwxmr_scripts="$(cd "$(dirname "$0")" && pwd)"
cwxmr_source="$(cd "$1" && pwd)"
mkdir "$2"
cwxmr_build="$(cd "$2" && pwd)"
cwxmr_rev=65c4a4233029ea3bbe16110a80731fcfd47cf300
git -C "$cwxmr_source" worktree add --detach "$cwxmr_build/source" "$cwxmr_rev"
cd "$cwxmr_build/source"
rustup run 1.91.1 cargo metadata --locked --format-version 1 > "$cwxmr_build/metadata.json"
python3 - "$cwxmr_build" <<'PY'
import json, shutil, sys
from pathlib import Path
out=Path(sys.argv[1])
packages=json.loads((out/'metadata.json').read_text())['packages']
sdk=[p for p in packages if p['name']=='sp1-sdk']
assert len(sdk)==1 and sdk[0]['version']=='6.1.0'
shutil.copytree(Path(sdk[0]['manifest_path']).parent, out/'sp1-sdk')
PY
git -C "$cwxmr_build/sp1-sdk" apply --check "$cwxmr_scripts/sp1-single-request.patch"
git -C "$cwxmr_build/sp1-sdk" apply "$cwxmr_scripts/sp1-single-request.patch"
mkdir -p crates/prover/examples .cargo
cp "$cwxmr_scripts/network-prover.rs" crates/prover/examples/cwxmr_network_proof.rs
python3 - "$cwxmr_build" <<'PY'
import json, sys
from pathlib import Path
out=Path(sys.argv[1])
Path('.cargo/config.toml').write_text('[patch.crates-io]\nsp1-sdk = { path = '+json.dumps(str(out/'sp1-sdk'))+' }\n')
PY
REPRODUCIBLE_BUILD=prebuilt CARGO_BUILD_JOBS=2 rustup run 1.91.1 cargo build --release \
  -p aws-nitro-enclave-attestation-prover --no-default-features --features sp1 --example cwxmr_network_proof
cwxmr_binary="${CARGO_TARGET_DIR:-$cwxmr_build/source/target}/release/examples/cwxmr_network_proof"
cp "$cwxmr_binary" "$cwxmr_build/cwxmr-network-prover"
shasum -a 256 "$cwxmr_build/cwxmr-network-prover" "$cwxmr_scripts/network-prover.rs" \
  "$cwxmr_scripts/sp1-single-request.patch" Cargo.lock crates/sp1-methods/elf/sp1-verifier.elf > "$cwxmr_build/build.sha256"
cat "$cwxmr_build/build.sha256"

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
scripts/nitro/preflight.sh build
[[ -f enclave/config/runtime.json && -f enclave/config/sidecar.json ]] || { echo 'Copy and configure enclave/config/*.example.json first' >&2; exit 1; }
python3 - <<'PY'
import json
runtime=json.load(open('enclave/config/runtime.json'))
for key in ('registry','bridge'):
    value=runtime['domain'][key]
    assert len(bytes.fromhex(value.removeprefix('0x')))==20 and int(value,16)>0, f'configure {key}'
assert ':000000000000:' not in runtime['kms']['key_arn'] and 'REPLACE' not in runtime['kms']['key_arn']
assert json.load(open('enclave/config/sidecar.json'))['ethereum_rpc'].startswith('https://')
PY
mkdir -p artifacts/nitro
cwxmr_epoch="$(git show -s --format=%ct HEAD)"
cwxmr_tag="${1:-cwxmr-nitro:local}"
docker build --platform linux/amd64 --build-arg "SOURCE_DATE_EPOCH=$cwxmr_epoch" -f enclave/Dockerfile -t "$cwxmr_tag" .
nitro-cli build-enclave --docker-uri "$cwxmr_tag" --output-file artifacts/nitro/cwxmr.eif > artifacts/nitro/build.json
nitro-cli describe-eif --eif-path artifacts/nitro/cwxmr.eif > artifacts/nitro/describe.json
python3 scripts/nitro/measurements.py artifacts/nitro/describe.json > artifacts/nitro/measurements.json
sha256sum artifacts/nitro/cwxmr.eif > artifacts/nitro/eif.sha256
{
  git rev-parse HEAD
  nitro-cli --version
  docker image inspect "$cwxmr_tag" --format '{{.Id}}'
  sha256sum service/Cargo.lock sidecar/package-lock.json enclave/Dockerfile enclave/config/runtime.json enclave/config/sidecar.json
} > artifacts/nitro/build-inputs.txt
cat artifacts/nitro/measurements.json

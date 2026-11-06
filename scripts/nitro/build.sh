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
    if len(bytes.fromhex(value.removeprefix('0x')))!=20 or int(value,16)==0: raise SystemExit(f'configure {key}')
if ':000000000000:' in runtime['kms']['key_arn'] or 'REPLACE' in runtime['kms']['key_arn']: raise SystemExit('configure KMS key ARN')
database=runtime.get('database', {})
if not all(isinstance(database.get(k), str) and database[k] and 'REPLACE' not in database[k] for k in ('tls_name','ca_pem','database','user')): raise SystemExit('configure database TLS identity and public CA')
monero=runtime.get('monero', {})
if not isinstance(monero.get('rpc_url'),str) or not monero['rpc_url'].startswith('https://') or type(monero.get('birth_height')) is not int or monero['birth_height'] < 0: raise SystemExit('configure stagenet HTTPS node and birth height')
sidecar=json.load(open('enclave/config/sidecar.json'))
if not sidecar['ethereum_rpc'].startswith('https://'): raise SystemExit('HTTPS RPC required')
nym=sidecar.get('nym', {})
if any(not isinstance(nym.get(k),str) or not nym[k] or nym[k].startswith('REPLACE') for k in ('provider','gateway','api')) or not nym['api'].startswith('https://'): raise SystemExit('configure Nym requester, gateway and HTTPS API')
PY
mkdir -p artifacts/nitro
cwxmr_epoch="$(git show -s --format=%ct HEAD)"
cwxmr_tag="${1:-cwxmr-nitro:local}"
docker build --no-cache --platform linux/amd64 --build-arg "SOURCE_DATE_EPOCH=$cwxmr_epoch" -f enclave/Dockerfile -t "$cwxmr_tag" .
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

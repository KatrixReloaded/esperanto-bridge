#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
scripts/nitro/preflight.sh launch
[[ $# -eq 1 ]] || { echo 'usage: launch.sh APPROVED_MEASUREMENTS.json' >&2; exit 1; }
nitro-cli describe-eif --eif-path artifacts/nitro/cwxmr.eif > artifacts/nitro/launch-describe.json
python3 scripts/nitro/measurements.py artifacts/nitro/launch-describe.json "$1" >/dev/null
# Deliberately omit --debug-mode and --attach-console; both destroy production attestation policy.
nitro-cli run-enclave --cpu-count 2 --memory 8192 --enclave-cid 16 --enclave-name cwxmr --eif-path artifacts/nitro/cwxmr.eif > artifacts/nitro/launch.json
nitro-cli describe-enclaves > artifacts/nitro/running.json
jq -e 'any(.[]; .EnclaveCID == 16 and .State == "RUNNING" and .Flags == "NONE")' artifacts/nitro/running.json >/dev/null
cat artifacts/nitro/launch.json

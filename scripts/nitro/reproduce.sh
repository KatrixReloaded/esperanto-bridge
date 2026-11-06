#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
scripts/nitro/build.sh cwxmr-nitro:repro-a
cp artifacts/nitro/measurements.json artifacts/nitro/measurements.first.json
cp artifacts/nitro/eif.sha256 artifacts/nitro/eif.first.sha256
scripts/nitro/build.sh cwxmr-nitro:repro-b
cmp artifacts/nitro/measurements.first.json artifacts/nitro/measurements.json
cmp artifacts/nitro/eif.first.sha256 artifacts/nitro/eif.sha256
# This establishes equality for these two local builds only; independent builds still required.
echo 'Two EIF byte hashes and PCR tuples match'

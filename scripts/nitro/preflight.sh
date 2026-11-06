#!/usr/bin/env bash
set -euo pipefail
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { echo 'Nitro build/launch requires Linux x86_64' >&2; exit 1; }
for binary in docker nitro-cli jq python3 sha256sum; do command -v "$binary" >/dev/null || { echo "Missing: $binary" >&2; exit 1; }; done
[[ "$(nitro-cli --version)" == *'1.5.2'* ]] || { echo 'Pinned nitro-cli 1.5.2 required' >&2; exit 1; }
docker info --format '{{.OSType}} {{.Architecture}}' | python3 -c 'import sys; sys.exit(0 if sys.stdin.read().strip() in ("linux x86_64", "linux amd64") else 1)'
if [[ "${1:-}" == launch ]]; then
  [[ -c /dev/nitro_enclaves && -c /dev/vsock ]] || { echo 'Nitro enclave/vsock device unavailable' >&2; exit 1; }
  systemctl is-active --quiet nitro-enclaves-allocator.service
  [[ "$(nproc)" -ge 4 ]] || { echo 'At least 4 parent vCPUs required' >&2; exit 1; }
fi

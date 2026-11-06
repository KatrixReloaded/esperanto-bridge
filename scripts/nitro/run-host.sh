#!/usr/bin/env bash
# Run foreground on the parent. No TLS termination and no SDK plaintext endpoint is forwarded.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ $# -eq 2 ]] || { echo 'usage: run-host.sh CIPHERTEXT_BACKUP_PATH OUTBOUND_ALLOWLIST.json' >&2; exit 1; }
scripts/nitro/preflight.sh launch
cwxmr_region="$(jq -er '.kms.region' enclave/config/runtime.json)"
cwxmr_allow="$(jq -ce 'if type=="array" and length>0 then . else error("allowlist") end' "$2")"
cwxmr_children=()
cleanup() { for cwxmr_pid in "${cwxmr_children[@]}"; do kill "$cwxmr_pid" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM
python3 scripts/nitro/host-store.py --file "$1" & cwxmr_children+=("$!")
python3 scripts/nitro/forward.py vsock-tcp --listen 8444 --target 8081 & cwxmr_children+=("$!")
python3 scripts/nitro/forward.py vsock-tcp --listen 8445 --host "kms.$cwxmr_region.amazonaws.com" --target 443 & cwxmr_children+=("$!")
python3 scripts/nitro/forward.py vsock-tcp --listen 8446 --target 5432 --idle 600 & cwxmr_children+=("$!")
python3 scripts/nitro/forward.py vsock-tcp --listen 8447 --target 8789 --idle 600 & cwxmr_children+=("$!")
python3 scripts/nitro/forward.py connect-proxy --listen 8889 --allow "$cwxmr_allow" & cwxmr_children+=("$!")
python3 scripts/nitro/forward.py vsock-tcp --listen 8888 --target 8889 & cwxmr_children+=("$!")
# Loopback listener; expose through a raw TCP load balancer only after independent fresh peer authentication.
python3 scripts/nitro/forward.py tcp-vsock --listen 8443 --cid 16 --target 8443 & cwxmr_children+=("$!")
# Linux bash: any forwarding failure stops this transport group; never claim the enclave is healthy.
wait -n
exit 1

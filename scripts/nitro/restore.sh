#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 2 ]] || { echo 'usage: restore.sh BACKUP_DIRECTORY NEW_HOST_ENVELOPE_PATH' >&2; exit 1; }
[[ ! -e "$2" ]] || { echo 'Refusing to overwrite an existing recovery envelope' >&2; exit 1; }
python3 - "$1" "$2" <<'PY'
import hashlib,pathlib,shutil,sys
root=pathlib.Path(sys.argv[1]); source=root/'identity.encrypted.json'
if hashlib.sha256(source.read_bytes()).hexdigest()!=(root/'identity.sha256').read_text().split()[0]: raise SystemExit('backup hash mismatch')
pathlib.Path(sys.argv[2]).parent.mkdir(parents=True,exist_ok=True)
with open(sys.argv[2],'xb') as output: output.write(source.read_bytes())
PY
echo 'Ciphertext staged; initialize=false required. KMS unwrap occurs only inside enclave. Spending remains disabled.'

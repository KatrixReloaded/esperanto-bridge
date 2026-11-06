#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 2 ]] || { echo 'usage: backup.sh CIPHERTEXT_ENVELOPE DESTINATION_DIRECTORY' >&2; exit 1; }
mkdir -p "$2"
# Current runtime backup is identity-only. Include encrypted core state if it has been initialized.
python3 - "$1" "$2" <<'PY'
import hashlib,json,pathlib,shutil,sys
source=pathlib.Path(sys.argv[1]); target=pathlib.Path(sys.argv[2])/'identity.encrypted.json'
value=json.loads(source.read_bytes())
if set(value)!={'version','wrapped_key','nonce','tag','ciphertext'} or value['version']!=1: raise SystemExit('invalid encrypted envelope')
shutil.copyfile(source,target)
(target.parent/'identity.sha256').write_text(hashlib.sha256(target.read_bytes()).hexdigest()+'  identity.encrypted.json\n')
PY
if [[ -n "${DATABASE_URL:-}" ]]; then
  pg_dump --dbname "$DATABASE_URL" --table encrypted_vault_state --data-only --column-inserts > "$2/core-state.encrypted.sql"
fi
echo 'Encrypted backup copied; freshness and recoverability require an enclave restore test'

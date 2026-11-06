#!/usr/bin/env bash
# Parent-only encrypted state store. TLS terminates inside the enclave against the measured CA.
# The trusted stagenet operator controls this database; it provides no rollback protection.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run with sudo on the EC2 parent' >&2; exit 1; }
cwxmr_pg=/var/lib/cwxmr/postgres
[[ ! -e "$cwxmr_pg" ]] || { echo 'PostgreSQL state already exists; refusing to overwrite' >&2; exit 1; }
umask 077
mkdir -p "$cwxmr_pg/tls" "$cwxmr_pg/data"
openssl req -x509 -newkey rsa:3072 -nodes -days 30 -subj /CN=cwXMR-demo-database-CA \
  -keyout "$cwxmr_pg/tls/ca.key" -out "$cwxmr_pg/tls/ca.crt" 2>/dev/null
openssl req -newkey rsa:3072 -nodes -subj /CN=postgres.internal \
  -keyout "$cwxmr_pg/tls/server.key" -out "$cwxmr_pg/tls/server.csr" 2>/dev/null
printf '%s\n' 'subjectAltName=DNS:postgres.internal' 'extendedKeyUsage=serverAuth' > "$cwxmr_pg/tls/extensions"
openssl x509 -req -in "$cwxmr_pg/tls/server.csr" -CA "$cwxmr_pg/tls/ca.crt" \
  -CAkey "$cwxmr_pg/tls/ca.key" -CAcreateserial -days 30 -extfile "$cwxmr_pg/tls/extensions" \
  -out "$cwxmr_pg/tls/server.crt" 2>/dev/null
chmod 644 "$cwxmr_pg/tls/ca.crt" "$cwxmr_pg/tls/server.crt"
chown 70:70 "$cwxmr_pg/data" "$cwxmr_pg/tls/server.key"
cat > "$cwxmr_pg/pg_hba.conf" <<'EOF'
local all all trust
hostssl all all 127.0.0.1/32 trust
hostssl all all ::1/128 trust
EOF
chmod 644 "$cwxmr_pg/pg_hba.conf"
docker run -d --name cwxmr-nitro-db --restart unless-stopped --network host \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=cwxmr \
  -v "$cwxmr_pg/data:/var/lib/postgresql/data" \
  -v "$cwxmr_pg/tls/server.key:/run/cwxmr/server.key:ro" \
  -v "$cwxmr_pg/tls/server.crt:/run/cwxmr/server.crt:ro" \
  -v "$cwxmr_pg/pg_hba.conf:/run/cwxmr/pg_hba.conf:ro" \
  postgres:16-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685 \
  -c listen_addresses=127.0.0.1 -c ssl=on -c ssl_cert_file=/run/cwxmr/server.crt \
  -c ssl_key_file=/run/cwxmr/server.key -c hba_file=/run/cwxmr/pg_hba.conf
for cwxmr_attempt in {1..60}; do
  if docker exec cwxmr-nitro-db pg_isready -U postgres -d cwxmr >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec cwxmr-nitro-db psql -v ON_ERROR_STOP=1 -U postgres -d cwxmr \
  -c 'CREATE ROLE cwxmr LOGIN; ALTER DATABASE cwxmr OWNER TO cwxmr;'
install -m 644 "$cwxmr_pg/tls/ca.crt" /home/ec2-user/cwxmr-postgres-ca.crt
echo 'Database ready on parent loopback 5432; public CA: /home/ec2-user/cwxmr-postgres-ca.crt'

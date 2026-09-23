#!/bin/sh
# Create .env from .env.example with random secrets (requires openssl). Never overwrites an existing .env.
set -eu
cd "$(dirname "$0")/.."
if [ -f .env ]; then
  echo ".env already exists; not overwriting (use scripts/generate_env.py to fill missing values)" >&2
  exit 1
fi
key32() { openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '='; }
rand() { openssl rand -base64 36 | tr -d '/+=\n' | cut -c1-40; }
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
admin_pw="$(rand | cut -c1-16)-Aa1!"
# Master transport key, and the default pool's key derived from it with HKDF-SHA256
# (same derivation as asm_sensors.jobs.pool_key; needs OpenSSL 3).
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
openssl rand -out "$tmp" 32
master="$(b64url < "$tmp")"
master_hex="$(od -An -tx1 "$tmp" | tr -d ' \n')"
pool_key="$(openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt "hexkey:${master_hex}" \
  -kdfopt "info:exteriq-asm/scanner-pool/v1/default" -binary HKDF | b64url)"
sed -e "s|^ASM_SECRET_KEY=.*|ASM_SECRET_KEY=$(rand)$(rand)|" \
    -e "s|^ASM_ENCRYPTION_KEYS=.*|ASM_ENCRYPTION_KEYS=k1:$(key32)|" \
    -e "s|^ASM_SCANNER_TRANSPORT_KEY=.*|ASM_SCANNER_TRANSPORT_KEY=${master}|" \
    -e "s|^ASM_SCANNER_POOL_KEY=.*|ASM_SCANNER_POOL_KEY=${pool_key}|" \
    -e "s|^ASM_POSTGRES_SUPERUSER_PASSWORD=.*|ASM_POSTGRES_SUPERUSER_PASSWORD=$(rand)|" \
    -e "s|^ASM_DB_PASSWORD=.*|ASM_DB_PASSWORD=$(rand)|" \
    -e "s|^ASM_REDIS_PASSWORD=.*|ASM_REDIS_PASSWORD=$(rand)|" \
    -e "s|^ASM_SCANNER_REDIS_PASSWORD=.*|ASM_SCANNER_REDIS_PASSWORD=$(rand)|" \
    -e "s|^ASM_BOOTSTRAP_ADMIN_PASSWORD=.*|ASM_BOOTSTRAP_ADMIN_PASSWORD=${admin_pw}|" \
    .env.example > .env
chmod 600 .env
echo "wrote .env — initial administrator password: ${admin_pw}"

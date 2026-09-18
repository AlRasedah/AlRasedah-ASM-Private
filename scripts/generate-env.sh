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
admin_pw="$(rand | cut -c1-16)-Aa1!"
sed -e "s|^ASM_SECRET_KEY=.*|ASM_SECRET_KEY=$(rand)$(rand)|" \
    -e "s|^ASM_ENCRYPTION_KEYS=.*|ASM_ENCRYPTION_KEYS=k1:$(key32)|" \
    -e "s|^ASM_SCANNER_TRANSPORT_KEY=.*|ASM_SCANNER_TRANSPORT_KEY=$(key32)|" \
    -e "s|^ASM_POSTGRES_SUPERUSER_PASSWORD=.*|ASM_POSTGRES_SUPERUSER_PASSWORD=$(rand)|" \
    -e "s|^ASM_DB_PASSWORD=.*|ASM_DB_PASSWORD=$(rand)|" \
    -e "s|^ASM_REDIS_PASSWORD=.*|ASM_REDIS_PASSWORD=$(rand)|" \
    -e "s|^ASM_BOOTSTRAP_ADMIN_PASSWORD=.*|ASM_BOOTSTRAP_ADMIN_PASSWORD=${admin_pw}|" \
    .env.example > .env
chmod 600 .env
echo "wrote .env — initial administrator password: ${admin_pw}"

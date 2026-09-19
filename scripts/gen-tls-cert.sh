#!/usr/bin/env sh
# Generate a self-signed TLS certificate for the reverse proxy, with the
# ownership/permissions the unprivileged nginx image (uid 101) needs to read it.
#
#   sh scripts/gen-tls-cert.sh [common-name]     # e.g. sh scripts/gen-tls-cert.sh asm.example.com
#
# For production, replace docker/proxy/certs/tls.crt|tls.key with a certificate
# from a real CA (keep the same filenames and run the chown/chmod below).
set -eu

CN="${1:-localhost}"
DIR="$(cd "$(dirname "$0")/.." && pwd)/docker/proxy/certs"
CRT="$DIR/tls.crt"
KEY="$DIR/tls.key"
NGINX_UID="${ASM_PROXY_UID:-101}"   # nginxinc/nginx-unprivileged runs as uid 101

mkdir -p "$DIR"
if [ -f "$CRT" ] && [ -f "$KEY" ] && [ "${FORCE:-}" != "1" ]; then
  echo "cert already exists at $CRT (set FORCE=1 to overwrite); fixing permissions only"
else
  echo "generating self-signed certificate for CN=$CN (valid 365 days)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$KEY" -out "$CRT" -subj "/CN=$CN" \
    -addext "subjectAltName=DNS:$CN"
fi

# The proxy runs as a non-root user, so the private key must be readable by it.
chmod 644 "$CRT"
chmod 640 "$KEY"
if chown "$NGINX_UID:$NGINX_UID" "$CRT" "$KEY" 2>/dev/null; then
  echo "set owner uid $NGINX_UID on cert and key"
else
  echo "could not chown (not root?); making key world-readable so the proxy can read it"
  chmod 644 "$KEY"
fi
echo "done. Enable TLS with ASM_PROXY_CONF=./docker/proxy/nginx-tls.conf and restart the proxy."

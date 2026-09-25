#!/bin/sh
# Exteriq ASM — install on Ubuntu 26.04 LTS (amd64).
#
#   sudo sh install.sh [--hostname <name>] [--https-port 443] [--http-port 80] [--pools default]
#
# Run from the directory holding the two .deb files and SHA256SUMS. It:
#   1. checks the host, 2. verifies the files against SHA256SUMS (and a signature when one
#   and the release key are present), 3. installs the packages with apt (dependencies come
#   from the host's configured Ubuntu repositories or mirror), then 4-9. runs
#   `exteriqctl install`, which generates secrets, sets up the database, broker, TLS and
#   logging, starts everything, checks readiness and prints a one-time setup link.
# Re-running is safe: every step checks what is already done.
set -eu
cd "$(dirname "$0")"

[ "$(id -u)" = 0 ] || { echo "run as root: sudo sh install.sh" >&2; exit 1; }
. /etc/os-release
if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID:-}" != "26.04" ] || [ "$(dpkg --print-architecture)" != amd64 ]; then
  echo "unsupported host: ${PRETTY_NAME:-unknown} $(dpkg --print-architecture); Ubuntu 26.04 LTS amd64 is required" >&2
  exit 1
fi

echo "[1/3] verifying files"
[ -f SHA256SUMS ] || { echo "SHA256SUMS is missing" >&2; exit 1; }
if [ -f SHA256SUMS.asc ] && [ -f /usr/share/keyrings/exteriq-release.gpg ]; then
  gpgv --keyring /usr/share/keyrings/exteriq-release.gpg SHA256SUMS.asc SHA256SUMS \
    || { echo "SHA256SUMS signature is NOT valid; do not install these files" >&2; exit 1; }
  echo "    signature ok"
else
  echo "    note: no signature checked (SHA256SUMS.asc or the release key is absent);"
  echo "          compare SHA256SUMS with the value published by your vendor."
fi
sha256sum --strict -c SHA256SUMS || { echo "checksum mismatch: the files are damaged or altered" >&2; exit 1; }

release=$(ls exteriq-release-*_amd64.deb | head -n 1)
tooling=$(ls exteriq_*_amd64.deb | head -n 1)

echo "[2/3] installing packages (apt resolves PostgreSQL, Valkey, nginx, rsyslog)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || echo "    note: apt-get update failed; using the package lists already on this host"
apt-get install -y --no-install-recommends "./$release" "./$tooling"

echo "[3/3] configuring"
exec exteriqctl install "$@"

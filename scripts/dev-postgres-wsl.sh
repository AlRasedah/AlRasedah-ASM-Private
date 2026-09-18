#!/usr/bin/env bash
# Development/test PostgreSQL without Docker or root, for Windows developers using WSL (Ubuntu).
#
# Downloads the distribution's PostgreSQL packages with `apt-get download` (no root needed),
# extracts them under ~/asm-pg, initialises a cluster and starts it on 127.0.0.1:55432
# (superuser postgres/postgres). WSL forwards localhost, so Windows tools can connect to it:
#
#   wsl -- bash scripts/dev-postgres-wsl.sh
#   set ASM_TEST_ADMIN_URL=postgresql://postgres:postgres@127.0.0.1:55432/postgres
#
# Stop it with:  ~/asm-pg/root/usr/lib/postgresql/<ver>/bin/pg_ctl -D ~/asm-pg/data stop
# Local development only — the cluster uses fsync=off.
set -euo pipefail

BASE="${ASM_PG_HOME:-$HOME/asm-pg}"
PORT="${ASM_PG_PORT:-55432}"
mkdir -p "$BASE/debs" "$BASE/root"
cd "$BASE/debs"

PGVER="$(apt-cache search --names-only '^postgresql-[0-9]+$' | sed -E 's/^postgresql-([0-9]+).*/\1/' | sort -n | tail -1)"
[ -n "$PGVER" ] || { echo "no postgresql-N package found in apt cache (run 'sudo apt-get update' once)"; exit 1; }
ls postgresql-"$PGVER"_*.deb >/dev/null 2>&1 || apt-get download "postgresql-$PGVER" "postgresql-client-$PGVER" libpq5

export LD_LIBRARY_PATH="$BASE/root/usr/lib/x86_64-linux-gnu:$BASE/root/lib/x86_64-linux-gnu"
BIN="$BASE/root/usr/lib/postgresql/$PGVER/bin"
for _ in 1 2 3; do
  for f in *.deb; do dpkg -x "$f" "$BASE/root"; done
  missing=$(ldd "$BIN/postgres" "$BIN/initdb" "$BIN/pg_ctl" 2>/dev/null | awk '/not found/{print $1}' | sort -u)
  [ -z "$missing" ] && break
  for lib in $missing; do
    case "$lib" in
      libnuma.so.1) pkg=libnuma1 ;;
      liburing.so.2) pkg=liburing2 ;;
      libLLVM*) pkg=$(apt-cache search --names-only '^libllvm[0-9]+$' | sort -V | tail -1 | cut -d' ' -f1) ;;
      *) echo "unknown missing library $lib"; continue ;;
    esac
    apt-get download "$pkg"
  done
done

DATA="$BASE/data"
if [ ! -f "$DATA/PG_VERSION" ]; then
  echo "postgres" > "$BASE/pwfile"
  "$BIN/initdb" -D "$DATA" -U postgres --pwfile="$BASE/pwfile" -A scram-sha-256 -E UTF8 --locale=C.UTF-8 >/dev/null
  cat >> "$DATA/postgresql.conf" <<EOF
listen_addresses = '127.0.0.1'
port = $PORT
unix_socket_directories = '$BASE'
fsync = off
synchronous_commit = off
full_page_writes = off
max_connections = 200
EOF
fi
"$BIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1 || "$BIN/pg_ctl" -D "$DATA" -l "$BASE/postgres.log" -w start
echo "PostgreSQL $PGVER listening on 127.0.0.1:$PORT (postgres/postgres)"

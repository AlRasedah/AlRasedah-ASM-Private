#!/bin/sh
# Build the native packages for Ubuntu 26.04 LTS (amd64).
#
#   sudo packaging/build-deb.sh <out-dir> [--engines <dir>] [--version <v>] [--extra-migration <file>]
#
# Produces in <out-dir>:
#   exteriq-release-<v>_<v>_amd64.deb   the release: /opt/exteriq/releases/<v>/ (prebuilt web app,
#                                       platform and scanner virtualenvs, pinned engines, migrations)
#   exteriq_<v>_amd64.deb               tooling: exteriqctl, systemd units, collector and rotation config
#   install.sh, SHA256SUMS              customer bootstrap and checksums of everything above
#
# Runs on a disposable Ubuntu 26.04 *build* host (compilers, Node and Go live only there). The
# release is assembled at its final path, /opt/exteriq/releases/<v>, because virtualenvs are
# not relocatable; the build host must not be a machine running Exteriq.
#
# --engines: directory from packaging/build-scanner-tools.sh (default: build them now).
# --extra-migration: test builds only (upgrade/recovery tests); never for customer packages.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/.." && pwd)
out=${1:?usage: build-deb.sh <out-dir> [--engines dir] [--version v] [--extra-migration file]}
shift
engines="" version="" extra=""
while [ $# -gt 0 ]; do
  case "$1" in
    --engines) engines=$2; shift 2 ;;
    --version) version=$2; shift 2 ;;
    --extra-migration) extra=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "run as root (it writes /opt/exteriq/releases/<v> on the build host)" >&2; exit 1; }
. /etc/os-release
[ "$ID" = ubuntu ] && [ "$VERSION_ID" = "26.04" ] || { echo "build on Ubuntu 26.04 (the target)" >&2; exit 1; }
[ "$(dpkg --print-architecture)" = amd64 ] || { echo "build on amd64" >&2; exit 1; }
for tool in python3.14 npm dpkg-deb sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing build tool: $tool" >&2; exit 1; }
done

version=${version:-$(tr -d '\r' < "$src/backend/app/__init__.py" | sed -n 's/^__version__ = "\(.*\)"/\1/p')}
commit=${BUILD_COMMIT:-$(git -C "$src" rev-parse HEAD 2>/dev/null || echo unknown)}
dirty=${BUILD_DIRTY:-$(git -C "$src" status --porcelain >/dev/null 2>&1 && { test -z "$(git -C "$src" status --porcelain)" && echo no || echo yes; } || echo unknown)}
echo "$version" | grep -Eq '^[0-9][0-9A-Za-z.+~]*$' || { echo "bad version $version" >&2; exit 1; }
mkdir -p "$out"
out=$(cd "$out" && pwd)
rel=/opt/exteriq/releases/$version
# Package names may not contain "~" (versions may: 0.2.0~rc1 sorts before 0.2.0).
pkg=exteriq-release-$(echo "$version" | tr "~" "-")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
log() { echo "==> $*" >&2; }

if [ -e /etc/exteriq/exteriq.env ]; then
  echo "this host has an Exteriq installation; build on a separate, disposable host" >&2; exit 1
fi
rm -rf "$rel"
mkdir -p "$rel/platform" "$rel/scanner/bin" "$rel/docs"

# Build from a copy with the package version stamped in, so every process, heartbeat and
# support bundle reports the version that is actually installed.
mkdir -p "$work/src"
cp -a "$src/backend" "$src/workers" "$work/src/"
find "$work/src" -name __pycache__ -prune -exec rm -rf {} +
for f in "$work/src/backend/app/__init__.py" "$work/src/workers/asm_sensors/__init__.py"; do
  sed -i "s/^__version__ = \".*\"/__version__ = \"$version\"/" "$f"
done
for f in "$work/src/backend/pyproject.toml" "$work/src/workers/pyproject.toml"; do
  sed -i "0,/^version = \".*\"/s//version = \"$(echo "$version" | sed 's/~/.dev0+/; s/[^0-9A-Za-z.+]/./g')\"/" "$f"
done
build_src=$work/src

# ------------------------------------------------------------------ web app (built here, shipped as files)
log "web app"
cp -a "$src/frontend" "$work/frontend"
rm -rf "$work/frontend/node_modules" "$work/frontend/dist"
(cd "$work/frontend" && npm ci --no-audit --no-fund --loglevel=error && npm run build >/dev/null)
cp -a "$work/frontend/dist" "$rel/web"

# ------------------------------------------------------------------ platform environment
log "platform virtualenv"
python3.14 -m venv "$rel/platform/venv"
"$rel/platform/venv/bin/pip" install --quiet --no-cache-dir --upgrade pip
"$rel/platform/venv/bin/pip" install --quiet --no-cache-dir "$build_src/workers" "$build_src/backend[pdf,s3]"
"$rel/platform/venv/bin/pip" freeze --all > "$rel/platform/python-packages.txt"
cp "$build_src/backend/alembic.ini" "$rel/platform/alembic.ini"
cp -a "$build_src/backend/alembic" "$rel/platform/alembic"
find "$rel/platform/alembic" -name __pycache__ -prune -exec rm -rf {} +
if [ -n "$extra" ]; then
  log "TEST BUILD: adding migration $(basename "$extra")"
  cp "$extra" "$rel/platform/alembic/versions/"
  echo "test build: extra migration $(basename "$extra")" > "$rel/TEST-BUILD"
fi
ASM_ALEMBIC_DIR="$rel/platform/alembic" "$rel/platform/venv/bin/python" -c \
  'from app.db.migrations import expected_head; h = expected_head(); assert h, "no head"; print(h)' \
  > "$rel/platform/SCHEMA_HEAD"

# ------------------------------------------------------------------ scanner environment
log "scanner virtualenv"
python3.14 -m venv "$rel/scanner/venv"
"$rel/scanner/venv/bin/pip" install --quiet --no-cache-dir --upgrade pip
"$rel/scanner/venv/bin/pip" install --quiet --no-cache-dir "$build_src/workers[worker]"
"$rel/scanner/venv/bin/pip" freeze --all > "$rel/scanner/python-packages.txt"

log "engines"
if [ -z "$engines" ]; then
  engines=$work/engines
  sh "$here/build-scanner-tools.sh" "$engines"
fi
(cd "$engines" && sha256sum -c --quiet SHA256SUMS)
for b in subfinder dnsx httpx naabu nuclei amass; do install -m 0755 "$engines/$b" "$rel/scanner/bin/$b"; done
cp "$engines/SHA256SUMS" "$rel/scanner/ENGINES.sha256"
cp "$engines/GO_VERSION" "$rel/scanner/GO_VERSION"
cp "$here/scanner-tools.env" "$rel/scanner/ENGINE_VERSIONS"
install -m 0755 "$here/scanner-update-templates" "$rel/scanner/bin/exteriq-update-templates"

# ------------------------------------------------------------------ docs, metadata, manifest
for d in NATIVE_INSTALL.md LOGGING.md DIAGNOSTICS.md; do
  [ -f "$src/docs/$d" ] && cp "$src/docs/$d" "$rel/docs/"
done
cp "$src/LICENSE" "$src/THIRD_PARTY_LICENSES.md" "$rel/docs/"
"$rel/platform/venv/bin/python" -m compileall -q "$rel/platform/venv/lib" >/dev/null || true
"$rel/scanner/venv/bin/python" -m compileall -q "$rel/scanner/venv/lib" >/dev/null || true
echo "$version" > "$rel/VERSION"
{
  echo "version: $version"
  echo "built_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit: $commit"
  echo "dirty: $dirty"
  echo "python: $(python3.14 --version 2>&1)"
  echo "go: $(cat "$engines/GO_VERSION")"
  echo "node: $(node --version)"
  echo "schema_head: $(cat "$rel/platform/SCHEMA_HEAD")"
} > "$rel/BUILDINFO"
(cd "$rel" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum | sed 's|  \./|  |') \
  > "$work/MANIFEST.sha256"
mv "$work/MANIFEST.sha256" "$rel/MANIFEST.sha256"

# ------------------------------------------------------------------ package: release
log "package $pkg"
stage=$work/release
mkdir -p "$stage/DEBIAN" "$stage/opt/exteriq/releases"
cp -a "$rel" "$stage/opt/exteriq/releases/"
size=$(du -sk "$stage/opt" | cut -f1)
cat > "$stage/DEBIAN/control" <<EOF
Package: $pkg
Version: $version
Architecture: amd64
Maintainer: Exteriq <support@exteriq.invalid>
Section: net
Priority: optional
Installed-Size: $size
Depends: python3.14 (>= 3.14.4), libpcap0.8t64, libpango-1.0-0, libpangoft2-1.0-0, libharfbuzz-subset0, fonts-dejavu-core, fonts-noto-core, ca-certificates
Description: Exteriq ASM release $version
 One immutable release of Exteriq ASM (web app, platform and scanner environments, scanner
 engines, database migrations) under /opt/exteriq/releases/$version. Activated with
 exteriqctl; several releases can be installed side by side.
EOF
sed "s/@VERSION@/$version/g" "$here/debian/release.prerm" > "$stage/DEBIAN/prerm"
chmod 0755 "$stage/DEBIAN/prerm"
dpkg-deb --root-owner-group -Zxz -z6 --build "$stage" "$out/${pkg}_$(echo "$version" | tr "~" "-")_amd64.deb" >/dev/null

# ------------------------------------------------------------------ package: tooling
log "package exteriq"
stage=$work/tooling
mkdir -p "$stage/DEBIAN" "$stage/usr/sbin" "$stage/usr/lib/systemd/system" "$stage/usr/share/exteriq/nginx" \
         "$stage/etc/rsyslog.d" "$stage/usr/share/doc/exteriq"
install -m 0755 "$here/exteriqctl" "$stage/usr/sbin/exteriqctl"
install -m 0644 "$here"/systemd/* "$stage/usr/lib/systemd/system/"
install -m 0644 "$here/nginx/exteriq.conf.in" "$stage/usr/share/exteriq/nginx/"
install -m 0644 "$here/logrotate/exteriq.conf" "$stage/usr/share/exteriq/logrotate.conf"
install -m 0644 "$here/rsyslog/40-exteriq.conf" "$stage/etc/rsyslog.d/40-exteriq.conf"
install -m 0644 "$src/LICENSE" "$stage/usr/share/doc/exteriq/copyright"
echo /etc/rsyslog.d/40-exteriq.conf > "$stage/DEBIAN/conffiles"
for s in postinst prerm postrm; do install -m 0755 "$here/debian/exteriq.$s" "$stage/DEBIAN/$s"; done
size=$(du -sk "$stage/usr" "$stage/etc" | awk '{s+=$1} END {print s}')
cat > "$stage/DEBIAN/control" <<EOF
Package: exteriq
Version: $version
Architecture: amd64
Maintainer: Exteriq <support@exteriq.invalid>
Section: net
Priority: optional
Installed-Size: $size
Depends: $pkg (= $version), python3 (>= 3.14), postgresql (>= 16), postgresql-client, valkey-server (>= 8), valkey-tools, nginx, rsyslog (>= 8.2400), logrotate, openssl, iproute2, systemd, adduser
Description: Exteriq ASM external attack surface management (native installation)
 Installation and operations tooling for Exteriq ASM on Ubuntu 26.04: exteriqctl, systemd
 units, log collection and rotation. Run 'exteriqctl install' after installing.
EOF
dpkg-deb --root-owner-group -Zxz --build "$stage" "$out/exteriq_$(echo "$version" | tr "~" "-")_amd64.deb" >/dev/null

install -m 0755 "$here/install.sh" "$out/install.sh"
(cd "$out" && sha256sum "${pkg}_$(echo "$version" | tr "~" "-")_amd64.deb" "exteriq_$(echo "$version" | tr "~" "-")_amd64.deb" install.sh \
  > SHA256SUMS)
log "done: $out"
cat "$out/SHA256SUMS" >&2

#!/bin/sh
# Build the scanner engines natively for the package's target (Ubuntu 26.04, amd64).
#
#   packaging/build-scanner-tools.sh <out-dir>
#
# Runs on the *build* host (it needs Go and libpcap-dev); customers never run it. Versions
# come from packaging/scanner-tools.env; every module is verified against the Go checksum
# database, and the resulting binaries' SHA-256 are written to <out-dir>/SHA256SUMS.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
out=${1:?usage: build-scanner-tools.sh <out-dir>}
. "$here/scanner-tools.env"
mkdir -p "$out"
out=$(cd "$out" && pwd)

export GOTOOLCHAIN="$GO_TOOLCHAIN" GOFLAGS="-trimpath -buildvcs=false" GOBIN="$out" CGO_ENABLED=1
export GOSUMDB="${GOSUMDB:-sum.golang.org}" GOPROXY="${GOPROXY:-https://proxy.golang.org}"
export GOPATH="${GOPATH:-$HOME/go}" GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"

build() {
  echo "building $1@$2" >&2
  go install -ldflags="-s -w" "$1@$2"
}
build github.com/projectdiscovery/subfinder/v2/cmd/subfinder "$SUBFINDER_VERSION"
build github.com/projectdiscovery/dnsx/cmd/dnsx "$DNSX_VERSION"
build github.com/projectdiscovery/httpx/cmd/httpx "$HTTPX_VERSION"
build github.com/projectdiscovery/naabu/v2/cmd/naabu "$NAABU_VERSION"
build github.com/projectdiscovery/nuclei/v3/cmd/nuclei "$NUCLEI_VERSION"
build github.com/owasp-amass/amass/v4/cmd/amass "$AMASS_VERSION"

cd "$out"
for b in subfinder dnsx httpx naabu nuclei amass; do
  test -x "$b" || { echo "missing $b" >&2; exit 1; }
done
sha256sum subfinder dnsx httpx naabu nuclei amass > SHA256SUMS
go version > GO_VERSION
echo "engines built in $out" >&2

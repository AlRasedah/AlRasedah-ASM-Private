# Exteriq ASM sensor worker image.
#
# Third-party reconnaissance tools are compiled from their upstream sources and
# executed strictly as separate programs by the asm_sensors adapters. This image
# receives jobs from Redis and returns observations; it has NO database access.
#
# Tool versions are build arguments so operators can pin/upgrade independently
# of the platform:  docker compose build --build-arg NUCLEI_VERSION=v3.x.y asm-scanner

ARG GO_IMAGE=golang:1.23-alpine
ARG PYTHON_IMAGE=python:3.12-alpine

FROM ${GO_IMAGE} AS tools
ARG SUBFINDER_VERSION=v2.6.6
ARG DNSX_VERSION=v1.2.1
ARG HTTPX_VERSION=v1.6.8
ARG NAABU_VERSION=v2.3.1
ARG NUCLEI_VERSION=v3.3.2
ARG AMASS_VERSION=v4.2.0
ENV CGO_ENABLED=1 GOTOOLCHAIN=auto GOBIN=/out GOFLAGS=-trimpath
RUN apk add --no-cache build-base libpcap-dev git
RUN go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}
RUN go install -ldflags="-s -w" github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}
RUN go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}
RUN go install -ldflags="-s -w" github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}
RUN go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}
RUN go install -ldflags="-s -w" github.com/owasp-amass/amass/v4/cmd/amass@${AMASS_VERSION}

FROM ${PYTHON_IMAGE}
ARG INSTALL_BBOT=false
# Website screenshots (docs/SCREENSHOTS.md): the distribution Chromium, pinned to an exact
# package version. Off by default; the build refuses an unpinned browser.
ARG INSTALL_SCREENSHOT_BROWSER=false
ARG CHROMIUM_VERSION=
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    PATH=/opt/asm/bin:$PATH \
    ASM_BIN_HTTPX=/opt/asm/bin/httpx \
    ASM_NUCLEI_TEMPLATES_DIR=/data/nuclei-templates \
    ASM_NUCLEI_HOME=/data/nuclei-home \
    HOME=/data/home

RUN apk add --no-cache libpcap ca-certificates tini bind-tools \
 && if [ "$INSTALL_SCREENSHOT_BROWSER" = "true" ]; then \
      if [ -z "$CHROMIUM_VERSION" ]; then \
        echo "set CHROMIUM_VERSION to the exact chromium package version to pin (see: apk policy chromium)" >&2; \
        exit 1; \
      fi; \
      # Alpine keeps only the newest build of a package, so an old pin stops resolving when
      # the repository moves on; say so instead of carrying on without a browser.
      apk add --no-cache "chromium=${CHROMIUM_VERSION}" font-noto font-noto-arabic setpriv \
        || { echo "chromium=${CHROMIUM_VERSION} cannot be installed; the repository offers:" >&2; \
             apk --no-cache policy chromium >&2; \
             echo "set ASM_CHROMIUM_VERSION in .env to that version (docs/DEPLOYMENT.md section 5b)" >&2; \
             exit 1; }; \
      # The package has shipped the binary as chromium and as chromium-browser; the adapter
      # finds either. Fail the build here rather than at the first capture if neither exists.
      command -v chromium >/dev/null || command -v chromium-browser >/dev/null \
        || { echo "chromium was installed but provides neither chromium nor chromium-browser" >&2; exit 1; }; \
      # util-linux setpriv ties the browser to its worker; BusyBox's applet cannot (no --pdeathsig).
      setpriv --help 2>&1 | grep -q -- --pdeathsig \
        || { echo "setpriv without --pdeathsig: the util-linux setpriv package did not replace BusyBox's" >&2; exit 1; }; \
    fi \
 && addgroup -S -g 10002 sensor && adduser -S -D -H -u 10002 -G sensor -h /data/home -s /sbin/nologin sensor

COPY --from=tools /out/ /opt/asm/bin/
COPY workers/ /src/workers/
RUN pip install "/src/workers[worker]" \
 && if [ "$INSTALL_BBOT" = "true" ]; then pip install "bbot>=2"; fi \
 && rm -rf /src \
 && mkdir -p /data/home /data/nuclei-templates /data/nuclei-home \
 && chown -R sensor:sensor /data

COPY docker/scanner/entrypoint.sh /usr/local/bin/sensor-entrypoint
COPY scripts/measure_screenshots.py /opt/asm/measure_screenshots.py
RUN chmod 0755 /usr/local/bin/sensor-entrypoint

USER sensor
ENTRYPOINT ["/sbin/tini", "--", "sensor-entrypoint"]
CMD ["worker"]

# Exteriq ASM platform image: used by asm-api, asm-worker, asm-scheduler and asm-migrate.
# No scanner binaries live in this image; sensors run in the separate asm-scanner image.
FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# WeasyPrint (PDF reports) needs Pango/HarfBuzz; fonts include Arabic coverage.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 libfontconfig1 \
      fonts-dejavu-core fonts-noto-core tini \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 asm && useradd --system --uid 10001 --gid asm --home /app --shell /usr/sbin/nologin asm

WORKDIR /app
COPY workers/ /src/workers/
COPY backend/pyproject.toml /src/backend/pyproject.toml
COPY backend/app /src/backend/app
RUN pip install /src/workers "/src/backend[pdf,s3]" && rm -rf /src

COPY backend/alembic.ini /app/alembic.ini
COPY backend/alembic /app/alembic
COPY docker/backend/entrypoint.sh /usr/local/bin/asm-entrypoint
RUN chmod 0755 /usr/local/bin/asm-entrypoint && mkdir -p /data/storage /data/exports && chown -R asm:asm /data

USER asm
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--", "asm-entrypoint"]
CMD ["api"]

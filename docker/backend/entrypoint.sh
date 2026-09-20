#!/bin/sh
# Exteriq ASM platform entrypoint.
set -eu

role="${1:-api}"
shift || true

case "$role" in
  api)
    # The root filesystem is read-only; gunicorn writes runtime state (e.g. its control
    # socket directory) relative to the working directory, so run it from the tmpfs.
    cd /tmp
    exec gunicorn app.main:app \
      --worker-class uvicorn.workers.UvicornWorker \
      --bind 0.0.0.0:8000 \
      --workers "${ASM_API_WORKERS:-4}" \
      --timeout "${ASM_API_TIMEOUT:-120}" \
      --forwarded-allow-ips "${ASM_FORWARDED_ALLOW_IPS:-*}" \
      --access-logfile - \
      "$@"
    ;;
  worker)
    exec celery -A app.workers.celery_app worker -Q core \
      --concurrency "${ASM_CORE_CONCURRENCY:-4}" --loglevel "${ASM_LOG_LEVEL:-INFO}" \
      --max-tasks-per-child 200 "$@"
    ;;
  ingest)
    # Consumes results.<pool> for every pool in ASM_WORKER_POOLS (default: default).
    exec celery -A app.workers.results:results_app worker \
      --concurrency "${ASM_INGEST_CONCURRENCY:-2}" --loglevel "${ASM_LOG_LEVEL:-INFO}" \
      --without-gossip --without-mingle --hostname "ingest@%h" \
      --max-tasks-per-child 200 "$@"
    ;;
  scheduler)
    exec celery -A app.workers.celery_app beat --loglevel "${ASM_LOG_LEVEL:-INFO}" \
      --schedule /tmp/celerybeat-schedule "$@"
    ;;
  migrate)
    # Advisory preflight: turn the opaque SQLAlchemy stack trace into an actionable
    # hint for the most common first-deploy failure (role password / stale volume).
    # Never blocks — alembic still runs and reports the authoritative result.
    python - <<'PY' || true
import os, sys
try:
    from sqlalchemy import create_engine, text
    with create_engine(os.environ.get("ASM_DATABASE_URL", ""), pool_pre_ping=True).connect() as c:
        c.execute(text("select 1"))
except Exception as exc:  # noqa: BLE001
    if "authentication failed" in str(exc).lower():
        sys.stderr.write(
            "\n[asm] Cannot authenticate to PostgreSQL as the application role.\n"
            "      The database volume was almost certainly initialised with a different\n"
            "      ASM_DB_PASSWORD than the one in .env now (the role password is only set on\n"
            "      first init of the volume). Fix with one of:\n"
            "        fresh deploy (no data to keep):  docker compose down -v && docker compose up -d\n"
            "        keep existing data:              docker compose exec postgres \\\n"
            "          psql -U postgres -c \"ALTER ROLE asm PASSWORD '<ASM_DB_PASSWORD from .env>';\"\n\n")
PY
    alembic -c /app/alembic.ini upgrade head
    exec python -m app.cli bootstrap
    ;;
  cli)
    exec python -m app.cli "$@"
    ;;
  *)
    exec "$role" "$@"
    ;;
esac

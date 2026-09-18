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
  scheduler)
    exec celery -A app.workers.celery_app beat --loglevel "${ASM_LOG_LEVEL:-INFO}" \
      --schedule /tmp/celerybeat-schedule "$@"
    ;;
  migrate)
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

#!/bin/sh
# Exteriq ASM sensor worker entrypoint.
set -eu

role="${1:-worker}"
shift || true

update_templates() {
  # Detection templates live on a volume so they can be updated without rebuilding.
  if [ "${ASM_NUCLEI_AUTO_UPDATE:-true}" = "true" ] || [ -z "$(ls -A "$ASM_NUCLEI_TEMPLATES_DIR" 2>/dev/null)" ]; then
    # Same HOME as the adapter uses at scan time, so nuclei sees templates as installed.
    HOME="$ASM_NUCLEI_HOME" nuclei -update-templates -ud "$ASM_NUCLEI_TEMPLATES_DIR" -duc -silent || \
      echo "warning: could not update detection templates (offline?); using the existing set" >&2
  fi
}

case "$role" in
  worker)
    update_templates
    # One container serves exactly one worker pool (ASM_SENSOR_POOL): its broker
    # user, queue and key are all per pool. Gossip/mingle/heartbeats are off because
    # a pool's broker user may only use its own pool's control channel.
    exec celery -A asm_sensors.worker worker \
      -Q "scanners.${ASM_SENSOR_POOL:-default}" \
      --concurrency "${ASM_SENSOR_CONCURRENCY:-2}" \
      --loglevel "${ASM_LOG_LEVEL:-INFO}" \
      --without-gossip --without-mingle --without-heartbeat \
      --hostname "sensor-${ASM_SENSOR_POOL:-default}@%h" "$@"
    ;;
  update-templates)
    update_templates
    ;;
  versions)
    for b in subfinder dnsx httpx naabu nuclei; do printf '%s: ' "$b"; "$b" -version 2>&1 | tail -n 1; done
    printf 'amass: '; amass -version 2>&1 | tail -n 1
    browser="${ASM_BIN_CHROMIUM:-$(command -v chromium || command -v chromium-browser || true)}"
    if [ -n "$browser" ] && [ -x "$browser" ]; then
      printf 'screenshot browser: '; "$browser" --version 2>&1 | tail -n 1
    else
      echo "screenshot browser: not installed"
    fi
    ;;
  browser-selftest)
    # Website screenshots: can this container start the pinned browser with its sandbox?
    # Prints JSON and exits non-zero when not. Needs no network.
    exec python -m asm_sensors.adapters.screenshot
    ;;
  *)
    exec "$role" "$@"
    ;;
esac

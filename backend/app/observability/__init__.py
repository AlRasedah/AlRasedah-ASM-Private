"""Operational observability: structured events, correlation, exports, diagnostics.

* :mod:`asm_sensors.eventlog` — the event schema, redaction and non-blocking writer
  shared with the scanners.
* :mod:`app.observability.setup` — per-process logging configuration.
* :mod:`app.observability.celery_hooks` — correlation across Celery tasks.
* :mod:`app.observability.codes` — stable error codes.
* :mod:`app.observability.export` — finding-lifecycle (alerts) and audit event exports.
* :mod:`app.observability.opsdb` — recent operational warnings/errors kept for the UI.
* :mod:`app.observability.health` — service heartbeats and health collection.
"""

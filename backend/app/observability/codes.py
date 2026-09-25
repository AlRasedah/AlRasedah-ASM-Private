"""Stable error codes for operational events (docs/LOGGING.md lists them).

Codes are part of the log schema: they never change meaning, so alerting rules and
support procedures can rely on them. Add new codes; never reuse or rename one.
"""

from __future__ import annotations

# Scans
SCAN_STAGE_FAILED = "ASM-SCAN-001"  # a required stage failed
SCAN_STAGE_PARTIAL = "ASM-SCAN-002"  # the stage ran but could not vouch for complete coverage
SCAN_STAGE_TIMEOUT = "ASM-SCAN-003"  # the stage hit its time limit
SCAN_STAGE_LOST = "ASM-SCAN-004"  # the watchdog failed a stage whose job never reported back
SCAN_DISPATCH_FAILED = "ASM-SCAN-005"  # the job could not be published to the scanner queue
SCAN_RESULT_REJECTED = "ASM-SCAN-006"  # a submitted result failed authentication or binding
SCAN_OUTPUT_REJECTED = "ASM-SCAN-007"  # stage output failed authentication or binding
SCAN_SKIPPED_OPTIONAL = "ASM-SCAN-008"  # an optional stage failed and was skipped

# Scanners
SCANNER_JOB_EXPIRED = "ASM-SCNR-001"  # a job arrived after its start deadline
SCANNER_BINARY_MISSING = "ASM-SCNR-002"
SCANNER_DETECTION_CONTENT_MISSING = "ASM-SCNR-003"
SCANNER_JOB_FAILED = "ASM-SCNR-004"

# Platform
EXPORT_FAILED = "ASM-OPS-001"  # alerts/audit export could not complete a batch
OPS_SINK_DROPPED = "ASM-OPS-002"  # operational events could not be stored for the UI
LOG_EVENTS_DROPPED = "ASM-OPS-003"  # the log writer dropped events (queue full / stdout broken)
BUNDLE_FAILED = "ASM-OPS-004"  # support bundle generation failed
DB_UNAVAILABLE = "ASM-OPS-005"
BROKER_UNAVAILABLE = "ASM-OPS-006"
NOTIFICATION_FAILED = "ASM-NTF-001"
INTEL_FEED_FAILED = "ASM-INT-001"

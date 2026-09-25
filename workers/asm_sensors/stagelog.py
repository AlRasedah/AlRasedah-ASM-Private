"""A stage's verbose output, safe to show to the tenant who ran the scan.

Every engine runs in verbose mode; its diagnostic stream (never its results, which go
to files) is read line by line while it runs. Each line is cleaned *here, in the
scanner*, before it leaves: engine and project names, version banners, ASCII-art
banners, installation paths, credentials and anything that looks like a secret are
removed or replaced. The platform runs the same cleaning again on arrival.

The log is bounded whatever the engine prints: the first ``HEAD`` lines are kept,
then the last ``TAIL`` lines, with a count of what was left out in between. Chunks
are handed to a sink every few seconds, so the scan page shows progress live.

Lines are ``[seconds since the stage started, level, text]``.
"""

from __future__ import annotations

import re
import time
from collections import deque
from collections.abc import Callable, Iterable
from contextvars import ContextVar
from typing import Any

from .logs import redact

HEAD = 2000
TAIL = 2000
MAX_LINE = 1000
CHUNK_LINES = 400
LIVE_TAIL = 200  # while running, the latest lines only; the full tail comes with the final chunk
FLUSH_SECONDS = 5.0

# Engines, the projects behind them and their content sets: never shown (ADR-022).
ENGINE_NAMES = ("nuclei", "subfinder", "amass", "dnsx", "httpx", "naabu", "zaproxy", "zap", "spiderfoot", "bbot",
                "shodan", "asnlookup", "crtsh", "crt.sh", "projectdiscovery", "owasp", "katana", "interactsh",
                "wappalyzer", "retryablehttp", "fastdialer")
_REWRITES = [
    (re.compile(r"\x1b\[[0-9;]*[A-Za-z]"), ""),  # colour codes
    (re.compile(r"https?://\S*(projectdiscovery|owasp|zaproxy|github\.com/owasp-amass)\S*", re.I), "[link removed]"),
    (re.compile(r"\S*/nuclei-templates\S*|nuclei-templates", re.I), "the detection set"),
    (re.compile(r"(/opt/asm/bin|/data/nuclei-home|/data/home|/usr/(local/)?(s?bin|lib))/\S*"), "[path]"),
    (re.compile(r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\s*[:=]\s*\S.*"),
     r"\1: [redacted]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]{8,}"), r"\1 [redacted]"),
]
_ENGINES = re.compile("|".join(re.escape(n) for n in sorted(ENGINE_NAMES, key=len, reverse=True)), re.I)
# Version announcements fingerprint the engine even without its name.
_VERSION = re.compile(r"\bversion\b|\bv\d+\.\d+(\.\d+)?\b|\blatest release\b|\bupdate available\b|\boutdated\b", re.I)
# A line that is nothing but a vendor's name or site (banner footer).
_VENDOR_ONLY = re.compile(r"^\S*(projectdiscovery|owasp|zaproxy)\S*$", re.I)
_LEVEL = re.compile(r"^\s*\[(INF|INFO|WRN|WARN|ERR|ERROR|FTL|FATAL|VER|DBG|DEBUG)\]\s*", re.I)
_LEVELS = {"inf": "info", "info": "info", "wrn": "warning", "warn": "warning", "err": "error", "error": "error",
           "ftl": "error", "fatal": "error", "ver": "debug", "dbg": "debug", "debug": "debug"}


def _is_art(text: str) -> bool:
    """Banner art: mostly punctuation, few letters."""
    chars = [c for c in text if not c.isspace()]
    return len(chars) >= 8 and sum(c.isalnum() for c in chars) < len(chars) * 0.4


def clean(line: str, secrets: Iterable[str] = ()) -> tuple[str, str] | None:
    """One raw line → (level, safe text), or None when it must not be shown at all."""
    text = line.replace("\r", "").rstrip()
    for pattern, repl in _REWRITES:
        text = pattern.sub(repl, text)
    level = "info"
    m = _LEVEL.match(text)
    if m:
        level = _LEVELS[m.group(1).lower()]
        text = text[m.end():]
    for s in secrets:
        if s and len(s) >= 4:
            text = text.replace(s, "[redacted]")
    text = redact(text).strip()
    if not text or _is_art(text) or _VERSION.search(text) or _VENDOR_ONLY.match(text):
        return None
    text = _ENGINES.sub("engine", text)
    return level, text[:MAX_LINE]


class StageLog:
    """Bounded, cleaned verbose output of one stage, handed out as chunks."""

    def __init__(self, secrets: Iterable[str] = (), clock: Callable[[], float] = time.monotonic) -> None:
        self.secrets = [s for s in secrets if s]
        self.clock = clock
        self.started = clock()
        self.total = 0  # lines kept or counted (after cleaning)
        self.head: list[list[Any]] = []
        self.tail: deque[list[Any]] = deque(maxlen=TAIL)
        self.sent_head = 0
        self.seq = 0
        self.tail_dirty = False

    def add(self, raw: str, level: str | None = None) -> None:
        for part in str(raw).splitlines() or [""]:
            cleaned = clean(part, self.secrets)
            if cleaned is None:
                continue
            lvl, text = cleaned
            entry = [round(self.clock() - self.started, 1), level or lvl, text]
            self.total += 1
            if len(self.head) < HEAD:
                self.head.append(entry)
            else:
                self.tail.append(entry)
                self.tail_dirty = True

    def info(self, text: str) -> None:
        self.add(text, "info")

    def warning(self, text: str) -> None:
        self.add(text, "warning")

    @property
    def omitted(self) -> int:
        return max(0, self.total - len(self.head) - len(self.tail))

    def chunk(self, final: bool = False) -> dict[str, Any] | None:
        """What has not been handed out yet; None when there is nothing new."""
        new_head = self.head[self.sent_head:self.sent_head + CHUNK_LINES]
        if not new_head and not self.tail_dirty and not final:
            return None
        self.sent_head += len(new_head)
        self.seq += 1
        out: dict[str, Any] = {"seq": self.seq, "head": new_head, "total": self.total, "omitted": self.omitted,
                               "final": final and self.sent_head >= len(self.head)}
        if self.tail_dirty or final:
            out["tail"] = list(self.tail) if final else list(self.tail)[-LIVE_TAIL:]
            self.tail_dirty = False
        return out

    def chunks(self, final: bool = False) -> list[dict[str, Any]]:
        out = []
        while (c := self.chunk(final)) is not None:
            out.append(c)
            if c["final"] or (not final and not c["head"]):
                break
        return out


CURRENT: ContextVar[StageLog | None] = ContextVar("asm_stage_log", default=None)


def current() -> StageLog | None:
    return CURRENT.get()


def note(text: str, level: str | None = None) -> None:
    """For adapters: add a line to the running stage's output, if there is one. The level
    defaults to the line's own ``[INF]``/``[WRN]``/... prefix, or info."""
    log = CURRENT.get()
    if log is not None:
        log.add(text, level)

"""Deterministic version comparison for advisory ranges.

Deliberately simple and explainable, because an analyst has to be able to
predict the result by reading the evidence:

* a version is split into numeric and alphabetic tokens (``2.4.58-1ubuntu`` →
  ``2, 4, 58, 1, "ubuntu"``); anything else is a separator;
* numbers compare as numbers, words as words, and a number outranks a word at
  the same position — so ``1.0`` > ``1.0rc1`` and ``1.0.1`` > ``1.0a``;
* missing trailing positions count as ``0``;
* a value that does not start with a number (``latest``, ``unknown``, empty) is
  *unparseable*, which the matcher reports as "version unknown" rather than
  guessing.

What this cannot know: distribution back-ports (a vendor may ship ``2.4.6`` with
the fix applied) and banners that lie. That is why a version match is only ever
"potentially affected", never "confirmed".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_TOKEN = re.compile(r"\d+|[a-z]+")
_MAX_TOKENS = 12


class UnparseableVersion(ValueError):
    pass


@total_ordering
@dataclass(frozen=True)
class Version:
    raw: str
    tokens: tuple[int | str, ...]

    @classmethod
    def parse(cls, value: str | None) -> Version:
        text = (value or "").strip().lower()
        if text.startswith("v") and text[1:2].isdigit():
            text = text[1:]
        tokens = _TOKEN.findall(text[:64])
        if not text[:1].isdigit() or not tokens:
            raise UnparseableVersion(value or "")
        return cls(value or "", tuple(int(t) if t.isdigit() else t for t in tokens[:_MAX_TOKENS]))

    def _cmp(self, other: Version) -> int:
        a, b = self.tokens, other.tokens
        for i in range(max(len(a), len(b))):
            x = a[i] if i < len(a) else 0
            y = b[i] if i < len(b) else 0
            if x == y:
                continue
            if isinstance(x, int) and isinstance(y, int):
                return -1 if x < y else 1
            if isinstance(x, str) and isinstance(y, str):
                return -1 if x < y else 1
            return 1 if isinstance(x, int) else -1  # a number outranks a word
        return 0

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self._cmp(other) == 0

    def __lt__(self, other: Version) -> bool:
        return self._cmp(other) < 0

    def __hash__(self) -> int:
        return hash(self.tokens)


def in_range(version: Version, *, introduced: str | None, fixed: str | None, last_affected: str | None) -> bool:
    """OSV-style range: ``introduced <= v``, ``v < fixed``, ``v <= last_affected`` (each optional)."""
    if introduced and version < Version.parse(introduced):
        return False
    if fixed and not version < Version.parse(fixed):
        return False
    return not (last_affected and Version.parse(last_affected) < version)

"""Stands in for Chromium in the screenshot tests.

It honours the flags the adapter relies on — it can only reach the network through
``--proxy-server``, writes a PNG of ``--window-size`` to ``--screenshot`` — and
behaves like a page load: it fetches the page, then every ``src``/``href`` in it
(frames, scripts, images, links a page script might follow). Markers in the page
body select a failure mode. It records what it did in its working directory.
"""

from __future__ import annotations

import json
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.request
import zlib
from pathlib import Path


def png(width: int, height: int, padding: int = 0) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + b"\x20" * (width * 3) for _ in range(height))
    body = chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9))
    if padding:
        body += chunk(b"tEXt", b"pad\x00" + b"x" * padding)
    return b"\x89PNG\r\n\x1a\n" + body + chunk(b"IEND", b"")


def main() -> int:
    args = sys.argv[1:]
    opt = {a.split("=", 1)[0]: (a.split("=", 1)[1] if "=" in a else "") for a in args if a.startswith("--")}
    url = [a for a in args if not a.startswith("--")][-1]
    here = Path.cwd()
    (here / "fake-browser.pid").write_text(str(os.getpid()))
    (here / "fake-browser.argv").write_text(json.dumps(args))
    proxy = opt["--proxy-server"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))

    def get(u: str) -> tuple[int | None, bytes]:
        try:
            with opener.open(u, timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception:  # noqa: BLE001
            return None, b""

    status, body = get(url)
    text = body.decode("utf-8", "replace")
    fetched = [[m.group(1), get(m.group(1))[0]] for m in re.finditer(r'(?:src|href)="([^"]+)"', text)]
    (here / "fake-browser.fetched").write_text(json.dumps({"page": status, "resources": fetched}))
    if "fake:sandbox" in text:
        sys.stderr.write("[0923/120000.000000:FATAL:zygote_host_impl_linux.cc(128)] No usable sandbox!\n")
        return 1
    if "fake:hang" in text:
        time.sleep(600)
    if "fake:noimage" in text:
        return 0
    width, height = map(int, opt["--window-size"].split(","))
    out = Path(opt["--screenshot"])
    if "fake:notpng" in text:
        out.write_bytes(b"GIF89a" + b"\x00" * 64)
    elif "fake:big" in text:
        out.write_bytes(png(width, height, padding=200_000))
    elif "fake:giant" in text:
        out.write_bytes(png(width * 3, height * 3))
    else:
        out.write_bytes(png(width, height))
    return 0


if __name__ == "__main__":
    sys.exit(main())

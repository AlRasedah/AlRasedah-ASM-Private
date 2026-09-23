#!/usr/bin/env python3
"""Derive the scanner's seccomp profile for website screenshots from Docker's default.

Chromium's sandbox creates unprivileged user (and PID/network) namespaces and
chroots into them. Docker's default seccomp profile allows ``clone``/``unshare``
with namespace flags, ``setns`` and ``chroot`` only to containers that have
CAP_SYS_ADMIN / CAP_SYS_CHROOT — which the scanner deliberately does not. Rather
than disabling seccomp or the browser sandbox (``--no-sandbox``), this adds exactly
those syscalls to *your engine's* default profile and changes nothing else.

    # the default profile for your Docker version, from the moby repository:
    #   Docker 29+:  https://raw.githubusercontent.com/moby/moby/docker-v<version>/vendor/github.com/moby/profiles/seccomp/default.json
    #   Docker ≤ 28: https://raw.githubusercontent.com/moby/moby/v<version>/profiles/seccomp/default.json
    # (DEPLOYMENT.md §5b has a command that picks the right one.)
    python scripts/make_browser_seccomp.py default.json > docker/scanner/seccomp-browser.json

The host kernel must allow unprivileged user namespaces
(``sysctl kernel.unprivileged_userns_clone`` = 1 on Debian-family kernels; on
Ubuntu 23.10+ also ``kernel.apparmor_restrict_unprivileged_userns`` = 0 or an
AppArmor profile for the browser). Then verify inside the container with
``docker compose ... run --rm asm-scanner browser-selftest``.
"""

from __future__ import annotations

import json
import sys

SANDBOX_SYSCALLS = ["clone", "unshare", "setns", "chroot"]


def derive(profile: dict) -> dict:
    if profile.get("defaultAction") not in ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS"):
        raise ValueError("expected a default-deny profile (Docker's default.json)")
    out = json.loads(json.dumps(profile))
    out.setdefault("syscalls", []).append({
        "names": SANDBOX_SYSCALLS,
        "action": "SCMP_ACT_ALLOW",
        "comment": "Chromium's namespace sandbox (Exteriq ASM website screenshots)",
    })
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        profile = json.load(fh)
    json.dump(derive(profile), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

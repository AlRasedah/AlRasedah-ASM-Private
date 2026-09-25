#!/usr/bin/python3
"""End-to-end check of a native install through its public API, on a DISPOSABLE test host.

Scans only a local fixture: a static HTTP server on a loopback alias (127.0.0.2:18081) that
this script starts. It enables lab mode (non-public targets) for the duration of the run and
restores the configuration afterwards. Creates synthetic tenants/users on the test host.

    sudo python3 packaging/tests/native-fixture-scan.py

Checks: first-run setup link (single use), sign-in, organization/scope/profile, a scan through
queue -> scanner -> ingestion with stage timing, tenant and platform diagnostics (native unit
data), tenant/platform support bundles (contents, no secrets), cross-tenant denial, log streams.
"""

from __future__ import annotations

import io
import json
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

INSTALL = json.loads(Path("/etc/exteriq/install.json").read_text())
BASE = f"https://127.0.0.1:{INSTALL['https_port']}/api/v1"
HOST = INSTALL["hostname"]
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # the test host's self-signed certificate
RUN = str(int(time.time()))
PASSWORD = "Fixture-Passw0rd-" + RUN
ENV = Path("/etc/exteriq/exteriq.env")
SCANNER_ENV = Path("/etc/exteriq/scanner/default.env")
failures: list[str] = []


def result(ok: bool, name: str, detail: str = "") -> None:
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail and not ok else ""), flush=True)
    if not ok:
        failures.append(name)


def api(method: str, path: str, token: str | None = None, body: object = None, raw: bool = False,
        expect: int | None = None):
    headers = {"Host": HOST}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            status, payload = r.status, r.read()
    except urllib.error.HTTPError as exc:
        status, payload = exc.code, exc.read()
    if expect is not None and status != expect:
        raise AssertionError(f"{method} {path} -> {status}, expected {expect}: {payload[:300]!r}")
    if raw:
        return status, payload
    return status, (json.loads(payload) if payload and payload[:1] in b"[{" else None)


def sh(*cmd: str, check: bool = True) -> str:
    return subprocess.run(cmd, check=check, capture_output=True, text=True).stdout


ORIGINAL: dict[tuple[Path, str], str | None] = {}


def _put(path: Path, key: str, value: str | None) -> None:
    text = re.sub(rf"^{key}=.*\n", "", path.read_text(), flags=re.M)
    path.write_text(text + (f"{key}={value}\n" if value is not None else ""))


def set_env(path: Path, key: str, value: str) -> None:
    """Change one key, remembering its original value; restore_env() puts back only these keys,
    so configuration changed meanwhile by exteriqctl (pools) is kept."""
    if (path, key) not in ORIGINAL:
        m = re.search(rf"^{key}=(.*)$", path.read_text(), flags=re.M)
        ORIGINAL[(path, key)] = m.group(1) if m else None
    _put(path, key, value)


def restore_env() -> None:
    for (path, key), value in ORIGINAL.items():
        if path.exists():
            _put(path, key, value)


def main() -> int:
    fixture = Path("/tmp/exteriq-fixture")
    try:
        # ------------------------------------------------------------ fixture + lab mode
        shutil.rmtree(fixture, ignore_errors=True)
        fixture.mkdir()
        (fixture / "index.html").write_text("<html><head><title>Exteriq fixture</title></head>"
                                            "<body>controlled test fixture</body></html>")
        sh("systemd-run", "--unit", "exteriq-fixture", "--collect", "-p", "DynamicUser=yes", "--working-directory",
           str(fixture), "/usr/bin/python3", "-m", "http.server", "18081", "--bind", "127.0.0.2", check=False)
        set_env(ENV, "ASM_ALLOW_NON_PUBLIC_SCOPE", "true")
        sh("systemctl", "restart", "exteriq-api", "exteriq-worker", "exteriq-ingest")
        for _ in range(60):
            if api("GET", "/health")[0] == 200:
                break
            time.sleep(2)

        # ------------------------------------------------------------ setup link
        status, needed = api("GET", "/setup")
        admin_email = "admin@example.org"
        if needed and needed.get("needed"):
            out = sh("exteriqctl", "setup-link")
            token = re.search(r"#token=([A-Za-z0-9_-]+)", out).group(1)
            body = {"token": token, "email": admin_email, "password": PASSWORD, "full_name": "Fixture Admin",
                    "tenant_name": "Fixture Tenant A"}
            st, r = api("POST", "/setup", body=body)
            result(st == 201, "setup link creates the first administrator", f"{st} {r}")
            st, r = api("POST", "/setup", body={**body, "email": "second@example.org"})
            result(st in (403, 409), "setup link works only once", f"{st} {r}")
        else:
            print("note: setup already completed on this host; re-using the fixture administrator")
            PASSWORD_FILE = Path("/root/.exteriq-fixture-password")
            globals()["PASSWORD"] = PASSWORD_FILE.read_text().strip()
        Path("/root/.exteriq-fixture-password").write_text(PASSWORD)
        Path("/root/.exteriq-fixture-password").chmod(0o600)
        _, tok = api("POST", "/auth/login", body={"email": admin_email, "password": PASSWORD}, expect=200)
        admin = tok["access_token"]
        _, me = api("GET", "/auth/me", admin, expect=200)
        tenant_a = me["tenant"]["id"]
        # Per-tenant scanner isolation: the new tenant's pool needs a scanner before it can scan.
        out = subprocess.run(["exteriqctl", "sync-pools"], capture_output=True, text=True)
        result(out.returncode == 0, "exteriqctl sync-pools provisions the tenant's scanner pool",
               out.stdout[-400:] + out.stderr[-400:])
        # Lab mode for every scanner pool on this test host (restored at the end).
        for f in sorted(SCANNER_ENV.parent.glob("*.env")):
            set_env(f, "ASM_SCANNER_ALLOW_NON_PUBLIC", "true")
            set_env(f, "ASM_NUCLEI_AUTO_UPDATE", "false")
            sh("systemctl", "restart", f"exteriq-scanner@{f.stem}")
        for _ in range(60):
            if api("GET", "/health")[0] == 200:
                break
            time.sleep(2)

        # ------------------------------------------------------------ platform health (native)
        _, health = api("GET", "/diagnostics/platform/health", admin, expect=200)
        units = health.get("units", {})
        result(isinstance(units, dict) and units.get("exteriq-api", {}).get("active") == "active",
               "platform health reports systemd units on a native install", json.dumps(units)[:300])
        result(all(s.get("status") == "ok" for s in health["services"].values()),
               "all platform services report heartbeats", json.dumps(health["services"])[:300])
        result(health["scanners"].get("default", {}).get("status") in ("ok", "degraded"),
               "scanner pool default reports", json.dumps(health["scanners"])[:300])
        result(health["database"].get("schema_version") == health["database"].get("expected_schema"),
               "schema matches the release")

        # ------------------------------------------------------------ org, scope, profile, scan
        _, org = api("POST", "/organizations", admin, {"name": f"Fixture Org {RUN}"}, expect=201)
        api("POST", "/scopes", admin, {"organization_id": org["id"], "entry_type": "ip", "value": "127.0.0.2",
                                       "allow_active_scanning": True}, expect=201)
        stages = [
            {"stage": "port_discovery", "engine": "naabu", "config": {"port_set": "custom", "custom_ports": "18081"}},
            {"stage": "http_discovery", "engine": "httpx", "config": {}},
        ]
        _, prof = api("POST", "/scan-profiles", admin, {"name": f"Fixture profile {RUN}", "stages": stages}, expect=201)
        _, scan = api("POST", "/scans", admin, {"organization_id": org["id"], "profile_id": prof["id"],
                                               "targets": ["127.0.0.2"]}, expect=201)
        deadline = time.time() + 900
        while time.time() < deadline:
            _, scan = api("GET", f"/scans/{scan['id']}", admin, expect=200)
            if scan["status"] in ("completed", "partial", "failed", "cancelled"):
                break
            time.sleep(5)
        stage_summary = [(s.get("label"), s.get("status")) for s in scan.get("stages", [])]
        result(scan["status"] == "completed", "fixture scan completes", f"{scan['status']} {stage_summary}")
        _, timelines = api("GET", "/diagnostics/tenant/scans", admin, expect=200)
        st = next(s for s in timelines["items"] if s["id"] == scan["id"])
        timing = [s["timing"] for s in st["stages"]]
        result(all(t and t.get("queue_wait_ms") is not None and t.get("execution_ms") is not None
                   and t.get("ingestion_ms") is not None for t in timing),
               "each stage records queue wait, run time and ingestion", json.dumps(timing)[:300])
        _, assets = api("GET", "/assets?q=127.0.0.2", admin)
        result(bool(assets and assets.get("total")), "scan results were ingested (asset stored)")

        # ------------------------------------------------------------ support bundles
        secrets = set(re.findall(r"[A-Za-z0-9_-]{24,}", "".join(f.read_text() for f in [ENV, *SCANNER_ENV.parent.glob("*.env")])))

        def bundle(scope: str, scan_ids: list[str]) -> tuple[dict, bytes]:
            q = f"?scope={scope}"
            _, prev = api("POST", "/diagnostics/bundles/preview", admin, {"scope": scope, "scan_ids": scan_ids},
                          expect=200)
            assert "database dumps" in prev["excluded"]
            _, b = api("POST", "/diagnostics/bundles", admin, {"scope": scope, "scan_ids": scan_ids}, expect=202)
            for _ in range(60):
                _, b = api("GET", f"/diagnostics/bundles/{b['id']}{q}", admin, expect=200)
                if b["status"] in ("ready", "failed"):
                    break
                time.sleep(2)
            assert b["status"] == "ready", b
            _, data = api("GET", f"/diagnostics/bundles/{b['id']}/download{q}", admin, raw=True, expect=200)
            return b, data

        b, data = bundle("tenant", [scan["id"]])
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        text = b"".join(zipfile.ZipFile(io.BytesIO(data)).read(n) for n in names).decode(errors="replace")
        result("manifest.json" in names and any(n.startswith("stage-output/") for n in names),
               "tenant bundle has manifest and the selected scan's stage output", str(names))
        result(not any(s in text for s in secrets), "tenant bundle contains no secret from /etc/exteriq")
        result(not re.search(r"\b(naabu|httpx|nuclei|subfinder|dnsx|amass)\b", text, re.I),
               "tenant bundle does not name the engines")
        pb, pdata = bundle("platform", [])
        ptext = b"".join(zipfile.ZipFile(io.BytesIO(pdata)).read(n)
                         for n in zipfile.ZipFile(io.BytesIO(pdata)).namelist()).decode(errors="replace")
        result(not any(s in ptext for s in secrets), "platform bundle contains no secret from /etc/exteriq")

        # ------------------------------------------------------------ cross-tenant denial
        _, t2 = api("POST", "/tenants", admin, {"name": f"Fixture Tenant B {int(time.time())}"}, expect=201)
        tenant_b = (t2.get("tenant") or t2)["id"]
        _, switched = api("POST", "/auth/switch-tenant", admin, {"tenant_id": tenant_b}, expect=200)
        other = switched["access_token"]
        result(api("GET", f"/diagnostics/bundles/{b['id']}", other)[0] == 404,
               "tenant B cannot see tenant A's bundle")
        result(api("GET", f"/diagnostics/bundles/{b['id']}/download", other)[0] == 404,
               "tenant B cannot download tenant A's bundle")
        result(api("DELETE", f"/diagnostics/bundles/{b['id']}", other)[0] == 404,
               "tenant B cannot delete tenant A's bundle")
        _, tb_scans = api("GET", "/diagnostics/tenant/scans", other, expect=200)
        result(not any(s["id"] == scan["id"] for s in tb_scans["items"]), "tenant B does not see tenant A's scans")
        result(api("GET", f"/scans/{scan['id']}", other)[0] == 404, "tenant B cannot open tenant A's scan")
        _, tb_events = api("GET", "/diagnostics/tenant/events", other, expect=200)
        result(tenant_a not in json.dumps(tb_events), "tenant B's events carry nothing of tenant A")

        # ------------------------------------------------------------ logs
        time.sleep(5)
        scans_log = [json.loads(line) for line in open("/var/log/exteriq/scans.json") if scan["id"] in line]
        finished = [e for e in scans_log if e.get("event") == "scan.stage.finished"]
        result(bool(finished) and all(e.get("tenant_id") == tenant_a for e in finished),
               "scans.json has the scan's stage events with its tenant", f"{len(scans_log)} lines")
        pool = f"t-{me['tenant']['slug']}"
        result(any(e.get("event") == "scanner.job.finished" and e.get("pool") == pool
                   and e.get("tenant_id") == tenant_a for e in scans_log),
               "scanner events carry the scan, its tenant and the tenant's own pool",
               json.dumps([e for e in scans_log if e.get("service") == "scanner"])[:400])
        deadline = time.time() + 150  # the export runs every minute
        audit_hit = False
        audit = Path("/var/log/exteriq/audit.json")
        while time.time() < deadline and not audit_hit:
            audit_hit = audit.exists() and "support_bundle" in audit.read_text()
            time.sleep(5)
        result(audit_hit, "audit.json receives the audit export (support bundle actions)")
    finally:
        restore_env()
        subprocess.run(["systemctl", "stop", "exteriq-fixture"], check=False, capture_output=True)
        subprocess.run(["systemctl", "restart", "exteriq-api", "exteriq-worker", "exteriq-ingest",
                        *(f"exteriq-scanner@{f.stem}" for f in SCANNER_ENV.parent.glob("*.env"))], check=False)
        shutil.rmtree(fixture, ignore_errors=True)
    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

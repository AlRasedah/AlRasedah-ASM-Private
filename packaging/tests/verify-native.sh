#!/bin/bash
# Verify a native Exteriq installation on a disposable test host (run as root).
#
#   packaging/tests/verify-native.sh          (pools: POOLS="a b", default: all in install.json)
#
# Read-only except for: one log probe unit, a synthetic setup/login when setup is still open
# (creates the first administrator on a TEST host), and nothing else. Prints PASS/FAIL per
# check and exits non-zero if anything failed. Never run it against a production host.
set -u
pools=${POOLS:-$(python3 -c 'import json; print(" ".join(json.load(open("/etc/exteriq/install.json"))["pools"]))')}
fails=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
not() { ! "$@"; }
env_get() { sed -n "s/^$2=//p" "$1"; }

host=$(python3 -c 'import json; print(json.load(open("/etc/exteriq/install.json"))["hostname"])')
https=$(python3 -c 'import json; print(json.load(open("/etc/exteriq/install.json"))["https_port"])')

echo "== units"
for u in exteriq-valkey exteriq-api exteriq-worker exteriq-ingest exteriq-scheduler nginx postgresql rsyslog; do
  check "$u active" systemctl is-active --quiet "$u"
done
for p in $pools; do check "exteriq-scanner@$p active" systemctl is-active --quiet "exteriq-scanner@$p"; done
check "exteriq-logrotate.timer enabled" systemctl is-enabled --quiet exteriq-logrotate.timer
check "exteriq.target enabled (starts at boot)" systemctl is-enabled --quiet exteriq.target

echo "== private listeners"
listen() { ss -Hltn "sport = :$1" | awk '{print $4}' | sed 's/:[0-9]*$//' | sort -u | tr '\n' ' '; }
[ "$(listen 8000)" = "127.0.0.1 " ] && pass "API only on 127.0.0.1:8000" || fail "API listens on: $(listen 8000)"
case "$(listen 6380)" in "127.0.0.1 [::1] "|"127.0.0.1 "|"[::1] 127.0.0.1 ") pass "broker only on loopback:6380" ;; *) fail "broker listens on: $(listen 6380)" ;; esac
for a in $(listen 5432); do case $a in 127.0.0.1|"[::1]") ;; *) fail "PostgreSQL listens on $a";; esac; done
pass "PostgreSQL listeners: $(listen 5432)"

echo "== files and permissions"
perm() { [ "$(stat -c '%U:%G %a' "$1")" = "$2" ] && pass "$1 is $2" || fail "$1 is $(stat -c '%U:%G %a' "$1"), want $2"; }
perm /etc/exteriq/exteriq.env "root:exteriq 640"
perm /etc/exteriq/scanner "root:exteriq-scanner 750"
for p in $pools; do perm "/etc/exteriq/scanner/$p.env" "root:exteriq-scanner 640"; done
perm /etc/exteriq/valkey-users.acl "root:exteriq-valkey 640"
perm /etc/exteriq/tls/tls.key "root:root 600"
perm /var/lib/exteriq/storage "exteriq:exteriq 750"
perm /var/lib/exteriq/backups "root:root 700"
perm /var/log/exteriq "syslog:adm 750"
check "no plain passwords in the ACL file" not grep -q '>' /etc/exteriq/valkey-users.acl
for p in $pools; do
  check "scanner $p env has no database credentials" not grep -q ASM_DATABASE_URL "/etc/exteriq/scanner/$p.env"
done

echo "== account separation"
check "scanner account cannot read platform secrets" not runuser -u exteriq-scanner -- cat /etc/exteriq/exteriq.env
check "platform account cannot read scanner keys" not runuser -u exteriq -- cat "/etc/exteriq/scanner/${pools%% *}.env"
check "scanner account has no database login" not runuser -u exteriq-scanner -- psql -X -h /run/postgresql -d exteriq -c 'select 1'
spid=$(systemctl show -p MainPID --value "exteriq-scanner@${pools%% *}")
apid=$(systemctl show -p MainPID --value exteriq-api)
# InaccessiblePaths= replaces the path with an empty mode-000 node inside the unit's mount
# namespace (so even a misconfigured file mode would not expose it).
hidden() { [ "$(nsenter -t "$1" -m -- stat -c %a "$2" 2>/dev/null)" = 0 ]; }
check "inside the scanner sandbox: platform config inaccessible" hidden "$spid" /etc/exteriq/exteriq.env
check "inside the scanner sandbox: stored data inaccessible" hidden "$spid" /var/lib/exteriq/storage
check "inside the scanner sandbox: database socket dir inaccessible" hidden "$spid" /run/postgresql
check "inside the scanner sandbox: logs inaccessible" hidden "$spid" /var/log/exteriq
check "inside the API sandbox: scanner keys inaccessible" hidden "$apid" /etc/exteriq/scanner
check "inside the API sandbox: backups inaccessible" hidden "$apid" /var/lib/exteriq/backups
check "inside the API sandbox: /opt read-only" not nsenter -t "$apid" -m -- touch /opt/exteriq/current/probe
for u in exteriq-api exteriq-worker exteriq-ingest exteriq-scheduler "exteriq-scanner@${pools%% *}" exteriq-valkey; do
  pid=$(systemctl show -p MainPID --value "$u")
  st=/proc/$pid/status
  if [ "$(awk '/^CapEff/{print $2}' $st)" = 0000000000000000 ] && [ "$(awk '/^NoNewPrivs/{print $2}' $st)" = 1 ] \
     && [ "$(awk '/^Seccomp:/{print $2}' $st)" = 2 ]; then
    pass "$u: no capabilities, no_new_privs, seccomp filter"
  else
    fail "$u: CapEff=$(awk '/^CapEff/{print $2}' $st) NoNewPrivs=$(awk '/^NoNewPrivs/{print $2}' $st) Seccomp=$(awk '/^Seccomp:/{print $2}' $st)"
  fi
  score=$(systemd-analyze security "$u" --no-pager 2>/dev/null \
    | sed -n 's/.*Overall exposure level for [^:]*: \([0-9][0-9.]*\).*/\1/p')
  awk -v s="$score" 'BEGIN{exit !(s ~ /^[0-9.]+$/ && s+0 <= 2.0)}' && pass "$u exposure score $score (<= 2.0)" \
    || fail "$u exposure score ${score:-unreadable} (want <= 2.0)"
done

echo "== database"
role=$(runuser -u postgres -- psql -XtA -c "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname='exteriq'")
[ "$role" = "f|f|f|f" ] && pass "role exteriq: no superuser, no BYPASSRLS, no CREATEROLE/CREATEDB" || fail "role exteriq: $role"
unprotected=$(runuser -u postgres -- psql -XtA -d exteriq -c "
  SELECT string_agg(c.relname, ',') FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id'
  WHERE c.relkind = 'r' AND c.relnamespace = 'public'::regnamespace AND NOT (c.relrowsecurity AND c.relforcerowsecurity)")
[ -z "$unprotected" ] && pass "every table with tenant_id has forced row-level security" || fail "tables without forced RLS: $unprotected"
owner=$(runuser -u postgres -- psql -XtA -c "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='exteriq'")
[ "$owner" = exteriq ] && pass "database owned by exteriq" || fail "database owner $owner"

echo "== broker ACL"
ppw=$(env_get /etc/exteriq/exteriq.env ASM_REDIS_URL | sed 's|redis://:\([^@]*\)@.*|\1|')
for p in $pools; do
  spw=$(env_get "/etc/exteriq/scanner/$p.env" ASM_CELERY_BROKER_URL | sed 's|redis://[^:]*:\([^@]*\)@.*|\1|')
  vs() { REDISCLI_AUTH=$spw valkey-cli -p 6380 --user "scanner-$p" --no-auth-warning "$@" 2>&1; }
  [ "$(vs llen "scanners.$p")" -ge 0 ] 2>/dev/null && pass "scanner-$p may read its own queue" || fail "scanner-$p cannot read its queue"
  vs llen core | grep -q NOPERM && pass "scanner-$p may not read the platform queue" || fail "scanner-$p can read core"
  vs llen scanners.other-pool | grep -q NOPERM && pass "scanner-$p may not read another pool's queue" || fail "scanner-$p reads other pools"
  vs config get '*' | grep -q NOPERM && pass "scanner-$p may not run admin commands" || fail "scanner-$p runs CONFIG"
  vs keys 'asm.health.*' | grep -q NOPERM && pass "scanner-$p may not read platform keys" || fail "scanner-$p reads platform keys"
done
REDISCLI_AUTH=wrong valkey-cli -p 6380 --no-auth-warning ping 2>&1 | grep -qE "WRONGPASS|NOAUTH" && pass "broker refuses a wrong password" || fail "broker accepts a wrong password"
REDISCLI_AUTH=$ppw valkey-cli -p 6380 --no-auth-warning ping | grep -q PONG && pass "platform broker user works" || fail "platform broker user"

echo "== scanners (what each pool's scanner reports from inside its sandbox)"
for p in $pools; do
  REDISCLI_AUTH=$ppw valkey-cli -p 6380 --no-auth-warning --scan --pattern "asm.pool.$p.health.*" \
    | while read -r k; do REDISCLI_AUTH=$ppw valkey-cli -p 6380 --no-auth-warning get "$k"; done \
    | python3 -c '
import json, sys
beats = sorted((json.loads(l) for l in sys.stdin if l.strip()), key=lambda b: b["ts"])
if not beats:
    sys.exit("no heartbeat")
b = beats[-1]
bad = [f"{n}: {v}" for n, v in b["engines"].items() if v == "not installed" or v.startswith(("failed", "unknown"))]
if bad:
    sys.exit("; ".join(bad))
if not b["detection_rules"].get("available"):
    sys.exit("detection content: " + str(b["detection_rules"].get("reason")))
print(len(b["engines"]), b["detection_rules"]["count"])
' >/tmp/scanner-$p.txt 2>&1 \
    && pass "pool $p: all engines run in the sandbox, detection content installed ($(cat /tmp/scanner-$p.txt) engines/templates)" \
    || fail "pool $p: $(cat /tmp/scanner-$p.txt)"
done

echo "== web"
code() { curl -sk -o /dev/null -w '%{http_code}' --resolve "$host:$1:127.0.0.1" "$2"; }
[ "$(code "$https" "https://$host:$https/api/v1/health")" = 200 ] && pass "API health over HTTPS" || fail "API health over HTTPS"
[ "$(code "$https" "https://$host:$https/")" = 200 ] && pass "web app over HTTPS" || fail "web app over HTTPS"
[ "$(code 80 "http://$host/")" = 301 ] && pass "HTTP redirects to HTTPS" || fail "HTTP redirect"
curl -skI --resolve "$host:$https:127.0.0.1" "https://$host:$https/" | grep -qi "content-security-policy" \
  && pass "security headers present" || fail "security headers missing"
check "API not reachable from outside loopback" not curl -s -m 3 "http://$(hostname -I | awk '{print $1}'):8000/api/v1/health"

echo "== logging"
probe=exteriq-logprobe-$$
big=$(python3 -c 'print("x" * 20000)')
systemd-run --quiet --wait --collect -p SyslogIdentifier=exteriq-logprobe --unit "$probe" /usr/bin/python3 -c "
import json
print(json.dumps({'schema':'exteriq.event/1','ts':'2026-01-01T00:00:00.000Z','event_id':'probe-big-$$','event':'probe.big','level':'INFO','stream':'application','msg':'$big'}))
print(json.dumps({'schema':'exteriq.event/1','ts':'2026-01-01T00:00:00.000Z','event_id':'probe-warn-$$','event':'probe.warn','level':'WARNING','stream':'scans','msg':'w'}))
print('plain text line probe-$$')
" >/dev/null 2>&1
for _ in $(seq 1 30); do grep -q "probe-warn-$$" /var/log/exteriq/errors.json 2>/dev/null && break; sleep 1; done
python3 - "$$" <<'PY' && pass "rsyslog files events by stream (20 KB event intact, WARNING also in errors.json, plain text wrapped)" || fail "log routing"
import json, sys
pid = sys.argv[1]
def events(name):
    with open(f"/var/log/exteriq/{name}") as fh:
        return [json.loads(line) for line in fh if line.strip()]
app = events("application.json")
big = [e for e in app if e.get("event_id") == f"probe-big-{pid}"]
assert big and len(big[0]["msg"]) == 20000, "big event missing or cut"
assert any(e.get("event_id") == f"probe-warn-{pid}" for e in events("scans.json")), "scans stream"
assert any(e.get("event_id") == f"probe-warn-{pid}" for e in events("errors.json")), "errors.json"
assert any(e.get("event") == "process.output" and f"probe-{pid}" in e.get("msg", "") for e in app), "wrapped line"
PY
for f in /var/log/exteriq/*.json; do
  [ -s "$f" ] || continue
  python3 -c "import json,sys; [json.loads(l) for l in open(sys.argv[1]) if l.strip()]" "$f" \
    && pass "$f: every line is JSON" || fail "$f has non-JSON lines"
  perm "$f" "syslog:adm 640"
done
check "no Exteriq events duplicated into /var/log/syslog" not grep -q '"schema":"exteriq.event/1"' /var/log/syslog
# The secret material only: passwords inside URLs (not user names or hosts) and key values.
secrets=$(python3 - /etc/exteriq/exteriq.env /etc/exteriq/scanner/*.env <<'PY'
import sys
from urllib.parse import urlsplit
out = set()
for path in sys.argv[1:]:
    for line in open(path):
        if "=" not in line or line.startswith("#"):
            continue
        k, v = line.strip().split("=", 1)
        if k.endswith("_URL") and "@" in v:
            if urlsplit(v).password:
                out.add(urlsplit(v).password)
        elif k.endswith(("_KEY", "_KEYS", "_PASSWORD", "_SECRET")):
            out.update(p.split(":", 1)[-1] for p in v.split(",") if p)
print("\n".join(s for s in out if len(s) >= 16))
PY
)
leak=0
for s in $secrets; do
  if grep -rqF -- "$s" /var/log/exteriq /var/log/nginx 2>/dev/null || journalctl -u 'exteriq-*' --no-pager -q | grep -qF -- "$s"; then
    leak=1
  fi
done
[ $leak = 0 ] && pass "no secret value from /etc/exteriq appears in logs or the journal" || fail "a secret value appears in logs"

echo "== diagnostics CLI"
exteriqctl diag >/tmp/diag.out 2>&1; rc=$?
[ $rc = 0 ] || [ $rc = 2 ] && pass "exteriqctl diag ran (exit $rc)" || fail "exteriqctl diag exit $rc"
check "diag archive written" ls /var/lib/exteriq/diagnostics/

echo
[ $fails = 0 ] && echo "ALL CHECKS PASSED" || echo "$fails CHECK(S) FAILED"
exit $fails

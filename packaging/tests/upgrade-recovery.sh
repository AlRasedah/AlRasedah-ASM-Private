#!/bin/bash
# Upgrade, rollback, failed-migration recovery, restore, uninstall and reinstall on a
# DISPOSABLE test host that runs release <from> (packaging/tests; never on a real server).
#
#   packaging/tests/upgrade-recovery.sh <artifacts-dir> <from> <next> <failing> <schema-change>
#
# <artifacts-dir>/<version>/ holds each build's .deb files (packaging/build-deb.sh output);
# <failing> and <schema-change> are test builds made with --extra-migration.
set -u
art=$1 from=$2 next=$3 failing=$4 schema=$5
fails=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }
q() { runuser -u postgres -- psql -XtA -d exteriq -c "$1" 2>/dev/null; }
current() { basename "$(readlink /opt/exteriq/current)"; }
schema() { q "SELECT version_num FROM alembic_version"; }
has_table() { [ "$(q "SELECT to_regclass('public.$1') IS NOT NULL")" = t ]; }
data_fp() { q "SELECT (SELECT count(*) FROM tenants) || '/' || (SELECT count(*) FROM users) || '/' || (SELECT count(*) FROM scans) || '/' || (SELECT count(*) FROM audit_logs)"; }
aptin() { DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades "$art/$1"/exteriq-release-*.deb "$art/$1"/exteriq_*.deb >/tmp/apt.log 2>&1 || { tail -20 /tmp/apt.log; return 1; }; }
healthy() { bash "$(dirname "$0")/verify-native.sh" >/tmp/verify.log 2>&1 && pass "$1: all native checks pass" || { fail "$1: native checks"; grep FAIL /tmp/verify.log; }; }
api_version() { curl -sk "https://127.0.0.1/api/v1/health" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("version",""))' 2>/dev/null; }
latest_backup() { ls -1dt /var/lib/exteriq/backups/*-"$1" 2>/dev/null | head -n 1; }
export POOLS
POOLS=$(python3 -c 'import json; print(" ".join(json.load(open("/etc/exteriq/install.json"))["pools"]))')

[ "$(current)" = "$from" ] || { echo "host must run $from (runs $(current))"; exit 2; }
fp0=$(data_fp)
echo "data fingerprint (tenants/users/scans/audit): $fp0"

echo "== A. upgrade $from -> $next (no schema change), rollback, upgrade again"
aptin "$next" && pass "packages $next installed next to $from"
[ "$(current)" = "$from" ] && is_active=1 && systemctl is-active --quiet exteriq-api && pass "installing the package changed nothing that runs" \
  || fail "package installation switched or stopped the running release"
exteriqctl upgrade --to "$next" >/tmp/up-a.log 2>&1 && pass "exteriqctl upgrade to $next" || { fail "upgrade to $next"; tail -30 /tmp/up-a.log; }
[ "$(current)" = "$next" ] && pass "active release is $next" || fail "active release $(current)"
[ -n "$(latest_backup "pre-upgrade-$next")" ] && pass "pre-upgrade backup taken" || fail "no pre-upgrade backup"
healthy "after upgrade to $next"
fpa=$(data_fp); [ "${fpa%/*}" = "${fp0%/*}" ] && pass "data preserved across upgrade" || fail "data changed: $fp0 -> $fpa"
exteriqctl rollback --to "$from" >/tmp/rb-a.log 2>&1 && [ "$(current)" = "$from" ] \
  && pass "rollback to $from allowed (schema unchanged)" || { fail "rollback to $from"; tail -20 /tmp/rb-a.log; }
exteriqctl upgrade --to "$next" >/tmp/up-a2.log 2>&1 && [ "$(current)" = "$next" ] && pass "upgrade to $next again" \
  || { fail "second upgrade"; tail -20 /tmp/up-a2.log; }

echo "== B. failed migration ($failing)"
aptin "$failing" && pass "packages $failing installed"
if exteriqctl upgrade --to "$failing" >/tmp/up-b.log 2>&1; then fail "upgrade with a failing migration reported success"
else pass "upgrade with a failing migration reports failure"; fi
grep -q "failed and was undone" /tmp/up-b.log && pass "operator told the upgrade was undone" || { fail "unclear failure message"; tail -20 /tmp/up-b.log; }
[ "$(current)" = "$next" ] && pass "still on $next" || fail "active release $(current)"
[ "$(schema)" = 0013 ] && pass "schema unchanged (0013)" || fail "schema $(schema)"
has_table failed_migration_probe && fail "partial migration left a table behind" || pass "no partial migration left behind"
healthy "after the failed upgrade"

echo "== C. upgrade with a schema change ($schema), rollback refused, restore"
aptin "$schema" && pass "packages $schema installed"
exteriqctl upgrade --to "$schema" >/tmp/up-c.log 2>&1 && pass "upgrade to $schema" || { fail "upgrade to $schema"; tail -30 /tmp/up-c.log; }
[ "$(schema)" = 0014 ] && has_table upgrade_probe && pass "schema migrated to 0014" || fail "schema $(schema)"
healthy "after upgrade to $schema"
if exteriqctl rollback --to "$next" >/tmp/rb-c.log 2>&1; then fail "rollback across a migration was allowed"
else pass "rollback across a migration refused"; fi
grep -q "cannot undo a migration" /tmp/rb-c.log && pass "refusal explains that a restore is needed" || tail -5 /tmp/rb-c.log
[ "$(current)" = "$schema" ] && pass "refused rollback changed nothing" || fail "active release $(current)"
bk=$(latest_backup "pre-upgrade-$schema")
exteriqctl restore "$(basename "$bk")" --yes >/tmp/restore.log 2>&1 && pass "restore of the pre-upgrade backup" \
  || { fail "restore"; tail -30 /tmp/restore.log; }
[ "$(current)" = "$next" ] && [ "$(schema)" = 0013 ] && ! has_table upgrade_probe \
  && pass "back on $next with schema 0013" || fail "after restore: $(current) schema $(schema)"
fpc=$(data_fp); [ "${fpc%%/*}" = "${fp0%%/*}" ] && pass "tenants preserved through restore ($fpc)" || fail "data after restore: $fpc"
ls -d /var/lib/exteriq/backups/*-pre-restore >/dev/null 2>&1 && pass "safety backup taken before restoring" || fail "no safety backup"
healthy "after restore"

echo "== D. uninstall keeps data; failed reinstall; recovery by re-running"
DEBIAN_FRONTEND=noninteractive apt-get remove -y -q exteriq 'exteriq-release-*' >/tmp/rm.log 2>&1 && pass "packages removed" \
  || { fail "apt remove"; tail -20 /tmp/rm.log; }
systemctl is-active --quiet exteriq-api && fail "services still running after removal" || pass "services stopped"
[ -f /etc/exteriq/exteriq.env ] && [ -d /var/lib/exteriq/storage ] && [ "$(q 'SELECT 1')" = 1 ] \
  && pass "configuration, keys, data and database kept" || fail "data removed on uninstall"
# Ubuntu's `postgresql` unit is an umbrella; the server runs as postgresql@<ver>-main.
cluster=$(systemctl list-units --plain --no-legend 'postgresql@*' | awk '{print $1}' | head -n 1)
systemctl stop "$cluster"; systemctl mask --quiet "$cluster"
aptin "$next" && pass "packages $next reinstalled"
if exteriqctl install >/tmp/re1.log 2>&1; then fail "install succeeded with PostgreSQL unavailable"
else pass "install stops when PostgreSQL is unavailable"; fi
tail -3 /tmp/re1.log | sed 's/^/      /'
systemctl unmask --quiet "$cluster"
exteriqctl install >/tmp/re2.log 2>&1 && pass "re-running install recovers" || { fail "recovery install"; tail -30 /tmp/re2.log; }
grep -q "keeping the existing certificate" /tmp/re2.log && pass "existing certificate kept" || fail "certificate replaced"
fpd=$(data_fp); [ "${fpd%%/*}" = "${fp0%%/*}" ] && pass "data intact after reinstall ($fpd)" || fail "data after reinstall: $fpd"
healthy "after reinstall"
[ "$(api_version)" = "$next" ] && pass "API reports version $next" || fail "API reports $(api_version)"

echo
[ $fails = 0 ] && echo "ALL CHECKS PASSED" || echo "$fails CHECK(S) FAILED"
exit $fails

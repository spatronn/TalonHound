#!/usr/bin/env bash
# Disposable end-to-end test for scripts/rename-postgres-identity.sh
# Does NOT touch the TalonHound compose stack or its volumes.
#
# Usage (on a Docker host):
#   ./scripts/test-rename-postgres-identity.sh

set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/scripts/rename-postgres-identity.sh"
NAME="th-pg-rename-e2e-$$"
PASS="e2e-secret-do-not-use-prod"
FAILED=0

log() { printf '[e2e-rename] %s\n' "$*"; }
fail() { printf '[e2e-rename] FAIL: %s\n' "$*" >&2; FAILED=1; }

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[ -x "$SCRIPT" ] || chmod +x "$SCRIPT"
bash -n "$SCRIPT"

log "starting disposable postgres ($NAME) with POSTGRES_USER=demo only..."
docker run -d --name "$NAME" \
  -e POSTGRES_USER=demo \
  -e POSTGRES_PASSWORD="$PASS" \
  -e POSTGRES_DB=demo \
  postgres:16-alpine >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$NAME" pg_isready -U demo -d demo >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
docker exec "$NAME" pg_isready -U demo -d demo >/dev/null

VOL_BEFORE=$(docker inspect "$NAME" --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{.Source}}{{end}}{{end}}')
log "volume marker before: $VOL_BEFORE"

log "seeding sample table..."
docker exec -i "$NAME" psql -U demo -d demo -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE e2e_probe (id int PRIMARY KEY, marker text NOT NULL);
INSERT INTO e2e_probe (id, marker) VALUES (1, 'keep-me');
SQL

log "dry-run..."
PG_CONTAINER="$NAME" "$SCRIPT" --dry-run | tee /tmp/th-rename-dryrun.out
grep -q 'temporary_admin_required=1' /tmp/th-rename-dryrun.out
grep -q 'database_rename=1' /tmp/th-rename-dryrun.out
grep -q 'role_rename=1' /tmp/th-rename-dryrun.out
grep -q 'postcheck_login=talonhound' /tmp/th-rename-dryrun.out
grep -q 'temporary_admin_cleanup=planned' /tmp/th-rename-dryrun.out
grep -q 'session user cannot be renamed' /tmp/th-rename-dryrun.out

# Confirm dry-run created no temp roles and left demo intact
roles=$(docker exec "$NAME" psql -U demo -d postgres -Atc \
  "SELECT string_agg(rolname, ',' ORDER BY 1) FROM pg_roles WHERE rolcanlogin;")
[ "$roles" = "demo" ] || fail "dry-run mutated login roles: $roles"

log "fault-injection: after_temp_create (expect trap cleanup)..."
set +e
RENAME_PG_FAULT=after_temp_create PG_CONTAINER="$NAME" "$SCRIPT" >/tmp/th-rename-fault.out 2>&1
fault_rc=$?
set -e
log "fault_injection_exit=$fault_rc"
[ "$fault_rc" -ne 0 ] || fail "fault injection should have failed"
grep -q 'fault injection: after_temp_create' /tmp/th-rename-fault.out || fail "fault injection marker missing"
grep -q 'dropping temporary admin role' /tmp/th-rename-fault.out || fail "trap did not drop temp admin"
temp_left=$(docker exec "$NAME" psql -U demo -d postgres -Atc \
  "SELECT count(*)::text FROM pg_roles WHERE rolname ~ '^th_rename_admin_[a-f0-9]{12}$';" | tr -d '[:space:]')
[ "$temp_left" = "0" ] || fail "temp admin leaked after fault injection (count=$temp_left)"
# still demo
docker exec "$NAME" psql -U demo -d demo -Atc "SELECT marker FROM e2e_probe" | grep -qx 'keep-me' \
  || fail "data lost during fault injection"

log "full rename..."
PG_CONTAINER="$NAME" "$SCRIPT" | tee /tmp/th-rename-full.out
grep -q 'SUCCESS' /tmp/th-rename-full.out

log "verifying identity..."
dbs=$(docker exec "$NAME" psql -U talonhound -d postgres -Atc \
  "SELECT string_agg(datname, ',' ORDER BY 1) FROM pg_database WHERE datistemplate = false;")
printf '%s\n' "$dbs" | grep -q 'talonhound' || fail "missing talonhound db (dbs=$dbs)"
printf '%s\n' "$dbs" | grep -vq '^demo$' || true
echo "$dbs" | tr ',' '\n' | grep -qx 'demo' && fail "demo database still present" || true
# clearer check
demo_db=$(docker exec "$NAME" psql -U talonhound -d postgres -Atc \
  "SELECT count(*) FROM pg_database WHERE datname='demo';" | tr -d '[:space:]')
[ "$demo_db" = "0" ] || fail "demo database still exists"

demo_role=$(docker exec "$NAME" psql -U talonhound -d postgres -Atc \
  "SELECT count(*) FROM pg_roles WHERE rolname='demo';" | tr -d '[:space:]')
[ "$demo_role" = "0" ] || fail "demo role still exists"

th_role=$(docker exec "$NAME" psql -U talonhound -d postgres -Atc \
  "SELECT count(*) FROM pg_roles WHERE rolname='talonhound' AND rolcanlogin;" | tr -d '[:space:]')
[ "$th_role" = "1" ] || fail "talonhound login role missing"

marker=$(docker exec "$NAME" psql -U talonhound -d talonhound -Atc "SELECT marker FROM e2e_probe WHERE id=1;")
[ "$marker" = "keep-me" ] || fail "marker not preserved (got '$marker')"

owner=$(docker exec "$NAME" psql -U talonhound -d talonhound -Atc \
  "SELECT pg_catalog.pg_get_userbyid(c.relowner) FROM pg_class c
   JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relname='e2e_probe';")
[ "$owner" = "talonhound" ] || fail "table owner expected talonhound got '$owner'"

log "password login as talonhound via TCP..."
docker exec -e PGPASSWORD="$PASS" "$NAME" \
  psql -h 127.0.0.1 -U talonhound -d talonhound -Atc "SELECT 1" | grep -qx 1 \
  || fail "password login as talonhound failed"

temp_left=$(docker exec "$NAME" psql -U talonhound -d postgres -Atc \
  "SELECT count(*)::text FROM pg_roles WHERE rolname ~ '^th_rename_admin_[a-f0-9]{12}$';" | tr -d '[:space:]')
[ "$temp_left" = "0" ] || fail "temp admin remains after success"

VOL_AFTER=$(docker inspect "$NAME" --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{.Source}}{{end}}{{end}}')
[ "$VOL_AFTER" = "$VOL_BEFORE" ] || fail "volume changed ($VOL_BEFORE -> $VOL_AFTER)"

log "second run (idempotent)..."
PG_CONTAINER="$NAME" "$SCRIPT" | tee /tmp/th-rename-idem.out
grep -q 'idempotent success' /tmp/th-rename-idem.out || fail "second run not idempotent"

log "leftover temp admin refusal..."
docker exec "$NAME" psql -U talonhound -d postgres -v ON_ERROR_STOP=1 \
  -c "CREATE ROLE th_rename_admin_deadbeefcafe LOGIN SUPERUSER PASSWORD 'x';"
set +e
PG_CONTAINER="$NAME" "$SCRIPT" >/tmp/th-rename-leftover.out 2>&1
left_rc=$?
set -e
[ "$left_rc" -ne 0 ] || fail "should refuse when leftover temp admin exists"
grep -qi 'leftover' /tmp/th-rename-leftover.out || fail "leftover message missing"
docker exec "$NAME" psql -U talonhound -d postgres -c "DROP ROLE th_rename_admin_deadbeefcafe;"

if [ "$FAILED" -ne 0 ]; then
  log "DONE WITH FAILURES"
  exit 1
fi
log "ALL CHECKS PASSED"
exit 0

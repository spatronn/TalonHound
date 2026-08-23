#!/usr/bin/env sh
# Partition-aware backup/restore smoke test.
# Validates that pg_restore --clean fails on inherited IOC partitions and that the
# supported restore model (fresh DB + pg_restore without --clean) succeeds.
#
# Usage:
#   ./scripts/test-backup-restore-partition.sh          # docker compose db
#   DB_HOST=127.0.0.1 DB_PASSWORD=... ./scripts/test-backup-restore-partition.sh  # CI postgres service
#
# Exit 0 on success. Skips (exit 0) when PostgreSQL is unreachable.

set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DB_USER="${DB_USER:-talonhound}"
DB_PASSWORD="${DB_PASSWORD:?DB_PASSWORD required}"
SOURCE_DB="${DB_NAME:-talonhound}"
RESTORE_DB="${RESTORE_TEST_DB:-${SOURCE_DB}_restore_test}"
MARKER="partition-restore-test-$(date -u +%Y%m%d%H%M%S)"

USE_COMPOSE=0
if [ -z "${DB_HOST:-}" ] || [ "$DB_HOST" = "db" ]; then
  if docker compose exec -T db pg_isready -U "$DB_USER" -d "$SOURCE_DB" >/dev/null 2>&1; then
    USE_COMPOSE=1
    DB_HOST=db
  fi
fi

if [ "$USE_COMPOSE" -eq 0 ] && [ -z "${DB_HOST:-}" ]; then
  echo "[partition-restore] no PostgreSQL target — skip"
  exit 0
fi

export PGPASSWORD="$DB_PASSWORD"

psql_cmd() {
  _db="$1"
  shift
  if [ "$USE_COMPOSE" -eq 1 ]; then
    docker compose exec -T db psql -U "$DB_USER" -d "$_db" -v ON_ERROR_STOP=1 "$@"
  else
    psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "$DB_USER" -d "$_db" -v ON_ERROR_STOP=1 "$@"
  fi
}

psql_at() {
  _db="$1"
  _sql="$2"
  if [ "$USE_COMPOSE" -eq 1 ]; then
    docker compose exec -T db psql -U "$DB_USER" -d "$_db" -Atc "$_sql"
  else
    psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "$DB_USER" -d "$_db" -Atc "$_sql"
  fi
}

pg_dump_file() {
  _src="$1"
  _out="$2"
  if [ "$USE_COMPOSE" -eq 1 ]; then
    docker compose exec -T db pg_dump -U "$DB_USER" -d "$_src" -Fc > "$_out"
  else
    pg_dump -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "$DB_USER" -d "$_src" -Fc -f "$_out"
  fi
}

pg_restore_list() {
  _dump="$1"
  if [ "$USE_COMPOSE" -eq 1 ]; then
    docker compose exec -T db pg_restore --list - < "$_dump"
  else
    pg_restore --list "$_dump"
  fi
}

pg_restore_clean_test() {
  _db="$1"
  _dump="$2"
  _err=$(mktemp)
  set +e
  if [ "$USE_COMPOSE" -eq 1 ]; then
    docker compose exec -T db pg_restore -U "$DB_USER" -d "$_db" --clean --if-exists - < "$_dump" 2>"$_err"
  else
    pg_restore -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "$DB_USER" -d "$_db" --clean --if-exists "$_dump" 2>"$_err"
  fi
  _code=$?
  set -eu
  if [ "$_code" -eq 0 ] && ! grep -qi 'pg_restore: error:' "$_err" 2>/dev/null; then
    echo "[partition-restore] unexpected: pg_restore --clean succeeded on partitioned schema" >&2
    rm -f "$_err"
    return 1
  fi
  if grep -qi 'cannot drop inherited constraint' "$_err" || grep -qi 'pg_restore: error:' "$_err"; then
    echo "[partition-restore] pg_restore --clean failed as expected on partitioned schema"
    rm -f "$_err"
    return 0
  fi
  echo "[partition-restore] pg_restore --clean did not show expected inherited-constraint errors" >&2
  sed -n '1,15p' "$_err" >&2 || true
  rm -f "$_err"
  return 1
}

recreate_db() {
  _db="$1"
  psql_cmd postgres <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${_db}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS "${_db}" WITH (FORCE);
CREATE DATABASE "${_db}" OWNER "${DB_USER}";
SQL
}

pg_restore_fresh() {
  _db="$1"
  _dump="$2"
  _err=$(mktemp)
  if [ "$USE_COMPOSE" -eq 1 ]; then
    docker compose exec -T db pg_restore -U "$DB_USER" -d "$_db" --no-owner --no-acl --exit-on-error - < "$_dump" 2>"$_err"
  else
    pg_restore -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "$DB_USER" -d "$_db" --no-owner --no-acl --exit-on-error "$_dump" 2>"$_err"
  fi
  _code=$?
  if [ "$_code" -ne 0 ]; then
    echo "[partition-restore] pg_restore into fresh DB failed" >&2
    sed -n '1,30p' "$_err" >&2 || true
    rm -f "$_err"
    return 1
  fi
  rm -f "$_err"
  return 0
}

cleanup() {
  psql_cmd postgres -c "DROP DATABASE IF EXISTS \"${RESTORE_DB}\";" >/dev/null 2>&1 || true
  rm -f "${WORK:-}"/*.dump 2>/dev/null || true
}
trap cleanup EXIT

WORK="${ROOT}/backups/.partition-restore-$$"
mkdir -p "$WORK"
DUMP="${WORK}/source.dump"

echo "[partition-restore] source=${SOURCE_DB} restore_test=${RESTORE_DB} compose=${USE_COMPOSE}"

# Require partitioned IOC schema on source
PARTS=$(psql_at "$SOURCE_DB" "SELECT COUNT(*)::text FROM pg_inherits WHERE inhparent = 'public.ioc_items'::regclass;" 2>/dev/null || echo "0")
if [ "${PARTS:-0}" -lt 1 ]; then
  echo "[partition-restore] source DB has no ioc_items partitions — skip (run after migrate)"
  exit 0
fi
echo "[partition-restore] ioc_items partition count on source: ${PARTS}"

echo "[partition-restore] creating marker on source"
psql_cmd "$SOURCE_DB" <<SQL
CREATE TABLE IF NOT EXISTS backup_restore_test_marker (id SERIAL PRIMARY KEY, marker TEXT NOT NULL);
INSERT INTO backup_restore_test_marker (marker) VALUES ('${MARKER}');
SQL

echo "[partition-restore] pg_dump source"
pg_dump_file "$SOURCE_DB" "$DUMP"
BYTES=$(wc -c < "$DUMP" | tr -d ' ')
test "$BYTES" -gt 0

echo "[partition-restore] validate dump TOC"
pg_restore_list "$DUMP" | grep -q schema_migrations

echo "[partition-restore] TEST: pg_restore --clean must fail on populated DB"
pg_restore_clean_test "$SOURCE_DB" "$DUMP"

echo "[partition-restore] TEST: fresh DB restore (DROP + CREATE + pg_restore)"
recreate_db "$RESTORE_DB"
pg_restore_fresh "$RESTORE_DB" "$DUMP"

MARKER_FOUND=$(psql_at "$RESTORE_DB" "SELECT marker FROM backup_restore_test_marker ORDER BY id DESC LIMIT 1;")
test "$MARKER_FOUND" = "$MARKER"

for pair in \
  "schema_migrations|SELECT COUNT(*)::text FROM schema_migrations" \
  "ioc_items|SELECT COUNT(*)::text FROM ioc_items" \
  "integration_feeds|SELECT COUNT(*)::text FROM integration_feeds" \
  "tags|SELECT COUNT(*)::text FROM tags"; do
  _label="${pair%%|*}"
  _sql="${pair#*|}"
  _src=$(psql_at "$SOURCE_DB" "$_sql")
  _dst=$(psql_at "$RESTORE_DB" "$_sql")
  if [ "$_src" != "$_dst" ]; then
    echo "[partition-restore] row count mismatch ${_label}: source=${_src} restored=${_dst}" >&2
    exit 1
  fi
done

PARTS_DST=$(psql_at "$RESTORE_DB" "SELECT COUNT(*)::text FROM pg_inherits WHERE inhparent = 'public.ioc_items'::regclass;")
test "$PARTS_DST" = "$PARTS"

echo "[partition-restore] TEST: second pg_restore idempotent migrate simulation"
if [ "$USE_COMPOSE" -eq 1 ]; then
  docker compose run --rm --no-deps \
    -e DB_HOST=db -e DB_NAME="$RESTORE_DB" -e DB_USER="$DB_USER" -e DB_PASSWORD="$DB_PASSWORD" \
    backend npm run migrate >/dev/null
else
  (cd "$ROOT/backend" && DB_HOST="$DB_HOST" DB_PORT="${DB_PORT:-5432}" DB_NAME="$RESTORE_DB" DB_USER="$DB_USER" DB_PASSWORD="$DB_PASSWORD" npm run migrate) >/dev/null
fi

echo "[partition-restore] ALL PASS marker=${MARKER}"

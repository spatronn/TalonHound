#!/usr/bin/env bash
# Full baseline validation suite (isolated DBs only — never production).
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

NETWORK="${BASELINE_NETWORK:-talonhound_default}"
DB_USER="${DB_USER:-talonhound}"
DB_PASSWORD="${DB_PASSWORD:-baseline_test_password}"
REF_CONTAINER="${REF_CONTAINER:-th-baseline-hist-$$}"
BASE_CONTAINER="${BASE_CONTAINER:-th-baseline-new-$$}"
REF_DB="${REF_DB:-th_baseline_hist}"
BASE_DB="${BASE_DB:-th_baseline_new}"

cleanup() {
  docker rm -f "$REF_CONTAINER" "$BASE_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_pg() {
  local c="$1"
  for _ in $(seq 1 30); do
    if docker exec "$c" pg_isready -U "$DB_USER" -d "$1" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "Postgres not ready in $c" >&2
  exit 1
}

start_db() {
  local name="$1" db="$2"
  docker run -d --name "$name" --network "$NETWORK" \
    -e POSTGRES_DB="$db" \
    -e POSTGRES_USER="$DB_USER" \
    -e POSTGRES_PASSWORD="$DB_PASSWORD" \
    postgres:16-alpine >/dev/null
  wait_pg "$name" "$db"
}

apply_init() {
  local c="$1" db="$2"
  for f in db/init/*.sql; do
    docker exec -i "$c" psql -U "$DB_USER" -d "$db" -v ON_ERROR_STOP=1 < "$f"
  done
}

run_migrate() {
  local host="$1"
  docker run --rm --network "$NETWORK" \
    -e DB_HOST="$host" -e DB_PORT=5432 \
    -e DB_USER="$DB_USER" -e DB_PASSWORD="$DB_PASSWORD" -e DB_NAME="$1" \
    -v "$ROOT/backend:/app" -w /app node:20-alpine node migrate.js
}

echo "=== [1/6] historical reference DB ==="
start_db "$REF_CONTAINER" "$REF_DB"
apply_init "$REF_CONTAINER" "$REF_DB"

# Temporarily use full migration set from git stash or backup if already squashed
MIG_BACKUP="$ROOT/.baseline-migrations-backup"
if [ -d "$MIG_BACKUP" ]; then
  rm -rf "$ROOT/backend/migrations"
  cp -a "$MIG_BACKUP" "$ROOT/backend/migrations"
fi

run_migrate "$REF_CONTAINER" "$REF_DB"
run_migrate "$REF_CONTAINER" "$REF_DB"

echo "=== [2/6] build 001_core.sql from reference ==="
DB_HOST="$REF_CONTAINER" DB_NAME="$REF_DB" DB_PASSWORD="$DB_PASSWORD" \
  bash "$ROOT/scripts/baseline/build-001-core.sh" --out "$ROOT/backend/migrations/001_core.sql"

echo "=== [3/6] baseline-only DB ==="
start_db "$BASE_CONTAINER" "$BASE_DB"
apply_init "$BASE_CONTAINER" "$BASE_DB"

# Swap to baseline-only migrations
rm -rf "$MIG_BACKUP"
cp -a "$ROOT/backend/migrations" "$MIG_BACKUP"
mkdir -p "$ROOT/backend/migrations"
cp "$MIG_BACKUP/001_core.sql" "$ROOT/backend/migrations/001_core.sql"

run_migrate "$BASE_CONTAINER" "$BASE_DB"
run_migrate "$BASE_CONTAINER" "$BASE_DB"

echo "=== [4/6] schema equivalence ==="
HIST_HOST="$REF_CONTAINER" HIST_DB="$REF_DB" \
BASE_HOST="$BASE_CONTAINER" BASE_DB="$BASE_DB" \
DB_PASSWORD="$DB_PASSWORD" \
  bash "$ROOT/scripts/baseline/compare-schema.sh"

echo "=== [5/6] seed data equivalence ==="
HIST_HOST="$REF_CONTAINER" HIST_DB="$REF_DB" \
BASE_HOST="$BASE_CONTAINER" BASE_DB="$BASE_DB" \
DB_PASSWORD="$DB_PASSWORD" \
  bash "$ROOT/scripts/baseline/compare-seed-data.sh"

echo "=== [6/6] legacy skip simulation ==="
# Re-run migrate on historical DB after baseline-only tree — must apply 0
run_migrate "$REF_CONTAINER" "$REF_DB" | tee /tmp/baseline-skip.log
if grep -q 'applying 001_core.sql' /tmp/baseline-skip.log; then
  echo "LEGACY SKIP TEST: FAIL (001_core.sql was re-applied)"
  exit 1
fi
echo "LEGACY SKIP TEST: PASS"

# Restore migrations dir from backup for caller
rm -rf "$ROOT/backend/migrations"
cp -a "$MIG_BACKUP" "$ROOT/backend/migrations"

echo "BASELINE VALIDATION: ALL PASS"

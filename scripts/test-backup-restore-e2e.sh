#!/usr/bin/env sh
# Disposable-DB backup → mutate → restore smoke test.
# Requires: docker compose db up, psql/pg_dump/pg_restore available via compose.
#
# Usage (from repo root):
#   ./scripts/test-backup-restore-e2e.sh
#
# Exit 0 on success. Skips (exit 0 with message) if compose db is unreachable.

set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DB_USER="${DB_USER:-talonhound}"
TEST_DB="talonhound_backup_test_$$"
MARKER="e2e-marker-$(date -u +%Y%m%d%H%M%S)"

if ! docker compose exec -T db pg_isready -U "$DB_USER" >/dev/null 2>&1; then
  echo "[e2e] docker compose db not ready — skip"
  exit 0
fi

cleanup() {
  docker compose exec -T db psql -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS ${TEST_DB};" >/dev/null 2>&1 || true
  rm -rf "$ROOT/backups/.e2e-$$" 2>/dev/null || true
}
trap cleanup EXIT

echo "[e2e] create disposable database ${TEST_DB}"
docker compose exec -T db psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${TEST_DB}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS ${TEST_DB};
CREATE DATABASE ${TEST_DB};
SQL

docker compose exec -T db psql -U "$DB_USER" -d "$TEST_DB" -v ON_ERROR_STOP=1 <<SQL
CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
INSERT INTO schema_migrations(name) VALUES ('127_system_backups.sql') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS e2e_fixture (id SERIAL PRIMARY KEY, marker TEXT NOT NULL);
INSERT INTO e2e_fixture(marker) VALUES ('${MARKER}');
SQL

WORK="$ROOT/backups/.e2e-$$"
mkdir -p "$WORK/database"
DUMP="$WORK/database/postgres.dump"

echo "[e2e] pg_dump"
docker compose exec -T db pg_dump -U "$DB_USER" -d "$TEST_DB" -Fc > "$DUMP"
BYTES=$(wc -c < "$DUMP" | tr -d ' ')
test "$BYTES" -gt 0

(
  cd "$WORK"
  sha256sum database/postgres.dump > checksums.sha256
)

cat > "$WORK/manifest.json" <<EOF
{
  "format_version": 2,
  "backup_id": "e2e-${TEST_DB}",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "application": "TalonHound",
  "database_schema_version": "127_system_backups.sql",
  "components": { "postgres": { "file": "database/postgres.dump", "format": "pg_custom", "bytes": ${BYTES} } }
}
EOF

echo "[e2e] mutate fixture"
docker compose exec -T db psql -U "$DB_USER" -d "$TEST_DB" -c "DELETE FROM e2e_fixture;"

echo "[e2e] restore dump"
docker compose exec -T db pg_restore -U "$DB_USER" -d "$TEST_DB" --clean --if-exists < "$DUMP" || true

echo "[e2e] assert marker restored"
FOUND=$(docker compose exec -T db psql -U "$DB_USER" -d "$TEST_DB" -Atc "SELECT marker FROM e2e_fixture LIMIT 1;")
test "$FOUND" = "$MARKER"

SCHEMA=$(docker compose exec -T db psql -U "$DB_USER" -d "$TEST_DB" -Atc "SELECT name FROM schema_migrations ORDER BY name DESC LIMIT 1;")
test "$SCHEMA" = "127_system_backups.sql"

echo "[e2e] OK marker=${MARKER} schema=${SCHEMA}"

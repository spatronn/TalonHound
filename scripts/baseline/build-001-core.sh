#!/usr/bin/env bash
# Build canonical 001_core.sql from a fully-migrated reference database.
# Usage:
#   DB_HOST=... DB_PORT=5432 DB_USER=talonhound DB_PASSWORD=... DB_NAME=... \
#     ./scripts/baseline/build-001-core.sh [--out backend/migrations/001_core.sql]
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

OUT="${1:-${OUT:-backend/migrations/001_core.sql}}"
if [ "${1:-}" = "--out" ]; then
  OUT="${2:?missing --out path}"
fi

DB_HOST="${DB_HOST:?DB_HOST required}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-talonhound}"
DB_PASSWORD="${DB_PASSWORD:?DB_PASSWORD required}"
DB_NAME="${DB_NAME:?DB_NAME required}"

export PGPASSWORD="$DB_PASSWORD"
PSQL=(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1)

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

SCHEMA="$TMP/schema.sql"
DATA="$TMP/seed.sql"

echo "[baseline] dumping schema (excluding schema_migrations)..."
pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
  --schema-only --no-owner --no-acl \
  --exclude-table=public.schema_migrations \
  > "$SCHEMA"

SEED_TABLES=()
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%%#*}"
  line="$(echo "$line" | tr -d '[:space:]')"
  [ -n "$line" ] || continue
  SEED_TABLES+=("$line")
done < "$ROOT/scripts/baseline/seed-tables.txt"

TABLE_ARGS=()
for t in "${SEED_TABLES[@]}"; do
  TABLE_ARGS+=(--table="public.${t}")
done

echo "[baseline] dumping seed data for ${#SEED_TABLES[@]} table(s)..."
pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
  --data-only --no-owner --no-acl --inserts --column-inserts \
  "${TABLE_ARGS[@]}" \
  > "$DATA"

mkdir -p "$(dirname "$OUT")"
{
  cat <<'HEADER'
-- TalonHound canonical database baseline (v0.1.0-beta.1)
-- Replaces private-development migrations 001–165 with a single public baseline.
-- Migration identity: 001_core.sql (full filename stored in schema_migrations).
-- Do NOT edit after public release; add forward migrations as 002_*.sql, 003_*.sql, ...
-- schema_migrations is created/owned by backend/migrate.js — not included here.

HEADER
  echo "BEGIN;"
  echo
  echo "-- Drop legacy docker-entrypoint-initdb.d stubs (see db/init/) so canonical schema can apply cleanly."
  echo "DROP TABLE IF EXISTS public.integration_checkpoints CASCADE;"
  echo "DROP TABLE IF EXISTS public.integration_runs CASCADE;"
  echo "DROP TABLE IF EXISTS public.user_preferences CASCADE;"
  echo
  echo "-- ===== SCHEMA ====="
  # Strip pg_dump connection/session noise; keep DDL.
  grep -vE '^\\(connect|restrict|unrestrict)' "$SCHEMA" \
    | sed '/^SET /d;/^SELECT pg_catalog/d;/^-- PostgreSQL database dump$/d' \
    || true
  echo
  echo "-- ===== CANONICAL SEED DATA ====="
  grep -vE '^\\(connect|restrict|unrestrict)' "$DATA" \
    | sed '/^SET /d;/^SELECT pg_catalog/d' \
    || true
  echo
  echo "COMMIT;"
} > "$OUT"

LINES="$(wc -l < "$OUT" | tr -d ' ')"
BYTES="$(wc -c < "$OUT" | tr -d ' ')"
echo "[baseline] wrote $OUT ($LINES lines, $BYTES bytes)"

# Quick sanity: no secrets patterns
if grep -qiE '(password|api_key|secret|token)\s*=\s*['\''"][^'\''"]{8,}' "$OUT"; then
  echo "[baseline] WARNING: possible secret-like literals in baseline — review before commit" >&2
fi

echo "[baseline] done"

#!/usr/bin/env bash
# Compare normalized schema between two PostgreSQL databases.
# Usage:
#   HIST_HOST=... HIST_DB=... BASE_HOST=... BASE_DB=... DB_USER=... DB_PASSWORD=... \
#     ./scripts/baseline/compare-schema.sh
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

DB_USER="${DB_USER:-talonhound}"
DB_PASSWORD="${DB_PASSWORD:?DB_PASSWORD required}"
HIST_HOST="${HIST_HOST:?HIST_HOST required}"
HIST_PORT="${HIST_PORT:-5432}"
HIST_DB="${HIST_DB:?HIST_DB required}"
BASE_HOST="${BASE_HOST:?BASE_HOST required}"
BASE_PORT="${BASE_PORT:-5432}"
BASE_DB="${BASE_DB:?BASE_DB required}"

export PGPASSWORD="$DB_PASSWORD"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

dump_norm() {
  local host="$1" port="$2" db="$3" out="$4"
  pg_dump -h "$host" -p "$port" -U "$DB_USER" -d "$db" \
    --schema-only --no-owner --no-acl \
    --exclude-table=public.schema_migrations \
    > "$out.raw"
  # Normalize: drop comments, SET lines, blank lines, dump headers, ordering-only noise
  grep -vE '^--|^$|^SET |^SELECT pg_catalog|^\\(connect|restrict|unrestrict)' "$out.raw" \
    | sed 's/[[:space:]]\+/ /g' \
    | sort \
    > "$out.norm"
}

dump_norm "$HIST_HOST" "$HIST_PORT" "$HIST_DB" "$TMP/hist"
dump_norm "$BASE_HOST" "$BASE_PORT" "$BASE_DB" "$TMP/base"

if diff -u "$TMP/hist.norm" "$TMP/base.norm" > "$TMP/schema.diff"; then
  echo "SCHEMA EQUIVALENCE: PASS"
  exit 0
fi

echo "SCHEMA EQUIVALENCE: FAIL"
echo "--- diff (normalized, first 200 lines) ---"
head -200 "$TMP/schema.diff" || true
HIST_LINES="$(wc -l < "$TMP/hist.norm" | tr -d ' ')"
BASE_LINES="$(wc -l < "$TMP/base.norm" | tr -d ' ')"
echo "--- line counts: historical=$HIST_LINES baseline=$BASE_LINES ---"
exit 1

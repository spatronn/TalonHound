#!/usr/bin/env bash
# Compare canonical seed/reference table contents between two databases.
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

FAIL=0
TABLES=()
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%%#*}"
  line="$(echo "$line" | tr -d '[:space:]')"
  [ -n "$line" ] || continue
  TABLES+=("$line")
done < "$ROOT/scripts/baseline/seed-tables.txt"

echo "Comparing ${#TABLES[@]} canonical seed table(s)..."

for t in "${TABLES[@]}"; do
  HIST_FILE="$(mktemp)"
  BASE_FILE="$(mktemp)"
  psql -h "$HIST_HOST" -p "$HIST_PORT" -U "$DB_USER" -d "$HIST_DB" -Atc \
    "SELECT row_to_json(x)::text FROM (SELECT * FROM ${t} ORDER BY 1) x" \
    | sort > "$HIST_FILE"
  psql -h "$BASE_HOST" -p "$BASE_PORT" -U "$DB_USER" -d "$BASE_DB" -Atc \
    "SELECT row_to_json(x)::text FROM (SELECT * FROM ${t} ORDER BY 1) x" \
    | sort > "$BASE_FILE"
  if diff -q "$HIST_FILE" "$BASE_FILE" >/dev/null 2>&1; then
    echo "  OK  $t"
  else
    echo "  FAIL $t"
    diff -u "$HIST_FILE" "$BASE_FILE" | head -40 || true
    FAIL=1
  fi
  rm -f "$HIST_FILE" "$BASE_FILE"
done

if [ "$FAIL" -eq 0 ]; then
  echo "CANONICAL DATA EQUIVALENCE: PASS"
  exit 0
fi
echo "CANONICAL DATA EQUIVALENCE: FAIL"
exit 1

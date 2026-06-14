#!/usr/bin/env sh
# Create a timestamped demo-runbook backup under backups/demo-runbook-<UTC_STAMP>/
#
# Usage:
#   ./scripts/backup-stack.sh                    # PostgreSQL only (default)
#   ./scripts/backup-stack.sh --include-clickhouse
#
# Env:
#   BACKUP_ROOT  default: <repo>/backups

set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/backup-common.sh"

INCLUDE_CLICKHOUSE=0
for arg in "$@"; do
  case "$arg" in
    --include-clickhouse) INCLUDE_CLICKHOUSE=1 ;;
    -h|--help)
      echo "Usage: $0 [--include-clickhouse]"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

load_dotenv

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_ROOT="${BACKUP_ROOT:-$ROOT/backups}"
BACKUP_DIR="${BACKUP_ROOT}/demo-runbook-${STAMP}"
mkdir -p "$BACKUP_DIR"

echo "[backup] bundle -> $BACKUP_DIR"
echo "[backup] quiet period recommended (see README.txt)"

PG_OUT="${BACKUP_DIR}/postgres.dump"
echo "[backup] PostgreSQL -> postgres.dump"
docker compose exec -T db pg_dump -U demo -d demo -Fc > "$PG_OUT"
PG_BYTES=$(wc -c < "$PG_OUT" | tr -d ' ')

CH_TABLES_JSON="[]"
if [ "$INCLUDE_CLICKHOUSE" -eq 1 ]; then
  mkdir -p "${BACKUP_DIR}/clickhouse"
  echo "[backup] ClickHouse (optional tables) -> clickhouse/"
  first=1
  CH_TABLES_JSON="["
  for table in $CH_BACKUP_TABLES; do
    outfile="${BACKUP_DIR}/clickhouse/$(ch_file_name "$table")"
    if ch_table_exists "$table"; then
      echo "[backup]   exporting ${table}"
      ch_client --query "SELECT * FROM ${table} FORMAT Native" > "$outfile"
      if [ "$first" -eq 1 ]; then
        CH_TABLES_JSON="${CH_TABLES_JSON}\"${table}\""
        first=0
      else
        CH_TABLES_JSON="${CH_TABLES_JSON},\"${table}\""
      fi
    else
      echo "[backup]   skipped ${table} (not found)"
    fi
  done
  CH_TABLES_JSON="${CH_TABLES_JSON}]"
else
  echo "[backup] ClickHouse skipped (default; pass --include-clickhouse to export)"
fi

write_readme "${BACKUP_DIR}/README.txt" "$STAMP" "$([ "$INCLUDE_CLICKHOUSE" -eq 1 ] && echo 'included (see clickhouse/)' || echo 'not included')"
write_manifest "$BACKUP_DIR" "$STAMP" "$([ "$INCLUDE_CLICKHOUSE" -eq 1 ] && echo true || echo false)" "$PG_BYTES" "$CH_TABLES_JSON"
write_checksums "$BACKUP_DIR"

echo "[backup] checksums -> checksums.sha256"
echo "[backup] manifest -> manifest.json"
echo "[backup] done: $BACKUP_DIR"

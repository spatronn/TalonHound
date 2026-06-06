#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_ROOT="${BACKUP_ROOT:-$ROOT/backups}"
mkdir -p "$BACKUP_ROOT"

PG_OUT="$BACKUP_ROOT/postgres-demo-${STAMP}.dump"
echo "[backup] PostgreSQL -> $PG_OUT"
docker compose exec -T db pg_dump -U demo -d demo -Fc > "$PG_OUT"

CH_DIR="$BACKUP_ROOT/clickhouse-${STAMP}"
mkdir -p "$CH_DIR"
echo "[backup] ClickHouse tables -> $CH_DIR"

for table in syslog_logs syslog_observables; do
  if docker compose exec -T clickhouse clickhouse-client --query "EXISTS TABLE ${table}" 2>/dev/null | grep -q 1; then
    docker compose exec -T clickhouse clickhouse-client \
      --query "SELECT * FROM ${table} FORMAT Native" > "${CH_DIR}/${table}.native"
    echo "[backup]   exported ${table}"
  else
    echo "[backup]   skipped ${table} (not found)"
  fi
done

echo "[backup] done stamp=$STAMP"

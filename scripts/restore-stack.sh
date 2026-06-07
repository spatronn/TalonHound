#!/usr/bin/env sh
# Restore a demo-runbook backup bundle created by backup-stack.sh (CLI-only; overwrites data).
#
# Usage:
#   ./scripts/restore-stack.sh --backup backups/demo-runbook-YYYYMMDDTHHMMSSZ --dry-run
#   ./scripts/restore-stack.sh --backup backups/demo-runbook-YYYYMMDDTHHMMSSZ --confirm
#   ./scripts/restore-stack.sh --backup <dir> --confirm --postgres-only
#   ./scripts/restore-stack.sh --backup <dir> --confirm --restore-clickhouse
#   ./scripts/restore-stack.sh --backup <dir> --confirm --skip-checksum
#
# Requires --confirm for mutating restore (except --dry-run).

set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/backup-common.sh"

BACKUP_DIR=""
DRY_RUN=0
CONFIRM=0
POSTGRES_ONLY=0
SKIP_CHECKSUM=0
RESTORE_CLICKHOUSE=0

usage() {
  echo "Usage: $0 --backup <bundle-dir> [--dry-run | --confirm] [--restore-clickhouse] [--postgres-only] [--skip-checksum]"
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --backup)
      shift
      BACKUP_DIR="${1:-}"
      ;;
    --dry-run) DRY_RUN=1 ;;
    --confirm) CONFIRM=1 ;;
    --restore-clickhouse) RESTORE_CLICKHOUSE=1 ;;
    --postgres-only) POSTGRES_ONLY=1 ;;
    --skip-checksum) SKIP_CHECKSUM=1 ;;
    -h|--help) usage ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      ;;
  esac
  shift
done

[ -n "$BACKUP_DIR" ] || usage

# Resolve relative paths from repo root.
case "$BACKUP_DIR" in
  /*) ;;
  *) BACKUP_DIR="$ROOT/$BACKUP_DIR" ;;
esac

if [ ! -d "$BACKUP_DIR" ]; then
  echo "[restore] backup directory not found: $BACKUP_DIR" >&2
  exit 1
fi

PG_DUMP="${BACKUP_DIR}/postgres.dump"
if [ ! -f "$PG_DUMP" ]; then
  echo "[restore] missing postgres.dump in $BACKUP_DIR" >&2
  exit 1
fi

if [ ! -f "${BACKUP_DIR}/manifest.json" ]; then
  echo "[restore] warning: manifest.json missing (legacy or incomplete bundle)" >&2
fi

load_dotenv

echo "[restore] bundle: $BACKUP_DIR"

if [ "$SKIP_CHECKSUM" -eq 0 ]; then
  if [ -f "${BACKUP_DIR}/checksums.sha256" ]; then
    echo "[restore] verifying checksums..."
    verify_checksums "$BACKUP_DIR"
  else
    echo "[restore] warning: checksums.sha256 missing; use --skip-checksum to silence" >&2
  fi
else
  echo "[restore] checksum verification skipped"
fi

if [ "$RESTORE_CLICKHOUSE" -eq 1 ] && [ ! -d "${BACKUP_DIR}/clickhouse" ]; then
  echo "[restore] warning: --restore-clickhouse set but clickhouse/ missing in bundle" >&2
fi

CH_FILES=""
if [ "$POSTGRES_ONLY" -eq 0 ] && [ "$RESTORE_CLICKHOUSE" -eq 1 ]; then
  for f in "${BACKUP_DIR}"/clickhouse/*.native; do
    [ -f "$f" ] || continue
    CH_FILES="${CH_FILES}${f} "
  done
fi

echo "[restore] plan:"
echo "  - PostgreSQL pg_restore (destructive overwrite)"
if [ -n "$CH_FILES" ]; then
  echo "  - ClickHouse native import:"
  for f in $CH_FILES; do
    echo "      $(basename "$f")"
  done
else
  echo "  - ClickHouse: skip"
fi
echo "  - Redis: not restored (restart implied)"
echo "  - post-step: npm run migrate + start writers"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "[restore] dry-run complete (no changes made)"
  exit 0
fi

if [ "$CONFIRM" -eq 0 ]; then
  echo "[restore] aborted: pass --confirm to execute (or --dry-run to preview)" >&2
  exit 1
fi

echo "[restore] WARNING: this overwrites current PostgreSQL data."
stop_writers

echo "[restore] PostgreSQL pg_restore..."
docker compose exec -T db pg_restore -U demo -d demo --clean --if-exists < "$PG_DUMP"

echo "[restore] running migrations (forward-only safety net)..."
docker compose run --rm backend npm run migrate

if [ -n "$CH_FILES" ]; then
  echo "[restore] ClickHouse import..."
  docker compose stop syslog-receiver ioc-correlation-engine ioc-retro-engine 2>/dev/null || true
  for f in $CH_FILES; do
    table=$(basename "$f" .native)
    echo "[restore]   TRUNCATE + INSERT ${table}"
    ch_client --query "TRUNCATE TABLE ${table}"
    ch_client --query "INSERT INTO ${table} FORMAT Native" < "$f"
  done
fi

start_writers

echo "[restore] done. Verify:"
echo "  docker compose exec backend wget -qO- http://127.0.0.1:3000/readyz"
echo "  docker compose run --rm backend npm run migrate:list"
echo "  Integration queue recover via UI if needed"

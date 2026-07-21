#!/usr/bin/env sh
# Restore a TalonHound backup bundle created by backup-stack.sh (CLI-only; overwrites data).
#
# Usage:
#   ./scripts/restore-stack.sh --backup backups/talonhound-YYYYMMDDTHHMMSSZ --dry-run
#   ./scripts/restore-stack.sh --backup backups/talonhound-YYYYMMDDTHHMMSSZ --confirm
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
SKIP_CHECKSUM=0

usage() {
  echo "Usage: $0 --backup <bundle-dir> [--dry-run | --confirm] [--skip-checksum]"
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

echo "[restore] plan:"
echo "  - PostgreSQL pg_restore (destructive overwrite)"
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

start_writers

echo "[restore] done. Verify:"
echo "  docker compose exec backend wget -qO- http://127.0.0.1:3000/readyz"
echo "  docker compose run --rm backend npm run migrate:list"
echo "  Integration queue recover via UI if needed"

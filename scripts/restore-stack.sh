#!/usr/bin/env sh
# Restore a TalonHound backup (CLI-only; overwrites PostgreSQL).
#
# Usage:
#   ./scripts/restore-stack.sh --backup-id backup-YYYYMMDD-HHMMSS-hex --dry-run
#   ./scripts/restore-stack.sh --backup-id backup-YYYYMMDD-HHMMSS-hex --confirm
#   ./scripts/restore-stack.sh --backup backups/talonhound-YYYYMMDDTHHMMSSZ --confirm
#
# Requires --confirm for mutating restore (except --dry-run).
# Creates a safety backup of the live DB before pg_restore; aborts if safety fails.

set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/backup-common.sh"

BACKUP_REF=""
DRY_RUN=0
CONFIRM=0
SKIP_CHECKSUM=0
SKIP_SAFETY=0

usage() {
  echo "Usage: $0 (--backup-id <id> | --backup <path>) [--dry-run | --confirm] [--skip-checksum] [--skip-safety]"
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --backup-id)
      shift
      BACKUP_REF="${1:-}"
      ;;
    --backup)
      shift
      BACKUP_REF="${1:-}"
      ;;
    --dry-run) DRY_RUN=1 ;;
    --confirm) CONFIRM=1 ;;
    --skip-checksum) SKIP_CHECKSUM=1 ;;
    --skip-safety) SKIP_SAFETY=1 ;;
    -h|--help) usage ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      ;;
  esac
  shift
done

[ -n "$BACKUP_REF" ] || usage

load_dotenv
BACKUP_ROOT="${BACKUP_ROOT:-$ROOT/backups}"
mkdir -p "$BACKUP_ROOT"

echo "[restore] resolving backup: $BACKUP_REF"
resolve_backup_bundle "$BACKUP_REF"
BUNDLE_DIR="${BUNDLE_DIR:?}"

PG_DUMP="$(find_postgres_dump "$BUNDLE_DIR")" || {
  echo "[restore] missing postgres.dump in $BUNDLE_DIR" >&2
  exit 1
}

if [ ! -f "${BUNDLE_DIR}/manifest.json" ]; then
  echo "[restore] warning: manifest.json missing (legacy or incomplete bundle)" >&2
fi

echo "[restore] bundle: $BUNDLE_DIR"
echo "[restore] dump: $PG_DUMP"

if [ "$SKIP_CHECKSUM" -eq 0 ]; then
  if [ -f "${BUNDLE_DIR}/checksums.sha256" ]; then
    echo "[restore] verifying checksums..."
    verify_checksums "$BUNDLE_DIR"
  else
    echo "[restore] warning: checksums.sha256 missing; use --skip-checksum to silence" >&2
  fi
else
  echo "[restore] checksum verification skipped"
fi

echo "[restore] plan:"
echo "  - safety backup of current DB (unless --skip-safety)"
echo "  - stop writer services"
echo "  - PostgreSQL pg_restore --clean --if-exists (destructive)"
echo "  - npm run migrate"
echo "  - start writers"
echo "  - Redis: not restored"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "[restore] dry-run complete (no changes made)"
  exit 0
fi

if [ "$CONFIRM" -eq 0 ]; then
  echo "[restore] aborted: pass --confirm to execute (or --dry-run to preview)" >&2
  exit 1
fi

echo "[restore] WARNING: this overwrites current PostgreSQL data."

if [ "$SKIP_SAFETY" -eq 0 ]; then
  create_safety_backup || exit 1
else
  echo "[restore] safety backup skipped (--skip-safety)"
fi

stop_writers

echo "[restore] PostgreSQL pg_restore..."
if ! docker compose exec -T db pg_restore -U demo -d demo --clean --if-exists < "$PG_DUMP"; then
  echo "[restore] pg_restore reported errors (some warnings are normal with --clean)." >&2
  echo "[restore] continuing to migrate; verify application health carefully." >&2
fi

echo "[restore] running migrations (forward-only safety net)..."
docker compose run --rm backend npm run migrate

start_writers

echo "[restore] done. Verify:"
echo "  docker compose exec backend wget -qO- http://127.0.0.1:3000/readyz"
echo "  docker compose run --rm backend npm run migrate:list"
echo "  Integration queue recover via UI if needed"
if [ -n "${SAFETY_BACKUP_DIR:-}" ]; then
  echo "  Safety backup kept at: $SAFETY_BACKUP_DIR"
fi

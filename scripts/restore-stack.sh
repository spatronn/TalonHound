#!/usr/bin/env sh
# Restore a TalonHound backup (CLI-only; replaces target PostgreSQL database).
#
# Preferred (external / disaster recovery archive — no DB registry required):
#   ./scripts/restore-stack.sh --file /path/to/backup-archive.tar.gz --dry-run
#   ./scripts/restore-stack.sh --file /path/to/backup-archive.tar.gz --confirm
#
# From backup volume / known backup_id:
#   ./scripts/restore-stack.sh --backup-id backup-YYYYMMDD-HHMMSS-hex --confirm
#
# Legacy alias for --file:
#   ./scripts/restore-stack.sh --backup /path/to/archive-or-dir --confirm
#
# Requires --confirm for mutating restore (except --dry-run).
# Creates a safety backup of the live DB when it appears populated; skips on empty/fresh DB.
#
# Restore model: stop writers → DROP DATABASE + CREATE DATABASE → pg_restore (no --clean).
# pg_restore --clean is NOT used (fails on declarative IOC partition inheritance).

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
  echo "Usage: $0 (--file <path> | --backup-id <id> | --backup <path>) [--dry-run | --confirm] [--skip-checksum] [--skip-safety]"
  echo ""
  echo "  --file <path>       External archive (.tar.gz / .tar.gz.enc) or extracted bundle dir"
  echo "  --backup-id <id>    Resolve archive from backup volume / backups/ by id"
  echo "  --backup <path>     Alias for --file (legacy)"
  echo "  --dry-run           Validate and print plan only (no mutate)"
  echo "  --confirm           Execute destructive restore"
  echo "  --skip-checksum     Skip checksums.sha256 verification"
  echo "  --skip-safety       Skip safety backup even if target DB looks populated"
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --backup-id)
      shift
      BACKUP_REF="${1:-}"
      ;;
    --file|--backup)
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

trap 'cleanup_restore_work' EXIT INT TERM

load_dotenv
resolve_restore_db_identifiers || exit 1

BACKUP_ROOT="${BACKUP_ROOT:-$ROOT/backups}"
mkdir -p "$BACKUP_ROOT"

echo "[restore] resolving backup: $BACKUP_REF"
resolve_backup_bundle "$BACKUP_REF" || {
  echo "[restore] failed to resolve backup" >&2
  exit 1
}
BUNDLE_DIR="${BUNDLE_DIR:?}"

PG_DUMP="$(find_postgres_dump "$BUNDLE_DIR")" || {
  echo "[restore] missing postgres.dump in $BUNDLE_DIR" >&2
  exit 1
}

MANIFEST="${BUNDLE_DIR}/manifest.json"
if [ ! -f "$MANIFEST" ]; then
  echo "[restore] error: manifest.json required" >&2
  exit 1
fi
validate_backup_manifest "$MANIFEST" || exit 1
echo "[restore] manifest validated (TalonHound)"

echo "[restore] bundle: $BUNDLE_DIR"
echo "[restore] dump: $PG_DUMP"
echo "[restore] target database: ${RESTORE_DB_NAME} (user ${RESTORE_DB_USER})"

if [ "$SKIP_CHECKSUM" -eq 0 ]; then
  if [ -f "${BUNDLE_DIR}/checksums.sha256" ]; then
    echo "[restore] verifying checksums..."
    verify_checksums "$BUNDLE_DIR" || {
      echo "[restore] checksum verification failed" >&2
      exit 1
    }
  else
    echo "[restore] warning: checksums.sha256 missing; use --skip-checksum to silence" >&2
  fi
else
  echo "[restore] checksum verification skipped"
fi

echo "[restore] validating dump readability..."
validate_dump_readable "$PG_DUMP" || exit 1

SAFETY_PLAN="safety backup of current DB (skipped automatically if target DB looks empty)"
if [ "$SKIP_SAFETY" -eq 1 ]; then
  SAFETY_PLAN="safety backup skipped (--skip-safety)"
fi

echo "[restore] plan:"
echo "  - $SAFETY_PLAN"
echo "  - stop writer services"
echo "  - DROP DATABASE ${RESTORE_DB_NAME} WITH (FORCE) and CREATE DATABASE (destructive)"
echo "  - pg_restore into fresh database (no --clean)"
echo "  - npm run migrate (forward-only safety net)"
echo "  - start writers"
echo "  - Redis: not restored"
echo "  - Note: restore does not require a system_backups DB registry row"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "[restore] dry-run complete (no changes made)"
  exit 0
fi

if [ "$CONFIRM" -eq 0 ]; then
  echo "[restore] aborted: pass --confirm to execute (or --dry-run to preview)" >&2
  exit 1
fi

echo "[restore] WARNING: this replaces the PostgreSQL database '${RESTORE_DB_NAME}'."

if [ "$SKIP_SAFETY" -eq 1 ]; then
  echo "[restore] safety backup skipped (--skip-safety)"
elif target_db_is_empty; then
  echo "[restore] target DB appears empty/fresh — skipping safety backup"
else
  create_safety_backup || exit 1
fi

trap - EXIT INT TERM

stop_writers

recreate_restore_target_database || {
  start_writers
  exit 1
}

run_pg_restore_into_target "$PG_DUMP" || {
  echo "[restore] restore failed — writers not restarted automatically; inspect DB and run start manually" >&2
  exit 1
}

echo "[restore] running migrations (forward-only safety net)..."
if ! docker compose run --rm --no-deps backend npm run migrate; then
  echo "[restore] migrate failed after restore" >&2
  exit 1
fi

start_writers

cleanup_restore_work

echo "[restore] done. Verify:"
echo "  docker compose exec backend wget -qO- http://127.0.0.1:3000/readyz"
echo "  docker compose run --rm backend npm run migrate:list"
echo "  Integration queue recover via UI if needed"
if [ -n "${SAFETY_BACKUP_DIR:-}" ]; then
  echo "  Safety backup kept at: $SAFETY_BACKUP_DIR"
fi

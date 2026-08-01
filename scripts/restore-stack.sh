#!/usr/bin/env sh
# Restore a TalonHound backup (CLI-only; overwrites PostgreSQL).
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

# Clean staging on unexpected exit (failed resolve / checksum / etc.)
trap 'cleanup_restore_work' EXIT INT TERM

load_dotenv
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

if [ ! -f "${BUNDLE_DIR}/manifest.json" ]; then
  echo "[restore] warning: manifest.json missing (legacy or incomplete bundle)" >&2
else
  echo "[restore] manifest present"
fi

echo "[restore] bundle: $BUNDLE_DIR"
echo "[restore] dump: $PG_DUMP"

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

SAFETY_PLAN="safety backup of current DB (skipped automatically if target DB looks empty)"
if [ "$SKIP_SAFETY" -eq 1 ]; then
  SAFETY_PLAN="safety backup skipped (--skip-safety)"
fi

echo "[restore] plan:"
echo "  - $SAFETY_PLAN"
echo "  - stop writer services"
echo "  - PostgreSQL pg_restore --clean --if-exists (destructive)"
echo "  - npm run migrate"
echo "  - start writers"
echo "  - Redis: not restored"
echo "  - Note: restore does not require a system_backups DB registry row"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "[restore] dry-run complete (no changes made)"
  # Keep staging for inspection on dry-run? Clean it — dry-run should not leave clutter.
  exit 0
fi

if [ "$CONFIRM" -eq 0 ]; then
  echo "[restore] aborted: pass --confirm to execute (or --dry-run to preview)" >&2
  exit 1
fi

echo "[restore] WARNING: this overwrites current PostgreSQL data."

if [ "$SKIP_SAFETY" -eq 1 ]; then
  echo "[restore] safety backup skipped (--skip-safety)"
elif target_db_is_empty; then
  echo "[restore] target DB appears empty/fresh — skipping safety backup"
else
  create_safety_backup || exit 1
fi

# Successful path: keep extracted bundle until pg_restore reads it; clear trap after copy into restore.
# Staging dirs under .restore-work can be removed after dump is streamed; keep until end for simplicity.
trap - EXIT INT TERM

stop_writers

echo "[restore] PostgreSQL pg_restore..."
if ! docker compose exec -T db pg_restore -U talonhound -d talonhound --clean --if-exists < "$PG_DUMP"; then
  echo "[restore] pg_restore reported errors (some warnings are normal with --clean)." >&2
  echo "[restore] continuing to migrate; verify application health carefully." >&2
fi

echo "[restore] running migrations (forward-only safety net)..."
docker compose run --rm backend npm run migrate

start_writers

cleanup_restore_work

echo "[restore] done. Verify:"
echo "  docker compose exec backend wget -qO- http://127.0.0.1:3000/readyz"
echo "  docker compose run --rm backend npm run migrate:list"
echo "  Integration queue recover via UI if needed"
if [ -n "${SAFETY_BACKUP_DIR:-}" ]; then
  echo "  Safety backup kept at: $SAFETY_BACKUP_DIR"
fi

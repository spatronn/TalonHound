#!/usr/bin/env sh
# Create a TalonHound backup via the backend Node CLI inside compose (preferred),
# with a legacy host-side pg_dump fallback.
#
# Usage:
#   ./scripts/backup-stack.sh
#
# Env:
#   BACKUP_ROOT  host mirror dir (default: <repo>/backups) — optional copy target

set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/backup-common.sh"

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      echo "Usage: $0"
      echo "Prefers: docker compose exec backup-worker npm run backup:create"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

load_dotenv

echo "[backup] creating backup via backup-worker CLI..."
if docker compose exec -T backup-worker npm run backup:create -- --json; then
  echo "[backup] done (see Administration > Backup & Restore or: docker compose exec backup-worker npm run backup:list)"
  exit 0
fi

echo "[backup] worker CLI unavailable; falling back to host pg_dump bundle..."
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_ROOT="${BACKUP_ROOT:-$ROOT/backups}"
BACKUP_DIR="${BACKUP_ROOT}/talonhound-${STAMP}"
mkdir -p "$BACKUP_DIR"

PG_OUT="${BACKUP_DIR}/postgres.dump"
echo "[backup] PostgreSQL -> postgres.dump"
docker compose exec -T db pg_dump -U talonhound -d talonhound -Fc > "$PG_OUT"
PG_BYTES=$(wc -c < "$PG_OUT" | tr -d ' ')
if [ "${PG_BYTES:-0}" -le 0 ]; then
  echo "[backup] empty dump; aborting" >&2
  rm -rf "$BACKUP_DIR"
  exit 1
fi

write_readme "${BACKUP_DIR}/README.txt" "$STAMP"
write_manifest "$BACKUP_DIR" "$STAMP" "$PG_BYTES"
write_checksums "$BACKUP_DIR"

echo "[backup] checksums -> checksums.sha256"
echo "[backup] manifest -> manifest.json"
echo "[backup] done: $BACKUP_DIR"

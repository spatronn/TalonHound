#!/usr/bin/env sh
# Create a timestamped TalonHound backup under backups/talonhound-<UTC_STAMP>/
#
# Usage:
#   ./scripts/backup-stack.sh                    # PostgreSQL backup
#
# Env:
#   BACKUP_ROOT  default: <repo>/backups

set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/backup-common.sh"

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      echo "Usage: $0"
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
BACKUP_DIR="${BACKUP_ROOT}/talonhound-${STAMP}"
mkdir -p "$BACKUP_DIR"

echo "[backup] bundle -> $BACKUP_DIR"
echo "[backup] quiet period recommended (see README.txt)"

PG_OUT="${BACKUP_DIR}/postgres.dump"
echo "[backup] PostgreSQL -> postgres.dump"
docker compose exec -T db pg_dump -U demo -d demo -Fc > "$PG_OUT"
PG_BYTES=$(wc -c < "$PG_OUT" | tr -d ' ')

write_readme "${BACKUP_DIR}/README.txt" "$STAMP"
write_manifest "$BACKUP_DIR" "$STAMP" "$PG_BYTES"
write_checksums "$BACKUP_DIR"

echo "[backup] checksums -> checksums.sha256"
echo "[backup] manifest -> manifest.json"
echo "[backup] done: $BACKUP_DIR"

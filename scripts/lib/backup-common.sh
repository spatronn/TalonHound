# Shared helpers for backup-stack.sh and restore-stack.sh (POSIX sh).

# Writer services stopped during restore to avoid concurrent writes.
WRITER_SERVICES="backend integration-scheduler integration-worker ioc-expiration-worker ioc-search-export-worker backup-worker"

load_dotenv() {
  if [ -f "$ROOT/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$ROOT/.env"
    set +a
  fi
}

git_sha() {
  git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo "unknown"
}

git_sha_short() {
  git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown"
}

resolve_backup_bundle() {
  # Sets BUNDLE_DIR to an extracted/legacy directory containing postgres.dump or database/postgres.dump
  # Input: BACKUP_REF (path to dir, .tar.gz, .tar.gz.enc, or backup_id)
  _ref="$1"
  if [ -z "$_ref" ]; then
    echo "[restore] missing backup reference" >&2
    return 1
  fi

  case "$_ref" in
    /*) ;;
    *) _ref="$ROOT/$_ref" ;;
  esac

  # backup_id only — look under BACKUP_ROOT / docker volume copy helpers
  if [ ! -e "$_ref" ]; then
    _id=$(basename "$_ref")
    for cand in \
      "${BACKUP_ROOT:-$ROOT/backups}/${_id}.tar.gz" \
      "${BACKUP_ROOT:-$ROOT/backups}/${_id}.tar.gz.enc" \
      "${BACKUP_ROOT:-$ROOT/backups}/${_id}" \
      "$ROOT/backups/${_id}.tar.gz" \
      "$ROOT/backups/${_id}"
    do
      if [ -e "$cand" ]; then
        _ref="$cand"
        break
      fi
    done
  fi

  if [ ! -e "$_ref" ]; then
    # Try docker volume via backup-worker / backend
    _id=$(basename "${1}")
    echo "[restore] looking up archive in backup_data volume for ${_id}..."
    _tmp="$ROOT/backups/.restore-work/$$"
    mkdir -p "$_tmp"
    if docker compose exec -T backup-worker sh -c "test -f /data/backups/${_id}.tar.gz" 2>/dev/null; then
      docker compose exec -T backup-worker cat "/data/backups/${_id}.tar.gz" > "${_tmp}/${_id}.tar.gz"
      _ref="${_tmp}/${_id}.tar.gz"
    elif docker compose exec -T backup-worker sh -c "test -f /data/backups/${_id}.tar.gz.enc" 2>/dev/null; then
      docker compose exec -T backup-worker cat "/data/backups/${_id}.tar.gz.enc" > "${_tmp}/${_id}.tar.gz.enc"
      _ref="${_tmp}/${_id}.tar.gz.enc"
    elif docker compose exec -T backend sh -c "test -f /data/backups/${_id}.tar.gz" 2>/dev/null; then
      docker compose exec -T backend cat "/data/backups/${_id}.tar.gz" > "${_tmp}/${_id}.tar.gz"
      _ref="${_tmp}/${_id}.tar.gz"
    else
      echo "[restore] backup not found: $1" >&2
      return 1
    fi
  fi

  if [ -d "$_ref" ]; then
    BUNDLE_DIR="$_ref"
    return 0
  fi

  case "$_ref" in
    *.tar.gz.enc)
      if [ -z "${BACKUP_ENCRYPTION_KEY_FILE:-}" ] || [ ! -f "$BACKUP_ENCRYPTION_KEY_FILE" ]; then
        echo "[restore] encrypted archive requires BACKUP_ENCRYPTION_KEY_FILE" >&2
        return 1
      fi
      _dec="${_ref%.enc}"
      echo "[restore] decrypting archive..."
      docker compose run --rm --no-deps \
        -v "$(dirname "$_ref"):/work" \
        -v "$BACKUP_ENCRYPTION_KEY_FILE:/key:ro" \
        -e BACKUP_ENCRYPTION_ENABLED=true \
        -e BACKUP_ENCRYPTION_KEY_FILE=/key \
        backend node -e "
          import { readFileSync } from 'fs';
          import { decryptFile } from './lib/backup/encryption.js';
          import { loadEncryptionKey } from './lib/backup/config.js';
          const key = loadEncryptionKey();
          await decryptFile('/work/$(basename "$_ref")', '/work/$(basename "$_dec")', key);
        "
      _ref="$_dec"
      ;;
  esac

  case "$_ref" in
    *.tar.gz)
      _extract="$ROOT/backups/.restore-work/extract-$$"
      mkdir -p "$_extract"
      tar -xzf "$_ref" -C "$_extract"
      _top=$(ls "$_extract" | head -n 1)
      BUNDLE_DIR="$_extract/$_top"
      ;;
    *)
      echo "[restore] unsupported backup artifact: $_ref" >&2
      return 1
      ;;
  esac
}

find_postgres_dump() {
  dir="$1"
  if [ -f "${dir}/database/postgres.dump" ]; then
    echo "${dir}/database/postgres.dump"
  elif [ -f "${dir}/postgres.dump" ]; then
    echo "${dir}/postgres.dump"
  else
    return 1
  fi
}

write_readme() {
  out="$1"
  stamp="$2"
  cat > "$out" <<EOF
TalonHound backup bundle
========================
Created (UTC): ${stamp}
Git commit: $(git_sha)

Components:
- PostgreSQL: postgres.dump (pg_dump custom format, required)
- Redis: excluded (runtime/queue state; not restored)

Restore:

  ./scripts/restore-stack.sh --backup-id <backup_id> --confirm

After restore, reconcile integration queues from Threat Intelligence > Job Queue Status
if recovery_needed is reported.
EOF
}

write_manifest() {
  dir="$1"
  stamp="$2"
  pg_bytes="$3"
  created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  cat > "${dir}/manifest.json" <<EOF
{
  "format_version": 2,
  "backup_id": "talonhound-${stamp}",
  "created_at": "${created_at}",
  "application": "TalonHound",
  "git_sha": "$(git_sha)",
  "trigger_type": "manual",
  "result": "completed",
  "encrypted": false,
  "compression": "none",
  "included_components": ["postgresql"],
  "excluded_components": ["redis", "env_secrets", "tls_certs", "ioc_search_exports", "clickhouse"],
  "components": {
    "postgres": {
      "file": "postgres.dump",
      "format": "pg_custom",
      "bytes": ${pg_bytes}
    }
  },
  "restore": {
    "method": "cli",
    "script": "scripts/restore-stack.sh",
    "api_restore_writes_data": false
  }
}
EOF
}

write_checksums() {
  dir="$1"
  (
    cd "$dir" || exit 1
    if [ -f postgres.dump ]; then
      sha256sum postgres.dump
    elif [ -f database/postgres.dump ]; then
      sha256sum database/postgres.dump
    fi
  ) > "${dir}/checksums.sha256"
}

verify_checksums() {
  dir="$1"
  if [ ! -f "${dir}/checksums.sha256" ]; then
    echo "[restore] checksums.sha256 missing" >&2
    return 1
  fi
  (
    cd "$dir" || exit 1
    sha256sum -c checksums.sha256
  )
}

stop_writers() {
  echo "[restore] stopping writer services..."
  # shellcheck disable=SC2086
  docker compose stop $WRITER_SERVICES
}

start_writers() {
  echo "[restore] starting core services..."
  docker compose up -d db redis
  docker compose up -d backend integration-scheduler integration-worker ioc-expiration-worker ioc-search-export-worker backup-worker frontend proxy
}

create_safety_backup() {
  echo "[restore] creating safety backup of current database..."
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  SAFETY_ROOT="${BACKUP_ROOT:-$ROOT/backups}"
  SAFETY_DIR="${SAFETY_ROOT}/safety-${STAMP}"
  mkdir -p "$SAFETY_DIR"
  PG_OUT="${SAFETY_DIR}/postgres.dump"
  if ! docker compose exec -T db pg_dump -U demo -d demo -Fc > "$PG_OUT"; then
    echo "[restore] safety backup pg_dump failed — aborting restore" >&2
    return 1
  fi
  PG_BYTES=$(wc -c < "$PG_OUT" | tr -d ' ')
  if [ "${PG_BYTES:-0}" -le 0 ]; then
    echo "[restore] safety backup empty — aborting restore" >&2
    return 1
  fi
  write_readme "${SAFETY_DIR}/README.txt" "safety-${STAMP}"
  write_manifest "$SAFETY_DIR" "safety-${STAMP}" "$PG_BYTES"
  write_checksums "$SAFETY_DIR"
  echo "[restore] safety backup -> $SAFETY_DIR"
  SAFETY_BACKUP_DIR="$SAFETY_DIR"
}

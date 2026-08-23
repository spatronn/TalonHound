# Shared helpers for backup-stack.sh and restore-stack.sh (POSIX sh).

# Writer services stopped during restore to avoid concurrent writes.
WRITER_SERVICES="backend integration-scheduler integration-worker ioc-expiration-worker ioc-search-export-worker ioc-deep-search-worker ioc-bulk-query-worker backup-worker"

# Staging dirs created during resolve; cleaned on failure via cleanup_restore_work.
RESTORE_WORK_DIRS=""

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

register_restore_work() {
  RESTORE_WORK_DIRS="${RESTORE_WORK_DIRS} $1"
}

cleanup_restore_work() {
  for _d in $RESTORE_WORK_DIRS; do
    [ -n "$_d" ] || continue
    rm -rf "$_d" 2>/dev/null || true
  done
  RESTORE_WORK_DIRS=""
}

# Reject tar members with absolute paths, .., or symlink/hardlink entries.
validate_tar_members() {
  _archive="$1"
  _members_file=$(mktemp)
  if ! tar -tzf "$_archive" > "$_members_file" 2>/dev/null; then
    rm -f "$_members_file"
    echo "[restore] cannot list archive members" >&2
    return 1
  fi
  _unsafe=0
  while IFS= read -r _member; do
    [ -n "$_member" ] || continue
    case "$_member" in
      /*|*".."*)
        echo "[restore] unsafe archive member rejected: $_member" >&2
        _unsafe=1
        break
        ;;
    esac
  done < "$_members_file"
  rm -f "$_members_file"
  if [ "$_unsafe" -ne 0 ]; then
    return 1
  fi

  if tar -tvzf "$_archive" 2>/dev/null | grep -E '^[lh]' >/dev/null 2>&1; then
    echo "[restore] archive contains symlink or hardlink entries — rejected" >&2
    return 1
  fi
  return 0
}

resolve_backup_bundle() {
  # Sets BUNDLE_DIR to an extracted/legacy directory containing postgres.dump or database/postgres.dump
  # Input: BACKUP_REF (path to dir, .tar.gz, .tar.gz.enc, or backup_id)
  # Does NOT require a system_backups DB registry row.
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
    register_restore_work "$_tmp"
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
      echo "[restore] validating archive members..."
      validate_tar_members "$_ref" || return 1
      _extract="$ROOT/backups/.restore-work/extract-$$"
      mkdir -p "$_extract"
      register_restore_work "$_extract"
      tar -xzf "$_ref" -C "$_extract"
      _top=$(ls "$_extract" | head -n 1)
      if [ -z "$_top" ]; then
        echo "[restore] archive extracted empty" >&2
        return 1
      fi
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

# Returns 0 when target DB looks empty/fresh (skip safety); 1 when populated.
target_db_is_empty() {
  # Prefer live tuple estimate across user tables; fall back to ioc_items/users if present.
  _count=$(docker compose exec -T db psql -U talonhound -d talonhound -Atc \
    "SELECT COALESCE(SUM(n_live_tup), 0)::bigint
     FROM pg_stat_user_tables
     WHERE schemaname = 'public'" 2>/dev/null | tr -d '[:space:]') || _count=""

  if [ -z "$_count" ]; then
    echo "[restore] could not probe target DB emptiness — treating as populated" >&2
    return 1
  fi

  if [ "$_count" -le 50 ]; then
    # Fresh installs after migrate have schema + seed rows but little app data.
    # Double-check meaningful tables when they exist.
    _app=$(docker compose exec -T db psql -U talonhound -d talonhound -Atc \
      "SELECT
         (CASE WHEN to_regclass('public.ioc_items') IS NOT NULL
               THEN (SELECT COUNT(*) FROM ioc_items) ELSE 0 END)
       + (CASE WHEN to_regclass('public.users') IS NOT NULL
               THEN (SELECT COUNT(*) FROM users) ELSE 0 END)" 2>/dev/null | tr -d '[:space:]') || _app="1"
    if [ "${_app:-1}" -eq 0 ]; then
      return 0
    fi
    if [ "$_count" -eq 0 ]; then
      return 0
    fi
  fi
  return 1
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

Restore (host CLI only — no GUI restore):

  ./scripts/restore-stack.sh --file /path/to/archive.tar.gz --confirm
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
  docker compose up -d backend integration-scheduler integration-worker \
    ioc-expiration-worker ioc-search-export-worker ioc-deep-search-worker ioc-bulk-query-worker \
    backup-worker frontend proxy
}

# --- Restore target validation (identifier-safe; no secrets in logs) ---

validate_restore_db_identifier() {
  _val="$1"
  _label="$2"
  case "$_val" in
    ''|*[!a-zA-Z0-9_]*)
      echo "[restore] invalid ${_label} identifier" >&2
      return 1
      ;;
  esac
  case "$_val" in
    [0-9]*)
      echo "[restore] invalid ${_label} identifier" >&2
      return 1
      ;;
  esac
  return 0
}

resolve_restore_db_identifiers() {
  RESTORE_DB_USER="${DB_USER:-talonhound}"
  RESTORE_DB_NAME="${DB_NAME:-talonhound}"
  validate_restore_db_identifier "$RESTORE_DB_USER" "DB user" || return 1
  validate_restore_db_identifier "$RESTORE_DB_NAME" "DB name" || return 1
  case "$RESTORE_DB_NAME" in
    postgres|template0|template1)
      echo "[restore] refused: cannot restore into system database '${RESTORE_DB_NAME}'" >&2
      return 1
      ;;
  esac
  return 0
}

validate_backup_manifest() {
  _manifest="$1"
  if [ ! -f "$_manifest" ]; then
    echo "[restore] manifest.json missing" >&2
    return 1
  fi
  if ! grep -q '"application"[[:space:]]*:[[:space:]]*"TalonHound"' "$_manifest" 2>/dev/null; then
    echo "[restore] manifest application is not TalonHound — refused" >&2
    return 1
  fi
  _fv=$(sed -n 's/.*"format_version"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$_manifest" | head -n 1)
  if [ -n "$_fv" ] && [ "$_fv" -gt 2 ]; then
    echo "[restore] unsupported manifest format_version ${_fv}" >&2
    return 1
  fi
  return 0
}

# docker compose exec does not reliably pass host stdin to pg_restore on all hosts;
# copy the dump into the db container and use a file path instead of "-".
stage_dump_in_db_container() {
  _host_dump="$1"
  _suffix="${2:-$$}"
  STAGED_DUMP_CONTAINER_PATH="/tmp/talonhound-restore-${_suffix}.dump"
  if ! docker compose cp "$_host_dump" "db:${STAGED_DUMP_CONTAINER_PATH}"; then
    echo "[restore] failed to copy dump into db container" >&2
    STAGED_DUMP_CONTAINER_PATH=""
    return 1
  fi
  return 0
}

unstage_dump_in_db_container() {
  _path="${1:-${STAGED_DUMP_CONTAINER_PATH:-}}"
  [ -n "$_path" ] || return 0
  docker compose exec -T db rm -f "$_path" 2>/dev/null || true
  STAGED_DUMP_CONTAINER_PATH=""
}

compose_pg_restore_list() {
  _dump="$1"
  if ! stage_dump_in_db_container "$_dump"; then
    return 1
  fi
  docker compose exec -T db pg_restore --list "$STAGED_DUMP_CONTAINER_PATH"
  _rc=$?
  unstage_dump_in_db_container
  return "$_rc"
}

compose_pg_restore_into_db() {
  _dump="$1"
  _db="$2"
  _user="$3"
  shift 3
  if ! stage_dump_in_db_container "$_dump"; then
    return 1
  fi
  _err=$(mktemp)
  if ! docker compose exec -T db pg_restore \
    -U "$_user" -d "$_db" \
    --no-owner --no-acl --exit-on-error \
    "$@" \
    "$STAGED_DUMP_CONTAINER_PATH" 2>"$_err"; then
    echo "[restore] pg_restore failed — restore aborted" >&2
    sed -n '1,40p' "$_err" >&2 || true
    rm -f "$_err"
    unstage_dump_in_db_container
    return 1
  fi
  rm -f "$_err"
  unstage_dump_in_db_container
  return 0
}

validate_dump_readable() {
  _dump="$1"
  if [ ! -s "$_dump" ]; then
    echo "[restore] postgres dump missing or empty" >&2
    return 1
  fi
  _list_err=$(mktemp)
  if ! stage_dump_in_db_container "$_dump"; then
    rm -f "$_list_err"
    return 1
  fi
  if ! docker compose exec -T db pg_restore --list "$STAGED_DUMP_CONTAINER_PATH" > /dev/null 2>"$_list_err"; then
    echo "[restore] pg_restore --list failed — dump unreadable" >&2
    sed -n '1,20p' "$_list_err" >&2 || true
    rm -f "$_list_err"
    unstage_dump_in_db_container
    return 1
  fi
  rm -f "$_list_err"
  if ! docker compose exec -T db pg_restore --list "$STAGED_DUMP_CONTAINER_PATH" 2>/dev/null | grep -q schema_migrations; then
    echo "[restore] dump missing schema_migrations — incompatible backup" >&2
    unstage_dump_in_db_container
    return 1
  fi
  unstage_dump_in_db_container
  return 0
}

recreate_restore_target_database() {
  _db="$RESTORE_DB_NAME"
  _user="$RESTORE_DB_USER"
  echo "[restore] recreating target database '${_db}' (terminate connections, DROP DATABASE WITH FORCE, CREATE)..."
  if ! docker compose exec -T db psql -U "$_user" -d postgres -v ON_ERROR_STOP=1 <<SQL
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = '${_db}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS "${_db}" WITH (FORCE);
CREATE DATABASE "${_db}" OWNER "${_user}";
SQL
  then
    echo "[restore] failed to recreate target database '${_db}'" >&2
    return 1
  fi
  return 0
}

run_pg_restore_into_target() {
  _dump="$1"
  _db="$RESTORE_DB_NAME"
  _user="$RESTORE_DB_USER"
  echo "[restore] pg_restore into ${_db} (fresh database; no --clean)..."
  compose_pg_restore_into_db "$_dump" "$_db" "$_user"
}

create_safety_backup() {
  echo "[restore] creating safety backup of current database..."
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  SAFETY_ROOT="${BACKUP_ROOT:-$ROOT/backups}"
  SAFETY_DIR="${SAFETY_ROOT}/safety-${STAMP}"
  mkdir -p "$SAFETY_DIR"
  PG_OUT="${SAFETY_DIR}/postgres.dump"
  if ! docker compose exec -T db pg_dump -U talonhound -d talonhound -Fc > "$PG_OUT"; then
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

#!/usr/bin/env bash
# Rename PostgreSQL database + login role in-place (no volume recreate).
#
# Default: demo → talonhound (database and role).
#
# Manual only — do NOT run automatically in CI/deploy.
# Prerequisites:
#   - Fresh verified backup completed
#   - App writer services stopped (db container stays up with existing volume)
#   - Run from the compose project root (unless PG_CONTAINER is set)
#
# Why a temporary admin role?
#   Official image with POSTGRES_USER=<app> has no separate "postgres" superuser.
#   PostgreSQL rejects: ALTER ROLE <session_user> RENAME TO ...
#   ("ERROR: session user cannot be renamed"). Role rename therefore runs on a
#   short-lived LOGIN SUPERUSER connection, never as the source role itself.
#
# Usage:
#   ./scripts/rename-postgres-identity.sh
#   ./scripts/rename-postgres-identity.sh --dry-run
#   PG_CONTAINER=my-pg ./scripts/rename-postgres-identity.sh   # disposable test
#
# Rollback (manual, after stopping writers):
#   SOURCE_DB=talonhound SOURCE_ROLE=talonhound TARGET_DB=demo TARGET_ROLE=demo \
#     ./scripts/rename-postgres-identity.sh
#
# Never runs docker compose down -v, volume rm, or password changes on app roles.

set -euo pipefail

SOURCE_DB="${SOURCE_DB:-demo}"
SOURCE_ROLE="${SOURCE_ROLE:-demo}"
TARGET_DB="${TARGET_DB:-talonhound}"
TARGET_ROLE="${TARGET_ROLE:-talonhound}"
MAINT_DB="${MAINT_DB:-postgres}"
# Optional: docker container name for disposable tests (skips compose + writer checks).
PG_CONTAINER="${PG_CONTAINER:-}"
DRY_RUN=0

ORIG_SOURCE_DB="$SOURCE_DB"
ORIG_SOURCE_ROLE="$SOURCE_ROLE"

# Set only while a temp admin created by THIS run exists; trap drops exact name only.
TEMP_ADMIN_ROLE=""
TEMP_ADMIN_PASS=""
PROBE_ROLE=""

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      sed -n '2,32p' "$0"
      exit 0
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    *)
      echo "[rename-pg] unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

log() { printf '[rename-pg] %s\n' "$*"; }
die() { printf '[rename-pg] ERROR: %s\n' "$*" >&2; exit 1; }

sql_ident() {
  printf '"%s"' "$(printf '%s' "$1" | sed 's/"/""/g')"
}

sql_literal() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

assert_safe_name() {
  case "$1" in
    ''|*[!a-zA-Z0-9_]*)
      die "unsafe identifier rejected: $1 (allowed: [A-Za-z0-9_]+)"
      ;;
  esac
}

assert_safe_name "$SOURCE_DB"
assert_safe_name "$SOURCE_ROLE"
assert_safe_name "$TARGET_DB"
assert_safe_name "$TARGET_ROLE"
assert_safe_name "$MAINT_DB"

if [ "$SOURCE_DB" = "$TARGET_DB" ] && [ "$SOURCE_ROLE" = "$TARGET_ROLE" ]; then
  die "source and target are identical; nothing to do"
fi
if [ "$TARGET_DB" = "$MAINT_DB" ] || [ "$SOURCE_DB" = "$MAINT_DB" ]; then
  die "refusing to rename maintenance database '$MAINT_DB'"
fi

# --- container helpers -------------------------------------------------------

db_cid() {
  if [ -n "$PG_CONTAINER" ]; then
    docker inspect -f '{{.Id}}' "$PG_CONTAINER" 2>/dev/null || true
  else
    docker compose ps -q db 2>/dev/null || true
  fi
}

# Unix-socket psql as role (trust inside official image). SQL via -c is OK when
# it contains no secrets. For secret SQL use psql_socket_sql_stdin.
psql_socket() {
  _role="$1"
  shift
  if [ -n "$PG_CONTAINER" ]; then
    docker exec -i "$PG_CONTAINER" \
      psql -U "$_role" -d "$MAINT_DB" -v ON_ERROR_STOP=1 "$@"
  else
    docker compose exec -T db \
      psql -U "$_role" -d "$MAINT_DB" -v ON_ERROR_STOP=1 "$@"
  fi
}

psql_socket_atc() {
  _role="$1"
  shift
  psql_socket "$_role" -Atc "$*"
}

# Feed SQL on stdin (keeps passwords out of psql argv).
psql_socket_sql_stdin() {
  _role="$1"
  if [ -n "$PG_CONTAINER" ]; then
    docker exec -i "$PG_CONTAINER" \
      psql -U "$_role" -d "$MAINT_DB" -v ON_ERROR_STOP=1 -f -
  else
    docker compose exec -T db \
      psql -U "$_role" -d "$MAINT_DB" -v ON_ERROR_STOP=1 -f -
  fi
}

# TCP + PGPASSWORD (password never on argv; env only for this invocation).
psql_tcp_atc() {
  _role="$1"
  shift
  if [ -z "${PGPASSWORD:-}" ]; then
    die "internal: PGPASSWORD unset for tcp auth as $_role"
  fi
  if [ -n "$PG_CONTAINER" ]; then
    docker exec -e PGPASSWORD -i "$PG_CONTAINER" \
      psql -h 127.0.0.1 -U "$_role" -d "$MAINT_DB" -v ON_ERROR_STOP=1 -Atc "$*"
  else
    docker compose exec -e PGPASSWORD -T db \
      psql -h 127.0.0.1 -U "$_role" -d "$MAINT_DB" -v ON_ERROR_STOP=1 -Atc "$*"
  fi
}

psql_tcp_sql_stdin() {
  _role="$1"
  if [ -z "${PGPASSWORD:-}" ]; then
    die "internal: PGPASSWORD unset for tcp auth as $_role"
  fi
  if [ -n "$PG_CONTAINER" ]; then
    docker exec -e PGPASSWORD -i "$PG_CONTAINER" \
      psql -h 127.0.0.1 -U "$_role" -d "$MAINT_DB" -v ON_ERROR_STOP=1 -f -
  else
    docker compose exec -e PGPASSWORD -T db \
      psql -h 127.0.0.1 -U "$_role" -d "$MAINT_DB" -v ON_ERROR_STOP=1 -f -
  fi
}

# App-db queries (postcheck) via unix socket.
psql_app_atc() {
  _role="$1"
  _db="$2"
  shift 2
  if [ -n "$PG_CONTAINER" ]; then
    docker exec -i "$PG_CONTAINER" \
      psql -U "$_role" -d "$_db" -v ON_ERROR_STOP=1 -Atc "$*"
  else
    docker compose exec -T db \
      psql -U "$_role" -d "$_db" -v ON_ERROR_STOP=1 -Atc "$*"
  fi
}

can_login_socket() {
  _role="$1"
  psql_socket_atc "$_role" "SELECT 1" >/dev/null 2>&1
}

role_exists_as() {
  _as="$1"
  _name="$2"
  _n=$(psql_socket_atc "$_as" "SELECT 1 FROM pg_roles WHERE rolname = $(sql_literal "$_name") LIMIT 1" | tr -d '[:space:]' || true)
  [ "${_n}" = "1" ]
}

db_exists_as() {
  _as="$1"
  _name="$2"
  _n=$(psql_socket_atc "$_as" "SELECT 1 FROM pg_database WHERE datname = $(sql_literal "$_name") LIMIT 1" | tr -d '[:space:]' || true)
  [ "${_n}" = "1" ]
}

list_temp_admins_as() {
  _as="$1"
  psql_socket_atc "$_as" \
    "SELECT rolname FROM pg_roles WHERE rolname ~ '^th_rename_admin_[a-f0-9]{12}$' ORDER BY 1" \
    | tr -d '\r' || true
}

gen_temp_admin_name() {
  _hex=""
  if command -v openssl >/dev/null 2>&1; then
    _hex=$(openssl rand -hex 6)
  else
    _hex=$(tr -dc 'a-f0-9' </dev/urandom | head -c 12)
  fi
  [ -n "$_hex" ] || die "failed to generate temp admin name"
  printf 'th_rename_admin_%s' "$_hex"
}

gen_temp_password() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 33 | tr -d '\n'
  else
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40
  fi
}

is_our_temp_admin_name() {
  case "$1" in
    th_rename_admin_[a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9][a-f0-9])
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

drop_temp_admin_as() {
  _as="$1"
  _temp="$2"
  is_our_temp_admin_name "$_temp" || die "refusing to drop non-temp role: $_temp"
  case "$_temp" in
    "$SOURCE_ROLE"|"$TARGET_ROLE"|"$ORIG_SOURCE_ROLE"|"postgres")
      die "refusing to drop protected role name: $_temp"
      ;;
  esac
  if role_exists_as "$_as" "$_temp"; then
    log "dropping temporary admin role ${_temp}"
    # stdin SQL — no password here
    printf 'DROP ROLE IF EXISTS %s;\n' "$(sql_ident "$_temp")" \
      | psql_socket_sql_stdin "$_as" >/dev/null
  fi
}

cleanup_on_exit() {
  _ec=$?
  # Never print TEMP_ADMIN_PASS.
  if [ -n "${TEMP_ADMIN_ROLE:-}" ] && is_our_temp_admin_name "$TEMP_ADMIN_ROLE"; then
    _drop_as=""
    if can_login_socket "$TARGET_ROLE" 2>/dev/null; then
      _drop_as="$TARGET_ROLE"
    elif can_login_socket "$SOURCE_ROLE" 2>/dev/null; then
      _drop_as="$SOURCE_ROLE"
    elif can_login_socket "$ORIG_SOURCE_ROLE" 2>/dev/null; then
      _drop_as="$ORIG_SOURCE_ROLE"
    fi
    if [ -n "$_drop_as" ]; then
      drop_temp_admin_as "$_drop_as" "$TEMP_ADMIN_ROLE" || \
        printf '[rename-pg] WARN: failed to drop temp admin %s — drop manually as superuser\n' "$TEMP_ADMIN_ROLE" >&2
    else
      printf '[rename-pg] WARN: cannot login to drop temp admin %s — drop manually\n' "$TEMP_ADMIN_ROLE" >&2
    fi
  fi
  TEMP_ADMIN_ROLE=""
  TEMP_ADMIN_PASS=""
  unset PGPASSWORD 2>/dev/null || true
  unset TEMP_ADMIN_PASS 2>/dev/null || true
  exit "$_ec"
}

trap cleanup_on_exit EXIT INT TERM

assert_writers_stopped() {
  [ -z "$PG_CONTAINER" ] || return 0
  _running=$(docker compose ps --status running --services 2>/dev/null || true)
  _bad=""
  for _svc in backend integration-scheduler integration-worker \
    ioc-expiration-worker ioc-search-export-worker backup-worker; do
    if printf '%s\n' "$_running" | grep -qx "$_svc"; then
      _bad="${_bad} ${_svc}"
    fi
  done
  if [ -n "$_bad" ]; then
    die "writer services still running:${_bad} — stop them before rename"
  fi
  log "writer services stopped (verified)"
}

# --- begin -------------------------------------------------------------------

log "project root: $ROOT"
log "plan: database ${SOURCE_DB} → ${TARGET_DB}, role ${SOURCE_ROLE} → ${TARGET_ROLE}"
log "maintenance DB: ${MAINT_DB}"
if [ -n "$PG_CONTAINER" ]; then
  log "PG_CONTAINER=$PG_CONTAINER (compose writer checks skipped)"
fi
if [ "$DRY_RUN" -eq 1 ]; then
  log "mode: dry-run (no DDL, no temporary role)"
fi

DB_CID="$(db_cid)"
[ -n "$DB_CID" ] || die "db container not running"

VOL_NAME="$(docker inspect "$DB_CID" --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}')"
# Disposable anonymous volumes may have empty Name — accept Source path then.
if [ -z "$VOL_NAME" ]; then
  VOL_NAME="$(docker inspect "$DB_CID" --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Source}}{{end}}{{end}}')"
fi
[ -n "$VOL_NAME" ] || die "could not resolve postgres data volume mount"
log "postgres data volume: $VOL_NAME (will not be modified/removed)"

PROBE_ROLE=""
if can_login_socket "$SOURCE_ROLE"; then
  PROBE_ROLE="$SOURCE_ROLE"
elif can_login_socket "$TARGET_ROLE"; then
  PROBE_ROLE="$TARGET_ROLE"
else
  die "cannot connect as '$SOURCE_ROLE' or '$TARGET_ROLE' to '$MAINT_DB'"
fi
log "probe login role: $PROBE_ROLE"

src_db=0; tgt_db=0; src_role=0; tgt_role=0
db_exists_as "$PROBE_ROLE" "$SOURCE_DB" && src_db=1
db_exists_as "$PROBE_ROLE" "$TARGET_DB" && tgt_db=1
role_exists_as "$PROBE_ROLE" "$SOURCE_ROLE" && src_role=1
role_exists_as "$PROBE_ROLE" "$TARGET_ROLE" && tgt_role=1

LEFTOVER_TEMP=$(list_temp_admins_as "$PROBE_ROLE" | tr '\n' ' ' | sed 's/[[:space:]]*$//')
if [ -n "$LEFTOVER_TEMP" ]; then
  log "leftover temporary admin role(s) detected: $LEFTOVER_TEMP"
fi

log "precheck: source_db=$src_db target_db=$tgt_db source_role=$src_role target_role=$tgt_role"

# Idempotent success
if [ "$tgt_db" -eq 1 ] && [ "$tgt_role" -eq 1 ] \
  && [ "$src_db" -eq 0 ] \
  && { [ "$src_role" -eq 0 ] || [ "$SOURCE_ROLE" = "$TARGET_ROLE" ]; }; then
  if [ -n "$LEFTOVER_TEMP" ]; then
    die "rename already complete but leftover temp admin(s) remain: $LEFTOVER_TEMP — drop exactly those roles as '$TARGET_ROLE', then re-run"
  fi
  log "already renamed: database='$TARGET_DB' role='$TARGET_ROLE'"
  log "idempotent success — no changes made"
  TEMP_ADMIN_ROLE=""
  exit 0
fi

if [ "$src_db" -eq 1 ] && [ "$tgt_db" -eq 1 ]; then
  die "conflict: both databases '$SOURCE_DB' and '$TARGET_DB' exist — resolve manually (no auto-merge/drop)"
fi
if [ "$src_role" -eq 1 ] && [ "$tgt_role" -eq 1 ] && [ "$SOURCE_ROLE" != "$TARGET_ROLE" ]; then
  die "conflict: both roles '$SOURCE_ROLE' and '$TARGET_ROLE' exist — resolve manually"
fi
if [ "$src_db" -eq 0 ] && [ "$tgt_db" -eq 0 ]; then
  die "neither source db '$SOURCE_DB' nor target db '$TARGET_DB' exists"
fi
if [ "$src_role" -eq 0 ] && [ "$tgt_role" -eq 0 ]; then
  die "neither source role '$SOURCE_ROLE' nor target role '$TARGET_ROLE' exists"
fi

need_db_rename=0
need_role_rename=0
[ "$src_db" -eq 1 ] && [ "$tgt_db" -eq 0 ] && need_db_rename=1
[ "$src_role" -eq 1 ] && [ "$tgt_role" -eq 0 ] && [ "$SOURCE_ROLE" != "$TARGET_ROLE" ] && need_role_rename=1

# Classify partial states explicitly
partial_kind="none"
if [ "$need_db_rename" -eq 0 ] && [ "$need_role_rename" -eq 1 ]; then
  partial_kind="db_done_role_pending"
elif [ "$need_db_rename" -eq 1 ] && [ "$need_role_rename" -eq 0 ]; then
  partial_kind="role_done_db_pending"
elif [ "$need_db_rename" -eq 1 ] && [ "$need_role_rename" -eq 1 ]; then
  partial_kind="full_rename"
else
  die "unexpected state (source_db=$src_db target_db=$tgt_db source_role=$src_role target_role=$tgt_role leftover_temp='${LEFTOVER_TEMP}') — refusing to change anything"
fi
log "state: $partial_kind"

if [ -n "$LEFTOVER_TEMP" ]; then
  die "refusing to proceed while leftover temp admin(s) exist: $LEFTOVER_TEMP — inspect, then DROP ROLE only those exact names as current superuser and re-run"
fi

# Role rename cannot use session user == source role.
temporary_admin_required=0
if [ "$need_role_rename" -eq 1 ]; then
  temporary_admin_required=1
fi

if [ "$need_db_rename" -eq 1 ]; then
  CONNS=$(psql_socket_atc "$PROBE_ROLE" \
    "SELECT count(*)::text FROM pg_stat_activity WHERE datname = $(sql_literal "$SOURCE_DB") AND pid <> pg_backend_pid()" \
    | tr -d '[:space:]' || echo "?")
  log "active sessions on '$SOURCE_DB' (excluding self): ${CONNS}"
  OWNER_BEFORE=$(psql_socket_atc "$PROBE_ROLE" \
    "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname = $(sql_literal "$SOURCE_DB")" \
    | tr -d '[:space:]')
  log "database '$SOURCE_DB' owner: ${OWNER_BEFORE:-unknown}"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  # Demonstrate the session-user constraint without mutating production roles:
  # we only assert that role rename must not run as SOURCE_ROLE.
  if [ "$need_role_rename" -eq 1 ]; then
    log "constraint: role rename MUST NOT run as session_user='$SOURCE_ROLE' (PG: session user cannot be renamed)"
    log "constraint: will open separate temporary LOGIN SUPERUSER connection for role rename"
  fi
  log "temporary_admin_required=$temporary_admin_required"
  log "database_rename=$need_db_rename"
  log "role_rename=$need_role_rename"
  log "postcheck_login=$TARGET_ROLE"
  if [ "$temporary_admin_required" -eq 1 ]; then
    log "temporary_admin_cleanup=planned"
  else
    log "temporary_admin_cleanup=not_needed"
  fi
  log "dry-run OK — no DDL executed"
  TEMP_ADMIN_ROLE=""
  exit 0
fi

assert_writers_stopped

SRC_DB_Q=$(sql_ident "$SOURCE_DB")
TGT_DB_Q=$(sql_ident "$TARGET_DB")
SRC_ROLE_Q=$(sql_ident "$SOURCE_ROLE")
TGT_ROLE_Q=$(sql_ident "$TARGET_ROLE")

# Connection A: create temp admin as current probe/source superuser (only if needed).
ADMIN_ROLE=""
if [ "$temporary_admin_required" -eq 1 ]; then
  # Must create temp admin while still able to login as SOURCE_ROLE (or PROBE if source).
  CREATE_AS="$SOURCE_ROLE"
  if ! can_login_socket "$CREATE_AS"; then
    die "cannot login as '$CREATE_AS' to create temporary admin (required for role rename)"
  fi

  TEMP_ADMIN_ROLE="$(gen_temp_admin_name)"
  TEMP_ADMIN_PASS="$(gen_temp_password)"
  [ -n "$TEMP_ADMIN_PASS" ] || die "failed to generate temporary password"
  is_our_temp_admin_name "$TEMP_ADMIN_ROLE" || die "internal: bad temp admin name"

  log "creating temporary admin role (name withheld pattern th_rename_admin_<hex>)..."
  # Password only on stdin to psql — never -c argv, never logged.
  {
    printf 'CREATE ROLE %s LOGIN SUPERUSER PASSWORD ' "$(sql_ident "$TEMP_ADMIN_ROLE")"
    printf '%s' "$(sql_literal "$TEMP_ADMIN_PASS")"
    printf ';\n'
  } | psql_socket_sql_stdin "$CREATE_AS" >/dev/null

  ADMIN_ROLE="$TEMP_ADMIN_ROLE"
  export PGPASSWORD="$TEMP_ADMIN_PASS"

  # Prove TCP auth works before mutating.
  if ! psql_tcp_atc "$ADMIN_ROLE" "SELECT current_user" >/dev/null; then
    die "temporary admin TCP login failed"
  fi
  _cu=$(psql_tcp_atc "$ADMIN_ROLE" "SELECT current_user" | tr -d '[:space:]')
  [ "$_cu" = "$ADMIN_ROLE" ] || die "temporary admin session user mismatch"
  log "temporary admin connection ready (session_user != $SOURCE_ROLE)"

  # Test-only fault injection (unset in production). Verifies trap cleanup.
  if [ "${RENAME_PG_FAULT:-}" = "after_temp_create" ]; then
    die "fault injection: after_temp_create"
  fi
else
  # DB-only rename: use TARGET_ROLE (already renamed) or SOURCE_ROLE.
  if [ "$tgt_role" -eq 1 ]; then
    ADMIN_ROLE="$TARGET_ROLE"
  else
    ADMIN_ROLE="$SOURCE_ROLE"
  fi
  log "temporary admin not required; using '$ADMIN_ROLE' for database rename"
fi

# Connection B: renames (as temp admin when role rename needed).
run_admin_sql() {
  if [ "$temporary_admin_required" -eq 1 ]; then
    printf '%s\n' "$1" | psql_tcp_sql_stdin "$ADMIN_ROLE" >/dev/null
  else
    printf '%s\n' "$1" | psql_socket_sql_stdin "$ADMIN_ROLE" >/dev/null
  fi
}

run_admin_atc() {
  if [ "$temporary_admin_required" -eq 1 ]; then
    psql_tcp_atc "$ADMIN_ROLE" "$1"
  else
    psql_socket_atc "$ADMIN_ROLE" "$1"
  fi
}

if [ "$need_db_rename" -eq 1 ]; then
  log "blocking new connections to '$SOURCE_DB'..."
  run_admin_sql "UPDATE pg_database SET datallowconn = false WHERE datname = $(sql_literal "$SOURCE_DB");"

  log "terminating remaining backends on '$SOURCE_DB'..."
  run_admin_atc "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $(sql_literal "$SOURCE_DB") AND pid <> pg_backend_pid();" >/dev/null || true

  log "renaming database ${SOURCE_DB} → ${TARGET_DB}..."
  run_admin_sql "ALTER DATABASE ${SRC_DB_Q} RENAME TO ${TGT_DB_Q};"

  log "allowing connections on '$TARGET_DB'..."
  run_admin_sql "UPDATE pg_database SET datallowconn = true WHERE datname = $(sql_literal "$TARGET_DB");"
fi

if [ "$need_role_rename" -eq 1 ]; then
  # Safety: ensure we are NOT session_user=SOURCE_ROLE
  _su=$(run_admin_atc "SELECT session_user" | tr -d '[:space:]')
  if [ "$_su" = "$SOURCE_ROLE" ]; then
    die "refusing role rename: session_user is still '$SOURCE_ROLE' (would fail: session user cannot be renamed)"
  fi
  log "renaming role ${SOURCE_ROLE} → ${TARGET_ROLE} via session_user=${_su} (password hash preserved)..."
  run_admin_sql "ALTER ROLE ${SRC_ROLE_Q} RENAME TO ${TGT_ROLE_Q};"
fi

# Drop PGPASSWORD before postcheck; close logical use of temp admin password.
unset PGPASSWORD 2>/dev/null || true
TEMP_ADMIN_PASS=""

# Connection C: postcheck as TARGET_ROLE; drop temp admin from here (not from temp's own session).
can_login_socket "$TARGET_ROLE" || die "postcheck: cannot login as '$TARGET_ROLE'"

if [ -n "$TEMP_ADMIN_ROLE" ]; then
  drop_temp_admin_as "$TARGET_ROLE" "$TEMP_ADMIN_ROLE"
  TEMP_ADMIN_ROLE=""
fi

log "postcheck..."
role_exists_as "$TARGET_ROLE" "$TARGET_ROLE" || die "postcheck failed: role '$TARGET_ROLE' missing"
db_exists_as "$TARGET_ROLE" "$TARGET_DB" || die "postcheck failed: database '$TARGET_DB' missing"

if [ "$ORIG_SOURCE_DB" != "$TARGET_DB" ] && db_exists_as "$TARGET_ROLE" "$ORIG_SOURCE_DB"; then
  die "postcheck failed: old database '$ORIG_SOURCE_DB' still exists"
fi
if [ "$ORIG_SOURCE_ROLE" != "$TARGET_ROLE" ] && role_exists_as "$TARGET_ROLE" "$ORIG_SOURCE_ROLE"; then
  die "postcheck failed: old role '$ORIG_SOURCE_ROLE' still exists"
fi

_left=$(list_temp_admins_as "$TARGET_ROLE" | tr '\n' ' ' | sed 's/[[:space:]]*$//')
[ -z "$_left" ] || die "postcheck failed: temporary admin role(s) still present: $_left"

OWNER_AFTER=$(psql_socket_atc "$TARGET_ROLE" \
  "SELECT pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname = $(sql_literal "$TARGET_DB")" \
  | tr -d '[:space:]')
log "database '$TARGET_DB' owner after: ${OWNER_AFTER}"

TABLE_OWNERS=$(psql_app_atc "$TARGET_ROLE" "$TARGET_DB" \
  "SELECT DISTINCT pg_catalog.pg_get_userbyid(c.relowner)
   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind = 'r'
   ORDER BY 1" | tr '\n' ',' | sed 's/,$//')
log "public table owners: ${TABLE_OWNERS:-none}"

VOL_AFTER="$(docker inspect "$DB_CID" --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Name}}{{end}}{{end}}')"
if [ -z "$VOL_AFTER" ]; then
  VOL_AFTER="$(docker inspect "$DB_CID" --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Source}}{{end}}{{end}}')"
fi
[ "$VOL_AFTER" = "$VOL_NAME" ] || die "volume mount changed unexpectedly ($VOL_NAME → $VOL_AFTER)"
log "volume unchanged: $VOL_AFTER"

log "SUCCESS: identity is database=$TARGET_DB role=$TARGET_ROLE"
log "Next: deploy compose with DB_USER/DB_NAME/POSTGRES_*=$TARGET_ROLE/$TARGET_DB, start writers, verify health + counts."
log "Rollback hint (manual): SOURCE_DB=$TARGET_DB SOURCE_ROLE=$TARGET_ROLE TARGET_DB=$ORIG_SOURCE_DB TARGET_ROLE=$ORIG_SOURCE_ROLE $0"

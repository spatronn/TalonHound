#!/usr/bin/env bash
#
# TalonHound safe upgrade — exact released versions only (never main/latest).
#
# Prefer GHCR images pinned by release-manifest.json digests/tags.
# Local .env secrets, volumes, and TLS material are preserved.
#
# Usage:
#   sudo ./scripts/upgrade.sh --upgrade
#   sudo ./scripts/upgrade.sh --upgrade-to 0.1.0-beta.3
#   sudo ./scripts/upgrade.sh --upgrade --dry-run
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

ENV_FILE="${TALONHOUND_ENV_FILE:-$ROOT/.env}"
COMPOSE=(docker compose --env-file "$ENV_FILE")
RELEASE_COMPOSE=(-f docker-compose.yml -f docker-compose.release.yml --env-file "$ENV_FILE")
LOCK_FILE="${TALONHOUND_UPGRADE_LOCK:-$ROOT/.talonhound-upgrade.lock}"
GITHUB_REPO="${TALONHOUND_GITHUB_REPO:-spatronn/TalonHound}"
GHCR_OWNER="${TALONHOUND_GHCR_OWNER:-spatronn}"
DISK_MIN_GB="${TALONHOUND_UPGRADE_DISK_MIN_GB:-15}"
HEALTH_TRIES="${TALONHOUND_UPGRADE_HEALTH_TRIES:-40}"
HEALTH_SLEEP_SEC="${TALONHOUND_UPGRADE_HEALTH_SLEEP_SEC:-5}"
MANIFEST_TIMEOUT_SEC="${TALONHOUND_UPGRADE_MANIFEST_TIMEOUT_SEC:-30}"

# Prefer host node when available; otherwise run helpers inside the backend image.
# Repo-root helpers mount the installation at /work (for release-manifest validation).
node_helper() {
  if command -v node >/dev/null 2>&1 && [ -d "$ROOT/backend/lib" ] && [ -f "$ROOT/backend/package.json" ]; then
    (cd "$ROOT/backend" && node "$@")
    return
  fi
  if docker compose --env-file "$ENV_FILE" ps --status running backend 2>/dev/null | grep -q backend; then
    docker compose --env-file "$ENV_FILE" exec -T backend node "$@"
    return
  fi
  docker compose --env-file "$ENV_FILE" run --rm --no-deps backend node "$@"
}

node_helper_stdin() {
  if command -v node >/dev/null 2>&1 && [ -d "$ROOT/backend/lib" ]; then
    (cd "$ROOT/backend" && node "$@")
    return
  fi
  if docker compose --env-file "$ENV_FILE" ps --status running backend 2>/dev/null | grep -q backend; then
    docker compose --env-file "$ENV_FILE" exec -T backend node "$@"
    return
  fi
  docker compose --env-file "$ENV_FILE" run --rm --no-deps -T backend node "$@"
}

# Node at repository root (host or bind-mounted into the backend image).
node_repo() {
  if command -v node >/dev/null 2>&1; then
    (cd "$ROOT" && node "$@")
    return
  fi
  docker compose --env-file "$ENV_FILE" run --rm --no-deps -T \
    -v "$ROOT:/work:ro" -w /work backend node "$@"
}

c_reset=$'\033[0m'; c_bold=$'\033[1m'; c_green=$'\033[32m'; c_yellow=$'\033[33m'; c_red=$'\033[31m'; c_cyan=$'\033[36m'
log()  { printf '%s\n' "$*"; }
info() { printf '%s[*]%s %s\n' "$c_cyan" "$c_reset" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$c_green" "$c_reset" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_yellow" "$c_reset" "$*"; }
die()  { printf '%s[x]%s %s\n' "$c_red" "$c_reset" "$*" >&2; exit 1; }

STEP=0
TOTAL_STEPS=8
phase_ok() {
  STEP=$((STEP + 1))
  printf '%s[%d/%d]%s %-28s %sOK%s\n' "$c_cyan" "$STEP" "$TOTAL_STEPS" "$c_reset" "$1" "$c_green" "$c_reset"
}
phase_fail() {
  STEP=$((STEP + 1))
  printf '%s[%d/%d]%s %-28s %sFAILED%s\n' "$c_cyan" "$STEP" "$TOTAL_STEPS" "$c_reset" "$1" "$c_red" "$c_reset" >&2
}

usage() {
  cat <<EOF
TalonHound upgrade

  sudo ./scripts/upgrade.sh --upgrade
  sudo ./scripts/upgrade.sh --upgrade-to <semver>
  sudo ./scripts/upgrade.sh --upgrade --dry-run
  sudo ./installation.sh --upgrade
  sudo ./installation.sh --upgrade-to <semver>
  sudo ./installation.sh --upgrade --dry-run

Upgrades always target an exact released version (GitHub Release + GHCR images).
Never upgrades from main or mutable tags like latest.

Options:
  --upgrade              Upgrade to the latest version for this installation's channel
  --upgrade-to VERSION   Upgrade to an exact SemVer (e.g. 0.1.0-beta.3)
  --dry-run              Validate only; do not mutate schema, containers, or data
  -h, --help             Show this help
EOF
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "Please run as root: sudo $0 --upgrade"
  fi
}

# Strict SemVer body (no leading v). Reject anything that could be shell-injected.
is_safe_semver() {
  local v="$1"
  [[ "$v" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]
}

normalize_version_arg() {
  local raw="$1"
  raw="${raw#v}"
  raw="$(printf '%s' "$raw" | tr -d '[:space:]')"
  if ! is_safe_semver "$raw"; then
    die "Invalid version: $1 (expected SemVer like 0.1.0-beta.3)"
  fi
  printf '%s' "$raw"
}

semver_cmp() {
  # prints -1, 0, or 1
  node_helper --input-type=module -e "
    import { compareSemVer } from './lib/releaseSemver.js';
    const r = compareSemVer(process.argv[1], process.argv[2]);
    if (r == null) process.exit(2);
    process.stdout.write(String(r));
  " "$1" "$2"
}

env_get() {
  local key="$1"
  [ -f "$ENV_FILE" ] || return 0
  sed -n "s/^${key}=//p" "$ENV_FILE" | head -n1
}

env_set() {
  local key="$1" value="$2"
  local tmp
  tmp="$(mktemp)"
  if [ -f "$ENV_FILE" ] && grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    grep -v "^${key}=" "$ENV_FILE" > "$tmp"
  elif [ -f "$ENV_FILE" ]; then
    cat "$ENV_FILE" > "$tmp"
  else
    : > "$tmp"
  fi
  printf '%s=%s\n' "$key" "$value" >> "$tmp"
  cat "$tmp" > "$ENV_FILE"
  rm -f "$tmp"
  chmod 600 "$ENV_FILE" 2>/dev/null || true
}

current_version() {
  local v
  v="$(env_get TALONHOUND_VERSION || true)"
  if [ -n "$v" ] && is_safe_semver "$v"; then
    printf '%s' "$v"
    return
  fi
  if [ -f "$ROOT/VERSION" ]; then
    tr -d '[:space:]' < "$ROOT/VERSION"
    return
  fi
  # Running container fallback
  if docker compose --env-file "$ENV_FILE" exec -T backend node -e \
      "fetch('http://127.0.0.1:3000/api/system/version').then(async r=>{const j=await r.json();process.stdout.write(j.version||'');process.exit(0)}).catch(()=>process.exit(1))" \
      2>/dev/null; then
    return
  fi
  die "Unable to determine current TalonHound version"
}

channel_for_version() {
  node_helper --input-type=module -e "
    import { releaseChannel } from './lib/releaseSemver.js';
    process.stdout.write(releaseChannel(process.argv[1]) || 'beta');
  " "$1"
}

default_manifest_url() {
  local channel="$1"
  local configured
  configured="$(env_get UPDATE_MANIFEST_URL || true)"
  if [ -n "$configured" ]; then
    printf '%s' "$configured"
    return
  fi
  printf 'https://raw.githubusercontent.com/%s/main/updates/%s.json' "$GITHUB_REPO" "$channel"
}

fetch_url() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time "$MANIFEST_TIMEOUT_SEC" --proto '=https' --proto-redir '=https' \
      -H 'Accept: application/json' -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$out" --timeout="$MANIFEST_TIMEOUT_SEC" "$url"
  else
    die "curl or wget is required to download release metadata"
  fi
}

resolve_latest_from_channel() {
  local channel="$1" url tmp latest
  url="$(default_manifest_url "$channel")"
  tmp="$(mktemp)"
  if ! fetch_url "$url" "$tmp"; then
    rm -f "$tmp"
    die "Failed to fetch channel update manifest from $url"
  fi
  if ! latest="$(node_helper_stdin --input-type=module -e "
    import { parseUpdateChannelManifestJson } from './lib/updateChannelManifest.js';
    const chunks = [];
    for await (const c of process.stdin) chunks.push(c);
    const text = Buffer.concat(chunks).toString('utf8');
    const parsed = parseUpdateChannelManifestJson(text);
    if (!parsed.ok) { console.error(parsed.error); process.exit(1); }
    if (parsed.manifest.channel !== process.argv[1]) {
      console.error('Channel mismatch in update manifest');
      process.exit(1);
    }
    process.stdout.write(parsed.manifest.latest);
  " "$channel" < "$tmp")"; then
    rm -f "$tmp"
    die "Channel update manifest was invalid"
  fi
  rm -f "$tmp"
  printf '%s' "$latest"
}

release_manifest_url() {
  local version="$1"
  printf 'https://github.com/%s/releases/download/v%s/release-manifest.json' "$GITHUB_REPO" "$version"
}

fetch_release_manifest() {
  local version="$1" dest="$2" url rel
  url="$(release_manifest_url "$version")"
  fetch_url "$url" "$dest" || die "Failed to download release-manifest.json for v${version} from ${url}"
  case "$dest" in
    "$ROOT"/*) rel="${dest#"$ROOT"/}" ;;
    *) die "Release manifest must be stored under the installation root for validation" ;;
  esac
  node_repo --input-type=module -e "
    import { readFileSync } from 'node:fs';
    import { validateReleaseManifest } from './scripts/release/generate-manifest.js';
    const raw = JSON.parse(readFileSync(process.argv[1], 'utf8'));
    const m = validateReleaseManifest(raw);
    if (m.version !== process.argv[2]) {
      console.error('Release manifest version mismatch');
      process.exit(1);
    }
  " "$rel" "$version"
}

image_ref_from_manifest() {
  local manifest="$1" key="$2" rel
  case "$manifest" in
    "$ROOT"/*) rel="${manifest#"$ROOT"/}" ;;
    *) die "Release manifest path must be under the installation root" ;;
  esac
  node_repo --input-type=module -e "
    import { readFileSync } from 'node:fs';
    const m = JSON.parse(readFileSync(process.argv[1], 'utf8'));
    const img = m.images?.[process.argv[2]];
    if (!img?.repository || !img?.tag) { process.exit(1); }
    process.stdout.write(img.repository + ':' + img.tag);
  " "$rel" "$key"
}

acquire_lock() {
  exec 9>"$LOCK_FILE"
  if command -v flock >/dev/null 2>&1; then
    if ! flock -n 9; then
      die "Another TalonHound upgrade is already running (lock: $LOCK_FILE)"
    fi
  else
    if [ -f "${LOCK_FILE}.pid" ]; then
      local old
      old="$(cat "${LOCK_FILE}.pid" 2>/dev/null || true)"
      if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
        die "Another TalonHound upgrade is already running (pid $old)"
      fi
    fi
    printf '%s\n' "$$" > "${LOCK_FILE}.pid"
  fi
}

release_lock() {
  if [ -f "${LOCK_FILE}.pid" ]; then
    rm -f "${LOCK_FILE}.pid"
  fi
}

check_disk() {
  local avail_kb avail_gb
  avail_kb=$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')
  avail_gb=$(( avail_kb / 1024 / 1024 ))
  if [ "$avail_gb" -lt "$DISK_MIN_GB" ]; then
    die "Insufficient free disk space: ${avail_gb} GB (need at least ${DISK_MIN_GB} GB for images, temp files, and backup). Override with TALONHOUND_UPGRADE_DISK_MIN_GB if appropriate."
  fi
  ok "Disk space: ${avail_gb} GB free (minimum ${DISK_MIN_GB} GB)."
}

preflight() {
  [ -f "$ENV_FILE" ] || die ".env not found at $ENV_FILE — is this a TalonHound installation?"
  [ -f "$ROOT/docker-compose.yml" ] || die "docker-compose.yml missing"
  [ -f "$ROOT/docker-compose.release.yml" ] || die "docker-compose.release.yml missing"
  command -v docker >/dev/null 2>&1 || die "Docker is required"
  docker compose version >/dev/null 2>&1 || die "Docker Compose plugin is required"
  docker info >/dev/null 2>&1 || die "Docker daemon is not accessible"
  # SemVer/manifest helpers use host Node when present, otherwise the backend container.
  # Database reachable
  "${COMPOSE[@]}" ps db >/dev/null 2>&1 || die "Database service is not running (start the stack before upgrading)"
  "${COMPOSE[@]}" exec -T db pg_isready -U talonhound -d talonhound >/dev/null 2>&1 \
    || die "PostgreSQL is not ready"
  # Backup destination writable (volume mount on backup-worker)
  "${COMPOSE[@]}" exec -T backup-worker sh -c 'test -w /data/backups' >/dev/null 2>&1 \
    || die "Backup destination /data/backups is not writable inside backup-worker"
}

create_pre_upgrade_backup() {
  local from="$1" to="$2" stamp backup_id
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  # backup ids allow ._- ; keep versions readable
  backup_id="pre-upgrade-${from}-to-${to}-${stamp}"
  info "Creating mandatory pre-upgrade backup: ${backup_id}"
  if ! "${COMPOSE[@]}" exec -T backup-worker \
      npm run backup:create -- --json --backup-id "$backup_id" --trigger-type pre_upgrade; then
    die "Pre-upgrade backup failed — upgrade aborted"
  fi
  printf '%s' "$backup_id"
}

stop_app_services() {
  # Keep db/redis up. Stop one generation of app/workers before starting the next.
  info "Stopping application services (database and Redis stay up)..."
  "${COMPOSE[@]}" stop \
    backend frontend proxy \
    integration-scheduler integration-worker \
    ioc-expiration-worker ioc-search-export-worker ioc-deep-search-worker ioc-bulk-query-worker \
    backup-worker \
    >/dev/null 2>&1 || true
}

apply_image_env() {
  local manifest="$1" version="$2"
  local backend frontend integration proxy
  backend="$(image_ref_from_manifest "$manifest" backend)"
  frontend="$(image_ref_from_manifest "$manifest" frontend)"
  integration="$(image_ref_from_manifest "$manifest" integration)"
  proxy="$(image_ref_from_manifest "$manifest" proxy)"
  [ -n "$backend" ] && [ -n "$frontend" ] && [ -n "$integration" ] && [ -n "$proxy" ] \
    || die "Release manifest is missing required image entries"

  env_set TALONHOUND_VERSION "$version"
  env_set TALONHOUND_BACKEND_IMAGE "$backend"
  env_set TALONHOUND_FRONTEND_IMAGE "$frontend"
  env_set TALONHOUND_INTEGRATION_IMAGE "$integration"
  env_set TALONHOUND_PROXY_IMAGE "$proxy"
}

pull_and_migrate() {
  info "Pulling exact release images..."
  docker compose "${RELEASE_COMPOSE[@]}" pull

  info "Running database migrations with the target backend image..."
  docker compose "${RELEASE_COMPOSE[@]}" run --rm --no-deps backend npm run migrate
}

start_services() {
  info "Starting services on the target release..."
  docker compose "${RELEASE_COMPOSE[@]}" up -d \
    db redis backend frontend proxy \
    integration-worker ioc-expiration-worker ioc-search-export-worker \
    ioc-deep-search-worker ioc-bulk-query-worker backup-worker
  docker compose "${RELEASE_COMPOSE[@]}" up -d integration-scheduler
}

wait_health() {
  local tries=0
  info "Waiting for health and readiness..."
  while [ "$tries" -lt "$HEALTH_TRIES" ]; do
    if docker compose "${RELEASE_COMPOSE[@]}" exec -T backend node -e "
      Promise.all([
        fetch('http://127.0.0.1:3000/healthz'),
        fetch('http://127.0.0.1:3000/readyz')
      ]).then(async ([h,r]) => {
        process.exit(h.ok && r.ok ? 0 : 1);
      }).catch(() => process.exit(1));
    " >/dev/null 2>&1; then
      return 0
    fi
    tries=$((tries + 1))
    sleep "$HEALTH_SLEEP_SEC"
  done
  return 1
}

verify_reported_version() {
  local expected="$1" reported
  reported="$(docker compose "${RELEASE_COMPOSE[@]}" exec -T backend node -e "
    fetch('http://127.0.0.1:3000/api/system/version').then(async (r) => {
      const j = await r.json();
      process.stdout.write(String(j.version || ''));
      process.exit(r.ok ? 0 : 1);
    }).catch(() => process.exit(1));
  " 2>/dev/null | tr -d '[:space:]')"
  if [ "$reported" != "$expected" ]; then
    die "Version mismatch after upgrade (expected ${expected}, reported ${reported:-unknown})"
  fi
  ok "Running version reports ${reported}"
}

print_recovery() {
  local phase="$1" from="$2" to="$3" backup_id="${4:-}"
  echo
  warn "Upgrade failed during ${phase}."
  echo "Current version: ${from}"
  echo "Target version:  ${to}"
  if [ -n "$backup_id" ]; then
    echo "Pre-upgrade backup: ${backup_id}"
    echo "Restore with: sudo ./scripts/restore-stack.sh --backup-id ${backup_id} --confirm"
  fi
  echo "See docs/upgrade.md for recovery guidance."
  echo
}

run_upgrade() {
  local target_arg="${1:-}" dry_run="${2:-0}"
  local from to channel cmp manifest_tmp backup_id="" phase="preflight"

  require_root
  acquire_lock
  mkdir -p "$ROOT/.talonhound-upgrade"
  manifest_tmp=""
  trap 'rm -f "$manifest_tmp"; release_lock' EXIT

  echo "${c_bold}TalonHound Upgrade${c_reset}"
  preflight
  from="$(current_version)"
  channel="$(channel_for_version "$from")"
  if [ -n "$target_arg" ]; then
    to="$(normalize_version_arg "$target_arg")"
  else
    info "Resolving latest ${channel} release from update manifest..."
    to="$(resolve_latest_from_channel "$channel")"
    to="$(normalize_version_arg "$to")"
  fi

  echo
  echo "Current version : ${from}"
  echo "Target version  : ${to}"
  echo "Channel         : ${channel}"
  if [ "$dry_run" = "1" ]; then
    echo "Mode            : dry-run (no mutations)"
  fi
  echo

  cmp="$(semver_cmp "$to" "$from" || true)"
  if [ -z "$cmp" ]; then
    die "Unable to compare versions"
  fi
  if [ "$cmp" -lt 0 ]; then
    die "Refusing downgrade from ${from} to ${to}. Restore from a pre-upgrade backup instead."
  fi
  if [ "$cmp" -eq 0 ]; then
    ok "Already running ${from}. Nothing to upgrade."
    exit 0
  fi

  phase_ok "Pre-flight checks"
  check_disk
  phase_ok "Disk space check"

  manifest_tmp="$ROOT/.talonhound-upgrade/release-manifest.$$.json"
  if ! fetch_release_manifest "$to" "$manifest_tmp"; then
    phase_fail "Download release"
    die "Target release artifacts are not reachable for v${to}"
  fi
  phase_ok "Download release"

  if [ "$dry_run" = "1" ]; then
    ok "Dry-run validation passed for ${from} → ${to}."
    echo "Would: create pre-upgrade backup, pull GHCR images, migrate, restart, verify version."
    exit 0
  fi

  phase="backup"
  backup_id="$(create_pre_upgrade_backup "$from" "$to")" || {
    phase_fail "Backup"
    print_recovery "backup" "$from" "$to" ""
    exit 1
  }
  phase_ok "Backup"

  phase="service transition"
  apply_image_env "$manifest_tmp" "$to"
  stop_app_services

  phase="database migration"
  if ! pull_and_migrate; then
    phase_fail "Database migrations"
    print_recovery "database migration" "$from" "$to" "$backup_id"
    echo "No further upgrade steps were executed after migration failure."
    echo "Database may be partially migrated — do not start an older app version against a newer schema."
    rm -f "$manifest_tmp"
    exit 1
  fi
  phase_ok "Database migrations"

  phase="start services"
  if ! start_services; then
    phase_fail "Start services"
    print_recovery "service start" "$from" "$to" "$backup_id"
    echo "Database migration already completed."
    rm -f "$manifest_tmp"
    exit 1
  fi
  phase_ok "Start services"

  phase="readiness"
  if ! wait_health; then
    phase_fail "Readiness checks"
    print_recovery "post-start health validation" "$from" "$to" "$backup_id"
    echo "Database migration already completed."
    rm -f "$manifest_tmp"
    exit 1
  fi
  phase_ok "Readiness checks"

  phase="final validation"
  if ! verify_reported_version "$to"; then
    phase_fail "Final validation"
    print_recovery "final version validation" "$from" "$to" "$backup_id"
    rm -f "$manifest_tmp"
    exit 1
  fi
  phase_ok "Final validation"

  rm -f "$manifest_tmp"
  echo
  ok "Upgrade completed successfully."
  echo "${from} → ${to}"
  echo "Pre-upgrade backup: ${backup_id}"
}

main() {
  local mode="" target="" dry_run=0
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --upgrade) mode=upgrade; shift ;;
      --upgrade-to)
        mode=upgrade-to
        target="${2:-}"
        [ -n "$target" ] || die "--upgrade-to requires a version"
        shift 2
        ;;
      --dry-run) dry_run=1; shift ;;
      *) usage; die "Unknown option: $1" ;;
    esac
  done

  case "$mode" in
    upgrade) run_upgrade "" "$dry_run" ;;
    upgrade-to) run_upgrade "$target" "$dry_run" ;;
    *) usage; die "Specify --upgrade or --upgrade-to <version>" ;;
  esac
}

main "$@"

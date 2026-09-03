#!/usr/bin/env bash
#
# TalonHound installer.
#
# Prepares infrastructure (Docker + Compose), generates the required secrets, applies
# database migrations, starts the stack, and prints the URL + one-time Setup Code needed to
# finish in the browser-based Setup Wizard. Idempotent: re-running on an existing install
# never regenerates secrets, recreates the administrator, or resets data.
#
# Usage:
#   sudo ./installation.sh                 # install / bring up
#   sudo ./installation.sh --rotate-setup-code   # print a fresh setup code (only before setup is completed)
#   sudo ./installation.sh --upgrade             # safe upgrade to latest channel release
#   sudo ./installation.sh --upgrade-to VER      # safe upgrade to an exact SemVer
#   sudo ./installation.sh --upgrade --dry-run   # validate upgrade without mutating
#   ./installation.sh --help
#
set -euo pipefail

PRODUCT_VERSION="$(cat VERSION 2>/dev/null | tr -d '[:space:]' || echo '0.1.1-beta.3')"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="$SCRIPT_DIR/.env"
COMPOSE="docker compose"

# Setup-code alphabet: Crockford-style, no ambiguous characters (must match backend/lib/setupCode.js).
SETUP_CODE_ALPHABET="ABCDEFGHJKMNPQRSTVWXYZ23456789"

c_reset=$'\033[0m'; c_bold=$'\033[1m'; c_green=$'\033[32m'; c_yellow=$'\033[33m'; c_red=$'\033[31m'; c_cyan=$'\033[36m'
log()  { printf '%s\n' "$*"; }
info() { printf '%s[*]%s %s\n' "$c_cyan" "$c_reset" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$c_green" "$c_reset" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_yellow" "$c_reset" "$*"; }
die()  { printf '%s[x]%s %s\n' "$c_red" "$c_reset" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
TalonHound ${PRODUCT_VERSION} installer

  sudo ./installation.sh                     Install and/or start the stack
  sudo ./installation.sh --rotate-setup-code Print a new one-time Setup Code (only before setup is completed)
  sudo ./installation.sh --upgrade           Upgrade to the latest release for this channel
  sudo ./installation.sh --upgrade-to VER    Upgrade to an exact SemVer release (e.g. 0.1.0-beta.3)
  sudo ./installation.sh --upgrade --dry-run Validate an upgrade without changing the installation
  ./installation.sh --help                   Show this help

The installer is safe to re-run: existing secrets, the .env file, the database, and the
completed setup state are never overwritten.

Upgrades never pull from main or latest; they use exact GitHub Release / GHCR artifacts.
See docs/upgrade.md.
EOF
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "Please run as root: sudo ./installation.sh"
  fi
}

# Minimum free space on / for a supported evaluation install; warn below the beta recommendation.
DISK_MIN_FREE_GB="${TALONHOUND_DISK_MIN_FREE_GB:-40}"
DISK_WARN_FREE_GB="${TALONHOUND_DISK_WARN_FREE_GB:-60}"

check_disk_space() {
  local avail_kb avail_gb
  avail_kb=$(df -Pk / | awk 'NR==2 {print $4}')
  avail_gb=$(( avail_kb / 1024 / 1024 ))
  if [ "$avail_gb" -lt "$DISK_MIN_FREE_GB" ]; then
    die "Insufficient disk space on /: ${avail_gb} GB free (need at least ${DISK_MIN_FREE_GB} GB). See README Requirements → Storage."
  fi
  if [ "$avail_gb" -lt "$DISK_WARN_FREE_GB" ]; then
    warn "Low disk space on /: ${avail_gb} GB free. TalonHound recommends ${DISK_WARN_FREE_GB} GB free (≈80 GB total disk) for public beta workloads."
  else
    ok "Disk space on /: ${avail_gb} GB free."
  fi
}

check_os() {
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [ "${ID:-}" != "ubuntu" ]; then
      warn "Detected ${PRETTY_NAME:-unknown OS}. TalonHound is tested on Ubuntu 24.04; continuing anyway."
    else
      info "Operating system: ${PRETTY_NAME}"
    fi
  else
    warn "Could not detect the operating system (/etc/os-release missing); continuing."
  fi
}

ensure_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "Docker and Compose are installed ($(docker --version | awk '{print $3}' | tr -d ','))."
    return
  fi
  info "Installing Docker Engine and the Compose plugin..."
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y curl
  fi
  curl -fsSL https://get.docker.com | sh
  if ! docker compose version >/dev/null 2>&1; then
    die "Docker installed but the Compose plugin is unavailable. Install docker-compose-plugin and re-run."
  fi
  ok "Docker installed."
}

rand_hex() { openssl rand -hex "${1:-32}"; }

# Generate a formatted setup code (XXXX-XXXX-XXXX-XXXX) from a CSPRNG.
generate_setup_code() {
  local n=${#SETUP_CODE_ALPHABET} out="" i idx byte
  for i in $(seq 1 16); do
    byte=$(od -An -N1 -tu1 < /dev/urandom | tr -d ' ')
    idx=$(( byte % n ))
    out="${out}${SETUP_CODE_ALPHABET:$idx:1}"
    if [ $((i % 4)) -eq 0 ] && [ "$i" -ne 16 ]; then out="${out}-"; fi
  done
  printf '%s' "$out"
}

# SHA-256 of the canonicalized code (uppercase, no separators) — matches backend hashSetupCode().
hash_setup_code() {
  local canonical
  canonical=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]' | tr -cd 'A-Z0-9')
  printf '%s' "$canonical" | sha256sum | awk '{print $1}'
}

# Read a KEY=value from .env (without exporting the whole file).
env_get() {
  local key="$1"
  [ -f "$ENV_FILE" ] || return 0
  sed -n "s/^${key}=//p" "$ENV_FILE" | head -n1
}

# Ensure KEY exists in .env; if missing, append with the provided value. Never overwrites.
env_ensure() {
  local key="$1" value="$2"
  if [ -f "$ENV_FILE" ] && grep -q "^${key}=" "$ENV_FILE"; then
    return 0
  fi
  printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
}

set_or_replace() {
  local key="$1" value="$2"
  if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    # portable in-place replace
    local tmp; tmp="$(mktemp)"
    grep -v "^${key}=" "$ENV_FILE" > "$tmp"
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
    cat "$tmp" > "$ENV_FILE"
    rm -f "$tmp"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

prepare_env() {
  local fresh_env=0
  if [ ! -f "$ENV_FILE" ]; then
    fresh_env=1
    info "Creating .env with generated secrets..."
    : > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
  else
    info "Existing .env found; keeping all existing secrets."
  fi
  chmod 600 "$ENV_FILE" 2>/dev/null || true

  # Required infrastructure secrets — generated once, never overwritten.
  env_ensure DB_PASSWORD "$(rand_hex 24)"
  env_ensure REDIS_PASSWORD "$(rand_hex 24)"
  env_ensure JWT_SECRET "$(rand_hex 32)"
  env_ensure API_INGEST_TOKEN "$(rand_hex 32)"
  env_ensure API_KEY_ENCRYPTION_KEY "$(rand_hex 32)"

  if [ "$fresh_env" -eq 1 ]; then ok ".env created (permissions 600)."; fi
}

# Is setup already completed in the database? Prints "yes"/"no"/"unknown".
db_setup_completed() {
  local out
  if ! $COMPOSE ps db >/dev/null 2>&1; then echo unknown; return; fi
  out=$($COMPOSE exec -T db psql -U talonhound -d talonhound -tAc \
    "SELECT CASE WHEN setup_completed_at IS NOT NULL OR EXISTS (SELECT 1 FROM users) THEN 'yes' ELSE 'no' END FROM system_settings WHERE id=1" 2>/dev/null | tr -d '[:space:]' || true)
  case "$out" in
    yes) echo yes ;;
    no)  echo no ;;
    *)   echo unknown ;;
  esac
}

configure_setup_code() {
  # Only relevant before setup is completed. If a hash already exists in .env keep it
  # (the code was already shown); regenerate only via --rotate-setup-code.
  local existing_hash rotate="${1:-0}"
  existing_hash="$(env_get SETUP_CODE_HASH || true)"

  local completed
  completed="$(db_setup_completed)"
  if [ "$completed" = "yes" ]; then
    if [ "$rotate" = "1" ]; then
      die "Setup is already completed; a new setup code cannot be issued. Manage administrators from the app."
    fi
    SETUP_CODE=""   # nothing to show
    return
  fi

  if [ -n "$existing_hash" ] && [ "$rotate" != "1" ]; then
    SETUP_CODE=""   # already issued earlier; not reprinted for safety
    return
  fi

  SETUP_CODE="$(generate_setup_code)"
  local hash; hash="$(hash_setup_code "$SETUP_CODE")"
  set_or_replace SETUP_CODE_HASH "$hash"
  chmod 600 "$ENV_FILE" 2>/dev/null || true
}

detect_host() {
  local ip
  ip=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -n1 || true)
  if [ -z "$ip" ]; then
    ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
  fi
  printf '%s' "$ip"
}

start_infra_and_migrate() {
  info "Starting PostgreSQL and Redis..."
  $COMPOSE --env-file "$ENV_FILE" up -d db redis

  # Stamp the canonical product version (and best-effort commit/date) into the images so the
  # running app reports the real version instead of the "dev" build-arg default.
  # Persist into .env so later compose rebuilds keep the same product identity without
  # requiring the operator to export TALONHOUND_VERSION manually.
  export TALONHOUND_VERSION="${PRODUCT_VERSION}"
  export TALONHOUND_COMMIT="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  export TALONHOUND_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
  set_or_replace TALONHOUND_VERSION "$TALONHOUND_VERSION"
  set_or_replace TALONHOUND_COMMIT "$TALONHOUND_COMMIT"
  set_or_replace TALONHOUND_BUILD_DATE "$TALONHOUND_BUILD_DATE"

  info "Building application images (first run can take several minutes)..."
  $COMPOSE --env-file "$ENV_FILE" build backend frontend integration-worker integration-scheduler proxy

  info "Applying database migrations..."
  $COMPOSE --env-file "$ENV_FILE" run --rm backend npm run migrate
}

start_app() {
  info "Starting application services..."
  $COMPOSE --env-file "$ENV_FILE" up -d backend frontend proxy \
    ioc-expiration-worker integration-worker ioc-search-export-worker backup-worker
  $COMPOSE --env-file "$ENV_FILE" up -d integration-scheduler
}

wait_for_ready() {
  info "Waiting for TalonHound to accept connections..."
  local tries=0 max=60
  while [ "$tries" -lt "$max" ]; do
    # /healthz is up as soon as the process is listening (does not require setup to be done,
    # unlike /readyz which stays 503 until the timezone is configured in the wizard).
    if $COMPOSE exec -T backend node -e \
        "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" \
        >/dev/null 2>&1; then
      ok "Backend is up."
      return 0
    fi
    tries=$((tries + 1))
    sleep 3
  done
  warn "Backend did not report healthy within the timeout. Check: $COMPOSE logs backend --tail=100"
  return 1
}

print_final() {
  local host candidates
  host="$(detect_host)"
  echo
  echo "${c_bold}============================================================${c_reset}"
  ok "TalonHound ${PRODUCT_VERSION} installed successfully."
  echo "${c_bold}============================================================${c_reset}"
  echo
  if [ -n "$host" ]; then
    echo "Open the following URL to complete setup:"
    echo
    echo "    ${c_bold}https://${host}${c_reset}"
  else
    echo "Open TalonHound in a browser to complete setup:"
    echo
    echo "    ${c_bold}https://<server-ip>${c_reset}"
    candidates=$(hostname -I 2>/dev/null || true)
    if [ -n "$candidates" ]; then echo "    (detected addresses: ${candidates})"; fi
  fi
  echo
  if [ -n "${SETUP_CODE:-}" ]; then
    echo "Setup Code:"
    echo
    echo "    ${c_bold}${c_green}${SETUP_CODE}${c_reset}"
    echo
    echo "Enter this one-time code in the Setup Wizard's first step. It is shown only now"
    echo "and becomes invalid once setup is complete."
  else
    echo "A setup code was issued earlier and is not reprinted. If you no longer have it and"
    echo "setup is not yet complete, run: ${c_bold}sudo ./installation.sh --rotate-setup-code${c_reset}"
  fi
  echo
  echo "The browser may show a certificate warning because TalonHound initially uses a"
  echo "self-signed certificate. This is expected on first run."
  echo
}

main() {
  case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    --upgrade|--upgrade-to)
      exec "$SCRIPT_DIR/scripts/upgrade.sh" "$@"
      ;;
    --rotate-setup-code)
      require_root
      [ -f "$ENV_FILE" ] || die ".env not found — run the installer first."
      configure_setup_code 1
      [ -n "${SETUP_CODE:-}" ] || die "Could not issue a setup code."
      # Restart backend so it re-seeds the new hash (greenfield only).
      $COMPOSE --env-file "$ENV_FILE" up -d backend >/dev/null 2>&1 || true
      echo
      ok "New one-time setup code:"
      echo
      echo "    ${c_bold}${c_green}${SETUP_CODE}${c_reset}"
      echo
      exit 0
      ;;
    "" ) ;;
    * ) usage; die "Unknown option: $1" ;;
  esac

  require_root
  echo "${c_bold}TalonHound ${PRODUCT_VERSION} installer${c_reset}"
  check_os
  check_disk_space
  ensure_docker
  prepare_env
  start_infra_and_migrate
  # DB is up + migrated: decide whether a one-time setup code is needed, and record its hash
  # in .env BEFORE the backend starts so it is seeded on first boot (greenfield only).
  configure_setup_code 0
  start_app
  wait_for_ready || true
  print_final
}

main "$@"

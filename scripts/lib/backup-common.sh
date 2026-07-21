# Shared helpers for backup-stack.sh and restore-stack.sh (POSIX sh).

# Writer services stopped during restore to avoid concurrent writes.
WRITER_SERVICES="backend integration-scheduler integration-worker ioc-expiration-worker"

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

Quiet period recommended
------------------------
Take backups during low activity when possible. Avoid backup while migrations
or large feed imports are running. Optionally pause the scheduler:

  docker compose stop integration-scheduler

Restore is CLI-only:

  ./scripts/restore-stack.sh --backup <this-directory> --dry-run
  ./scripts/restore-stack.sh --backup <this-directory> --confirm

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
  "version": 1,
  "bundle": "talonhound-${stamp}",
  "created_at": "${created_at}",
  "git_sha": "$(git_sha)",
  "quiet_period_recommended": true,
  "redis_included": false,
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
  docker compose up -d backend integration-scheduler integration-worker ioc-expiration-worker frontend proxy
}

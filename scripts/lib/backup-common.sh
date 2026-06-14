# Shared helpers for backup-stack.sh and restore-stack.sh (POSIX sh).

# Writer services stopped during restore to avoid concurrent writes.
WRITER_SERVICES="backend integration-scheduler integration-worker signal-engine ioc-correlation-engine ioc-retro-engine ioc-expiration-worker ioc-match-count-worker llm-risk-worker syslog-receiver"

# ClickHouse tables included in optional backup (Faz 1 MVP).
CH_BACKUP_TABLES="default.syslog_logs default.syslog_observables security_evidence.incident_related_logs"

# Rebuildable from PostgreSQL / workers; documented in manifest only.
CH_EXCLUDED_REBUILDABLE="default.ioc_lookup default.ioc_lookup_by_updated default.ioc_lookup_sync_state default.ioc_retro_state"

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

ch_client() {
  if [ -n "${CLICKHOUSE_PASSWORD:-}" ]; then
    docker compose exec -T clickhouse clickhouse-client \
      --user "${CLICKHOUSE_USER:-demo}" \
      --password "$CLICKHOUSE_PASSWORD" \
      "$@"
  else
    docker compose exec -T clickhouse clickhouse-client "$@"
  fi
}

ch_table_exists() {
  table="$1"
  ch_client --query "EXISTS TABLE ${table}" 2>/dev/null | grep -q '^1$'
}

ch_file_name() {
  # default.syslog_logs -> default.syslog_logs.native
  printf '%s.native' "$1"
}

write_readme() {
  out="$1"
  stamp="$2"
  include_ch="$3"
  cat > "$out" <<EOF
demo-runbook backup bundle
==========================
Created (UTC): ${stamp}
Git commit: $(git_sha)

Components:
- PostgreSQL: postgres.dump (pg_dump custom format, required)
- ClickHouse: ${include_ch}
- Redis: excluded (runtime/queue state; not restored)

Quiet period recommended
------------------------
Take backups during low activity when possible. Avoid backup while migrations,
large feed imports, or retro scans are running. Optionally pause the scheduler:

  docker compose stop integration-scheduler

Restore is CLI-only in Faz 1:

  ./scripts/restore-stack.sh --backup <this-directory> --dry-run
  ./scripts/restore-stack.sh --backup <this-directory> --confirm

After restore, reconcile integration queues from Threat Intelligence > Job Queue Status
if recovery_needed is reported.
EOF
}

write_manifest() {
  dir="$1"
  stamp="$2"
  include_ch="$3"
  pg_bytes="$4"
  ch_tables_json="$5"
  created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  excluded_json=""
  for t in $CH_EXCLUDED_REBUILDABLE; do
    excluded_json="${excluded_json}\"${t}\","
  done
  excluded_json="${excluded_json%,}"

  cat > "${dir}/manifest.json" <<EOF
{
  "version": 1,
  "bundle": "demo-runbook-${stamp}",
  "created_at": "${created_at}",
  "git_sha": "$(git_sha)",
  "quiet_period_recommended": true,
  "redis_included": false,
  "components": {
    "postgres": {
      "file": "postgres.dump",
      "format": "pg_custom",
      "bytes": ${pg_bytes}
    },
    "clickhouse": {
      "included": ${include_ch},
      "tables": ${ch_tables_json},
      "excluded_rebuildable_tables": [${excluded_json}]
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
    if [ -d clickhouse ]; then
      for f in clickhouse/*.native; do
        [ -f "$f" ] || continue
        sha256sum "$f"
      done
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
  docker compose up -d db redis clickhouse
  docker compose up -d backend integration-scheduler integration-worker signal-engine \
    ioc-correlation-engine ioc-retro-engine ioc-expiration-worker ioc-match-count-worker \
    llm-risk-worker syslog-receiver frontend proxy
}

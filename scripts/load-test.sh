#!/usr/bin/env bash
set -euo pipefail

EPS="${EPS:-2000}"
DURATION="${DURATION:-120}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-514}"
# Default empty: syslog health is not on the host unless you use docker-compose.syslog-host.yml. Set HEALTH_URL + SYSLOG_HEALTH_TOKEN when published.
HEALTH_URL="${HEALTH_URL:-}"
SYSLOG_HEALTH_TOKEN="${SYSLOG_HEALTH_TOKEN:-}"
# ClickHouse HTTP is not published on the host by default (see docker-compose). Leave empty to skip CH curls,
# or set e.g. CH_URL=http://127.0.0.1:8123 if you publish 8123 locally / use an SSH tunnel.
CH_URL="${CH_URL:-}"

TOTAL=$((EPS * DURATION))
START_TS=$(date +%s)

echo "[load-test] target=${TARGET_HOST}:${TARGET_PORT} eps=${EPS} duration=${DURATION}s total=${TOTAL}"

for ((s=0; s<DURATION; s++)); do
  ts=$(date '+%b %d %H:%M:%S')
  for ((i=0; i<EPS; i++)); do
    printf '<134>%s loadgen app[%d]: synthetic log second=%d idx=%d\n' "$ts" "$i" "$s" "$i" | nc -u -w0 "$TARGET_HOST" "$TARGET_PORT" >/dev/null 2>&1 || true
  done
  sleep 1
  if (( (s+1) % 10 == 0 )); then
    echo "[load-test] sent_seconds=$((s+1))/$DURATION"
  fi
done

sleep 3
END_TS=$(date +%s)
WALL=$((END_TS - START_TS))

echo "\n=== Receiver metrics ==="
if [[ -n "$HEALTH_URL" ]]; then
  if [[ -n "$SYSLOG_HEALTH_TOKEN" ]]; then
    curl -fsS -H "Authorization: Bearer ${SYSLOG_HEALTH_TOKEN}" "$HEALTH_URL" || true
  else
    curl -fsS "$HEALTH_URL" || true
  fi
else
  echo "(skipped: set HEALTH_URL if you publish 8081, e.g. docker compose -f docker-compose.yml -f docker-compose.syslog-host.yml up -d)"
fi

if [[ -n "${CH_URL}" ]]; then
  echo "\n=== ClickHouse insert rate (last 5m) ==="
  curl -fsS "$CH_URL" --data-binary "SELECT count() AS events_5m, round(count()/300,2) AS eps_5m FROM syslog_logs WHERE ts > now() - INTERVAL 5 MINUTE FORMAT JSONEachRow" || true

  echo "\n=== ClickHouse query latency ==="
  T0=$(date +%s%3N)
  curl -fsS "$CH_URL" --data-binary "SELECT toStartOfMinute(ts) AS m, count() AS c FROM syslog_logs WHERE ts > now() - INTERVAL 1 HOUR GROUP BY m ORDER BY m FORMAT JSONEachRow" >/dev/null || true
  T1=$(date +%s%3N)
  echo "query_latency_ms=$((T1-T0))"
else
  echo "\n=== ClickHouse (skipped: set CH_URL to query HTTP API from this host) ==="
fi

echo "[load-test] done wall=${WALL}s"

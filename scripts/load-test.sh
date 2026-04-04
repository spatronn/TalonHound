#!/usr/bin/env bash
set -euo pipefail

EPS="${EPS:-2000}"
DURATION="${DURATION:-120}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-514}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8081/receiver/health}"
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
curl -fsS "$HEALTH_URL" || true

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

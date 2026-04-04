#!/usr/bin/env bash
set -u

FILE="${1:-}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-514}"
SYSLOG_UDP_SHARED_SECRET="${SYSLOG_UDP_SHARED_SECRET:-}"
SLEEP_EVERY="${SLEEP_EVERY:-0}"
SLEEP_MS="${SLEEP_MS:-1}"

if [[ -z "$FILE" || ! -f "$FILE" ]]; then
  echo "Usage: $0 <log-file>"
  echo "Optional env: TARGET_HOST=127.0.0.1 TARGET_PORT=514 SLEEP_EVERY=0 SLEEP_MS=1"
  echo "Host UDP 514: docker compose -f docker-compose.yml -f docker-compose.syslog-host.yml up -d"
  echo "Set SYSLOG_UDP_SHARED_SECRET in .env; each datagram is sent as SECRET|line"
  exit 1
fi

count=0
while IFS= read -r line; do
  if [[ -n "$SYSLOG_UDP_SHARED_SECRET" ]]; then
    printf '%s|%s\n' "$SYSLOG_UDP_SHARED_SECRET" "$line" | nc -u -w0 "$TARGET_HOST" "$TARGET_PORT" >/dev/null 2>&1 || true
  else
    printf '%s\n' "$line" | nc -u -w0 "$TARGET_HOST" "$TARGET_PORT" >/dev/null 2>&1 || true
  fi
  count=$((count + 1))
  if [[ "$SLEEP_EVERY" -gt 0 ]] && (( count % SLEEP_EVERY == 0 )); then
    python3 - <<PY
import time
time.sleep(${SLEEP_MS}/1000)
PY
  fi
done < "$FILE"

echo "sent=$count target=${TARGET_HOST}:${TARGET_PORT}"
exit 0

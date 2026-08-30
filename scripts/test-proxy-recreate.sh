#!/usr/bin/env bash
#
# Host-level integration test for automatic proxy recovery after a backend container is
# recreated with a NEW Docker IP (the "stale nginx upstream / 502" regression class).
#
# Runs against a live TalonHound stack on the current host (needs Docker + a running stack).
# It is NOT part of the CI unit suite — service recreation is too expensive/racy for every CI
# run. The cheap static guard is scripts/test-proxy-dynamic-upstreams.sh. Run this on a host
# after proxy/nginx changes, e.g. the ARM64 validation host.
#
# For each cycle it forces the backend onto a NEW IP (by parking a placeholder container on
# the old IP), waits for backend health, then — WITHOUT touching the proxy — verifies that
# /healthz, /readyz and an API route recover automatically within a bounded window.
#
# Usage: sudo ./scripts/test-proxy-recreate.sh [CYCLES] [BASE_URL]
set -euo pipefail

CYCLES="${1:-5}"
BASE="${2:-https://localhost}"
RECOVER_TIMEOUT="${RECOVER_TIMEOUT:-15}"
HOLDER="talonhound-proxy-recreate-holder"

dc() { docker compose "$@"; }

net="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$(dc ps -q backend)")"
proxy_start="$(dc ps -q proxy)"
pass=0

cleanup() { docker rm -f "$HOLDER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

for c in $(seq 1 "$CYCLES"); do
  old_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(dc ps -q backend)")"
  dc stop backend >/dev/null 2>&1; dc rm -f backend >/dev/null 2>&1
  docker rm -f "$HOLDER" >/dev/null 2>&1 || true
  docker run -d --name "$HOLDER" --network "$net" --ip "$old_ip" alpine sleep 300 >/dev/null 2>&1
  dc up -d backend >/dev/null 2>&1

  st=missing
  for _ in $(seq 1 30); do
    st="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$(dc ps -q backend)" 2>/dev/null || echo missing)"
    [ "$st" = "healthy" ] && break
    sleep 2
  done
  new_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(dc ps -q backend)")"

  rec=-1
  for s in $(seq 0 "$RECOVER_TIMEOUT"); do
    [ "$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/healthz")" = "200" ] && { rec=$s; break; }
    sleep 1
  done
  rz="$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/readyz")"
  api="$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/api/setup/status")"
  docker rm -f "$HOLDER" >/dev/null 2>&1 || true

  if [ "$rec" -ge 0 ] && [ "$rz" = "200" ] && [ "$api" = "200" ]; then
    res=PASS; pass=$((pass + 1))
  else
    res=FAIL
  fi
  printf 'cycle %d: ip %s->%s health=%s recover=%ss readyz=%s api=%s => %s\n' \
    "$c" "$old_ip" "$new_ip" "$st" "$rec" "$rz" "$api" "$res"
done

if [ "$proxy_start" != "$(dc ps -q proxy)" ]; then
  echo "FAIL: proxy container changed during the test (should be untouched)"
  exit 1
fi

echo "RESULT: $pass/$CYCLES cycles recovered automatically (proxy untouched)"
[ "$pass" -eq "$CYCLES" ] || exit 1

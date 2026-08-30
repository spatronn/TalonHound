#!/usr/bin/env bash
#
# Regression guard for the "stale nginx upstream after container recreate" class of bug.
#
# nginx resolves a LITERAL `proxy_pass http://<name>:<port>` once at config load and caches
# the IP for the worker's lifetime, ignoring the `resolver` directive. When a Docker service
# container is recreated with a new IP, such a proxy keeps hitting the dead IP and returns a
# persistent 502 until it is reloaded/recreated. Using a variable in proxy_pass (with a
# `resolver`) makes nginx re-resolve the service name at request time, so it recovers
# automatically.
#
# This test statically asserts that every nginx config which proxies to an internal Docker
# service name uses a variable-based proxy_pass AND declares a resolver. It needs no Docker,
# so it runs cheaply in CI. A companion host-level recreate test lives in
# scripts/test-proxy-recreate.sh.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# nginx configs that proxy to internal Docker service names, and the service names they target.
CONFIGS=(
  "proxy/nginx.conf"
  "frontend/nginx.conf"
)
# Internal compose service names that must never be reached via a literal proxy_pass.
SERVICES="backend|frontend"

fail=0

for cfg in "${CONFIGS[@]}"; do
  path="$ROOT/$cfg"
  cfg_fail=0
  if [ ! -f "$path" ]; then
    echo "FAIL: $cfg not found"
    fail=1
    continue
  fi

  # Any proxy_pass to an internal service name that is NOT via a variable ($) is a static-DNS
  # upstream. Match: proxy_pass http://backend...  (no '$' anywhere in the value).
  literal=$(grep -nE "proxy_pass[[:space:]]+https?://($SERVICES)" "$path" \
            | grep -vE "proxy_pass[[:space:]]+https?://[^;]*\\\$" || true)
  if [ -n "$literal" ]; then
    echo "FAIL: $cfg has literal (static-DNS) proxy_pass to an internal service:"
    echo "$literal" | sed 's/^/    /'
    cfg_fail=1
  fi

  # If the config proxies to internal services, it must declare a resolver for runtime
  # re-resolution.
  if grep -qE "proxy_pass[[:space:]]+https?://[^;]*\\\$" "$path"; then
    if ! grep -qE "^\s*resolver\s+" "$path"; then
      echo "FAIL: $cfg uses variable proxy_pass but declares no resolver"
      cfg_fail=1
    fi
  fi

  if [ "$cfg_fail" -eq 0 ]; then
    echo "PASS: $cfg — dynamic upstreams + resolver present"
  else
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "proxy dynamic-upstream regression check: FAIL"
  exit 1
fi
echo "proxy dynamic-upstream regression check: PASS"

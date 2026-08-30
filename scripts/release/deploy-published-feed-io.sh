#!/usr/bin/env bash
set -euo pipefail
ROOT="/opt/TalonHound"
cd "$ROOT"

echo "=== stash local prod drift (recoverable) ==="
git stash push -u -m "pre-published-feed-io-remediation-$(date +%Y%m%d)" || true

echo "=== fast-forward main ==="
git fetch origin main
git merge --ff-only origin/main

cp /tmp/publishedFeedWindowEligibility.test.js backend/lib/publishedFeedWindowEligibility.test.js

echo "=== env flags ==="
touch .env
set_kv() {
  local k="$1" v="$2"
  if grep -q "^${k}=" .env; then
    sed -i "s|^${k}=.*|${k}=${v}|" .env
  else
    echo "${k}=${v}" >> .env
  fi
}
set_kv PUBLISHED_FEED_SLIDING_WINDOW_INCREMENTAL_ENABLED true
set_kv PUBLISHED_FEED_RECONCILIATION_ENABLED true
set_kv PUBLISHED_FEED_INCREMENTAL_FEED_IDS "11,12,14"
set_kv PUBLISHED_FEED_CHUNKED_FEED_IDS "11"

echo "=== migrate ==="
docker compose up -d db redis
docker compose run --rm backend npm run migrate

echo "=== build + deploy ==="
export TALONHOUND_VERSION="$(tr -d '\r\n' < VERSION 2>/dev/null || echo dev)"
export TALONHOUND_COMMIT="$(git rev-parse HEAD)"
export TALONHOUND_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker compose build backend frontend proxy integration-worker integration-scheduler
docker compose up -d --no-deps backend
docker compose up -d --no-deps --force-recreate frontend proxy
docker compose up -d --no-deps --force-recreate \
  ioc-expiration-worker ioc-search-export-worker ioc-deep-search-worker ioc-bulk-query-worker backup-worker \
  integration-worker integration-scheduler

echo "=== readyz ==="
for i in $(seq 1 30); do
  status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' talonhound-backend-1 2>/dev/null || echo missing)"
  echo "try $i: $status"
  [ "$status" = "healthy" ] && break
  sleep 5
done
docker compose exec -T backend node -e "fetch('http://127.0.0.1:3000/readyz').then(async (r)=>{const b=await r.json(); console.log(JSON.stringify(b)); process.exit(r.ok?0:1);}).catch(()=>process.exit(1))"

echo "DEPLOY_SHA=$(git rev-parse HEAD)"

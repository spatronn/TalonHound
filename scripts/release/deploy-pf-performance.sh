#!/usr/bin/env bash
set -euo pipefail
ROOT="/opt/TalonHound"
cd "$ROOT"

echo "=== fast-forward main ==="
git fetch origin main
git merge --ff-only origin/main

echo "=== env flags (chunk allowlist updated after URL bootstrap) ==="
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
set_kv PUBLISHED_FEED_RECONCILIATION_USE_BUCKETS true
set_kv PUBLISHED_FEED_INCREMENTAL_FEED_IDS "11,12,14"
set_kv PUBLISHED_FEED_CHUNKED_ENABLED true
# feed 12 added after chunk bootstrap completes below
set_kv PUBLISHED_FEED_CHUNKED_FEED_IDS "11"

echo "=== build backend image (before migrate so new SQL is present) ==="
export TALONHOUND_VERSION="$(tr -d '\r\n' < VERSION 2>/dev/null || echo dev)"
export TALONHOUND_COMMIT="$(git rev-parse HEAD)"
export TALONHOUND_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker compose build backend

echo "=== migrate ==="
docker compose up -d db redis
docker compose run --rm backend npm run migrate

echo "=== reconciliation bucket backfill + index ==="
docker compose run --rm backend npm run published-feeds:reconciliation-bucket-backfill
docker compose exec -T db psql -U talonhound -d talonhound -c \
  "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pf_items_feed_recon_bucket ON published_feed_items (feed_id, snapshot_window, reconciliation_bucket, identity_key) WHERE snapshot_window = 'all' AND reconciliation_bucket IS NOT NULL;"
docker compose exec -T db psql -U talonhound -d talonhound -c "ANALYZE published_feed_items;"

echo "=== URL chunk backfill (feed 12) ==="
docker compose run --rm backend npm run published-feeds:chunk-backfill -- --feed-id 12

echo "=== URL chunk bootstrap (feed 12) ==="
docker compose run --rm backend npm run published-feeds:chunk-bootstrap -- --feed-id 12

echo "=== enable URL chunking ==="
set_kv PUBLISHED_FEED_CHUNKED_FEED_IDS "11,12"

echo "=== deploy services ==="
docker compose up -d --no-deps backend integration-scheduler

for i in $(seq 1 30); do
  status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' talonhound-backend-1 2>/dev/null || echo missing)"
  echo "ready try $i: $status"
  [ "$status" = "healthy" ] && break
  sleep 5
done

docker compose exec -T backend node -e "fetch('http://127.0.0.1:3000/readyz').then(async (r)=>{const b=await r.json(); console.log(JSON.stringify(b)); process.exit(r.ok?0:1);}).catch(()=>process.exit(1))"

echo "DEPLOY_SHA=$(git rev-parse HEAD)"

#!/usr/bin/env bash
# Deploy TalonHound application changes on an existing installation host.
# Builds from local source (development/production workflow). Does not switch to GHCR release images.
set -euo pipefail

ROOT="${TALONHOUND_ROOT:-/opt/TalonHound}"
cd "$ROOT"

echo "=== TalonHound source deploy ==="
git fetch origin main
git merge --ff-only origin/main

if [ -f VERSION ]; then
  export TALONHOUND_VERSION="$(tr -d '\r\n' < VERSION)"
  export TALONHOUND_COMMIT="$(git rev-parse HEAD)"
  export TALONHOUND_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Product version: ${TALONHOUND_VERSION}"
fi

echo "=== build backend + frontend ==="
docker compose build backend frontend proxy integration-worker integration-scheduler

echo "=== recreate application services ==="
docker compose up -d --no-deps backend
docker compose up -d --no-deps --force-recreate frontend proxy
docker compose up -d --no-deps --force-recreate \
  ioc-expiration-worker ioc-search-export-worker ioc-deep-search-worker ioc-bulk-query-worker backup-worker \
  integration-worker integration-scheduler

echo "=== wait for backend health ==="
for i in $(seq 1 30); do
  status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' talonhound-backend-1 2>/dev/null || echo missing)"
  echo "try $i: $status"
  if [ "$status" = "healthy" ]; then
    break
  fi
  sleep 5
done

echo "=== readyz ==="
docker compose exec -T backend node -e "fetch('http://127.0.0.1:3000/readyz').then(async (r)=>{const b=await r.json(); console.log(JSON.stringify(b)); process.exit(r.ok?0:1);}).catch(()=>process.exit(1))"

echo "=== version ==="
docker compose exec -T backend node -e "fetch('http://127.0.0.1:3000/api/system/version').then(async (r)=>{console.log('status', r.status); console.log(await r.text()); process.exit(r.status===401||r.status===200?0:1);}).catch(()=>process.exit(1))"

echo "Deploy complete."

#!/usr/bin/env bash
# Deploy TalonHound application changes on an existing installation host.
# Builds from local source (development/production workflow). Does not switch to GHCR release images.
set -euo pipefail

ROOT="${TALONHOUND_ROOT:-/opt/TalonHound}"
cd "$ROOT"

echo "=== TalonHound source deploy ==="
PREVIOUS_HEAD="$(git rev-parse --short HEAD)"
git fetch origin main
git merge --ff-only origin/main

if [ -f VERSION ]; then
  export TALONHOUND_VERSION="$(tr -d '\r\n' < VERSION)"
  export TALONHOUND_COMMIT="$(git rev-parse HEAD)"
  export TALONHOUND_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Product version: ${TALONHOUND_VERSION}"
fi

echo "=== tag running images as rollback-${PREVIOUS_HEAD} ==="
# One rollback generation per deploy; prune-rollback-images.sh bounds how many are kept.
IMAGE_PREFIX="${TALONHOUND_IMAGE_PREFIX:-talonhound-}"
for svc in backend frontend proxy integration-worker integration-scheduler; do
  cid="$(docker compose ps -q "$svc" 2>/dev/null | head -n1 || true)"
  [ -n "$cid" ] || { echo "skip $svc (not running)"; continue; }
  ref="${IMAGE_PREFIX}${svc}:rollback-${PREVIOUS_HEAD}"
  if docker image inspect "$ref" >/dev/null 2>&1; then
    echo "keep existing $ref"
  else
    docker tag "$(docker inspect -f '{{.Image}}' "$cid")" "$ref" && echo "tagged $ref"
  fi
done

echo "=== build backend + frontend ==="
# backend image is shared by all backend-derived workers (see docker-compose.yml
# x-backend-image). Building `backend` refreshes the tag workers recreate from.
docker compose build backend frontend proxy integration-worker integration-scheduler

echo "=== recreate application services ==="
docker compose up -d --no-deps backend
docker compose up -d --no-deps --force-recreate frontend proxy
docker compose up -d --no-deps --force-recreate \
  ioc-expiration-worker ioc-search-export-worker ioc-deep-search-worker ioc-bulk-query-worker threat-library-worker backup-worker \
  integration-worker integration-scheduler

echo "=== verify threat-library-worker shares backend image ==="
backend_img="$(docker inspect -f '{{.Image}}' talonhound-backend-1)"
tl_img="$(docker inspect -f '{{.Image}}' talonhound-threat-library-worker-1)"
echo "backend=$backend_img"
echo "threat-library-worker=$tl_img"
if [ "$backend_img" != "$tl_img" ]; then
  echo "ERROR: threat-library-worker is not running the shared backend image" >&2
  exit 1
fi
if ! docker compose exec -T threat-library-worker test -f /app/lib/threatLibrary/ai/client.js; then
  echo "ERROR: threat-library-worker missing long-running AI client module" >&2
  exit 1
fi

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

echo "=== rollback image retention ==="
# Dry run unless TALONHOUND_PRUNE_ROLLBACK_IMAGES=1; never fails the deploy.
prune_args=()
[ "${TALONHOUND_PRUNE_ROLLBACK_IMAGES:-0}" = "1" ] && prune_args+=(--apply)
bash "$ROOT/scripts/release/prune-rollback-images.sh" "${prune_args[@]}"   || echo "WARN: rollback image retention reported a problem (deploy unaffected)" >&2

echo "Deploy complete."

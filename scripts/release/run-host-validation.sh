#!/usr/bin/env bash
# Run release foundation validation on the TalonHound host (/opt/TalonHound).
set -euo pipefail

ROOT="${TALONHOUND_ROOT:-/opt/TalonHound}"
cd "$ROOT"

echo "=== release validation ==="
node scripts/release/validate-version-tag.js "v$(tr -d '\r\n' < VERSION)"
node --test scripts/release/generate-manifest.test.js
node scripts/release/latest-migration.js

echo "=== backend tests ==="
cd backend
npm run test:release
npm run test:migrate
npm run test:sprint-smoke

echo "=== frontend tests ==="
cd ../frontend
npm run test:product-version
npm test
npm run build

echo "=== compose validation ==="
cd ..
docker compose -f docker-compose.yml config >/dev/null
TALONHOUND_BACKEND_IMAGE=ghcr.io/example/talonhound-backend:0.0.0 \
TALONHOUND_FRONTEND_IMAGE=ghcr.io/example/talonhound-frontend:0.0.0 \
TALONHOUND_INTEGRATION_IMAGE=ghcr.io/example/talonhound-integration:0.0.0 \
TALONHOUND_PROXY_IMAGE=ghcr.io/example/talonhound-proxy:0.0.0 \
  docker compose -f docker-compose.yml -f docker-compose.release.yml config >/dev/null

echo "All host validation checks passed."

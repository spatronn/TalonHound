#!/usr/bin/env bash
# Run release foundation validation on the TalonHound host (/opt/TalonHound).
# Uses Docker for Node.js and tests because production hosts do not install Node locally.
set -euo pipefail

ROOT="${TALONHOUND_ROOT:-/opt/TalonHound}"
cd "$ROOT"

NODE_IMAGE="${TALONHOUND_NODE_IMAGE:-node:20-alpine}"
COMPOSE_NETWORK="${TALONHOUND_COMPOSE_NETWORK:-talonhound_default}"

run_repo_node() {
  docker run --rm -v "${ROOT}:/repo" -w /repo "${NODE_IMAGE}" node "$@"
}

run_repo_node_test() {
  docker run --rm -v "${ROOT}:/repo" -w /repo "${NODE_IMAGE}" node --test "$@"
}

echo "=== release validation ==="
version="$(tr -d '\r\n' < VERSION)"
run_repo_node scripts/release/validate-version-tag.js "v${version}"
run_repo_node_test scripts/release/generate-manifest.test.js
run_repo_node scripts/release/latest-migration.js

if run_repo_node scripts/release/validate-version-tag.js "v${version}.bad" >/dev/null 2>&1; then
  echo "Expected mismatched tag validation to fail"
  exit 1
fi
echo "Mismatch correctly rejected"

echo "=== rebuild application images for current source ==="
export TALONHOUND_VERSION="${version}"
export TALONHOUND_COMMIT="$(git rev-parse HEAD)"
export TALONHOUND_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker compose build backend frontend

echo "=== backend tests ==="
docker compose run --rm --no-deps backend npm run test:release
docker compose run --rm --no-deps backend npm run test:migrate
docker compose run --rm --no-deps backend npm run test:sprint-smoke

echo "=== frontend tests ==="
docker run --rm -v "${ROOT}/frontend:/app" -w /app "${NODE_IMAGE}" \
  sh -c "npm ci && npm run test:product-version && npm test && npm run build"

echo "=== compose validation ==="
docker compose -f docker-compose.yml config >/dev/null
TALONHOUND_BACKEND_IMAGE=ghcr.io/example/talonhound-backend:0.0.0 \
TALONHOUND_FRONTEND_IMAGE=ghcr.io/example/talonhound-frontend:0.0.0 \
TALONHOUND_INTEGRATION_IMAGE=ghcr.io/example/talonhound-integration:0.0.0 \
TALONHOUND_PROXY_IMAGE=ghcr.io/example/talonhound-proxy:0.0.0 \
  docker compose -f docker-compose.yml -f docker-compose.release.yml config >/dev/null

echo "=== docker build smoke (no publish) ==="
docker compose build proxy integration-worker

echo "=== fresh database migration test (isolated) ==="
test_db="talonhound-migrate-test-$$"
cleanup() {
  docker rm -f "${test_db}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "${test_db}" --network "${COMPOSE_NETWORK}" \
  -e POSTGRES_DB=talonhound \
  -e POSTGRES_USER=talonhound \
  -e POSTGRES_PASSWORD=ci-test-password \
  postgres:16-alpine >/dev/null

for i in $(seq 1 30); do
  if docker exec "${test_db}" pg_isready -U talonhound -d talonhound >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

for file in db/init/*.sql; do
  echo "Applying ${file}"
  docker exec -i "${test_db}" psql -U talonhound -d talonhound -v ON_ERROR_STOP=1 < "${file}"
done

docker compose run --rm --no-deps \
  -e DB_HOST="${test_db}" \
  -e DB_PASSWORD=ci-test-password \
  backend npm run migrate

docker compose run --rm --no-deps \
  -e DB_HOST="${test_db}" \
  -e DB_PASSWORD=ci-test-password \
  backend npm run migrate

echo "=== release manifest dry run ==="
cat > /tmp/talonhound-release-images.json <<EOF
{
  "backend": {
    "repository": "ghcr.io/spatronn/talonhound-backend",
    "tag": "${version}",
    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "frontend": {
    "repository": "ghcr.io/spatronn/talonhound-frontend",
    "tag": "${version}",
    "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "integration": {
    "repository": "ghcr.io/spatronn/talonhound-integration",
    "tag": "${version}",
    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  },
  "proxy": {
    "repository": "ghcr.io/spatronn/talonhound-proxy",
    "tag": "${version}",
    "digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  }
}
EOF
latest_migration="$(run_repo_node scripts/release/latest-migration.js | python3 -c "import sys,json; print(json.load(sys.stdin)['latestMigration'])")"
images_file="${ROOT}/.tmp-release-images.json"
manifest_file="${ROOT}/.tmp-release-manifest.json"
cp /tmp/talonhound-release-images.json "${images_file}"
run_repo_node scripts/release/write-manifest-file.js \
  --version "${version}" \
  --git-tag "v${version}" \
  --git-commit "$(git rev-parse HEAD)" \
  --released-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --latest-migration "${latest_migration}" \
  --images-file "/repo/.tmp-release-images.json" \
  --out "/repo/.tmp-release-manifest.json"

docker run --rm -v "${ROOT}:/repo" -w /repo "${NODE_IMAGE}" \
  node --input-type=module -e "import { validateReleaseManifest } from './scripts/release/generate-manifest.js'; import { readFileSync } from 'node:fs'; validateReleaseManifest(JSON.parse(readFileSync('.tmp-release-manifest.json','utf8'))); console.log('manifest ok');"
rm -f "${images_file}" "${manifest_file}"

echo "All host validation checks passed."

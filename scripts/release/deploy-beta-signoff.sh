#!/usr/bin/env bash
set -euo pipefail
ROOT="/opt/TalonHound"
cd "$ROOT"
git fetch origin main
git merge --ff-only origin/main
sed -i 's/^PUBLISHED_FEED_CHUNKED_FEED_IDS=.*/PUBLISHED_FEED_CHUNKED_FEED_IDS=11/' .env
docker compose up -d db redis
docker compose run --rm backend npm run migrate
export TALONHOUND_VERSION="$(tr -d '\r\n' < VERSION 2>/dev/null || echo dev)"
export TALONHOUND_COMMIT="$(git rev-parse HEAD)"
export TALONHOUND_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker compose build backend
docker compose up -d --no-deps backend integration-scheduler
sed -i 's/\r$//' scripts/pg_io_benchmark.sh scripts/prod-pf-status.sh scripts/prod-pf-run-feed.sh
chmod +x scripts/pg_io_benchmark.sh scripts/prod-pf-*.sh
nohup bash scripts/pg_io_benchmark.sh 3600 > /tmp/pg_io_beta_signoff.log 2>&1 &
echo "BENCHMARK_PID=$!"
echo "DEPLOY_SHA=$(git rev-parse HEAD)"

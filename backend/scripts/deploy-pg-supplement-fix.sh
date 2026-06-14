#!/bin/bash
set -eu
cd /opt/demo-runbook

echo "=== BEFORE CPU ==="
docker stats --no-stream --format '{{.Name}} CPU={{.CPUPerc}}' demo-db demo-ioc-correlation-engine || true

echo "=== APPLY MIGRATION 086 ==="
docker exec -i demo-db psql -U demo -d demo -P pager=off < backend/migrations/086_ioc_supplement_lookup_index.sql

echo "=== UNIT TESTS ==="
docker compose exec -T backend npm run test:ioc-match-reactivation

echo "=== REBUILD correlation worker ==="
docker compose build ioc-correlation-engine
docker compose up -d ioc-correlation-engine

echo "=== WAIT 60s for ticks ==="
sleep 60

echo "=== AFTER CPU ==="
docker stats --no-stream --format '{{.Name}} CPU={{.CPUPerc}}' demo-db demo-ioc-correlation-engine demo-backend

echo "=== pg_stat_activity ==="
docker exec demo-db psql -U demo -d demo -P pager=off -c \
  "SELECT pid, now() - query_start AS duration, left(query, 100) AS query FROM pg_stat_activity WHERE datname=current_database() AND state='active' AND pid <> pg_backend_pid();"

echo "=== CORRELATION LOGS ==="
docker logs demo-ioc-correlation-engine --tail 10 2>&1 | grep ioc-correlation || docker logs demo-ioc-correlation-engine --tail 10

echo "=== SMOKE ==="
bash backend/scripts/smoke-pg-supplement-lookup.sh

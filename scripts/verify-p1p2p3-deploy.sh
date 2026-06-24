#!/bin/bash
set -eu
cd /opt/demo-runbook
git pull
docker compose build integration-worker
docker compose up -d integration-worker
sleep 5
docker compose ps integration-worker backend
docker compose exec -T integration-worker npm run test:urlhaus
docker compose exec -T db psql -U demo -d demo -P pager=off -c "SHOW shared_buffers; SHOW effective_cache_size; SHOW work_mem; SHOW shared_preload_libraries;"
docker compose exec -T db psql -U demo -d demo -P pager=off -c "SELECT extname FROM pg_extension WHERE extname = 'pg_stat_statements';"
curl -sk -o /dev/null -w "frontend_http=%{http_code}\n" https://localhost/

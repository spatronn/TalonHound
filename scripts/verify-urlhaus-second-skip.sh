#!/bin/bash
set -eu
cd /opt/demo-runbook
echo "=== Seed checkpoint from live export ==="
docker compose exec -T integration-worker node scripts/seed-urlhaus-checkpoint.js
echo "=== Trigger URLHaus (expect skipped_unchanged) ==="
docker compose exec -T backend node scripts/trigger-feed-run.js urlhaus-abusech
sleep 30
docker compose logs integration-worker --tail 10 2>&1 | grep -E 'skipped unchanged|urlhaus_import' || true
docker compose exec -T db psql -U demo -d demo -P pager=off -c \
  "SELECT id, status, records_processed, records_updated, records_inserted
   FROM integration_runs WHERE job_type='urlhaus_import' ORDER BY id DESC LIMIT 1;"

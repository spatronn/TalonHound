#!/bin/bash
set -eu
cd /opt/demo-runbook
echo "=== Trigger URLHaus import ==="
docker compose exec -T backend node scripts/trigger-feed-run.js urlhaus-abusech
echo "=== Wait 120s for worker ==="
sleep 120
echo "=== Worker logs ==="
docker compose logs integration-worker --tail 20 2>&1 | grep -E 'urlhaus|skipped unchanged|integration-import' || true
echo "=== Recent integration_runs ==="
docker compose exec -T db psql -U demo -d demo -P pager=off -c \
  "SELECT id, job_type, status, records_processed, records_updated, records_inserted, records_skipped
   FROM integration_runs WHERE job_type='urlhaus_import' ORDER BY id DESC LIMIT 3;"
echo "=== Checkpoint ==="
docker compose exec -T db psql -U demo -d demo -P pager=off -c \
  "SELECT left(last_cursor, 120) AS checkpoint FROM integration_checkpoints WHERE source_name='URLhaus:abuse.ch';"

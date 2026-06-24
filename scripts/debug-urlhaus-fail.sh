#!/bin/bash
set -eu
cd /opt/demo-runbook
docker compose exec -T db psql -U demo -d demo -P pager=off -c \
  "SELECT id, status, left(error_message, 200) AS err, started_at, finished_at FROM integration_runs WHERE id=6181;"
docker compose logs integration-worker --since 15m 2>&1 | grep -E '6181|urlhaus|error|failed|skipped unchanged' | tail -30

#!/bin/bash
# Smoke checks for PG supplement lookup optimization (run on stack host).
set -eu

echo "=== 1. Migration 086 index present ==="
docker exec demo-db psql -U demo -d demo -P pager=off -c \
  "SELECT indexname FROM pg_indexes WHERE indexname = 'idx_ioc_items_supplement_lookup';"

echo
echo "=== 2. signal_events absent (raw syslog not in PG) ==="
docker exec demo-db psql -U demo -d demo -P pager=off -c \
  "SELECT to_regclass('public.signal_events') AS signal_events;"

echo
echo "=== 3. syslog-receiver LOG_STORAGE ==="
docker exec demo-syslog-receiver printenv LOG_STORAGE

echo
echo "=== 4. correlation env ==="
docker exec demo-ioc-correlation-engine printenv PG_SUPPLEMENT_LOOKUP_ENABLED 2>/dev/null || echo "unset"
docker exec demo-ioc-correlation-engine printenv PG_SUPPLEMENT_LOOKUP_MAX_KEYS 2>/dev/null || echo "unset"

echo
echo "=== 5. docker stats (db) ==="
docker stats --no-stream --format '{{.Name}} CPU={{.CPUPerc}}' demo-db demo-ioc-correlation-engine

echo
echo "=== 6. pg_stat_activity (active queries) ==="
docker exec demo-db psql -U demo -d demo -P pager=off -c \
  "SELECT pid, now() - query_start AS duration, left(query, 120) AS query
   FROM pg_stat_activity
   WHERE datname = current_database() AND state = 'active' AND pid <> pg_backend_pid();"

echo
echo "=== 7. correlation worker recent metrics ==="
docker logs demo-ioc-correlation-engine --tail 5 2>&1 | grep ioc-correlation || true

echo
echo "=== 8. EXPLAIN supplement lookup (indexed) ==="
docker exec demo-db psql -U demo -d demo -P pager=off -c \
  "EXPLAIN (FORMAT TEXT) SELECT DISTINCT ON (lower(i.observable), CASE WHEN i.observable_type = 'hostname' THEN 'domain' ELSE i.observable_type END)
   i.observable FROM ioc_items i
   WHERE (lower(i.observable), CASE WHEN i.observable_type = 'hostname' THEN 'domain' ELSE i.observable_type END) IN (('8.8.8.8','ip'))
   AND COALESCE(i.status, 'active') IN ('active','expired')
   ORDER BY lower(i.observable), CASE WHEN i.observable_type = 'hostname' THEN 'domain' ELSE i.observable_type END, i.created_at ASC;"

echo
echo "SMOKE OK"

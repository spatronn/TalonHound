#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
\timing on
\echo '=== Reconciliation indexed slice 1 (buckets 4-7) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT ioc_item_id AS id, observable_type, identity_key
FROM published_feed_items
WHERE feed_id = 11
  AND snapshot_window = 'all'
  AND reconciliation_bucket >= 4 AND reconciliation_bucket < 8
ORDER BY identity_key
LIMIT 500;
SQL

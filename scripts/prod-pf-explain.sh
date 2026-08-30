#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound
OUT="/tmp/pf_explain_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee "$OUT") 2>&1
echo "EXPLAIN output: $OUT"
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
\timing on
\echo '=== Domain boundary (feed 11) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT identity_key, recency_ts
FROM published_feed_items
WHERE feed_id = 11
  AND snapshot_window = 'all'
  AND recency_ts >= NOW() - INTERVAL '2 days'
  AND recency_ts < NOW() - INTERVAL '1 day'
ORDER BY identity_key
LIMIT 500;

\echo '=== URL boundary (feed 12) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT identity_key, recency_ts
FROM published_feed_items
WHERE feed_id = 12
  AND snapshot_window = 'all'
  AND recency_ts >= NOW() - INTERVAL '2 days'
  AND recency_ts < NOW() - INTERVAL '1 day'
ORDER BY identity_key
LIMIT 500;

\echo '=== Reconciliation batch indexed (feed 11 slice 1 buckets 4-7) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT ioc_item_id AS id, observable_type, identity_key
FROM published_feed_items
WHERE feed_id = 11
  AND snapshot_window = 'all'
  AND reconciliation_bucket = ANY(ARRAY[4,5,6,7]::smallint[])
ORDER BY identity_key
LIMIT 500;

\echo '=== Dirty chunk projection (feed 11 chunk 42) ==='
EXPLAIN (ANALYZE, BUFFERS)
SELECT identity_key, observable, observable_type, recency_ts
FROM published_feed_items
WHERE feed_id = 11
  AND snapshot_window = 'all'
  AND chunk_key = 42
ORDER BY identity_key
LIMIT 5000;
SQL
echo "DONE $OUT"

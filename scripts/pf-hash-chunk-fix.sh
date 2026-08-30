#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
SELECT chunk_backfill_status, chunk_count,
       COUNT(*) AS total,
       COUNT(*) FILTER (WHERE chunk_key IS NULL) AS missing_chunk,
       COUNT(*) FILTER (WHERE partition_identity IS NULL) AS missing_part
FROM published_feed_items
WHERE feed_id = 25 AND snapshot_window = 'all'
GROUP BY 1,2;

SELECT identity_key, partition_identity, chunk_key, observable_type, updated_at
FROM published_feed_items
WHERE feed_id = 25 AND snapshot_window = 'all' AND chunk_key IS NULL
ORDER BY updated_at DESC
LIMIT 15;
SQL

echo '=== RE-RUN BACKFILL ==='
docker compose exec -T backend node /app/scripts/published-feed-chunk-backfill.js --feed-id 25

docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
SELECT chunk_backfill_status, chunk_count,
       COUNT(*) FILTER (WHERE chunk_key IS NOT NULL) AS keyed,
       COUNT(*) AS total
FROM published_feed_items
WHERE feed_id = 25 AND snapshot_window = 'all'
GROUP BY 1,2;
SQL

#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
SELECT id, name, projection_status, last_refresh_mode, reconciliation_slice
FROM published_feeds WHERE id IN (11,12,14,15) ORDER BY id;
SELECT feed_id, snapshot_window, COUNT(*)::bigint AS n
FROM published_feed_items WHERE feed_id IN (11,12,14) GROUP BY 1,2 ORDER BY 1,2;
SELECT pg_size_pretty(pg_database_size(current_database())) AS db_size;
SQL
echo "--- bootstrap feed 12 ---"
tail -3 /tmp/bootstrap-feed-12.log 2>/dev/null || true
echo "--- recent refresh logs ---"
docker compose logs integration-scheduler --since=30m 2>/dev/null | grep 'published feed refresh' | tail -10 || true

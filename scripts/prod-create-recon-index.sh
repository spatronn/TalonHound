#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
DROP INDEX CONCURRENTLY IF EXISTS idx_pf_items_feed_recon_bucket;
CREATE INDEX CONCURRENTLY idx_pf_items_feed_recon_bucket
  ON published_feed_items (feed_id, reconciliation_bucket, identity_key)
  WHERE snapshot_window = 'all' AND reconciliation_bucket IS NOT NULL;
ANALYZE published_feed_items;
SQL
echo "INDEX_DONE"

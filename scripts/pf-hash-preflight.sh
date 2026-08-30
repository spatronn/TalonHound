#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound

echo '=== HASH FEED ==='
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
SELECT id, name, slug, enabled, ioc_type, ioc_types, formats, time_window,
       filter_mode, projection_status, projection_cutoff, projection_pending_cutoff,
       chunk_count, chunk_algo_version, chunk_backfill_status,
       last_refresh_mode, last_status, last_item_count, last_changed_count,
       last_refresh_ms, last_generated_at, last_error,
       canonicalize_hashes, max_items, refresh_interval_minutes
FROM published_feeds
WHERE slug ILIKE '%hash%' OR name ILIKE '%hash%' OR ioc_types::text ILIKE '%hash%'
ORDER BY id;
SQL

echo '=== PROJECTION COUNT ==='
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
SELECT pf.id, pf.slug, COUNT(pfi.*) AS projection_rows
FROM published_feeds pf
LEFT JOIN published_feed_items pfi ON pfi.feed_id = pf.id AND pfi.snapshot_window = 'all'
WHERE pf.slug ILIKE '%hash%' OR pf.name ILIKE '%hash%'
GROUP BY pf.id, pf.slug;
SQL

echo '=== ACTIVE GENERATION ==='
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
SELECT a.feed_id, pf.slug, a.snapshot_window, a.ioc_type_key, g.id AS gen_id, g.state,
       g.item_count, g.created_at
FROM published_feed_active_generations a
JOIN published_feeds pf ON pf.id = a.feed_id
JOIN published_feed_generations g ON g.id = a.generation_id
WHERE pf.slug ILIKE '%hash%' OR pf.name ILIKE '%hash%';
SQL

echo '=== RECENT SNAPSHOTS ==='
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
SELECT s.id, s.feed_id, pf.slug, s.status, s.generated_at, s.item_count,
       s.params->>'refresh_mode' AS refresh_mode,
       s.params->>'projection_rows_read' AS projection_rows_read,
       s.params->>'dirty_candidates' AS dirty_candidates,
       s.params->>'chunks_generated' AS chunks_generated,
       s.params->>'chunks_reused' AS chunks_reused
FROM published_feed_snapshots s
JOIN published_feeds pf ON pf.id = s.feed_id
WHERE pf.slug ILIKE '%hash%' OR pf.name ILIKE '%hash%'
ORDER BY s.id DESC LIMIT 10;
SQL

echo '=== BACKEND ENV PF FLAGS ==='
docker compose exec -T backend printenv | grep -E 'PUBLISHED_FEED_(INCREMENTAL|CHUNKED)' | sort

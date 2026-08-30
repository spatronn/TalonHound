#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound
FEED_ID=25

docker compose exec -T db psql -U talonhound -d talonhound -c \
  "UPDATE published_feeds SET projection_status='ready', last_status='success', last_refresh_mode='chunked_incremental' WHERE id=$FEED_ID RETURNING projection_status, chunk_backfill_status, chunk_count;"

capture_snap() {
  local snap_tag="$1"
  local out="/tmp/pf_hash_${snap_tag}_$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$out"
  echo "UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out/meta.txt"
  local pg_cid cgroup
  pg_cid=$(docker compose ps -q db --no-trunc)
  cgroup="/sys/fs/cgroup/system.slice/docker-$(docker inspect "$pg_cid" --format '{{.Id}}' | sed 's|^/||').scope"
  grep '^259:0 ' "$cgroup/io.stat" | tee "$out/cgroup_io.stat"
  docker compose exec -T db psql -U talonhound -d talonhound -At -c \
    "SELECT blks_read, blks_hit, temp_bytes FROM pg_stat_database WHERE datname='talonhound';" > "$out/pg_db.txt"
  docker compose exec -T db psql -U talonhound -d talonhound -v ON_ERROR_STOP=1 -c \
    "COPY (SELECT queryid, calls, shared_blks_read, shared_blks_hit, temp_blks_read+temp_blks_written AS temp_blks, total_exec_time, left(regexp_replace(query, E'[\\n\\r\\t]+', ' ', 'g'), 180) AS q FROM pg_stat_statements WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database())) TO STDOUT WITH CSV HEADER" > "$out/pgss.csv"
  echo "$out"
}

T0_DIR=$(capture_snap T0)
echo "T0_DIR=$T0_DIR"
START_EPOCH=$(date +%s)
docker compose exec -T backend node -e "
import pg from 'pg';
import { generatePublishedFeedSnapshot } from './lib/feedPublisherService.js';
const pool = new pg.Pool({ host: process.env.DB_HOST||'db', port:5432, user: process.env.DB_USER||'talonhound', password: process.env.DB_PASSWORD, database: process.env.DB_NAME||'talonhound' });
const r = await generatePublishedFeedSnapshot(pool, $FEED_ID, { force: false });
console.log(JSON.stringify(r, null, 2));
await pool.end();
"
END_EPOCH=$(date +%s)
echo "NOOP_SEC=$((END_EPOCH-START_EPOCH))"
T1_DIR=$(capture_snap T1)
echo "T1_DIR=$T1_DIR"

docker compose exec -T db psql -U talonhound -d talonhound -c \
  "SELECT id, status, item_count, params->>'refresh_mode' AS refresh_mode, params->>'dirty_candidates' AS dirty_candidates, params->>'semantic_changes' AS semantic_changes, params->>'projection_rows_read' AS projection_rows_read, params->>'chunks_generated' AS chunks_generated, params->>'chunks_reused' AS chunks_reused, params->>'rows_read' AS rows_read FROM published_feed_snapshots WHERE feed_id=$FEED_ID ORDER BY id DESC LIMIT 3;"
docker compose exec -T db psql -U talonhound -d talonhound -c \
  "SELECT last_refresh_mode, last_refresh_ms, last_changed_count, last_status FROM published_feeds WHERE id=$FEED_ID;"

#!/usr/bin/env bash
# Activate HASH published feed (id=25) incremental+chunked path and validate.
set -euo pipefail
cd /opt/TalonHound
FEED_ID=25
LOG=/tmp/pf_hash_activate_$(date -u +%Y%m%dT%H%M%SZ).log
exec > >(tee -a "$LOG") 2>&1

echo "=== LOG $LOG ==="
echo "UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

update_env() {
  local key="$1" val="$2"
  if grep -q "^${key}=" .env; then
    sed -i "s|^${key}=.*|${key}=${val}|" .env
  else
    echo "${key}=${val}" >> .env
  fi
}

echo '=== UPDATE ALLOWLISTS ==='
update_env PUBLISHED_FEED_INCREMENTAL_FEED_IDS '11,12,14,25'
update_env PUBLISHED_FEED_CHUNKED_FEED_IDS '11,12,25'
grep -E 'PUBLISHED_FEED_(INCREMENTAL|CHUNKED)' .env

echo '=== RECREATE BACKEND ==='
docker compose up -d backend --force-recreate
sleep 8
docker compose exec -T backend printenv | grep -E 'PUBLISHED_FEED_(INCREMENTAL|CHUNKED)' | sort

capture_t0() {
  local tag="$1"
  local out="/tmp/pf_hash_${tag}_$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$out"
  echo "UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out/meta.txt"
  PG_CID=$(docker compose ps -q db --no-trunc)
  CGROUP="/sys/fs/cgroup/system.slice/docker-$(docker inspect "$PG_CID" --format '{{.Id}}' | sed 's|^/||').scope"
  grep '^259:0 ' "$CGROUP/io.stat" | tee "$out/cgroup_io.stat"
  docker compose exec -T db psql -U talonhound -d talonhound -v ON_ERROR_STOP=1 <<SQL > "$out/pg_snapshot.txt"
\pset format unaligned
SELECT datname, blks_read, blks_hit, temp_bytes FROM pg_stat_database WHERE datname=current_database();
SELECT wal_bytes FROM pg_stat_wal;
SQL
  docker compose exec -T db psql -U talonhound -d talonhound -v ON_ERROR_STOP=1 -c \
    "COPY (SELECT queryid, calls, shared_blks_read, shared_blks_hit, temp_blks_read+temp_blks_written AS temp_blks,
                  total_exec_time, left(regexp_replace(query, E'[\\n\\r\\t]+', ' ', 'g'), 200) AS q
           FROM pg_stat_statements WHERE dbid=(SELECT oid FROM pg_database WHERE datname=current_database())
          ) TO STDOUT WITH CSV HEADER" > "$out/pg_stat_statements.csv"
  echo "$out"
}

echo '=== BOOTSTRAP PROJECTION (may take several minutes) ==='
BOOT_START=$(date +%s)
docker compose exec -T backend node /app/scripts/bootstrap-published-feed-projection.js --feed-id=$FEED_ID
BOOT_END=$(date +%s)
echo "BOOTSTRAP_SEC=$((BOOT_END-BOOT_START))"

docker compose exec -T db psql -U talonhound -d talonhound -c \
  "SELECT projection_status, projection_cutoff, chunk_backfill_status, chunk_count,
          (SELECT COUNT(*) FROM published_feed_items WHERE feed_id=$FEED_ID AND snapshot_window='all') AS proj_rows
   FROM published_feeds WHERE id=$FEED_ID;"

echo '=== CHUNK BACKFILL ==='
BF_START=$(date +%s)
docker compose exec -T backend node /app/scripts/published-feed-chunk-backfill.js --feed-id=$FEED_ID
BF_END=$(date +%s)
echo "BACKFILL_SEC=$((BF_END-BF_START))"

docker compose exec -T db psql -U talonhound -d talonhound -c \
  "SELECT chunk_count, chunk_algo_version, chunk_backfill_status,
          COUNT(*) FILTER (WHERE chunk_key IS NOT NULL) AS keyed,
          COUNT(*) AS total
   FROM published_feed_items WHERE feed_id=$FEED_ID AND snapshot_window='all'
   GROUP BY chunk_count, chunk_algo_version, chunk_backfill_status;"

echo '=== CHUNK BOOTSTRAP ==='
CB_START=$(date +%s)
docker compose exec -T backend node /app/scripts/published-feed-chunk-bootstrap.js --feed-id=$FEED_ID --ioc-type-key=hash
CB_END=$(date +%s)
echo "CHUNK_BOOTSTRAP_SEC=$((CB_END-CB_START))"

echo '=== STEADY STATE NOOP TEST ==='
T0=$(capture_t0 T0)
echo "T0=$T0"
NOOP_START=$(date +%s)
docker compose exec -T backend node -e "
import pg from 'pg';
import { generatePublishedFeedSnapshot } from './lib/feedPublisherService.js';
const pool = new pg.Pool({ host: process.env.DB_HOST||'db', port:5432, user: process.env.DB_USER||'talonhound', password: process.env.DB_PASSWORD, database: process.env.DB_NAME||'talonhound' });
const r = await generatePublishedFeedSnapshot(pool, $FEED_ID, { force: false });
console.log(JSON.stringify(r, null, 2));
await pool.end();
"
NOOP_END=$(date +%s)
echo "NOOP_REFRESH_SEC=$((NOOP_END-NOOP_START))"
T1=$(capture_t0 T1)
echo "T1=$T1"

echo '=== FEED STATE AFTER NOOP ==='
docker compose exec -T db psql -U talonhound -d talonhound -c \
  "SELECT id, last_refresh_mode, last_status, last_refresh_ms, last_changed_count, projection_status, chunk_backfill_status, chunk_count
   FROM published_feeds WHERE id=$FEED_ID;"
docker compose exec -T db psql -U talonhound -d talonhound -c \
  "SELECT id, status, item_count, params->>'refresh_mode' AS refresh_mode,
          params->>'dirty_candidates' AS dirty_candidates,
          params->>'semantic_changes' AS semantic_changes,
          params->>'projection_rows_read' AS projection_rows_read,
          params->>'chunks_generated' AS chunks_generated,
          params->>'chunks_reused' AS chunks_reused,
          params->>'rows_read' AS rows_read
   FROM published_feed_snapshots WHERE feed_id=$FEED_ID ORDER BY id DESC LIMIT 3;"

echo '=== ACTIVE GENERATION ==='
docker compose exec -T db psql -U talonhound -d talonhound -c \
  "SELECT a.feed_id, a.ioc_type_key, g.id, g.state, g.item_count, gf.format, gf.item_count
   FROM published_feed_active_generations a
   JOIN published_feed_generations g ON g.id=a.generation_id
   JOIN published_feed_generation_formats gf ON gf.generation_id=g.id
   WHERE a.feed_id=$FEED_ID ORDER BY gf.format;"

echo "DONE LOG=$LOG T0=$T0 T1=$T1"

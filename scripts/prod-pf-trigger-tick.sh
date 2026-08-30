#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound
docker compose exec -T db psql -U talonhound -d talonhound <<'SQL'
SELECT id, name, projection_status, chunk_backfill_status, chunk_count, last_refresh_mode, last_refresh_ms
FROM published_feeds WHERE id IN (11,12,14) ORDER BY id;
SQL
echo "=== trigger feed tick ==="
docker compose exec -T backend node -e "
import pg from 'pg';
import { regenerateAllEnabledFeeds } from './lib/feedPublisherService.js';
const pool = new pg.Pool({host:'db',port:5432,user:process.env.DB_USER,password:process.env.DB_PASSWORD,database:process.env.DB_NAME});
const r = await regenerateAllEnabledFeeds(pool, { force: false });
console.log(JSON.stringify(r, null, 2));
await pool.end();
"

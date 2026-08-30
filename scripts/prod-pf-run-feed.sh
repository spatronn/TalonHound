#!/usr/bin/env bash
set -euo pipefail
cd /opt/TalonHound
FEED_ID="${1:-11}"
docker compose exec -T -e FEED_ID="$FEED_ID" backend node -e "
import pg from 'pg';
import { generatePublishedFeedSnapshot } from './lib/feedPublisherService.js';
const pool = new pg.Pool({host:'db',port:5432,user:process.env.DB_USER,password:process.env.DB_PASSWORD,database:process.env.DB_NAME});
const r = await generatePublishedFeedSnapshot(pool, Number(process.env.FEED_ID), { force: false });
console.log(JSON.stringify(r, null, 2));
await pool.end();
"

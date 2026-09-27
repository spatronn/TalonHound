#!/usr/bin/env node
/**
 * Published Feed artifact orphan GC (the same sweep the scheduler runs hourly).
 *
 * Usage (inside backend container):
 *   node scripts/published-feed-orphan-gc.js                 # dry-run report (default)
 *   node scripts/published-feed-orphan-gc.js --apply         # delete delete-eligible files
 *   node scripts/published-feed-orphan-gc.js --feed 25 --min-age-minutes 720
 *
 * Dry-run never modifies the filesystem or the database. Apply deletes only files that
 * no database row references, that belong to an existing feed, that are older than the
 * minimum age, and only while holding that feed's generation lock. UNKNOWN files are
 * reported and never deleted.
 */
import pg from 'pg';
import { runPublishedFeedOrphanGc, resolveOrphanGcMinAgeMinutes } from '../lib/publishedFeedArtifact/orphanGc.js';

function argValue(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const apply = process.argv.includes('--apply');
const feedArg = argValue('--feed');
const minAgeArg = argValue('--min-age-minutes');
const feedIds = feedArg
  ? String(feedArg).split(',').map(Number).filter((n) => Number.isInteger(n) && n > 0)
  : null;

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  max: 2
});

try {
  const report = await runPublishedFeedOrphanGc(pool, {
    apply,
    feedIds,
    minAgeMinutes: resolveOrphanGcMinAgeMinutes(minAgeArg)
  });
  console.log(JSON.stringify(report, null, 1));
  process.exitCode = report.delete_failed ? 1 : 0;
} finally {
  await pool.end();
}

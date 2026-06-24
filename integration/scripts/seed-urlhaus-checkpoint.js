#!/usr/bin/env node
/**
 * Verify URLHaus unchanged-export skip: seed checkpoint from live export, re-run import.
 */
import pg from 'pg';
import { fetchUrlhausExport, buildUrlhausCanonicalIocHash, parseUrlhausRecentCsv, resolveUrlhausAuthKey, saveUrlhausCheckpoint } from '../lib/urlhaus.js';

const sourceName = process.env.URLHAUS_SOURCE_NAME || 'URLhaus:abuse.ch';
const pool = new pg.Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

const client = await pool.connect();
try {
  const authKey = await resolveUrlhausAuthKey(client, process.env.URLHAUS_AUTH_KEY);
  if (!authKey) throw new Error('URLHaus auth key missing');

  const exportFetch = await fetchUrlhausExport(authKey, {
    fetchImpl: globalThis.fetch
  });
  const { entries } = parseUrlhausRecentCsv(exportFetch.text);
  const canonical = buildUrlhausCanonicalIocHash(entries);

  await saveUrlhausCheckpoint(client, sourceName, {
    etag: exportFetch.etag,
    last_modified: exportFetch.lastModified,
    raw_content_hash: exportFetch.rawContentHash,
    canonical_ioc_hash: canonical
  });

  await client.query(
    `UPDATE integration_source_state SET updated_at = NOW() - INTERVAL '10 minutes' WHERE source_name = $1`,
    [sourceName]
  );

  console.log(JSON.stringify({
    ok: true,
    action: 'checkpoint_seeded',
    canonical_ioc_hash: canonical,
    entries: entries.length,
    etag: exportFetch.etag
  }));
} finally {
  client.release();
  await pool.end();
}

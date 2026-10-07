import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

/**
 * Real-Postgres check of migration 039: existing MCP Analyst keys (scopes are
 * stored per key) gain mcp:enrichment:write; no other key type does; re-running
 * is a no-op; the widened CHECK constraint (038) accepts the result. Opt-in
 * (ENRICHMENT_JOB_ITEST=1) and only against a throwaway migrated database.
 */

const { Pool } = pg;
const enabled = process.env.ENRICHMENT_JOB_ITEST === '1';
const pool = enabled
  ? new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound',
    connectionTimeoutMillis: 3000,
    max: 2
  })
  : null;

let hasDb = false;
if (pool) {
  try {
    await pool.query('SELECT 1 FROM published_feed_access_keys LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ENRICHMENT_JOB_ITEST=1 and DB_* for a migrated throwaway database' };

const here = path.dirname(fileURLToPath(import.meta.url));
const MIGRATION = readFileSync(path.join(here, '..', 'migrations', '039_mcp_analyst_enrichment_scope.sql'), 'utf8');

test.after(async () => { await pool?.end().catch(() => {}); });

test('039 upgrades live MCP Analyst keys only, idempotently', opts, async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const seed = [
      ['itest analyst', 'mcp_analyst', ['mcp:ioc:read', 'mcp:ioc:create', 'mcp:sources:read', 'mcp:enrichment:read'], false],
      ['itest analyst deleted', 'mcp_analyst', ['mcp:ioc:read', 'mcp:ioc:create', 'mcp:sources:read', 'mcp:enrichment:read'], true],
      ['itest read', 'mcp_read', ['mcp:ioc:read', 'mcp:sources:read', 'mcp:enrichment:read'], false],
      ['itest ioc read', 'ioc_read', ['ioc:read', 'ioc:export'], false],
      ['itest feed', 'published_feed', ['published_feeds:read'], false]
    ];
    const ids = {};
    for (const [name, type, scopes, deleted] of seed) {
      const { rows } = await client.query(
        `INSERT INTO published_feed_access_keys (name, token_hash, key_type, scopes, enabled, deleted_at)
         VALUES ($1, md5(random()::text), $2, $3::jsonb, true, CASE WHEN $4 THEN now() ELSE NULL END) RETURNING id`,
        [name, type, JSON.stringify(scopes), deleted]
      );
      ids[name] = rows[0].id;
    }
    await client.query(MIGRATION);
    await client.query(MIGRATION); // idempotent
    const { rows } = await client.query(
      'SELECT name, scopes FROM published_feed_access_keys WHERE id = ANY($1::bigint[])',
      [Object.values(ids)]
    );
    const byName = Object.fromEntries(rows.map((r) => [r.name, r.scopes]));
    assert.deepEqual(byName['itest analyst'], [
      'mcp:ioc:read', 'mcp:ioc:create', 'mcp:sources:read', 'mcp:enrichment:read', 'mcp:enrichment:write'
    ]);
    assert.ok(!byName['itest analyst deleted'].includes('mcp:enrichment:write'), 'deleted keys untouched');
    assert.ok(!byName['itest read'].includes('mcp:enrichment:write'));
    assert.ok(!byName['itest ioc read'].includes('mcp:enrichment:write'));
    assert.ok(!byName['itest feed'].includes('mcp:enrichment:write'));
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
});

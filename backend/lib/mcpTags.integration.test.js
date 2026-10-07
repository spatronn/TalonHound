import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { mcpAddIocTags, mcpRemoveIocTags, mcpListTags } from './mcpTagService.js';

/**
 * Real-Postgres check of the MCP tag tools and migration 040: the service SQL
 * against the real ioc_tags / tags / ioc_items schema (partitioned ioc_items,
 * uq_ioc_tags_assignment, the hydrator's tag aggregate), and the 040 scope
 * backfill. Everything runs inside one transaction that is rolled back. Opt-in
 * (MCP_TAGS_ITEST=1) and only against a throwaway migrated database.
 */

const { Pool } = pg;
const enabled = process.env.MCP_TAGS_ITEST === '1';
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
    await pool.query('SELECT 1 FROM ioc_tags LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set MCP_TAGS_ITEST=1 and DB_* for a migrated throwaway database' };

const here = path.dirname(fileURLToPath(import.meta.url));
const MIGRATION_040 = readFileSync(path.join(here, '..', 'migrations', '040_mcp_tags_write_scope.sql'), 'utf8');

test.after(async () => { await pool?.end().catch(() => {}); });

/**
 * Pool facade over one client inside an outer transaction: the service's own
 * BEGIN/COMMIT/ROLLBACK become savepoints so the whole test still rolls back.
 */
function savepointPool(client) {
  const q = (sql, params) => {
    const text = String(sql).trim();
    if (text === 'BEGIN') return client.query('SAVEPOINT mcp_tags');
    if (text === 'COMMIT') return client.query('RELEASE SAVEPOINT mcp_tags');
    if (text === 'ROLLBACK') return client.query('ROLLBACK TO SAVEPOINT mcp_tags');
    return client.query(sql, params);
  };
  return { query: q, connect: async () => ({ query: q, release() {} }) };
}

test('MCP tag tools on real Postgres: add / idempotent / all-or-nothing / remove analyst-only / list', opts, async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: [ioc] } = await client.query(
      `INSERT INTO ioc_items (observable, observable_type, source_name)
       VALUES ('mcp-tags-itest.example', 'domain', 'itest') RETURNING id, public_id`
    );
    const tagIds = {};
    for (const [name, en] of [['itest-mcp-tag-a', true], ['itest-mcp-tag-b', true], ['itest-mcp-tag-off', false]]) {
      const { rows } = await client.query(
        `INSERT INTO tags (name, slug, type, category, enabled, created_origin)
         VALUES ($1, $1, 'context', 'custom', $2, 'manual') RETURNING id`,
        [name, en]
      );
      tagIds[name] = rows[0].id;
    }
    // Feed-provided tag on the same IOC.
    await client.query(
      `INSERT INTO ioc_tags (ioc_id, ioc_observable_type, tag_id, origin, source_name, source_key)
       VALUES ($1, 'domain', $2, 'integration', 'ThreatFox:abuse.ch', 'threatfox:abuse.ch')`,
      [ioc.id, tagIds['itest-mcp-tag-b']]
    );

    const db = savepointPool(client);
    const events = [];
    const ctx = {
      config: { tagWriteMax: 10, tagListMax: 100 },
      req: { user: { id: null, username: 'itest', role: 'analyst' }, headers: {} },
      mcpAuth: { apiKeyId: 1, apiKeyName: 'itest', keyType: 'mcp_analyst' },
      audit: { auditSuccess: async (e) => { events.push(e); } }
    };

    const rejected = await mcpAddIocTags(db, { ioc_id: ioc.public_id, tags: ['itest-mcp-tag-a', 'itest-mcp-tag-off', 'itest-mcp-new'] }, ctx);
    assert.equal(rejected.error.code, 'TAG_NOT_ALLOWED');
    const { rows: [{ n: afterReject }] } = await client.query(
      `SELECT count(*)::int AS n FROM ioc_tags WHERE ioc_id = $1 AND origin = 'manual'`, [ioc.id]
    );
    assert.equal(afterReject, 0);
    const { rows: [{ n: newTags }] } = await client.query(`SELECT count(*)::int AS n FROM tags WHERE name = 'itest-mcp-new'`);
    assert.equal(newTags, 0, 'catalog never written');

    const added = await mcpAddIocTags(db, { ioc_id: ioc.public_id, tags: ['ITEST-MCP-TAG-A', 'itest-mcp-tag-b'] }, ctx);
    assert.equal(added.error, undefined);
    assert.deepEqual(added.body.added, ['itest-mcp-tag-a', 'itest-mcp-tag-b']);
    assert.deepEqual(added.body.tags, ['itest-mcp-tag-a', 'itest-mcp-tag-b']);
    const b = added.body.tags_detail.find((t) => t.name === 'itest-mcp-tag-b');
    assert.deepEqual([...b.origins].sort(), ['integration', 'manual']);

    const again = await mcpAddIocTags(db, { ioc_id: String(ioc.id), tags: ['itest-mcp-tag-a'] }, ctx);
    assert.deepEqual(again.body.added, []);
    assert.deepEqual(again.body.already_present, ['itest-mcp-tag-a']);

    const removed = await mcpRemoveIocTags(db, { ioc_id: ioc.public_id, tags: ['itest-mcp-tag-a', 'itest-mcp-tag-b', 'itest-mcp-tag-off'] }, ctx);
    assert.equal(removed.error, undefined);
    assert.deepEqual([...removed.body.removed].sort(), ['itest-mcp-tag-a', 'itest-mcp-tag-b']);
    assert.deepEqual(removed.body.not_assigned, ['itest-mcp-tag-off']);
    assert.deepEqual(removed.body.tags, ['itest-mcp-tag-b'], 'feed tag survives');

    const removeFeed = await mcpRemoveIocTags(db, { ioc_id: ioc.public_id, tags: ['itest-mcp-tag-b'] }, ctx);
    assert.deepEqual(removeFeed.body.removed, []);
    assert.equal(removeFeed.body.not_removable[0].tag, 'itest-mcp-tag-b');
    const { rows: left } = await client.query(
      `SELECT origin FROM ioc_tags WHERE ioc_id = $1 ORDER BY origin`, [ioc.id]
    );
    assert.deepEqual(left.map((r) => r.origin), ['integration']);

    const eventsOf = (action) => events.filter((e) => e.action === action).map((e) => e.metadata.tag_name).sort();
    assert.equal(events.length, 4);
    assert.deepEqual(eventsOf('ioc.tag.added'), ['itest-mcp-tag-a', 'itest-mcp-tag-b']);
    assert.deepEqual(eventsOf('ioc.tag.removed'), ['itest-mcp-tag-a', 'itest-mcp-tag-b']);

    const listed = await mcpListTags(db, { query: 'itest-mcp' }, ctx);
    assert.deepEqual(listed.body.tags.map((t) => t.name), ['itest-mcp-tag-a', 'itest-mcp-tag-b']);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
});

test('040 admits mcp:tags:write and upgrades live MCP Analyst keys only, idempotently', opts, async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const pre = ['mcp:ioc:read', 'mcp:ioc:create', 'mcp:sources:read', 'mcp:enrichment:read', 'mcp:enrichment:write'];
    const seed = [
      ['itest analyst', 'mcp_analyst', pre, false],
      ['itest analyst deleted', 'mcp_analyst', pre, true],
      ['itest read', 'mcp_read', ['mcp:ioc:read', 'mcp:sources:read', 'mcp:enrichment:read'], false],
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
    await client.query(MIGRATION_040);
    await client.query(MIGRATION_040); // idempotent
    const { rows } = await client.query(
      'SELECT name, scopes FROM published_feed_access_keys WHERE id = ANY($1::bigint[])',
      [Object.values(ids)]
    );
    const byName = Object.fromEntries(rows.map((r) => [r.name, r.scopes]));
    assert.deepEqual(byName['itest analyst'], [...pre, 'mcp:tags:write']);
    assert.ok(!byName['itest analyst deleted'].includes('mcp:tags:write'), 'deleted keys untouched');
    assert.ok(!byName['itest read'].includes('mcp:tags:write'));
    assert.ok(!byName['itest feed'].includes('mcp:tags:write'));
    // The widened constraint still rejects unknown scopes.
    await assert.rejects(client.query(
      `UPDATE published_feed_access_keys SET scopes = '["mcp:tags:admin"]'::jsonb WHERE id = $1`,
      [ids['itest read']]
    ), /chk_pf_access_keys_scopes/);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
});

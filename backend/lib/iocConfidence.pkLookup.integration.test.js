import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { buildDisplayConfidenceForItems, loadIocItemRowsById, FILE_HASH_OBSERVABLE_TYPES } from './iocConfidence.js';

/**
 * Real-Postgres proof for the /api/ioc/list confidence-enrichment lookup on the
 * LIST-partitioned ioc_items table: the type-qualified lookup returns exactly the
 * id-only result set (file-hash aliases and DEFAULT-partition rows included) and
 * is served by the (observable_type, id) primary key instead of a scan of every
 * partition. Runs inside a rolled-back transaction; needs
 * ALLOW_IOC_CONFIDENCE_DB_TESTS=1 and a migrated throwaway database.
 */

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 2
});

let hasDb = false;
if (process.env.ALLOW_IOC_CONFIDENCE_DB_TESTS === '1') {
  try {
    await pool.query('SELECT observable_type, id FROM ioc_items LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_IOC_CONFIDENCE_DB_TESTS=1 with a migrated throwaway database to run' };
test.after(() => pool.end());

const ID_ONLY = `SELECT i.id, i.observable_type, i.confidence, i.analyst_confidence_override, i.ioc_source_id, i.source_name
  FROM ioc_items i WHERE i.id = ANY($1::bigint[])`;

async function seeded(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Enough rows per partition that a seq scan is clearly the wrong plan.
    await client.query(`
      INSERT INTO ioc_items (observable, observable_type, source_name, confidence, created_at)
      SELECT CASE t WHEN 'domain' THEN 'bulk' || g || '.example'
                    WHEN 'url' THEN 'https://bulk.example/' || g
                    WHEN 'ip' THEN '10.' || (g / 65536) % 256 || '.' || (g / 256) % 256 || '.' || g % 256
                    ELSE md5(t || g) END,
             t, 'Bulk', 'low', now() - (g || ' seconds')::interval
      FROM generate_series(1, 20000) g, unnest(ARRAY['domain', 'url', 'ip', 'md5', 'sha1']) t`);
    const ins = async (observable, type, fields = {}) => (await client.query(
      `INSERT INTO ioc_items (observable, observable_type, source_name, confidence, analyst_confidence_override)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [observable, type, fields.source_name || 'Manual', fields.confidence ?? null, fields.override ?? null]
    )).rows[0].id;
    const ids = {
      domain: Number(await ins('page.example', 'domain', { confidence: 'high' })),
      url: Number(await ins('https://page.example/r', 'url', { confidence: 'medium' })),
      md5: Number(await ins('a'.repeat(32), 'md5', { confidence: 'high', source_name: 'Threat_Library' })),
      sha1: Number(await ins('b'.repeat(40), 'sha1', { confidence: 'medium', override: 'low' })),
      sha256: Number(await ins('c'.repeat(64), 'sha256', { confidence: 'medium' })),
      // Not one of the ten known types: lands in the DEFAULT partition.
      other: Number(await ins('host.page.example', 'hostname', { confidence: 'low' }))
    };
    await client.query('ANALYZE ioc_items');
    await fn(client, ids);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

const sortRows = (rows) => rows.map((r) => ({ ...r, id: Number(r.id) })).sort((a, b) => a.id - b.id);

test('type-qualified lookup returns exactly the id-only rows for every hint, incl. aliases and DEFAULT-partition rows', opts, async () => {
  await seeded(async (client, ids) => {
    const all = Object.values(ids);
    const reference = sortRows((await client.query(ID_ONLY, [all])).rows);
    assert.equal(reference.length, 6);
    for (const hint of [['domain', 'url'], ['sha256'], [...FILE_HASH_OBSERVABLE_TYPES], ['domain', 'url', 'ip', ...FILE_HASH_OBSERVABLE_TYPES], []]) {
      assert.deepEqual(sortRows(await loadIocItemRowsById(client, all, hint)), reference, JSON.stringify(hint));
    }
  });
});

test('the lookup is served by the partitions\' (observable_type, id) primary keys, not a scan of every partition', opts, async () => {
  await seeded(async (client, ids) => {
    const plan = async (sql, params) => (await client.query(`EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF) ${sql}`, params)).rows.map((r) => r['QUERY PLAN']).join('\n');
    // Root node's buffer total (first Buffers line; the plans have no InitPlans).
    const buffers = (text) => {
      const m = text.match(/Buffers: shared(?: hit=(\d+))?(?: read=(\d+))?/);
      return m ? Number(m[1] || 0) + Number(m[2] || 0) : 0;
    };
    const cols = 'i.id, i.observable_type, i.confidence, i.analyst_confidence_override, i.ioc_source_id, i.source_name';
    const typed = await plan(
      `SELECT ${cols} FROM ioc_items i WHERE i.observable_type = ANY($2::text[]) AND i.id = ANY($1::bigint[])`,
      [[ids.domain, ids.url], ['domain', 'url']]
    );
    // Key lookups on the leading (observable_type) column of each partition's primary key.
    assert.match(typed, /Index (Only )?Scan using \w*pkey[\s\S]*?Index Cond: \(\(observable_type = ANY/, typed);
    assert.doesNotMatch(typed, /Seq Scan on ioc_(domain|url|file_hash|ip)\b/, typed);
    // Control: without the type the key cannot be probed, so Postgres walks every
    // partition (prod: Parallel Seq Scan; small cached DB: full pkey walk).
    const idOnly = await plan(`SELECT ${cols} FROM ioc_items i WHERE i.id = ANY($1::bigint[])`, [[ids.domain, ids.url]]);
    assert.doesNotMatch(idOnly, /Index Cond: \(\(observable_type/, idOnly);
    assert.ok(buffers(idOnly) > 20 * buffers(typed), `id-only touches ${buffers(idOnly)} buffers vs ${buffers(typed)} typed`);
  });
});

test('buildDisplayConfidenceForItems on real rows: page types, rewritten SHA256 display, aliases and DEFAULT-partition fallback', opts, async () => {
  await seeded(async (client, ids) => {
    const map = await buildDisplayConfidenceForItems(client, [
      { id: ids.domain, observable: 'page.example', observable_type: 'domain', active_source_count: 1 },
      { id: ids.url, observable: 'https://page.example/r', observable_type: 'url', active_source_count: 1 },
      // MD5 row displayed as its artifact's primary SHA256.
      { id: ids.md5, observable: 'c'.repeat(64), observable_type: 'sha256', active_source_count: 1 },
      // SHA1 seed whose alias group also contains the MD5 row.
      { id: ids.sha1, observable: 'c'.repeat(64), observable_type: 'sha256', active_source_count: 1 },
      // DEFAULT-partition row shown as a domain: only the fallback can find it.
      { id: ids.other, observable: 'host.page.example', observable_type: 'domain', active_source_count: 1 }
    ], {
      linkedBySeed: new Map([
        [ids.domain, [ids.domain]], [ids.url, [ids.url]], [ids.md5, [ids.md5]],
        [ids.sha1, [ids.sha1, ids.md5]], [ids.other, [ids.other]]
      ])
    });
    assert.equal(map.get(`${ids.domain}|domain`).confidence_effective, 'high');
    assert.equal(map.get(`${ids.url}|url`).confidence_effective, 'medium');
    assert.equal(map.get(`${ids.md5}|sha256`).confidence_effective, 'high');
    assert.equal(map.get(`${ids.sha1}|sha256`).confidence_effective, 'low', 'analyst override on the seed row still wins');
    assert.equal(map.get(`${ids.other}|domain`).confidence_effective, 'low');
  });
});

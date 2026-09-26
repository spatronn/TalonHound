/**
 * /api/ioc/list confidence enrichment must read ioc_items through the
 * (observable_type, id) primary key. An id-only `WHERE id = ANY(...)` has no usable
 * index on the LIST-partitioned table and seq-scans every partition (~1.8 GB,
 * ~0.2–0.5 s per page load in prod). The fake pool below behaves like the
 * partitioned table: a type-qualified lookup only sees rows whose REAL type is in
 * the candidate set, so a too-narrow type hint would silently drop rows.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildDisplayConfidenceForItems, loadIocItemRowsById, FILE_HASH_OBSERVABLE_TYPES } from './iocConfidence.js';

const ROWS = [
  { id: 101, observable_type: 'domain', confidence: 'high', analyst_confidence_override: null, ioc_source_id: 7, source_name: 'Manual' },
  { id: 102, observable_type: 'url', confidence: 'medium', analyst_confidence_override: null, ioc_source_id: 7, source_name: 'Manual' },
  // File artifact: MD5 row (owns the source) + SHA1 alias; list displays the primary SHA256.
  { id: 201, observable_type: 'md5', confidence: 'high', analyst_confidence_override: null, ioc_source_id: 7, source_name: 'Threat_Library' },
  { id: 202, observable_type: 'sha1', confidence: null, analyst_confidence_override: 'low', ioc_source_id: null, source_name: null },
  // A row in an unexpected partition (DEFAULT) whose type is never hinted.
  { id: 301, observable_type: 'hostname', confidence: 'low', analyst_confidence_override: null, ioc_source_id: 7, source_name: 'Manual' }
];

function partitionedPool() {
  const log = [];
  return {
    log,
    async query(sql, params = []) {
      const flat = sql.replace(/\s+/g, ' ').trim();
      log.push({ sql: flat, params });
      if (flat.includes('FROM ioc_feed_memberships')) return { rows: [] };
      if (flat.includes('FROM ioc_items i')) {
        const ids = new Set(params[0].map(Number));
        const typed = /observable_type = ANY\(\$2::text\[\]\)/.test(flat);
        const types = typed ? new Set(params[1]) : null;
        return { rows: ROWS.filter((r) => ids.has(r.id) && (!types || types.has(r.observable_type))) };
      }
      return { rows: [] };
    }
  };
}

const itemsLookups = (pool) => pool.log.filter((q) => q.sql.includes('FROM ioc_items i'));

test('default browse page (domain/url): one PK-qualified ioc_items lookup, no id-only scan', async () => {
  const pool = partitionedPool();
  const map = await buildDisplayConfidenceForItems(pool, [
    { id: 101, observable: 'a.example', observable_type: 'domain', active_source_count: 1 },
    { id: 102, observable: 'https://b.example/x', observable_type: 'url', active_source_count: 1 }
  ]);
  const lookups = itemsLookups(pool);
  assert.equal(lookups.length, 1, 'no fallback query when every id resolves');
  assert.match(lookups[0].sql, /WHERE i\.observable_type = ANY\(\$2::text\[\]\) AND i\.id = ANY\(\$1::bigint\[\]\)$/);
  assert.deepEqual(lookups[0].params[1].sort(), ['domain', 'url'], 'no file-hash types needed for a domain/url page');
  assert.equal(map.get('101|domain').confidence_effective, 'high');
  assert.equal(map.get('102|url').confidence_effective, 'medium');
});

test('rewritten SHA256 display type still resolves the underlying MD5 row via file-hash types', async () => {
  const pool = partitionedPool();
  const map = await buildDisplayConfidenceForItems(pool, [
    { id: 201, observable: 'e'.repeat(64), observable_type: 'sha256', active_source_count: 1 }
  ], { linkedBySeed: new Map([[201, [201]]]) });
  const [lookup] = itemsLookups(pool);
  for (const t of FILE_HASH_OBSERVABLE_TYPES) assert.ok(lookup.params[1].includes(t), t);
  assert.equal(itemsLookups(pool).length, 1);
  assert.equal(map.get('201|sha256').confidence_effective, 'high');
});

test('artifact aliases (linked ids beyond the page) are fetched by the same PK lookup', async () => {
  const pool = partitionedPool();
  // Seed displayed as sha256; alias row 202 is the SHA1 of the same artifact.
  const map = await buildDisplayConfidenceForItems(pool, [
    { id: 202, observable: 'e'.repeat(64), observable_type: 'sha256', active_source_count: 1 }
  ], { linkedBySeed: new Map([[202, [202, 201]]]) });
  const [lookup] = itemsLookups(pool);
  assert.deepEqual(lookup.params[0].sort(), [201, 202]);
  assert.equal(itemsLookups(pool).length, 1);
  // Analyst override on the seed row wins, exactly as before.
  assert.equal(map.get('202|sha256').confidence_effective, 'low');
});

test('an id whose real type is outside the hint falls back to an id-only lookup for THAT id only', async () => {
  const pool = partitionedPool();
  const map = await buildDisplayConfidenceForItems(pool, [
    { id: 101, observable: 'a.example', observable_type: 'domain', active_source_count: 1 },
    { id: 301, observable: 'host.example', observable_type: 'domain', active_source_count: 1 }
  ]);
  const lookups = itemsLookups(pool);
  assert.equal(lookups.length, 2);
  assert.match(lookups[1].sql, /WHERE i\.id = ANY\(\$1::bigint\[\]\)$/);
  assert.deepEqual(lookups[1].params, [[301]], 'fallback is scoped to unresolved ids');
  assert.equal(map.get('301|domain').confidence_effective, 'low');
});

test('loadIocItemRowsById returns exactly the id-only result set for every hint (parity)', async () => {
  const allIds = ROWS.map((r) => r.id);
  const reference = ROWS.map((r) => r.id).sort();
  for (const hint of [[], ['domain'], ['md5'], ['domain', 'url'], [...FILE_HASH_OBSERVABLE_TYPES], ['hostname', 'domain', 'url', ...FILE_HASH_OBSERVABLE_TYPES]]) {
    const rows = await loadIocItemRowsById(partitionedPool(), allIds, hint);
    assert.deepEqual(rows.map((r) => r.id).sort(), reference, JSON.stringify(hint));
  }
  // Ids that do not exist are simply absent (as with the id-only query).
  assert.deepEqual(await loadIocItemRowsById(partitionedPool(), [999], ['domain']), []);
});

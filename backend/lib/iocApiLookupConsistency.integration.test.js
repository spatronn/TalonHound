/**
 * Real-Postgres regression for two API/MCP IOC read bugs:
 *
 *   BUG 1 — exact SHA256/SHA1 lookup returned found:false / missing / 404 for a
 *           file whose IOC row is stored under another hash type, although the
 *           proven file-artifact alias was known (search_iocs already found it).
 *   BUG 2 — search_iocs (and REST /api/v1/iocs/search) serialized confidence,
 *           note, classifications and tags as null / [] for every result.
 *
 * Exercises the real SQL (shared alias fragment, LATERAL batch resolver,
 * batched hydrator) against a migrated schema.
 *
 * Commits fixture rows (search opens its own transaction), so it only runs on a
 * disposable database: guarded by assertFileArtifactDbTestAllowed
 * (ALLOW_FILE_ARTIFACT_DB_TESTS=1, localhost, DB_NAME containing "_test").
 * Fixture rows use random hashes/markers and are deleted in `after`.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { assertFileArtifactDbTestAllowed } from './fileArtifacts/dbTestGuard.js';
import { mcpLookupIoc, mcpBulkLookupIocs, mcpGetIocContext, mcpSearchIocs } from './mcpIocService.js';
import { searchApiIocs } from './apiIocReadService.js';
import { hydrateIocApiMetadata } from './iocApiMetadata.js';
import { loadCatalogTags } from './apiIocService.js';
import { loadEffectiveIocClassificationSlugs, iocPairKey } from './iocThreatClassifications.js';

let dbConfig = null;
try {
  dbConfig = assertFileArtifactDbTestAllowed();
} catch {
  dbConfig = null;
}

const pool = dbConfig
  ? new pg.Pool({ ...dbConfig, connectionTimeoutMillis: 3000, max: 4 })
  : null;

let hasDb = false;
if (pool) {
  try {
    await pool.query('SELECT 1 FROM file_artifact_hashes LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'disposable test DB not available (ALLOW_FILE_ARTIFACT_DB_TESTS=1 + *_test DB)' };

const CONFIG = { valueMaxChars: 2048, bulkLookupMax: 100, searchPageMax: 50 };
const hex = (n) => crypto.randomBytes(n / 2).toString('hex');
const MARK = `itest${hex(8)}`;

const F = {
  // Artifact A — the production shape: only an MD5 IOC row, SHA1/SHA256 proven aliases.
  A_MD5: hex(32), A_SHA1: hex(40), A_SHA256: hex(64),
  // Artifact B — unrelated file with its own direct SHA256 row.
  B_SHA256: hex(64), B_MD5: hex(32),
  // Artifact C — survivor; C_TOMB merged into it, holding a SHA1 on the tombstone.
  C_SHA256: hex(64), C_TOMB_SHA1: hex(40),
  // Artifact D — two IOC memberships (expired MD5, active SHA1), queried by SHA256.
  D_MD5: hex(32), D_SHA1: hex(40), D_SHA256: hex(64),
  UNKNOWN_SHA256: hex(64),
  DOMAIN_FULL: `${MARK}-full.example`,
  DOMAIN_LEGACY: `${MARK}-legacy.example`
};
const TAGS = { a1: `${MARK}-alpha`, a2: `${MARK}-bravo`, a3: `${MARK}-feedtag`, b1: `${MARK}-other`, d1: `${MARK}-delta`, d2: `${MARK}-echo`, d3: `${MARK}-foxtrot` };

const ids = {};
const artifactIds = [];
let sourceId = null;

async function insertIoc(client, { value, type, confidence, note, legacy = 'unknown', status = 'active', createdAt = 'NOW()' }) {
  const { rows } = await client.query(
    `INSERT INTO ioc_items (public_id, observable, observable_type, source_name, confidence, category, note,
                            threat_classification, status, created_at, last_seen_at, ioc_source_id)
     VALUES (gen_random_uuid(), $1, $2, $3, $4, 'itest', $5, $6, $7, ${createdAt}, ${createdAt}, $8)
     RETURNING id, public_id, observable_type`,
    [value, type, MARK, confidence, note, legacy, status, sourceId]
  );
  return rows[0];
}

async function insertArtifact(client, { status = 'active', mergedInto = null } = {}) {
  const { rows } = await client.query(
    `INSERT INTO file_artifacts (status, merged_into_artifact_id) VALUES ($1, $2) RETURNING id`,
    [status, mergedInto]
  );
  artifactIds.push(rows[0].id);
  return rows[0].id;
}

async function addHash(client, artifactId, type, value, primary = false) {
  await client.query(
    `INSERT INTO file_artifact_hashes (artifact_id, hash_type, normalized_hash_value, is_primary)
     VALUES ($1, $2, $3, $4)`,
    [artifactId, type, value, primary]
  );
}

async function link(client, artifactId, ioc) {
  await client.query(
    `INSERT INTO file_artifact_ioc_links (artifact_id, ioc_item_id, ioc_observable_type, ioc_public_id)
     VALUES ($1, $2, $3, $4)`,
    [artifactId, ioc.id, ioc.observable_type, ioc.public_id]
  );
}

async function tag(client, ioc, name, { origin = 'manual', source = null } = {}) {
  const { rows } = await client.query(
    `INSERT INTO tags (name, type, slug) VALUES ($1, 'threat', $1)
     ON CONFLICT DO NOTHING RETURNING id`,
    [name]
  );
  const tagId = rows[0]?.id ?? (await client.query('SELECT id FROM tags WHERE name = $1', [name])).rows[0].id;
  await client.query(
    `INSERT INTO ioc_tags (ioc_id, ioc_observable_type, tag_id, origin, source_name, source_key)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [ioc.id, ioc.observable_type, tagId, origin, source, source ? source.toLowerCase() : '']
  );
}

async function classify(client, ioc, slug) {
  await client.query(
    `INSERT INTO ioc_threat_classifications (ioc_id, ioc_observable_type, classification_slug)
     VALUES ($1, $2, $3)`,
    [ioc.id, ioc.observable_type, slug]
  );
}

function withReadFlag(fn) {
  const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
  process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
  return Promise.resolve(fn()).finally(() => {
    if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
  });
}

function countingPool() {
  const counter = { n: 0 };
  const wrapped = {
    query: (...args) => { counter.n += 1; return pool.query(...args); },
    connect: async () => {
      const client = await pool.connect();
      return {
        query: (...args) => { counter.n += 1; return client.query(...args); },
        release: () => client.release()
      };
    }
  };
  return { wrapped, counter };
}

const semantic = (o) => ({
  confidence: o.confidence ?? null,
  note: o.note ?? null,
  classifications: [...(o.classifications || [])],
  tags: [...(o.tags || [])]
});

describe('API/MCP IOC lookup identity + metadata consistency (real Postgres)', opts, () => {
  before(async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const src = await client.query(
        `INSERT INTO ioc_sources (name, display_name, source_type, active)
         VALUES ($1, $1, 'test', TRUE) RETURNING id`,
        [MARK]
      );
      sourceId = src.rows[0].id;

      // A: MD5-only IOC row + SHA1/SHA256 aliases.
      ids.A = await insertIoc(client, { value: F.A_MD5, type: 'md5', confidence: 'high', note: `${MARK} note A`, legacy: 'unknown' });
      const artA = await insertArtifact(client);
      await addHash(client, artA, 'sha256', F.A_SHA256, true);
      await addHash(client, artA, 'sha1', F.A_SHA1);
      await addHash(client, artA, 'md5', F.A_MD5);
      await link(client, artA, ids.A);
      await classify(client, ids.A, 'phishing');
      await tag(client, ids.A, TAGS.a1);
      await tag(client, ids.A, TAGS.a2);
      await tag(client, ids.A, TAGS.a3, { origin: 'integration', source: 'ItestFeed' });

      // B: unrelated artifact with a direct SHA256 row.
      ids.B = await insertIoc(client, { value: F.B_SHA256, type: 'sha256', confidence: 'low', note: `${MARK} note B` });
      const artB = await insertArtifact(client);
      await addHash(client, artB, 'sha256', F.B_SHA256, true);
      await addHash(client, artB, 'md5', F.B_MD5);
      await link(client, artB, ids.B);
      await classify(client, ids.B, 'credential_theft');
      await tag(client, ids.B, TAGS.b1);

      // C: survivor + merged tombstone carrying a SHA1.
      ids.C = await insertIoc(client, { value: F.C_SHA256, type: 'sha256', confidence: 'medium', note: `${MARK} note C` });
      const artC = await insertArtifact(client);
      await addHash(client, artC, 'sha256', F.C_SHA256, true);
      await link(client, artC, ids.C);
      const artCTomb = await insertArtifact(client, { status: 'merged', mergedInto: artC });
      await addHash(client, artCTomb, 'sha1', F.C_TOMB_SHA1);

      // D: two memberships — older expired MD5, newer active SHA1; SHA256 has no row.
      ids.D_MD5 = await insertIoc(client, { value: F.D_MD5, type: 'md5', confidence: 'low', note: 'D md5', status: 'expired', createdAt: "NOW() - INTERVAL '10 days'" });
      ids.D_SHA1 = await insertIoc(client, { value: F.D_SHA1, type: 'sha1', confidence: 'high', note: 'D sha1' });
      const artD = await insertArtifact(client);
      await addHash(client, artD, 'sha256', F.D_SHA256, true);
      await addHash(client, artD, 'sha1', F.D_SHA1);
      await addHash(client, artD, 'md5', F.D_MD5);
      await link(client, artD, ids.D_MD5);
      await link(client, artD, ids.D_SHA1);

      // BUG 2 domains: full metadata (junction classification + several tags) and legacy-only.
      ids.DOM_FULL = await insertIoc(client, { value: F.DOMAIN_FULL, type: 'domain', confidence: 'high', note: `${MARK} full note` });
      await classify(client, ids.DOM_FULL, 'phishing');
      await tag(client, ids.DOM_FULL, TAGS.d1, { origin: 'integration', source: 'ThreatFox' });
      await tag(client, ids.DOM_FULL, TAGS.d2, { origin: 'integration', source: 'ThreatFox' });
      await tag(client, ids.DOM_FULL, TAGS.d3);
      ids.DOM_LEGACY = await insertIoc(client, { value: F.DOMAIN_LEGACY, type: 'domain', confidence: 'medium', note: null, legacy: 'phishing' });

      // Page filler for the query-count (no N+1) check.
      for (let i = 0; i < 12; i += 1) {
        const row = await insertIoc(client, { value: `${MARK}-fill${i}.example`, type: 'domain', confidence: 'low', note: `fill ${i}` });
        await tag(client, row, `${MARK}-fill-tag-${i}`);
        await classify(client, row, 'phishing');
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  });

  after(async () => {
    if (!pool) return;
    try {
      await pool.query(`DELETE FROM ioc_tags WHERE tag_id IN (SELECT id FROM tags WHERE name LIKE $1)`, [`${MARK}%`]);
      await pool.query(`DELETE FROM tags WHERE name LIKE $1`, [`${MARK}%`]);
      await pool.query(
        `DELETE FROM ioc_threat_classifications WHERE (ioc_observable_type, ioc_id) IN (
           SELECT observable_type, id FROM ioc_items WHERE source_name = $1)`,
        [MARK]
      );
      await pool.query(`DELETE FROM file_artifact_ioc_links WHERE artifact_id = ANY($1::uuid[])`, [artifactIds]);
      await pool.query(`DELETE FROM file_artifact_hashes WHERE artifact_id = ANY($1::uuid[])`, [artifactIds]);
      await pool.query(`UPDATE file_artifacts SET status = 'active', merged_into_artifact_id = NULL WHERE id = ANY($1::uuid[])`, [artifactIds]);
      await pool.query(`DELETE FROM file_artifacts WHERE id = ANY($1::uuid[])`, [artifactIds]);
      await pool.query(`DELETE FROM ioc_items WHERE source_name = $1`, [MARK]);
      await pool.query(`DELETE FROM ioc_sources WHERE name = $1`, [MARK]);
    } finally {
      await pool.end();
    }
  });

  // ---------------------------------------------------------------- BUG 1 --

  it('lookup_ioc(SHA256 alias) finds the MD5-backed IOC and says so', () => withReadFlag(async () => {
    const out = await mcpLookupIoc(pool, { value: F.A_SHA256 }, { config: CONFIG });
    assert.equal(out.status, 200);
    assert.equal(out.body.found, true);
    assert.equal(out.body.id, Number(ids.A.id));
    assert.equal(out.body.type, 'md5');
    assert.equal(out.body.value, F.A_MD5);
    assert.equal(out.body.matched_via, 'file_artifact_alias');
    assert.deepEqual(out.body.queried, { type: 'sha256', value: F.A_SHA256 });
    assert.deepEqual(out.body.record, { id: Number(ids.A.id), public_id: ids.A.public_id, type: 'md5', value: F.A_MD5 });
    assert.equal(out.body.artifact_memberships.length, 1);
    assert.deepEqual(out.body.classifications, ['phishing']);
    assert.deepEqual(out.body.tags, [TAGS.a1, TAGS.a2, TAGS.a3].sort());
    assert.equal(out.body.confidence, 'high');
    assert.equal(out.body.sources.length, 1);
  }));

  it('lookup_ioc(SHA1 alias) resolves the same logical file', () => withReadFlag(async () => {
    const out = await mcpLookupIoc(pool, { value: F.A_SHA1 }, { config: CONFIG });
    assert.equal(out.body.found, true);
    assert.equal(out.body.id, Number(ids.A.id));
    assert.equal(out.body.matched_via, 'file_artifact_alias');
    assert.deepEqual(out.body.queried, { type: 'sha1', value: F.A_SHA1 });
  }));

  it('lookup_ioc(stored hash) stays an exact match, not an alias', () => withReadFlag(async () => {
    const md5 = await mcpLookupIoc(pool, { value: F.A_MD5 }, { config: CONFIG });
    assert.equal(md5.body.matched_via, 'exact');
    assert.equal(md5.body.id, Number(ids.A.id));
    assert.equal(md5.body.artifact_memberships, undefined);
    const sha = await mcpLookupIoc(pool, { value: F.B_SHA256 }, { config: CONFIG });
    assert.equal(sha.body.matched_via, 'exact');
    assert.equal(sha.body.id, Number(ids.B.id));
    assert.deepEqual(sha.body.queried, { type: 'sha256', value: F.B_SHA256 });
    assert.equal(sha.body.record.value, F.B_SHA256);
  }));

  it('unknown SHA256 stays missing on lookup, bulk and context', () => withReadFlag(async () => {
    const lookup = await mcpLookupIoc(pool, { value: F.UNKNOWN_SHA256 }, { config: CONFIG });
    assert.equal(lookup.body.found, false);
    const bulk = await mcpBulkLookupIocs(pool, { iocs: [F.UNKNOWN_SHA256] }, { config: CONFIG });
    assert.equal(bulk.body.counts.missing, 1);
    assert.equal(bulk.body.counts.existing, 0);
    const ctx = await mcpGetIocContext(pool, { value: F.UNKNOWN_SHA256 }, { config: CONFIG });
    assert.equal(ctx.status, 404);
  }));

  it('flag off: alias is NOT resolved (same gate as search) and SHA256 stays missing', async () => {
    const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
    process.env.FILE_ARTIFACTS_READ_ENABLED = '0';
    try {
      const out = await mcpLookupIoc(pool, { value: F.A_SHA256 }, { config: CONFIG });
      assert.equal(out.body.found, false);
    } finally {
      if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
      else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
    }
  });

  it('bulk_lookup_iocs resolves aliases in one request; unrelated artifacts keep their own metadata', () => withReadFlag(async () => {
    const out = await mcpBulkLookupIocs(
      pool,
      { iocs: [F.A_SHA256, F.A_SHA1, F.UNKNOWN_SHA256, F.B_SHA256] },
      { config: CONFIG }
    );
    assert.equal(out.body.counts.existing, 3);
    assert.equal(out.body.counts.missing, 1);
    const byValue = new Map(out.body.existing.map((e) => [e.value, e]));
    const a256 = byValue.get(F.A_SHA256);
    assert.equal(a256.id, Number(ids.A.id));
    assert.equal(a256.matched_via, 'file_artifact_alias');
    assert.deepEqual(a256.record, { id: Number(ids.A.id), public_id: ids.A.public_id, type: 'md5', value: F.A_MD5 });
    assert.equal(byValue.get(F.A_SHA1).id, Number(ids.A.id));
    const b = byValue.get(F.B_SHA256);
    assert.equal(b.matched_via, 'exact');
    assert.deepEqual(b.classifications, ['credential_theft']);
    assert.deepEqual(b.tags, [TAGS.b1]);
    assert.ok(!a256.tags.includes(TAGS.b1), 'artifact A must not inherit artifact B tags');
    assert.ok(!b.tags.includes(TAGS.a1), 'artifact B must not inherit artifact A tags');
  }));

  it('get_ioc_context(SHA256 alias) uses the same resolved IOC', () => withReadFlag(async () => {
    const out = await mcpGetIocContext(pool, { value: F.A_SHA256 }, { config: CONFIG });
    assert.equal(out.status, 200);
    assert.equal(out.body.id, Number(ids.A.id));
    assert.equal(out.body.type, 'md5');
    assert.equal(out.body.matched_via, 'file_artifact_alias');
    assert.deepEqual(out.body.queried, { type: 'sha256', value: F.A_SHA256 });
    assert.deepEqual(out.body.classifications, ['phishing']);
    assert.deepEqual(out.body.tags, [TAGS.a1, TAGS.a2, TAGS.a3].sort());
    assert.equal(out.body.tags_detail.find((t) => t.name === TAGS.a3).origin, 'integration');
  }));

  it('search_iocs(SHA256) resolves the same logical file as lookup/bulk/context', () => withReadFlag(async () => {
    const search = await mcpSearchIocs(pool, { query: F.A_SHA256 }, { config: CONFIG });
    assert.equal(search.status, 200);
    assert.deepEqual(search.body.items.map((i) => i.id), [Number(ids.A.id)]);
    const lookup = await mcpLookupIoc(pool, { value: F.A_SHA256 }, { config: CONFIG });
    assert.deepEqual(semantic(search.body.items[0]), semantic(lookup.body));
  }));

  it('merged artifact: a hash left on the tombstone resolves to the survivor IOC', () => withReadFlag(async () => {
    const out = await mcpLookupIoc(pool, { value: F.C_TOMB_SHA1 }, { config: CONFIG });
    assert.equal(out.body.found, true);
    assert.equal(out.body.id, Number(ids.C.id));
    assert.equal(out.body.matched_via, 'file_artifact_alias');
    const search = await mcpSearchIocs(pool, { query: F.C_TOMB_SHA1 }, { config: CONFIG });
    assert.deepEqual(search.body.items.map((i) => i.id), [Number(ids.C.id)]);
  }));

  it('multiple memberships: deterministic primary (active, strongest hash) + all memberships exposed', () => withReadFlag(async () => {
    const first = await mcpLookupIoc(pool, { value: F.D_SHA256 }, { config: CONFIG });
    const again = await mcpLookupIoc(pool, { value: F.D_SHA256 }, { config: CONFIG });
    assert.equal(first.body.id, Number(ids.D_SHA1.id), 'active SHA1 beats older expired MD5');
    assert.equal(again.body.id, first.body.id);
    assert.deepEqual(
      first.body.artifact_memberships.map((m) => [m.id, m.type, m.status]),
      [[Number(ids.D_SHA1.id), 'sha1', 'active'], [Number(ids.D_MD5.id), 'md5', 'expired']]
    );
    const bulk = await mcpBulkLookupIocs(pool, { iocs: [F.D_SHA256] }, { config: CONFIG });
    assert.equal(bulk.body.existing[0].id, first.body.id);
    assert.equal(bulk.body.existing[0].artifact_memberships.length, 2);
  }));

  // ---------------------------------------------------------------- BUG 2 --

  it('search_iocs returns real confidence/note/classifications/tags, equal to lookup and bulk', async () => {
    for (const value of [F.DOMAIN_FULL, F.DOMAIN_LEGACY]) {
      const search = await mcpSearchIocs(pool, { query: value }, { config: CONFIG });
      assert.equal(search.body.items.length, 1);
      const item = search.body.items[0];
      const lookup = await mcpLookupIoc(pool, { value }, { config: CONFIG });
      const bulk = await mcpBulkLookupIocs(pool, { iocs: [value] }, { config: CONFIG });
      assert.deepEqual(semantic(item), semantic(lookup.body), `search vs lookup for ${value}`);
      assert.deepEqual(semantic(bulk.body.existing[0]), semantic(lookup.body), `bulk vs lookup for ${value}`);
    }
    const full = (await mcpSearchIocs(pool, { query: F.DOMAIN_FULL }, { config: CONFIG })).body.items[0];
    assert.equal(full.confidence, 'high');
    assert.equal(full.note, `${MARK} full note`);
    assert.deepEqual(full.classifications, ['phishing']);
    assert.deepEqual(full.tags, [TAGS.d1, TAGS.d2, TAGS.d3].sort());
    const legacy = (await mcpSearchIocs(pool, { query: F.DOMAIN_LEGACY }, { config: CONFIG })).body.items[0];
    assert.deepEqual(legacy.classifications, ['phishing'], 'legacy-column classification is reported');
  });

  it('REST /api/v1/iocs/search shares the fix (searchApiIocs)', async () => {
    const out = await searchApiIocs(pool, { query: `ioc equals "${F.DOMAIN_FULL}"` });
    assert.equal(out.status, 200);
    const item = out.body.items[0];
    assert.equal(item.confidence, 'high');
    assert.notEqual(item.note, null);
    assert.deepEqual(item.classifications, ['phishing']);
    assert.equal(item.tags.length, 3);
  });

  it('classification filter never contradicts the returned classifications', async () => {
    const out = await mcpSearchIocs(pool, { query: `ioc contains "${MARK}"`, classification: 'phishing', limit: 50 }, { config: CONFIG });
    assert.equal(out.status, 200);
    assert.ok(out.body.items.length >= 13);
    for (const item of out.body.items) {
      assert.ok(item.classifications.includes('phishing'), `${item.value} returned by phishing filter must report phishing`);
    }
  });

  it('hydrator agrees with the single-IOC Details loaders for every fixture row', () => withReadFlag(async () => {
    const rows = [ids.A, ids.B, ids.C, ids.D_MD5, ids.D_SHA1, ids.DOM_FULL, ids.DOM_LEGACY]
      .map((r) => ({ id: r.id, observable_type: r.observable_type }));
    const map = await hydrateIocApiMetadata(pool, rows);
    for (const r of rows) {
      const meta = map.get(iocPairKey(r.id, r.observable_type));
      const single = await loadEffectiveIocClassificationSlugs(pool, r.id, r.observable_type);
      const singleTags = await loadCatalogTags(pool, r.id, r.observable_type);
      assert.deepEqual(meta.classifications, single, `classifications for ${r.id}`);
      assert.deepEqual(meta.tags_detail, singleTags, `tags for ${r.id}`);
    }
  }));

  it('no N+1: search hydration query count is independent of page size', () => withReadFlag(async () => {
    const small = countingPool();
    const smallOut = await mcpSearchIocs(small.wrapped, { query: `ioc contains "${MARK}-fill"`, limit: 2 }, { config: CONFIG });
    const large = countingPool();
    const largeOut = await mcpSearchIocs(large.wrapped, { query: `ioc contains "${MARK}-fill"`, limit: 12 }, { config: CONFIG });
    assert.equal(smallOut.body.items.length, 2);
    assert.equal(largeOut.body.items.length, 12);
    assert.equal(large.counter.n, small.counter.n, `queries: 2 rows=${small.counter.n}, 12 rows=${large.counter.n}`);
    for (const item of largeOut.body.items) {
      assert.equal(item.tags.length, 1);
      assert.deepEqual(item.classifications, ['phishing']);
    }
  }));

  it('no N+1: bulk lookup query count is independent of batch size', () => withReadFlag(async () => {
    const values = Array.from({ length: 12 }, (_, i) => `${MARK}-fill${i}.example`);
    const small = countingPool();
    await mcpBulkLookupIocs(small.wrapped, { iocs: values.slice(0, 2) }, { config: CONFIG });
    const large = countingPool();
    const out = await mcpBulkLookupIocs(large.wrapped, { iocs: values }, { config: CONFIG });
    assert.equal(out.body.counts.existing, 12);
    assert.equal(large.counter.n, small.counter.n);
  }));
});

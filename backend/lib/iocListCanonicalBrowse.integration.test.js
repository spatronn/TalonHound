/**
 * Real-Postgres equivalence proof for the /ioc default active browse page SQL.
 *
 * The two-stage query (rank identities by MIN(created_at) → cap → page → full
 * winner-row grouping for the page's identities only) must return exactly what the
 * single-stage reference (full grouping of every candidate identity, then cap and
 * page) returns: same ids, order and every field, for page sizes 25 and 100 across
 * the whole browse cap. The fixture covers duplicate source rows (incl. an older
 * duplicate outside the candidate window), md5/sha1/sha256 aliases, merged
 * artifacts, active / expired / purged memberships, manual rows, expired rows and
 * equal timestamps that need the identity_key tie-break.
 *
 * Commits fixture rows (the browse helper opens its own transaction), so it only
 * runs on a disposable database: guarded by assertFileArtifactDbTestAllowed
 * (ALLOW_FILE_ARTIFACT_DB_TESTS=1, localhost, DB_NAME containing "_test").
 * Fixture rows carry a random marker and are deleted in `after`.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { assertFileArtifactDbTestAllowed } from './fileArtifacts/dbTestGuard.js';
import {
  buildCanonicalActiveBrowsePageSql,
  buildSingleStageActiveBrowsePageSql
} from './fileArtifacts/canonicalListSql.js';
import {
  canonicalBrowseCandidateLimit,
  queryActiveIocCanonicalBrowsePage,
  fetchActiveIocListPage
} from './iocActiveSources.js';

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
    await pool.query('SELECT 1 FROM file_artifact_ioc_links LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'disposable test DB not available (ALLOW_FILE_ARTIFACT_DB_TESTS=1 + *_test DB)' };

const MARK = `browse${crypto.randomBytes(6).toString('hex')}`;
const BROWSE_CAP = 2000;
const PAGES = [
  [25, 1], [25, 2], [25, 10], [25, 20], [25, 40], [25, 80],
  [100, 1], [100, 2], [100, 10], [100, 20]
];

let prevReadFlag;
let manualSourceId;

/** Seed ~21k committed rows newer than anything else in the test DB. */
async function seedFixture(db) {
  const feeds = (await db.query('SELECT integration_id FROM integration_feeds ORDER BY key LIMIT 2')).rows;
  if (feeds.length < 2) throw new Error('fixture needs two integration_feeds rows (migrated seed)');
  const [feedA, feedB] = feeds.map((f) => f.integration_id);
  manualSourceId = (await db.query(
    `INSERT INTO ioc_sources (name, source_type) VALUES ($1, 'manual') RETURNING id`, [MARK]
  )).rows[0].id;

  await db.query('BEGIN');
  try {
    await db.query(`CREATE TEMP TABLE fx_base ON COMMIT DROP AS
      SELECT now() + interval '1 day' AS t0, (SELECT COALESCE(MAX(id), 0) FROM ioc_items) AS base_id`);

    // Domains: triples share a timestamp (identity_key tie-break); mixed eligibility.
    await db.query(`
      INSERT INTO ioc_items (observable, observable_type, source_name, confidence, category, created_at, status, ioc_source_id)
      SELECT 'd' || g || '.${MARK}.example', 'domain',
             'src-' || (g % 5), (ARRAY['low','medium','high'])[1 + g % 3], (ARRAY['malware','phishing',NULL])[1 + g % 3],
             (SELECT t0 FROM fx_base) - (g / 3) * interval '1 second',
             CASE WHEN g % 13 = 0 THEN 'expired' ELSE 'active' END,
             CASE WHEN g % 17 = 0 THEN $1::bigint ELSE NULL END
      FROM generate_series(1, 14000) g`, [manualSourceId]);

    // Duplicate source rows: same identity (case-folded) from another source, some
    // newer inside the window, some far older (outside the 16k candidate window).
    await db.query(`
      INSERT INTO ioc_items (observable, observable_type, source_name, confidence, category, created_at, status)
      SELECT CASE WHEN g % 2 = 0 THEN upper('d' || g || '.${MARK}.example') ELSE 'd' || g || '.${MARK}.example' END,
             'domain', 'dup-src', 'high', 'c2',
             CASE WHEN g % 4 = 0 THEN (SELECT t0 FROM fx_base) - interval '30 days' - g * interval '1 second'
                  ELSE (SELECT t0 FROM fx_base) - (g / 3) * interval '1 second' + interval '400 milliseconds' END,
             'active'
      FROM generate_series(3, 6000, 3) g`);

    // Hash rows: sha256 per artifact, md5/sha1 siblings, md5-only artifacts, duplicate sha256 rows.
    await db.query(`
      CREATE TEMP TABLE fx_hash ON COMMIT DROP AS
      SELECT g,
             encode(sha256(('${MARK}-' || g)::bytea), 'hex') AS h256,
             md5('${MARK}-' || g) AS h5,
             substr(encode(sha256(('${MARK}-s1-' || g)::bytea), 'hex'), 1, 40) AS h1,
             gen_random_uuid() AS art,
             (SELECT t0 FROM fx_base) - (g * 7) * interval '1 second' - interval '250 milliseconds' AS ts
      FROM generate_series(1, 1800) g`);
    await db.query(`
      INSERT INTO ioc_items (observable, observable_type, source_name, confidence, created_at, status)
      SELECT h256, 'sha256', 'hash-src', 'medium', ts, 'active' FROM fx_hash WHERE g % 6 <> 0
      UNION ALL SELECT h5, 'md5', 'hash-src', 'low', ts - interval '1 second', 'active' FROM fx_hash WHERE g % 3 = 0
      UNION ALL SELECT h1, 'sha1', 'sha1-src', 'high', ts + interval '1 second', 'active' FROM fx_hash WHERE g % 5 = 0
      UNION ALL SELECT h256, 'sha256', 'dup-hash-src', 'high', ts + interval '2 seconds', 'active' FROM fx_hash WHERE g % 11 = 0
      UNION ALL SELECT md5('${MARK}-lonely-' || g), 'md5', 'hash-src', 'low', ts, 'active' FROM fx_hash WHERE g % 9 = 0`);

    // Artifacts + hashes (primary sha256 even when only an md5 IOC row exists).
    await db.query(`INSERT INTO file_artifacts (id, status) SELECT art, 'active' FROM fx_hash`);
    await db.query(`
      INSERT INTO file_artifact_hashes (artifact_id, hash_type, normalized_hash_value, is_primary)
      SELECT art, 'sha256', h256, true FROM fx_hash
      UNION ALL SELECT art, 'md5', h5, false FROM fx_hash
      UNION ALL SELECT art, 'sha1', h1, false FROM fx_hash WHERE g % 5 = 0`);
    // Every 10th artifact is merged into the previous one (links still point at the merged id).
    await db.query(`
      UPDATE file_artifacts fa SET status = 'merged', merged_into_artifact_id = tgt.art
      FROM fx_hash src JOIN fx_hash tgt ON tgt.g = src.g - 1
      WHERE fa.id = src.art AND src.g % 10 = 0`);
    await db.query(`
      INSERT INTO file_artifact_ioc_links (artifact_id, ioc_item_id, ioc_observable_type, ioc_public_id, is_canonical_ioc)
      SELECT h.art, i.id, i.observable_type, i.public_id,
             ROW_NUMBER() OVER (PARTITION BY h.art ORDER BY i.observable_type DESC, i.id) = 1
      FROM fx_hash h
      JOIN ioc_items i
        ON (i.observable_type = 'sha256' AND i.observable = h.h256)
        OR (i.observable_type = 'md5' AND i.observable = h.h5)
        OR (i.observable_type = 'sha1' AND i.observable = h.h1)
      WHERE i.observable_type IN ('sha256', 'md5', 'sha1')`);

    // Every fixture ioc_items row (ids are allocated after base_id), for membership seeding and cleanup.
    await db.query(`CREATE TABLE ${MARK}_ids AS
      SELECT id AS ioc_item_id, observable_type FROM ioc_items WHERE id > (SELECT base_id FROM fx_base)`);
    // Memberships for non-manual fixture rows: mostly active, some expired / purged, some none.
    await db.query(`
      INSERT INTO ioc_feed_memberships (ioc_item_id, ioc_observable_type, feed_id, status, purged_at)
      SELECT i.id, i.observable_type, $1::uuid,
             CASE WHEN i.id % 7 = 0 THEN 'expired' ELSE 'active' END,
             CASE WHEN i.id % 19 = 0 THEN now() ELSE NULL END
      FROM ioc_items i
      JOIN ${MARK}_ids x ON x.ioc_item_id = i.id AND x.observable_type = i.observable_type
      WHERE i.ioc_source_id IS NULL AND i.id % 23 <> 0`, [feedA]);
    // A second active feed rescues some rows whose first membership is inactive.
    await db.query(`
      INSERT INTO ioc_feed_memberships (ioc_item_id, ioc_observable_type, feed_id, status)
      SELECT m.ioc_item_id, m.ioc_observable_type, $2::uuid, 'active'
      FROM ioc_feed_memberships m
      JOIN ${MARK}_ids x ON x.ioc_item_id = m.ioc_item_id AND x.observable_type = m.ioc_observable_type
      WHERE m.feed_id = $1::uuid AND (m.status <> 'active' OR m.purged_at IS NOT NULL) AND m.ioc_item_id % 2 = 0`,
    [feedA, feedB]);
    await db.query(`CREATE TABLE ${MARK}_arts AS SELECT art FROM fx_hash`);
    await db.query('COMMIT');
  } catch (err) {
    await db.query('ROLLBACK').catch(() => {});
    throw err;
  }
  await db.query('ANALYZE ioc_items');
  await db.query('ANALYZE ioc_feed_memberships');
  await db.query('ANALYZE file_artifact_ioc_links');
}

async function cleanupFixture(db) {
  const exists = (await db.query(`SELECT to_regclass($1) AS t`, [`${MARK}_ids`])).rows[0].t;
  if (exists) {
    await db.query(`DELETE FROM ioc_feed_memberships m USING ${MARK}_ids x WHERE m.ioc_item_id = x.ioc_item_id AND m.ioc_observable_type = x.observable_type`);
    await db.query(`DELETE FROM file_artifact_ioc_links l USING ${MARK}_arts a WHERE l.artifact_id = a.art`);
    await db.query(`DELETE FROM ioc_items i USING ${MARK}_ids x WHERE i.id = x.ioc_item_id AND i.observable_type = x.observable_type`);
    await db.query(`UPDATE file_artifacts SET primary_hash_id = NULL WHERE id IN (SELECT art FROM ${MARK}_arts)`);
    await db.query(`DELETE FROM file_artifact_hashes WHERE artifact_id IN (SELECT art FROM ${MARK}_arts)`);
    await db.query(`DELETE FROM file_artifacts WHERE status = 'merged' AND id IN (SELECT art FROM ${MARK}_arts)`);
    await db.query(`DELETE FROM file_artifacts WHERE id IN (SELECT art FROM ${MARK}_arts)`);
    await db.query(`DROP TABLE ${MARK}_ids`);
    await db.query(`DROP TABLE ${MARK}_arts`);
  }
  if (manualSourceId != null) await db.query('DELETE FROM ioc_sources WHERE id = $1', [manualSourceId]);
}

const params = (limit, offset) => [
  canonicalBrowseCandidateLimit({ limit, offset, browseCap: BROWSE_CAP }),
  BROWSE_CAP,
  Math.min(limit, BROWSE_CAP - offset),
  offset
];

/** Aggregate nodes (VERBOSE output) that compute the winner-row array_agg set. */
function fullGroupingNodes(plan, out = []) {
  const output = (plan.Output || []).join(' ');
  if (plan['Node Type'] === 'Aggregate' && /array_agg/i.test(output)) out.push(plan);
  for (const child of plan.Plans || []) fullGroupingNodes(child, out);
  return out;
}

describe('canonical active browse: two-stage vs single-stage reference', () => {
  before(async () => {
    if (!hasDb) return;
    prevReadFlag = process.env.FILE_ARTIFACTS_READ_ENABLED;
    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    await seedFixture(pool);
  });

  after(async () => {
    if (!hasDb) return;
    try {
      await cleanupFixture(pool);
    } finally {
      if (prevReadFlag == null) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
      else process.env.FILE_ARTIFACTS_READ_ENABLED = prevReadFlag;
      await pool.end();
    }
  });

  it('builds the two-stage shape only when READ is on', opts, () => {
    assert.notEqual(buildCanonicalActiveBrowsePageSql(), buildSingleStageActiveBrowsePageSql());
  });

  for (const [limit, page] of PAGES) {
    it(`page ${page} / size ${limit}: identical ids, order and every field`, opts, async () => {
      const offset = (page - 1) * limit;
      const reference = (await pool.query(buildSingleStageActiveBrowsePageSql(), params(limit, offset))).rows;
      const actual = await queryActiveIocCanonicalBrowsePage(pool, { limit, offset, browseCap: BROWSE_CAP });
      assert.equal(reference.length, Math.min(limit, BROWSE_CAP - offset), 'fixture must fill the page');
      assert.deepEqual(actual, reference);

      // Public page helper (JIT-off transaction + JS mapping) returns the same identities in order.
      const mapped = await fetchActiveIocListPage(pool, { limit, offset, browseCap: BROWSE_CAP });
      assert.deepEqual(mapped.map((r) => [r.id, r.identity_key, String(r.created_at)]),
        reference.map((r) => [r.id, r.identity_key, String(r.created_at)]));
    });
  }

  it('whole browse cap (2000 identities) is identical and exercises every fixture edge', opts, async () => {
    const reference = (await pool.query(buildSingleStageActiveBrowsePageSql(), params(BROWSE_CAP, 0))).rows;
    const actual = await queryActiveIocCanonicalBrowsePage(pool, { limit: BROWSE_CAP, offset: 0, browseCap: BROWSE_CAP });
    assert.equal(reference.length, BROWSE_CAP);
    assert.deepEqual(actual, reference);

    const mine = reference.filter((r) => r.source_names?.some((s) => ['src-0', 'src-1', 'src-2', 'src-3', 'src-4', 'dup-src', 'hash-src', 'sha1-src', 'dup-hash-src'].includes(s)) || String(r.observable).includes(MARK));
    assert.ok(mine.length > BROWSE_CAP * 0.9, 'fixture rows must dominate the browse window');
    const artifactRows = reference.filter((r) => r.identity_key.startsWith('a:'));
    assert.ok(artifactRows.length > 50, 'artifact identities present');
    assert.ok(artifactRows.some((r) => r.observable_type === 'sha256' && r.source_names?.includes('hash-src') && r.source_count > 1),
      'sha256 identity with sibling alias rows collapsed');
    assert.ok(reference.some((r) => r.identity_key.startsWith('o:md5:')), 'unlinked md5 stays its own identity');
    assert.ok(reference.some((r) => r.identity_key.startsWith('o:domain:') && r.source_count > 1), 'duplicate source rows collapsed');
    const merged = (await pool.query(
      `SELECT merged_into_artifact_id::text AS t FROM file_artifacts WHERE status = 'merged' AND id IN (SELECT art FROM ${MARK}_arts)`
    )).rows.map((r) => `a:${r.t}`);
    assert.ok(reference.some((r) => merged.includes(r.identity_key)), 'merged artifact resolves to its target identity');
    const byTs = new Map();
    for (const r of reference) byTs.set(String(r.created_at), (byTs.get(String(r.created_at)) || 0) + 1);
    assert.ok([...byTs.values()].some((n) => n > 1), 'equal platform_imported_at requires identity_key tie-break');
    const statuses = await pool.query(
      `SELECT COUNT(*) FILTER (WHERE status = 'expired')::int AS expired, COUNT(*) FILTER (WHERE ioc_source_id IS NOT NULL)::int AS manual
       FROM ioc_items WHERE observable LIKE $1`, [`%${MARK}%`]);
    assert.ok(statuses.rows[0].expired > 0 && statuses.rows[0].manual > 0, 'expired and manual rows seeded');
    // Window-local MIN: an identity with an older duplicate outside the candidate
    // window keeps the in-window timestamp (existing semantics, unchanged).
    const outside = await pool.query(
      `SELECT lower(observable) AS o, MIN(created_at) AS m FROM ioc_items
       WHERE observable_type = 'domain' AND observable ILIKE $1 AND source_name = 'dup-src' AND created_at < now()
       GROUP BY 1`, [`%${MARK}%`]);
    const oldest = new Map(outside.rows.map((r) => [`o:domain:${r.o}`, r.m]));
    assert.ok(reference.some((r) => oldest.has(r.identity_key) && +new Date(r.created_at) > +oldest.get(r.identity_key)),
      'window-local platform_imported_at preserved');
  });

  it('full winner-row grouping only sees the page identities (plan)', opts, async () => {
    const plans = {};
    for (const [name, sql] of [['reference', buildSingleStageActiveBrowsePageSql()], ['twoStage', buildCanonicalActiveBrowsePageSql()]]) {
      const { rows } = await pool.query(`EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) ${sql}`, params(25, 0));
      plans[name] = fullGroupingNodes(rows[0]['QUERY PLAN'][0].Plan);
    }
    assert.equal(plans.twoStage.length, 1);
    assert.ok(plans.twoStage[0]['Actual Rows'] <= 25, `two-stage full grouping groups=${plans.twoStage[0]['Actual Rows']}`);
    assert.equal(plans.reference.length, 1);
    assert.ok(plans.reference[0]['Actual Rows'] > BROWSE_CAP, `reference full grouping groups=${plans.reference[0]['Actual Rows']}`);
  });
});

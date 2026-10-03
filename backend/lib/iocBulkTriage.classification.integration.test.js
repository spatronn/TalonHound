/**
 * Real-Postgres: bulk triage "add classification" must be additive.
 * Manual-create junction rows (source_type=manual) must survive bulk add.
 *
 * Guarded by assertFileArtifactDbTestAllowed.
 */

import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { assertFileArtifactDbTestAllowed } from './fileArtifacts/dbTestGuard.js';
import { bulkAddClassification } from './iocBulkTriage.js';
import { loadCanonicalIocClassification } from './iocCanonicalClassifications.js';
import { syncThreatClassificationOverrides } from './iocThreatClassificationOverrides.js';

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
    await pool.query('SELECT 1 FROM ioc_threat_classifications LIMIT 0');
    await pool.query('SELECT 1 FROM ioc_threat_classification_overrides LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}

const opts = {
  skip: hasDb
    ? false
    : 'disposable migrated test DB not available (ALLOW_FILE_ARTIFACT_DB_TESTS=1 + *_test DB)'
};

const MARK = `bulkcls${crypto.randomBytes(4).toString('hex')}`;

async function ensureSource(client) {
  const name = `ITest BulkCls ${MARK}`;
  const { rows: existing } = await client.query(
    `SELECT id FROM ioc_sources WHERE name = $1 LIMIT 1`,
    [name]
  );
  if (existing[0]) return existing[0].id;
  const { rows } = await client.query(
    `INSERT INTO ioc_sources (name, source_type, active)
     VALUES ($1, 'manual', TRUE)
     RETURNING id`,
    [name]
  );
  return rows[0].id;
}

async function ensureFeed(client) {
  const key = `itest-bulkcls-${MARK}`;
  const { rows: existing } = await client.query(
    `SELECT integration_id FROM integration_feeds WHERE key = $1`,
    [key]
  );
  if (existing[0]) return existing[0].integration_id;
  const { rows } = await client.query(
    `INSERT INTO integration_feeds (key, name, source_url, schedule_cron, active, integration_id)
     VALUES ($1, $2, 'https://example.test/bulkcls', '0 * * * *', TRUE, gen_random_uuid())
     RETURNING integration_id`,
    [key, `BulkCls ${MARK}`]
  );
  return rows[0].integration_id;
}

async function insertManualIoc(client, { value, type = 'domain', sourceId, legacy = 'malware' }) {
  const { rows } = await client.query(
    `INSERT INTO ioc_items (
       public_id, observable, observable_type, source_name, confidence, category, note,
       threat_classification, status, created_at, last_seen_at, ioc_source_id
     ) VALUES (
       gen_random_uuid(), $1, $2, $3, 'high', 'itest', $4, $5, 'active', NOW(), NOW(), $6
     ) RETURNING id, observable_type, observable, threat_classification, ioc_source_id, source_name`,
    [value, type, `ITest BulkCls ${MARK}`, MARK, legacy, sourceId]
  );
  return rows[0];
}

async function insertManualJunction(client, ioc, slug) {
  await client.query(
    `INSERT INTO ioc_threat_classifications
       (ioc_id, ioc_observable_type, classification_slug, source_type, source_name)
     VALUES ($1, $2, $3, 'manual', $4)`,
    [ioc.id, ioc.observable_type, slug, ioc.source_name]
  );
}

async function listJunction(client, ioc) {
  const { rows } = await client.query(
    `SELECT classification_slug, source_type
     FROM ioc_threat_classifications
     WHERE ioc_id = $1 AND ioc_observable_type = $2
     ORDER BY classification_slug`,
    [ioc.id, ioc.observable_type]
  );
  return rows;
}

async function cleanup() {
  if (!pool) return;
  await pool.query(
    `DELETE FROM ioc_threat_classification_overrides
     WHERE ioc_id IN (SELECT id FROM ioc_items WHERE note = $1)`,
    [MARK]
  );
  await pool.query(
    `DELETE FROM ioc_threat_classifications
     WHERE ioc_id IN (SELECT id FROM ioc_items WHERE note = $1)`,
    [MARK]
  );
  await pool.query(
    `DELETE FROM ioc_feed_source_evidence
     WHERE ioc_item_id IN (SELECT id FROM ioc_items WHERE note = $1)`,
    [MARK]
  );
  await pool.query(`DELETE FROM ioc_items WHERE note = $1`, [MARK]);
}

describe('bulk triage add classification — additive (real Postgres)', () => {
  after(async () => {
    try { await cleanup(); } catch { /* ignore */ }
    if (pool) await pool.end();
  });

  it('manual-create malware + bulk add credential_theft keeps both', opts, async () => {
    await cleanup();
    const sourceId = await ensureSource(pool);
    const ioc = await insertManualIoc(pool, {
      value: `${MARK}-keep.example`,
      sourceId,
      legacy: 'malware'
    });
    await insertManualJunction(pool, ioc, 'malware');

    const before = await loadCanonicalIocClassification(pool, ioc);
    assert.deepEqual(before.classifications, ['malware']);

    const out = await bulkAddClassification(pool, {
      iocIds: [Number(ioc.id)],
      slug: 'credential_theft',
      user: { email: 'itest@talonhound.test' }
    });
    assert.equal(out.succeeded, 1);

    const rows = await listJunction(pool, ioc);
    assert.deepEqual(
      rows.map((r) => r.classification_slug),
      ['credential_theft', 'malware']
    );
    assert.equal(rows.find((r) => r.classification_slug === 'malware').source_type, 'manual');
    assert.equal(rows.find((r) => r.classification_slug === 'credential_theft').source_type, 'analyst');

    const after = await loadCanonicalIocClassification(pool, ioc);
    assert.deepEqual(after.classifications, ['credential_theft', 'malware']);
  });

  it('duplicate bulk add is idempotent (no duplicate junction rows)', opts, async () => {
    await cleanup();
    const sourceId = await ensureSource(pool);
    const ioc = await insertManualIoc(pool, {
      value: `${MARK}-dup.example`,
      sourceId,
      legacy: 'malware'
    });
    await insertManualJunction(pool, ioc, 'malware');

    const first = await bulkAddClassification(pool, {
      iocIds: [Number(ioc.id)],
      slug: 'malware',
      user: { email: 'itest@talonhound.test' }
    });
    assert.equal(first.skipped, 1);

    const second = await bulkAddClassification(pool, {
      iocIds: [Number(ioc.id)],
      slug: 'credential_theft',
      user: { email: 'itest@talonhound.test' }
    });
    assert.equal(second.succeeded, 1);
    const third = await bulkAddClassification(pool, {
      iocIds: [Number(ioc.id)],
      slug: 'credential_theft',
      user: { email: 'itest@talonhound.test' }
    });
    assert.equal(third.skipped, 1);

    const rows = await listJunction(pool, ioc);
    assert.equal(rows.length, 2);
    assert.deepEqual(rows.map((r) => r.classification_slug), ['credential_theft', 'malware']);
  });

  it('multi-IOC bulk add extends each IOC independently', opts, async () => {
    await cleanup();
    const sourceId = await ensureSource(pool);
    const a = await insertManualIoc(pool, { value: `${MARK}-a.example`, sourceId, legacy: 'malware' });
    const b = await insertManualIoc(pool, { value: `${MARK}-b.example`, sourceId, legacy: 'credential_theft' });
    await insertManualJunction(pool, a, 'malware');
    await insertManualJunction(pool, b, 'credential_theft');

    const out = await bulkAddClassification(pool, {
      iocIds: [Number(a.id), Number(b.id)],
      slug: 'dropper_downloader',
      user: { email: 'itest@talonhound.test' }
    });
    assert.equal(out.succeeded, 2);

    assert.deepEqual(
      (await listJunction(pool, a)).map((r) => r.classification_slug),
      ['dropper_downloader', 'malware']
    );
    assert.deepEqual(
      (await listJunction(pool, b)).map((r) => r.classification_slug),
      ['credential_theft', 'dropper_downloader']
    );
  });

  it('feed proposal + suppression survive bulk add; only analyst set grows', opts, async () => {
    await cleanup();
    const sourceId = await ensureSource(pool);
    const feedId = await ensureFeed(pool);
    const ioc = await insertManualIoc(pool, {
      value: `${MARK}-feed.example`,
      sourceId,
      legacy: 'malware'
    });
    await insertManualJunction(pool, ioc, 'malware');
    await pool.query(
      `INSERT INTO ioc_feed_source_evidence (
         ioc_item_id, ioc_observable_type, feed_id, source_name, category, note
       ) VALUES ($1, $2, $3, 'AlienVault OTX', NULL, 'x | tags=infostealer')`,
      [ioc.id, ioc.observable_type, feedId]
    );
    await pool.query(
      `INSERT INTO ioc_threat_classification_overrides
         (ioc_id, ioc_observable_type, classification_slug, action, source_name, created_by)
       VALUES ($1, $2, 'credential_theft', 'suppress', NULL, 'itest')`,
      [ioc.id, ioc.observable_type]
    );

    const before = await loadCanonicalIocClassification(pool, ioc);
    assert.deepEqual(before.classifications, ['malware']);
    assert.equal(before.suppressions.length, 1);

    const out = await bulkAddClassification(pool, {
      iocIds: [Number(ioc.id)],
      slug: 'dropper_downloader',
      user: { email: 'itest@talonhound.test' }
    });
    assert.equal(out.succeeded, 1);

    const after = await loadCanonicalIocClassification(pool, ioc);
    assert.deepEqual(after.classifications, ['dropper_downloader', 'malware']);
    assert.equal(after.suppressions.length, 1);
    assert.equal(after.suppressions[0].classification_slug, 'credential_theft');
    assert.ok(after.feed.some((f) => f.value === 'credential_theft'));

    const { rows: suppressRows } = await pool.query(
      `SELECT classification_slug, cleared_at FROM ioc_threat_classification_overrides
       WHERE ioc_id = $1 AND action = 'suppress' AND cleared_at IS NULL`,
      [ioc.id]
    );
    assert.equal(suppressRows.length, 1);
  });

  it('editor sync replace still drops unchecked analyst classifications', opts, async () => {
    await cleanup();
    const sourceId = await ensureSource(pool);
    const ioc = await insertManualIoc(pool, {
      value: `${MARK}-replace.example`,
      sourceId,
      legacy: 'malware'
    });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await syncThreatClassificationOverrides(client, {
        iocId: ioc.id,
        observableType: ioc.observable_type,
        additions: ['malware', 'credential_theft'],
        suppressions: [],
        actor: 'itest'
      });
      await client.query('COMMIT');
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch { /* ignore */ }
      throw err;
    } finally {
      client.release();
    }

    const mid = await listJunction(pool, ioc);
    assert.deepEqual(mid.map((r) => r.classification_slug), ['credential_theft', 'malware']);

    const client2 = await pool.connect();
    try {
      await client2.query('BEGIN');
      await syncThreatClassificationOverrides(client2, {
        iocId: ioc.id,
        observableType: ioc.observable_type,
        additions: ['malware'],
        suppressions: [],
        actor: 'itest'
      });
      await client2.query('COMMIT');
    } catch (err) {
      try { await client2.query('ROLLBACK'); } catch { /* ignore */ }
      throw err;
    } finally {
      client2.release();
    }

    const after = await listJunction(pool, ioc);
    assert.deepEqual(after.map((r) => r.classification_slug), ['malware']);
  });
});

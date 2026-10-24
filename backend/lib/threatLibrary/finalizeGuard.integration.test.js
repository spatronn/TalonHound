import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { createThreatReport } from './store.js';
import { finalizeReport } from './reviewService.js';

/**
 * Real-Postgres checks of the guarded finalize write (tl-finalize-guard-v1):
 * a competing commit from a second connection lands at the exact point
 * between finalizeReport's read and its conditional UPDATE, and the UPDATE
 * itself must refuse to finalize. Rows are committed (two connections), so
 * every test deletes its own report afterwards.
 *
 * ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database; run
 * with --test-concurrency=1 alongside the other TL itest files.
 */

const config = {
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 4
};
const pool = new pg.Pool(config);
const other = new pg.Pool({ ...config, max: 2 });

let hasDb = false;
if (process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1') {
  try {
    await pool.query('SELECT lifecycle_status FROM threat_report_ioc_sources LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };

test.after(async () => {
  await pool.end();
  await other.end();
});

const GUARDED_UPDATE_RE = /^\s*UPDATE threat_reports r/;

/** Pool that runs `beforeWrite()` (a committed competing change) right before the guarded UPDATE. */
function racingPool(beforeWrite) {
  return {
    query: async (sql, params) => {
      if (typeof sql === 'string' && GUARDED_UPDATE_RE.test(sql) && beforeWrite) await beforeWrite();
      return pool.query(sql, params);
    }
  };
}

async function setupReport({ review = 'approved' } = {}) {
  const report = await createThreatReport(pool, {
    title: `itest-finalize-guard-${crypto.randomUUID()}`,
    source_type: 'url',
    source_url: `https://vendor-research.example/${crypto.randomUUID()}`
  });
  await pool.query(`UPDATE threat_reports SET analysis_status = 'review_required', import_status = 'review_required' WHERE id = $1`, [report.id]);
  const { rows } = await pool.query(
    `INSERT INTO threat_report_candidates (
       report_id, candidate_type, original_value, normalized_value, assessment, role, review_status,
       match_state, is_ioc, source_assertion, evidence, has_original_document_occurrence
     ) VALUES ($1,'ip','203.0.113.10','203.0.113.10','malicious','malicious_infrastructure',$2,'new',true,'explicit_ioc',
       '{"source_assertion":"explicit_ioc","document_has_authoritative_scope":true}'::jsonb, true) RETURNING id`,
    [report.id, review]
  );
  return { report, candidateId: rows[0].id };
}

async function addSource(db, reportId, lifecycle) {
  const url = `https://github.com/vendor/iocs/tree/main/${crypto.randomUUID()}`;
  await db.query(
    `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, source_type, discovery_method, discovery_evidence, lifecycle_status)
     VALUES ($1,$2,$2,'github_dir','auto','{}'::jsonb,$3)`,
    [reportId, url, lifecycle]
  );
}

async function cleanup(reportId) {
  await pool.query(`DELETE FROM threat_report_ioc_sources WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_report_candidates WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_reports WHERE id = $1`, [reportId]);
}

const finalizedAt = async (id) => (await pool.query('SELECT finalized_at FROM threat_reports WHERE id = $1', [id])).rows[0].finalized_at;

test('control: resolved sources (extracted + dismissed) finalize', opts, async () => {
  const { report } = await setupReport();
  try {
    await addSource(pool, report.id, 'extracted');
    await addSource(pool, report.id, 'dismissed');
    const r = await finalizeReport(racingPool(null), report.id, { user: { role: 'analyst' } });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(await finalizedAt(report.id));
  } finally {
    await cleanup(report.id);
  }
});

test('a pending linked source blocks finalize in the database', opts, async () => {
  const { report } = await setupReport();
  try {
    await addSource(pool, report.id, 'discovered');
    const r = await finalizeReport(racingPool(null), report.id, { user: { role: 'analyst' } });
    assert.equal(r.code, 'linked_ioc_sources_unresolved');
    assert.equal(await finalizedAt(report.id), null);
  } finally {
    await cleanup(report.id);
  }
});

test('race: a source committed after the read is seen by the guarded write', opts, async () => {
  const { report } = await setupReport();
  try {
    const r = await finalizeReport(racingPool(() => addSource(other, report.id, 'discovered')), report.id, { user: { role: 'analyst' } });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'linked_ioc_sources_unresolved');
    assert.equal(await finalizedAt(report.id), null);
  } finally {
    await cleanup(report.id);
  }
});

test('race: an Indicator returned to pending after the read blocks the write', opts, async () => {
  const { report, candidateId } = await setupReport();
  try {
    const flip = () => other.query(`UPDATE threat_report_candidates SET review_status = 'pending' WHERE id = $1`, [candidateId]);
    const r = await finalizeReport(racingPool(flip), report.id, { user: { role: 'analyst' } });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'pending_review_remaining');
    assert.equal(await finalizedAt(report.id), null);
  } finally {
    await cleanup(report.id);
  }
});

test('administrator override finalizes over an unresolved source', opts, async () => {
  const { report } = await setupReport();
  try {
    await addSource(pool, report.id, 'failed');
    const r = await finalizeReport(racingPool(null), report.id, { user: { role: 'admin' }, sourceOverride: { reason: 'pack duplicates the article tables exactly' } });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(await finalizedAt(report.id));
  } finally {
    await cleanup(report.id);
  }
});

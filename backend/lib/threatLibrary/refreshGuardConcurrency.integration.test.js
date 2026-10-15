import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { candidateColumns, createJob, createThreatReport } from './store.js';
import { REFRESH_CONCURRENT_CHANGE_CODE, REFRESH_BLOCKED_CODE, previewExtractionRefresh, runExtractionRefresh } from './extractionRefresh.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildLayoutVariant } from './benchmark/layoutVariants.js';

/**
 * Real-Postgres concurrency checks of Refresh extraction's membership guard
 * (time-of-check / time-of-use). The refresh computes and guards its diff from
 * a snapshot read outside the write transaction; these tests commit a
 * competing write from a second connection at the exact point between that
 * snapshot and the candidate-row lock (`SELECT … FOR UPDATE`), or while the
 * refresh holds the locks. Rows are committed (two connections), so every
 * test deletes its own report afterwards.
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
    await pool.query('SELECT has_original_document_occurrence FROM threat_report_candidates LIMIT 0');
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

const LOCK_SQL_RE = /FROM threat_report_candidates WHERE report_id = \$1 ORDER BY id FOR UPDATE/;

/**
 * Pool whose transaction clients run `hooks.beforeLock()` right before the
 * candidate-row lock query is sent and `hooks.afterLock()` right after it
 * returns. Everything else passes straight through to the real pool.
 */
function racingPool(hooks) {
  return {
    query: (...args) => pool.query(...args),
    connect: async () => {
      const client = await pool.connect();
      return {
        query: async (sql, params) => {
          const isLock = typeof sql === 'string' && LOCK_SQL_RE.test(sql);
          if (isLock && hooks.beforeLock) await hooks.beforeLock();
          const res = await client.query(sql, params);
          if (isLock && hooks.afterLock) await hooks.afterLock();
          return res;
        },
        release: (...a) => client.release(...a)
      };
    }
  };
}

async function insertRow(reportId, col) {
  const { rows } = await pool.query(
    `INSERT INTO threat_report_candidates (
       report_id, candidate_type, original_value, normalized_value, assessment, role, review_status,
       match_state, is_ioc, source_assertion, evidence, has_original_document_occurrence, promotion_outcome
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13) RETURNING id`,
    [
      reportId, col.candidate_type, col.original_value, col.normalized_value, col.assessment, col.role, col.review_status,
      col.match_state, col.is_ioc, col.source_assertion, JSON.stringify(col.evidence), col.has_original_document_occurrence !== false,
      col.promotion_outcome || null
    ]
  );
  return rows[0].id;
}

/** A refreshable report whose stored rows equal the current extraction (a refresh is a no-op). */
async function setupReport() {
  const variant = buildLayoutVariant('html_c2_then_loaders/table');
  const report = await createThreatReport(pool, {
    title: `itest-guard-race-${crypto.randomUUID()}`,
    source_type: 'url',
    source_url: variant.sourceUrl
  });
  const extracted = extractReportCandidates({ source_type: 'url', source_url: variant.sourceUrl }, variant.document);
  await pool.query(
    `UPDATE threat_reports SET canonical_document = $2::jsonb, analysis_status = 'review_required', import_status = 'ready' WHERE id = $1`,
    [report.id, JSON.stringify(extracted.document)]
  );
  for (const c of extracted.candidates) await insertRow(report.id, candidateColumns(c));
  const job = await createJob(pool, { reportId: report.id, jobType: 'refresh_extraction' });
  return { report, extracted, job };
}

async function cleanup(reportId) {
  await pool.query(
    `DELETE FROM threat_report_candidate_source_links WHERE candidate_id IN (SELECT id FROM threat_report_candidates WHERE report_id = $1)`,
    [reportId]
  );
  await pool.query(`DELETE FROM threat_report_ioc_sources WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_report_candidates WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_library_jobs WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_reports WHERE id = $1`, [reportId]);
}

const rowsOf = async (reportId) =>
  (await pool.query(
    `SELECT id, normalized_value, review_status, assessment, has_original_document_occurrence, updated_at
     FROM threat_report_candidates WHERE report_id = $1 ORDER BY id`,
    [reportId]
  )).rows;

const firstIndicatorId = async (reportId) =>
  (await pool.query(
    `SELECT id FROM threat_report_candidates WHERE report_id = $1 AND is_ioc = true ORDER BY id LIMIT 1`,
    [reportId]
  )).rows[0].id;

test('control: with no competing write the refresh applies and keeps prior review decisions', opts, async () => {
  const { report, job } = await setupReport();
  try {
    const target = await firstIndicatorId(report.id);
    await pool.query(`UPDATE threat_report_candidates SET review_status = 'ignored', updated_at = NOW() WHERE id = $1`, [target]);
    const res = await runExtractionRefresh(racingPool({}), { reportId: report.id, jobId: job.id, restoreStatus: { analysis_status: 'review_required', import_status: 'ready' } });
    assert.equal(res.ok, true, JSON.stringify(res));
    const row = (await rowsOf(report.id)).find((r) => String(r.id) === String(target));
    assert.equal(row.review_status, 'ignored');
  } finally {
    await cleanup(report.id);
  }
});

test('a review committed between the guard snapshot and the row lock aborts the refresh; nothing is written and the review survives', opts, async () => {
  const { report, job } = await setupReport();
  try {
    const target = await firstIndicatorId(report.id);
    const before = await rowsOf(report.id);
    let raced = false;
    const res = await runExtractionRefresh(
      racingPool({
        beforeLock: async () => {
          if (raced) return;
          raced = true;
          // A concurrent analyst decision, committed on another connection.
          await other.query(`UPDATE threat_report_candidates SET review_status = 'ignored', updated_at = NOW() WHERE id = $1`, [target]);
        }
      }),
      { reportId: report.id, jobId: job.id, restoreStatus: { analysis_status: 'review_required', import_status: 'ready' } }
    );
    assert.equal(raced, true, 'the race point was reached');
    assert.equal(res.ok, false);
    assert.equal(res.code, REFRESH_CONCURRENT_CHANGE_CODE);

    const after = await rowsOf(report.id);
    assert.equal(after.length, before.length, 'no row added or deleted');
    for (const b of before) {
      const a = after.find((r) => String(r.id) === String(b.id));
      if (String(b.id) === String(target)) {
        assert.equal(a.review_status, 'ignored', 'the concurrent review decision is not reverted');
      } else {
        assert.deepEqual(a, b, `row ${b.id} untouched`);
      }
    }
    const { rows: rep } = await pool.query(`SELECT analysis_status, analysis_progress FROM threat_reports WHERE id = $1`, [report.id]);
    assert.equal(rep[0].analysis_status, 'review_required', 'status restored');
    assert.equal(rep[0].analysis_progress.last_refresh.error_code, REFRESH_CONCURRENT_CHANGE_CODE);
    const { rows: jobs } = await pool.query(`SELECT status FROM threat_library_jobs WHERE id = $1`, [job.id]);
    assert.equal(jobs[0].status, 'failed');
  } finally {
    await cleanup(report.id);
  }
});

test('an accepted preview no longer matches once link provenance is removed before the lock: the locked guard refuses, nothing is written', opts, async () => {
  const { report, extracted, job } = await setupReport();
  try {
    // An approved row the document no longer produces, kept only by an IOC Source link.
    const template = candidateColumns(extracted.candidates.find((c) => c.candidate_type === 'domain'));
    const linkedId = await insertRow(report.id, {
      ...template,
      normalized_value: 'linked-kept.example',
      original_value: 'linked-kept.example',
      review_status: 'approved'
    });
    const { rows: src } = await pool.query(
      `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, lifecycle_status, approved_at)
       VALUES ($1, $2, $2, 'extracted', NOW()) RETURNING id`,
      [report.id, `https://example.test/iocs/${crypto.randomUUID()}`]
    );
    await pool.query(
      `INSERT INTO threat_report_candidate_source_links (candidate_id, source_id, source_assertion) VALUES ($1, $2, 'linked_source_ioc')`,
      [linkedId, src[0].id]
    );
    // The analyst previews the refresh while the link exists (the linked row's
    // original occurrence is cleared, not deleted) and accepts that loss.
    const { rows: stored } = await pool.query(`SELECT * FROM threat_reports WHERE id = $1`, [report.id]);
    const preview = await previewExtractionRefresh(pool, stored[0]);
    assert.equal(preview.guard.decision, 'block', 'the previewed loss needs an explicit acceptance');
    const removedRow = preview.membership_diff.removed_indicators.find((r) => r.identity === 'domain:linked-kept.example');
    assert.equal(removedRow.row_outcome, 'original_occurrence_cleared');
    const membershipPolicy = {
      mode: 'accept',
      reason: 'Accepting the reviewed publisher row moving to the IOC Source only',
      preview_fingerprint: preview.membership_diff.material_fingerprint,
      requested_by: null,
      requested_at: new Date().toISOString()
    };

    const before = await rowsOf(report.id);
    let raced = false;
    const res = await runExtractionRefresh(
      racingPool({
        beforeLock: async () => {
          if (raced) return;
          raced = true;
          // The IOC Source link disappears after the worker's guard check:
          // the same refresh would now DELETE the reviewed row.
          await other.query(`DELETE FROM threat_report_candidate_source_links WHERE candidate_id = $1`, [linkedId]);
        }
      }),
      { reportId: report.id, jobId: job.id, restoreStatus: { analysis_status: 'review_required', import_status: 'ready' }, membershipPolicy }
    );
    assert.equal(raced, true, 'the pre-lock guard accepted the previewed loss and the race point was reached');
    assert.equal(res.ok, false, JSON.stringify(res));
    assert.equal(res.code, REFRESH_BLOCKED_CODE);
    const mg = res.summary.membership_guard;
    assert.ok(mg.reasons.some((r) => r.code === 'reviewed_candidate_deleted'), JSON.stringify(mg));
    assert.notEqual(mg.material_fingerprint, membershipPolicy.preview_fingerprint, 'the locked state no longer matches the accepted preview');
    assert.deepEqual(await rowsOf(report.id), before, 'blocked: no candidate written');
    const { rows: still } = await pool.query(`SELECT id FROM threat_report_candidates WHERE id = $1`, [linkedId]);
    assert.equal(still.length, 1, 'the reviewed row was not deleted');
  } finally {
    await cleanup(report.id);
  }
});

test('a review issued while the refresh holds the row locks waits, then applies on the committed set (no deadlock, no lost decision)', opts, async () => {
  const { report, job } = await setupReport();
  try {
    const target = await firstIndicatorId(report.id);
    let review = null;
    const res = await runExtractionRefresh(
      racingPool({
        afterLock: async () => {
          if (review) return;
          review = other.query(
            `UPDATE threat_report_candidates SET review_status = 'ignored', updated_at = NOW() WHERE id = $1`,
            [target]
          );
          // Give the review time to reach the row lock it must wait on.
          await new Promise((r) => setTimeout(r, 300));
          const { rows } = await pool.query(
            `SELECT count(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE 'UPDATE threat_report_candidates SET review_status%'`
          );
          assert.equal(rows[0].n, 1, 'the review is blocked on the refresh row lock');
        }
      }),
      { reportId: report.id, jobId: job.id, restoreStatus: { analysis_status: 'review_required', import_status: 'ready' } }
    );
    assert.equal(res.ok, true, JSON.stringify(res));
    const done = await review;
    assert.equal(done.rowCount, 1);
    const row = (await rowsOf(report.id)).find((r) => String(r.id) === String(target));
    assert.equal(row.review_status, 'ignored');
  } finally {
    await cleanup(report.id);
  }
});

/**
 * Extraction run ledger against real PostgreSQL: append-only enforcement,
 * first-pass semantics, idempotency, reproducible identity comparison.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {
  compareReferenceRunToCurrent,
  listExtractionRuns,
  recordExtractionRun,
  recordLegacyBaseline
} from './extractionRuns.js';

const allowed = process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1';
const skip = allowed ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run';

function pool() {
  return new pg.Pool({
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
  });
}

const SHA = 'a'.repeat(64);
const row = (patch = {}) => ({
  candidate_type: 'domain',
  normalized_value: 'evil.example.net',
  original_value: 'evil[.]example[.]net',
  assessment: 'malicious',
  role: 'malicious_infrastructure',
  review_status: 'pending',
  match_state: 'new',
  is_ioc: true,
  source_assertion: 'explicit_ioc',
  has_original_document_occurrence: true,
  evidence: {
    source_assertion: 'explicit_ioc',
    document_has_authoritative_scope: true,
    policy_decision: 'explicit_report_assertion',
    occurrences: [{ block_id: 'b001', zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row', section_path: ['IOCs'] }]
  },
  ...patch
});

async function newReport(db, label) {
  const { rows } = await db.query(
    `INSERT INTO threat_reports (title, source_type, source_url, import_status, analysis_status)
     VALUES ($1, 'url', $2, 'review_required', 'review_required') RETURNING *`,
    [label, `https://ledger-itest.example/${label}-${Date.now()}-${Math.random()}`]
  );
  return rows[0];
}

const document = { blocks: [{ id: 'b001', type: 'list', text: 'evil[.]example[.]net' }], meta: {} };

test('first completed analysis is the first pass; refresh adds a run and never rewrites it', { skip }, async (t) => {
  const db = pool();
  const report = await newReport(db, 'first-pass');
  t.after(async () => {
    await db.query('DELETE FROM threat_reports WHERE id = $1', [report.id]);
    await db.end();
  });

  const first = await recordExtractionRun(db, { report, jobId: 9001, jobType: 'analyze', document, candidates: [row()] });
  assert.equal(first.recorded, true);
  assert.equal(first.is_first_pass, true);

  // The same job completing twice records nothing more (retry idempotency).
  const again = await recordExtractionRun(db, { report, jobId: 9001, jobType: 'analyze', document, candidates: [row(), row({ normalized_value: 'other.example.net' })] });
  assert.equal(again.recorded, false);

  const refresh = await recordExtractionRun(db, {
    report,
    jobId: 9002,
    jobType: 'refresh_extraction',
    document,
    candidates: [row({ normalized_value: 'added-later.example.net' })]
  });
  assert.equal(refresh.recorded, true);
  assert.equal(refresh.is_first_pass, false);

  const runs = await listExtractionRuns(db, report.id);
  assert.deepEqual(runs.map((r) => [r.run_type, r.is_first_pass]), [['initial', true], ['refresh', false]]);
  const { rows } = await db.query(
    'SELECT normalized_value FROM threat_report_extraction_run_candidates WHERE run_id = $1',
    [first.run_id]
  );
  assert.deepEqual(rows.map((r) => r.normalized_value), ['evil.example.net'], 'first-pass identities are exactly what the first run produced');
  assert.equal(runs[0].contract_fingerprint.length, 32);
  assert.ok(runs[0].contract_bundle.candidates);
  assert.ok(runs[0].document_hash);
});

test('the database refuses to update or directly delete ledger rows; deleting the report cascades', { skip }, async (t) => {
  const db = pool();
  t.after(() => db.end());
  const report = await newReport(db, 'immutable');
  const { run_id: runId } = await recordExtractionRun(db, { report, jobId: 9101, jobType: 'analyze', document, candidates: [row()] });

  await assert.rejects(db.query(`UPDATE threat_report_extraction_runs SET run_type = 'refresh' WHERE id = $1`, [runId]), /append-only/);
  await assert.rejects(db.query('DELETE FROM threat_report_extraction_runs WHERE id = $1', [runId]), /append-only/);
  await assert.rejects(db.query(`UPDATE threat_report_extraction_run_candidates SET is_member = FALSE WHERE run_id = $1`, [runId]), /append-only/);
  await assert.rejects(db.query('DELETE FROM threat_report_extraction_run_candidates WHERE run_id = $1', [runId]), /append-only/);
  await assert.rejects(db.query(`UPDATE threat_report_observable_dispositions SET disposition = 'accepted' WHERE run_id = $1`, [runId]), /append-only/);

  await db.query('DELETE FROM threat_reports WHERE id = $1', [report.id]);
  const { rows } = await db.query('SELECT 1 FROM threat_report_extraction_runs WHERE id = $1', [runId]);
  assert.equal(rows.length, 0, 'deleting the report removes its runs');
});

test('a second first pass cannot exist for one report', { skip }, async (t) => {
  const db = pool();
  const report = await newReport(db, 'one-first-pass');
  t.after(async () => {
    await db.query('DELETE FROM threat_reports WHERE id = $1', [report.id]);
    await db.end();
  });
  await recordExtractionRun(db, { report, jobId: 9201, jobType: 'analyze', document, candidates: [row()] });
  await assert.rejects(
    db.query(
      `INSERT INTO threat_report_extraction_runs (report_id, run_type, is_first_pass, contract_fingerprint, idempotency_key)
       VALUES ($1, 'retry', TRUE, 'x', 'manual')`,
      [report.id]
    ),
    /uq_threat_report_extraction_runs_first_pass/
  );
});

test('a pre-ledger report gets a labelled baseline and later jobs never claim a first pass', { skip }, async (t) => {
  const db = pool();
  const report = await newReport(db, 'legacy');
  t.after(async () => {
    await db.query('DELETE FROM threat_reports WHERE id = $1', [report.id]);
    await db.end();
  });

  const baseline = await recordLegacyBaseline(db, { report, candidates: [row({ review_status: 'approved' })] });
  assert.equal(baseline.is_first_pass, false);
  assert.equal((await recordLegacyBaseline(db, { report, candidates: [row()] })).recorded, false, 'baseline is idempotent');

  const later = await recordExtractionRun(db, { report, jobId: 9301, jobType: 'retry', document, candidates: [row()] });
  assert.equal(later.is_first_pass, false, 'a run after a baseline is not a first pass');

  const compare = await compareReferenceRunToCurrent(db, report.id);
  assert.equal(compare.reference.run_type, 'legacy_baseline');
  assert.equal(compare.reference.is_first_pass, false);
});

test('first-pass versus current is queryable by exact identity', { skip }, async (t) => {
  const db = pool();
  const report = await newReport(db, 'compare');
  t.after(async () => {
    await db.query('DELETE FROM threat_reports WHERE id = $1', [report.id]);
    await db.end();
  });

  const kept = row({ normalized_value: 'kept.example.net' });
  const dropped = row({ normalized_value: 'dropped.example.net' });
  await recordExtractionRun(db, { report, jobId: 9401, jobType: 'analyze', document, candidates: [kept, dropped] });

  const insert = (value, review, inDoc = true) => db.query(
    `INSERT INTO threat_report_candidates (report_id, candidate_type, original_value, normalized_value, review_status, has_original_document_occurrence)
     VALUES ($1, 'domain', $2, $2, $3, $4)`,
    [report.id, value, review, inDoc]
  );
  await insert('kept.example.net', 'approved');
  await insert('from-pack.example.net', 'approved', false);
  await insert('analyst-found.example.net', 'approved');

  const compare = await compareReferenceRunToCurrent(db, report.id);
  assert.equal(compare.reference.is_first_pass, true);
  assert.equal(compare.kept, 1);
  assert.deepEqual(compare.lost_from_reference, [{ candidate_type: 'domain', normalized_value: 'dropped.example.net' }]);
  assert.deepEqual(
    compare.added_after_reference.sort((a, b) => a.normalized_value.localeCompare(b.normalized_value)),
    [
      { candidate_type: 'domain', normalized_value: 'analyst-found.example.net', from_linked_source: false },
      { candidate_type: 'domain', normalized_value: 'from-pack.example.net', from_linked_source: true }
    ]
  );
});

test('dispositions and dropped regions of a run persist with their reasons', { skip }, async (t) => {
  const db = pool();
  const report = await newReport(db, 'evidence');
  t.after(async () => {
    await db.query('DELETE FROM threat_reports WHERE id = $1', [report.id]);
    await db.end();
  });
  const doc = {
    blocks: [{ id: 'b002', type: 'paragraph', text: `hash ${SHA}`, zone: 'report_body', section_path: ['Overview'] }],
    meta: {
      source_accounting: {
        dropped_regions: [{
          region_kind: 'textarea', reason: 'noise_element', locator: 'textarea', text_chars: 64,
          observable_count: 1, observable_types: { hash: 1 }, sample_observables: [SHA], significant: true
        }]
      }
    }
  };
  const { run_id: runId } = await recordExtractionRun(db, {
    report, jobId: 9501, jobType: 'analyze', document: doc, candidates: [],
    tokenLog: [{ observable_type: 'md5', raw_value: 'b'.repeat(32), reason_code: 'credential_labeled_hex' }],
    blocks: doc.blocks
  });
  const { rows: disp } = await db.query(
    'SELECT disposition, reason_code, section_path FROM threat_report_observable_dispositions WHERE run_id = $1 ORDER BY id',
    [runId]
  );
  assert.deepEqual(disp.map((d) => d.reason_code), ['credential_labeled_hex', 'undispositioned_token']);
  assert.deepEqual(disp[1].section_path, ['Overview']);
  const { rows: regions } = await db.query('SELECT region_kind, significant, sample_observables FROM threat_report_dropped_regions WHERE run_id = $1', [runId]);
  assert.deepEqual(regions, [{ region_kind: 'textarea', significant: true, sample_observables: [SHA] }]);
  const { rows: run } = await db.query('SELECT counts FROM threat_report_extraction_runs WHERE id = $1', [runId]);
  assert.equal(run[0].counts.dropped_significant_observables, 1);
  assert.equal(run[0].counts.dispositions.undispositioned, 1);
});

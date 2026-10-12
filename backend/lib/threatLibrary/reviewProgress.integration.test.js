import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { loadReportReviewProgress, summarizeReviewProgress } from './reviewProgress.js';
import { attachReportCounts, createThreatReport } from './store.js';

/**
 * Real-Postgres check of the effective review-progress SQL
 * (loadReportReviewProgress) against the pure contract (summarizeReviewProgress)
 * and the report's Total Unique Indicators count, for the scenarios in
 * reviewProgress.test.js. Every scenario runs inside a rolled-back transaction,
 * so it only needs ALLOW_THREAT_LIBRARY_DB_TESTS=1 and a migrated database.
 */

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 4
});

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

test.after(() => pool.end());

const MODE_A_EVIDENCE = {
  document_has_authoritative_scope: true,
  source_assertion: 'explicit_ioc',
  is_direct_source_observable: true,
  occurrences: [{ zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row' }]
};

let seq = 0;
function orig(overrides = {}) {
  seq += 1;
  return {
    candidate_type: 'domain',
    normalized_value: `o${seq}.example`,
    is_ioc: true,
    assessment: 'malicious',
    review_status: 'approved',
    match_state: 'new',
    matched_ioc_id: null,
    source_assertion: 'explicit_ioc',
    has_original_document_occurrence: true,
    document_has_authoritative_scope: true,
    evidence: MODE_A_EVIDENCE,
    sourceKeys: [],
    ...overrides
  };
}
function linked(sourceKeys, overrides = {}) {
  seq += 1;
  return {
    candidate_type: 'sha256',
    normalized_value: crypto.createHash('sha256').update(`l${seq}`).digest('hex'),
    is_ioc: true,
    assessment: 'malicious',
    review_status: 'approved',
    match_state: 'new',
    matched_ioc_id: null,
    source_assertion: 'linked_source_ioc',
    has_original_document_occurrence: false,
    evidence: { source_assertion: 'linked_source_ioc', is_direct_source_observable: true },
    sourceKeys,
    ...overrides
  };
}
const many = (n, fn) => Array.from({ length: n }, () => fn());

/**
 * @param {{ sources: Record<string, { approved: boolean, lifecycle?: string }>, rows: object[] }} scenario
 */
async function runScenario(scenario) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const report = await createThreatReport(client, { title: `itest-${crypto.randomUUID()}`, source_type: 'url' });
    const sourceIds = {};
    const sourceMeta = {};
    for (const [key, s] of Object.entries(scenario.sources || {})) {
      const url = `https://example.test/${key}/${crypto.randomUUID()}`;
      const { rows } = await client.query(
        `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, lifecycle_status, approved_at)
         VALUES ($1, $2, $2, $3, $4) RETURNING id, approved_at`,
        [report.id, url, s.lifecycle || (s.approved ? 'extracted' : 'inspected'), s.approved ? new Date() : null]
      );
      sourceIds[key] = rows[0].id;
      sourceMeta[key] = { id: key, approved_at: rows[0].approved_at };
    }
    for (const r of scenario.rows) {
      const { rows } = await client.query(
        `INSERT INTO threat_report_candidates (
           report_id, candidate_type, original_value, normalized_value, assessment, review_status,
           match_state, matched_ioc_id, is_ioc, source_assertion, evidence, has_original_document_occurrence
         ) VALUES ($1,$2,$3,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11) RETURNING id`,
        [
          report.id, r.candidate_type, r.normalized_value, r.assessment, r.review_status, r.match_state,
          r.matched_ioc_id, r.is_ioc, r.source_assertion, JSON.stringify(r.evidence), r.has_original_document_occurrence
        ]
      );
      for (const key of r.sourceKeys) {
        await client.query(
          `INSERT INTO threat_report_candidate_source_links (candidate_id, source_id, source_assertion) VALUES ($1, $2, 'linked_source_ioc')`,
          [rows[0].id, sourceIds[key]]
        );
      }
    }
    const sql = await loadReportReviewProgress(client, report.id);
    const js = summarizeReviewProgress(scenario.rows.map((r) => ({ ...r, sources: r.sourceKeys.map((k) => sourceMeta[k]) })));
    const counts = await attachReportCounts(client, report);
    return { sql, js, counts };
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

function assertCoherent({ sql, js, counts }) {
  assert.deepEqual(sql, js, 'SQL and pure contract agree');
  assert.equal(sql.total, counts.total_unique_indicator_count, 'denominator == Total Unique Indicators');
  assert.equal(sql.original.total, counts.review_candidate_count, 'original bucket == Original Indicators');
  assert.equal(sql.linked_only.total, counts.linked_only_indicator_count, 'linked-only bucket == Linked Only');
  assert.deepEqual(counts.review_progress, sql, 'attachReportCounts carries the same review_progress');
  assert.ok(sql.reviewed >= 0 && sql.reviewed <= sql.total);
}

test('original-only: 70/70', opts, async () => {
  const r = await runScenario({ rows: many(70, () => orig()) });
  assertCoherent(r);
  assert.deepEqual([r.sql.total, r.sql.reviewed, r.sql.pending], [70, 70, 0]);
});

test('original + accepted linked source (no overlap): 100/100', opts, async () => {
  const r = await runScenario({ sources: { A: { approved: true } }, rows: [...many(70, () => orig()), ...many(30, () => linked(['A']))] });
  assertCoherent(r);
  assert.deepEqual([r.sql.total, r.sql.reviewed, r.sql.pending], [100, 100, 0]);
});

test('linked rows not yet decided stay pending; decided rows under an unaccepted source stay pending', opts, async () => {
  const r1 = await runScenario({ sources: { A: { approved: true } }, rows: [...many(70, () => orig()), ...many(30, () => linked(['A'], { review_status: 'pending' }))] });
  assertCoherent(r1);
  assert.deepEqual([r1.sql.total, r1.sql.reviewed, r1.sql.pending], [100, 70, 30]);
  const r2 = await runScenario({ sources: { X: { approved: false } }, rows: [...many(70, () => orig()), ...many(30, () => linked(['X']))] });
  assertCoherent(r2);
  assert.deepEqual([r2.sql.total, r2.sql.reviewed, r2.sql.pending], [100, 70, 30]);
  assert.equal(r2.sql.linked_only.decided_without_accepted_source, 30);
});

test('overlap: 70 original, source has 10 of them + 20 new → 90, no double count', opts, async () => {
  const originals = many(70, () => orig());
  originals.slice(0, 10).forEach((o) => { o.sourceKeys = ['A']; });
  const r = await runScenario({ sources: { A: { approved: true } }, rows: [...originals, ...many(20, () => linked(['A']))] });
  assertCoherent(r);
  assert.deepEqual([r.sql.total, r.sql.reviewed, r.sql.overlap], [90, 90, 10]);
});

test('multiple sources (A accepted, B rows pending) and one IOC in both sources', opts, async () => {
  const both = linked(['A', 'B']);
  const r = await runScenario({
    sources: { A: { approved: true }, B: { approved: true } },
    rows: [...many(70, () => orig()), ...many(30, () => linked(['A'])), ...many(25, () => linked(['B'], { review_status: 'pending' })), both]
  });
  assertCoherent(r);
  assert.deepEqual([r.sql.total, r.sql.reviewed, r.sql.pending], [126, 101, 25]);
});

test('matched_ioc_id is not a decision; context-only / body mention / non-IOC never enter the denominator', opts, async () => {
  const r = await runScenario({
    sources: { A: { approved: true } },
    rows: [
      orig({ review_status: 'pending', match_state: 'existing', matched_ioc_id: 4242 }),
      linked(['A'], { review_status: 'pending', match_state: 'existing', matched_ioc_id: 4243 }),
      orig({ review_status: 'pending', assessment: 'context_only', match_state: 'context_only', source_assertion: 'body_mention' }),
      orig({
        review_status: 'pending',
        match_state: 'existing',
        matched_ioc_id: 4244,
        source_assertion: 'body_mention',
        evidence: { ...MODE_A_EVIDENCE, source_assertion: 'body_mention', occurrences: [{ zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }] }
      }),
      orig({ candidate_type: 'cve', normalized_value: 'CVE-2026-0001', is_ioc: false, review_status: 'rejected' }),
      orig({ review_status: 'ignored' }),
      orig({ review_status: 'rejected' }),
      orig({ review_status: 'created_ioc' })
    ]
  });
  assertCoherent(r);
  assert.deepEqual([r.sql.total, r.sql.reviewed, r.sql.pending], [5, 3, 2]);
});

test('Warden-shaped ready report: 70 original (2 overlap) + 3148 linked-only, all decided → 3218/3218', opts, async () => {
  const originals = many(70, () => orig());
  originals.slice(0, 2).forEach((o) => { o.sourceKeys = ['A']; });
  const r = await runScenario({ sources: { A: { approved: true } }, rows: [...originals, ...many(3148, () => linked(['A']))] });
  assertCoherent(r);
  assert.deepEqual([r.sql.total, r.sql.reviewed, r.sql.pending], [3218, 3218, 0]);
  assert.deepEqual([r.sql.original.total, r.sql.linked_only.total, r.sql.overlap], [70, 3148, 2]);
});

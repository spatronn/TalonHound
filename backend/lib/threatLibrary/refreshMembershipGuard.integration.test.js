import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { candidateColumns, createThreatReport, loadSourceLinkedCandidateIds } from './store.js';
import { previewExtractionRefresh } from './extractionRefresh.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildLayoutVariant } from './benchmark/layoutVariants.js';

/**
 * Real-Postgres check of the refresh membership guard's database reads: the
 * linked-source lookup and the read-only preview over stored rows. Every
 * scenario runs in a rolled-back transaction (ALLOW_THREAT_LIBRARY_DB_TESTS=1
 * and a migrated throwaway database).
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

async function insertRow(client, reportId, col) {
  const { rows } = await client.query(
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

test('preview over real rows: a linked reviewed row is kept, an unlinked one is a deletion; nothing is written', opts, async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const variant = buildLayoutVariant('html_c2_then_loaders/table');
    const report = await createThreatReport(client, {
      title: `itest-guard-${crypto.randomUUID()}`,
      source_type: 'url',
      source_url: variant.sourceUrl
    });
    const extracted = extractReportCandidates({ source_type: 'url', source_url: variant.sourceUrl }, variant.document);
    await client.query(`UPDATE threat_reports SET canonical_document = $2::jsonb WHERE id = $1`, [report.id, JSON.stringify(extracted.document)]);
    for (const c of extracted.candidates) await insertRow(client, report.id, candidateColumns(c));
    // Two analyst-approved rows the document no longer produces.
    const template = candidateColumns(extracted.candidates.find((c) => c.candidate_type === 'domain'));
    const linkedId = await insertRow(client, report.id, { ...template, normalized_value: 'linked-kept.example', original_value: 'linked-kept.example', review_status: 'approved' });
    const unlinkedId = await insertRow(client, report.id, { ...template, normalized_value: 'unlinked-gone.example', original_value: 'unlinked-gone.example', review_status: 'approved' });
    const { rows: src } = await client.query(
      `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, lifecycle_status, approved_at)
       VALUES ($1, $2, $2, 'extracted', NOW()) RETURNING id`,
      [report.id, `https://example.test/iocs/${crypto.randomUUID()}`]
    );
    await client.query(
      `INSERT INTO threat_report_candidate_source_links (candidate_id, source_id, source_assertion) VALUES ($1, $2, 'linked_source_ioc')`,
      [linkedId, src[0].id]
    );

    const linked = await loadSourceLinkedCandidateIds(client, [String(linkedId), unlinkedId, null]);
    assert.deepEqual([...linked], [String(linkedId)]);
    assert.equal((await loadSourceLinkedCandidateIds(client, [])).size, 0);

    const { rows: before } = await client.query(`SELECT id, updated_at, has_original_document_occurrence, review_status FROM threat_report_candidates WHERE report_id = $1 ORDER BY id`, [report.id]);
    const { rows: stored } = await client.query(`SELECT * FROM threat_reports WHERE id = $1`, [report.id]);
    const preview = await previewExtractionRefresh(client, stored[0]);
    const { rows: after } = await client.query(`SELECT id, updated_at, has_original_document_occurrence, review_status FROM threat_report_candidates WHERE report_id = $1 ORDER BY id`, [report.id]);
    assert.deepEqual(after, before, 'preview never writes');

    const removed = Object.fromEntries(preview.membership_diff.removed_indicators.map((r) => [r.identity, r]));
    assert.equal(removed['domain:linked-kept.example'].row_outcome, 'original_occurrence_cleared');
    assert.equal(removed['domain:linked-kept.example'].union_member_after, true);
    assert.equal(removed['domain:unlinked-gone.example'].row_outcome, 'deleted');
    assert.deepEqual(preview.membership_diff.reviewed_candidates_deleted.map((d) => d.identity), ['domain:unlinked-gone.example']);
    assert.equal(preview.guard.decision, 'block');
    assert.match(preview.membership_diff.material_fingerprint, /^[a-f0-9]{64}$/);
    assert.equal(preview.ai_invoked, false);
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
});

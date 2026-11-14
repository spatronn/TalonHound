/**
 * Real-Postgres Refresh AI provenance (P1).
 *
 * A publisher assertion can own membership while an applied model label is
 * still evidence. Refresh must keep a grounded label, drop a stale quote,
 * refuse a never-applied label, keep analyst decisions, and stay idempotent.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { createThreatReport, candidateColumns } from './store.js';
import { computeExtractionRefresh } from './extractionRefresh.js';
import { extractReportCandidates as extract } from './extractionStages.js';
import { isReportIndicatorMember } from './indicatorMembership.js';

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

function fixtureDocument() {
  const table = createTableBlock({
    id: 't1',
    headers: ['Indicator', 'Context'],
    rows: [
      ['157.20.241.16', 'C2'],
      ['relay-upstream.info', 'Loader host']
    ]
  });
  return createCanonicalDocument({
    title: 'P1 AI provenance fixture',
    blocks: [
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators' },
      table,
      {
        id: 'narr',
        type: 'paragraph',
        text: 'During staging the sample also contacted refused-label.example before the operator blocked it.'
      }
    ],
    meta: { source_url: 'https://research.example/p1-ai-provenance/' }
  });
}

async function insertRow(client, reportId, col) {
  const { rows } = await client.query(
    `INSERT INTO threat_report_candidates (
       report_id, candidate_type, original_value, normalized_value, assessment, role, confidence,
       evidence_text, section, block_id, review_status, match_state, is_ioc, source_assertion,
       evidence, has_original_document_occurrence
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16)
     RETURNING id, candidate_type, normalized_value, assessment, role, review_status, evidence, evidence_text, section, block_id, confidence`,
    [
      reportId, col.candidate_type, col.original_value, col.normalized_value, col.assessment, col.role, col.confidence,
      col.evidence_text, col.section, col.block_id, col.review_status, col.match_state, col.is_ioc, col.source_assertion,
      JSON.stringify(col.evidence), col.has_original_document_occurrence !== false
    ]
  );
  return rows[0];
}

test('Refresh keeps grounded AI labels, drops stale ones, refuses applied=false, keeps analyst decisions, and is idempotent', opts, async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const document = fixtureDocument();
    const report = await createThreatReport(client, {
      title: `itest-p1-ai-${crypto.randomUUID()}`,
      source_type: 'url',
      source_url: document.meta.source_url
    });
    await client.query(`UPDATE threat_reports SET canonical_document = $2::jsonb WHERE id = $1`, [report.id, JSON.stringify(document)]);

    const extracted = extract({ source_type: 'url', source_url: document.meta.source_url }, document);
    const byValue = new Map(extracted.candidates.map((c) => [c.normalized_value, c]));
    assert.equal(isReportIndicatorMember(byValue.get('157.20.241.16')), true);
    assert.equal(isReportIndicatorMember(byValue.get('relay-upstream.info')), true);

    const ip = byValue.get('157.20.241.16');
    const domain = byValue.get('relay-upstream.info');

    // Deterministic publisher assertion that still carries an applied model label.
    const ipCol = candidateColumns({
      ...ip,
      decision_source: 'deterministic',
      ai_classification: {
        assessment: 'malicious',
        role: 'command_and_control',
        confidence: 0.91,
        applied: true,
        supported: true
      }
    });
    ipCol.evidence = {
      ...ipCol.evidence,
      decision_source: 'deterministic',
      policy_decision: 'explicit_report_assertion',
      ai_classification: {
        assessment: 'malicious',
        role: 'command_and_control',
        confidence: 0.91,
        applied: true,
        supported: true
      }
    };

    // Analyst Context Only on a value the publisher still asserts: the
    // analyst decision wins membership across refresh.
    const analystCol = candidateColumns({
      ...domain,
      assessment: 'context_only',
      role: 'reference',
      match_state: 'context_only',
      review_status: 'context_only',
      source_assertion: 'body_mention'
    });
    analystCol.evidence = {
      ...analystCol.evidence,
      decision_source: 'analyst',
      policy_decision: 'analyst_context_only',
      promoted_from: {
        assessment: 'malicious',
        role: 'command_and_control',
        decision_source: 'deterministic',
        match_state: 'new'
      }
    };

    const refusedBase = byValue.get('refused-label.example');
    assert.ok(refusedBase, 'refused-label.example is extractable as a narrative mention');
    assert.equal(isReportIndicatorMember(refusedBase), false);
    const refusedCol = candidateColumns({
      ...refusedBase,
      assessment: 'unknown',
      role: 'unknown',
      match_state: 'needs_review'
    });
    refusedCol.evidence = {
      ...refusedCol.evidence,
      decision_source: 'deterministic',
      policy_decision: 'ai_needed_authoritative_narrative',
      ai_classification: {
        assessment: 'malicious',
        role: 'command_and_control',
        applied: false,
        supported: false
      }
    };

    const ipRow = await insertRow(client, report.id, ipCol);
    const analystRow = await insertRow(client, report.id, analystCol);
    await insertRow(client, report.id, refusedCol);

    const previousRows = (await client.query(
      `SELECT * FROM threat_report_candidates WHERE report_id = $1 ORDER BY id`,
      [report.id]
    )).rows;

    const first = await computeExtractionRefresh(client, {
      report: { ...report, canonical_document: document },
      document,
      previousRows,
      documentRebuilt: false
    });
    const firstIp = first.candidates.find((c) => c.normalized_value === '157.20.241.16');
    const firstRefused = first.candidates.find((c) => c.normalized_value === 'refused-label.example');
    const firstAnalyst = first.candidates.find((c) => c.normalized_value === analystRow.normalized_value);

    assert.equal(isReportIndicatorMember(firstIp), true);
    assert.equal(firstIp.membership_decision.rule_id, 'R10_publisher_assertion');
    assert.equal(firstIp.membership_decision.inputs.model_assessment, 'malicious');
    assert.equal(firstIp.ai_classification.applied, true);
    assert.equal(firstIp.ai_classification.stale, undefined);

    assert.ok(firstRefused);
    assert.equal(isReportIndicatorMember(firstRefused), false);
    assert.notEqual(firstRefused.ai_classification?.applied, true);

    assert.ok(firstAnalyst);
    assert.equal(firstAnalyst.review_status, 'context_only');
    assert.equal(firstAnalyst.assessment, 'context_only');
    assert.equal(isReportIndicatorMember(firstAnalyst), false);

    // Second refresh with the same rows: idempotent membership and label.
    const second = await computeExtractionRefresh(client, {
      report: { ...report, canonical_document: document },
      document,
      previousRows,
      documentRebuilt: false
    });
    const secondIp = second.candidates.find((c) => c.normalized_value === '157.20.241.16');
    assert.equal(isReportIndicatorMember(secondIp), true);
    assert.equal(secondIp.membership_decision.inputs.model_assessment, 'malicious');
    assert.deepEqual(
      first.candidates.filter((c) => isReportIndicatorMember(c)).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort(),
      second.candidates.filter((c) => isReportIndicatorMember(c)).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort()
    );

    // Stale quote: evidence_text no longer in the document → label dropped, membership stays.
    const staleRows = previousRows.map((row) => (
      row.normalized_value === '157.20.241.16'
        ? { ...row, evidence_text: 'this fabricated quote names 157.20.241.16 but is not in the document' }
        : row
    ));
    const stale = await computeExtractionRefresh(client, {
      report: { ...report, canonical_document: document },
      document,
      previousRows: staleRows,
      documentRebuilt: false
    });
    const staleIp = stale.candidates.find((c) => c.normalized_value === '157.20.241.16');
    assert.equal(isReportIndicatorMember(staleIp), true);
    assert.equal(staleIp.membership_decision.rule_id, 'R10_publisher_assertion');
    assert.equal(staleIp.membership_decision.inputs.model_assessment, null);
    assert.equal(staleIp.ai_classification.applied, false);
    assert.equal(staleIp.ai_classification.stale, true);
    assert.equal(staleIp.ai_classification.assessment, 'malicious');

    assert.equal(ipRow.id != null, true);
    await client.query('ROLLBACK');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
});

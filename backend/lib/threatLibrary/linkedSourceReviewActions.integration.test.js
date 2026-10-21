import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { applyCandidateReviewActions, finalizeReport } from './reviewService.js';
import { createThreatReport } from './store.js';
import { linkedSourceIndicatorMembershipSql, reviewActionableIndicatorSql } from './indicatorMembership.js';

/**
 * Real-Postgres regression for linked-source membership that rests only on
 * `threat_report_candidate_source_links` (30305 candidate 13702 shape): an
 * original MODE A body mention, not an original Indicator, that an approved
 * linked IOC Source also lists. Approve, Create IOCs and Finalize must all
 * treat it as a union Indicator. Each case runs in a rolled-back transaction.
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

const MODE_A_BODY_MENTION = {
  document_has_authoritative_scope: true,
  source_assertion: 'body_mention',
  is_direct_source_observable: true,
  occurrences: [{ zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }]
};

async function withLinkOnlyRow(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const report = await createThreatReport(client, {
      title: `itest-${crypto.randomUUID()}`,
      source_type: 'url',
      analysis_status: 'review_required'
    });
    const url = `https://example.test/pack/${crypto.randomUUID()}`;
    const { rows: [source] } = await client.query(
      `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, lifecycle_status, approved_at)
       VALUES ($1, $2, $2, 'extracted', NOW()) RETURNING id`,
      [report.id, url]
    );
    const insert = (value, linked) => client.query(
      `INSERT INTO threat_report_candidates (
         report_id, candidate_type, original_value, normalized_value, assessment, review_status,
         match_state, is_ioc, source_assertion, evidence, has_original_document_occurrence
       ) VALUES ($1, 'ip', $2, $2, 'malicious', 'pending', 'new', true, 'body_mention', $3::jsonb, true)
       RETURNING id`,
      [report.id, value, JSON.stringify(MODE_A_BODY_MENTION)]
    ).then(async ({ rows: [row] }) => {
      if (linked) {
        // A link row id that differs from the candidate id, so a bare `id`
        // bound to `lsl.id` would not match by accident.
        await client.query(`SELECT nextval('threat_report_candidate_source_links_id_seq') FROM generate_series(1, 7)`);
        await client.query(
          `INSERT INTO threat_report_candidate_source_links (candidate_id, source_id, source_assertion)
           VALUES ($1, $2, 'linked_source_ioc')`,
          [row.id, source.id]
        );
      }
      return Number(row.id);
    });
    const linkedId = await insert('198.51.100.7', true);
    const narrativeId = await insert('198.51.100.8', false);
    return await fn({ client, report, linkedId, narrativeId });
  } finally {
    await client.query('ROLLBACK').catch(() => {});
    client.release();
  }
}

test('unaliased and aliased linked-source SQL agree on a link-table-only row', opts, async () => {
  await withLinkOnlyRow(async ({ client, report, linkedId, narrativeId }) => {
    const { rows } = await client.query(
      `SELECT id,
              (${linkedSourceIndicatorMembershipSql('c')}) AS aliased,
              (SELECT (${reviewActionableIndicatorSql('')}) FROM threat_report_candidates WHERE id = c.id) AS unaliased
       FROM threat_report_candidates c WHERE c.report_id = $1 ORDER BY id`,
      [report.id]
    );
    const byId = Object.fromEntries(rows.map((r) => [Number(r.id), r]));
    assert.equal(byId[linkedId].aliased, true);
    assert.equal(byId[linkedId].unaliased, true);
    assert.equal(byId[narrativeId].aliased, false);
    assert.equal(byId[narrativeId].unaliased, false);
  });
});

test('link-table-only Indicator blocks Finalize, is approved, and is creatable', opts, async () => {
  await withLinkOnlyRow(async ({ client, report, linkedId, narrativeId }) => {
    const blocked = await finalizeReport(client, report.id);
    assert.equal(blocked.ok, false);
    assert.equal(blocked.code, 'pending_review_remaining');
    assert.equal(blocked.pending_count, 1, 'only the linked row is a pending Indicator');

    const approved = await applyCandidateReviewActions(client, report.id, {
      action: 'approve',
      candidateIds: [linkedId, narrativeId]
    });
    assert.equal(approved.ok, true);
    assert.equal(approved.updated, 1);
    assert.equal(approved.skipped_context_only, 1, 'the MODE A narrative row stays out');
    const { rows } = await client.query(
      `SELECT id, review_status FROM threat_report_candidates WHERE report_id = $1 ORDER BY id`,
      [report.id]
    );
    const status = Object.fromEntries(rows.map((r) => [Number(r.id), r.review_status]));
    assert.equal(status[linkedId], 'approved');
    assert.equal(status[narrativeId], 'pending');

    const preview = await applyCandidateReviewActions(client, report.id, {
      action: 'create_iocs',
      candidateIds: [linkedId]
    });
    assert.equal(preview.ok, true);
    assert.equal(preview.preview, true);
    assert.equal(preview.summary.eligible, 1);
    assert.equal(preview.results[0].outcome, 'will_create');

    const finalized = await finalizeReport(client, report.id);
    assert.equal(finalized.ok, true);
  });
});

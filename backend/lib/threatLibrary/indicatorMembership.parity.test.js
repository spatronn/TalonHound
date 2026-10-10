/**
 * Cross-layer parity: frontend isReviewIndicator / isContextOnlyCandidate,
 * backend isReportIndicatorMember / isActionableReviewIndicator, and the SQL
 * predicates produced by indicatorMembership must agree on every fixture case.
 *
 * If you change membership semantics in one place and forget another, this
 * suite fails.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import pg from 'pg';
import {
  membershipParityCases,
  isReportIndicatorMember,
  isActionableReviewIndicator,
  isContextOnlyCandidate,
  isPendingReviewActionableIndicator,
  isReviewActionableIndicator,
  isUnionReportIndicatorMember,
  reportIndicatorMembershipSql,
  isContextOnlySql,
  countCandidateBuckets,
  publisherAuthoritativeIocMembershipSql
} from './indicatorMembership.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const { existsSync } = await import('node:fs');
const frontendCandidates = [
  // Optional: docker-cp / image-local fixture (backend container has no frontend tree)
  path.resolve(here, '../../test-fixtures/candidateReview.frontend.js'),
  // Monorepo checkout (agent workstation / source tree with backend+frontend)
  path.resolve(here, '../../../../frontend/src/components/threatLibrary/candidateReview.js'),
  // Host deploy tree when tests run on the metal rather than inside the image
  '/opt/TalonHound/frontend/src/components/threatLibrary/candidateReview.js'
].filter((p) => existsSync(p));

if (!frontendCandidates.length) {
  throw new Error(
    'frontend candidateReview.js not found for parity import; place it at frontend/src/... or docker-cp to /app/test-fixtures/candidateReview.frontend.js'
  );
}

const frontend = await import(pathToFileURL(frontendCandidates[0]).href);

test('parity matrix: frontend == backend JS for every membership branch', () => {
  for (const row of membershipParityCases()) {
    const { candidate, expect } = row;
    assert.equal(frontend.isReviewIndicator(candidate), expect.member, `${row.id} FE member`);
    assert.equal(isReportIndicatorMember(candidate), expect.member, `${row.id} BE member`);
    assert.equal(isActionableReviewIndicator(candidate), expect.member, `${row.id} BE alias`);
    assert.equal(frontend.isReportIndicatorMember(candidate), expect.member, `${row.id} FE alias`);
    assert.equal(frontend.isContextOnlyCandidate(candidate), expect.context_only, `${row.id} FE context`);
    assert.equal(isContextOnlyCandidate(candidate), expect.context_only, `${row.id} BE context`);
    assert.equal(
      isPendingReviewActionableIndicator(candidate),
      expect.pending_actionable,
      `${row.id} pending actionable`
    );
    assert.equal(
      isReviewActionableIndicator(candidate),
      isUnionReportIndicatorMember(candidate),
      `${row.id} review actionable == union`
    );
    assert.equal(
      frontend.isReviewActionableIndicator(candidate),
      isReviewActionableIndicator(candidate),
      `${row.id} FE/BE review actionable`
    );
  }
});

test('MODE A body_mention malicious is not a member; MODE B narrative is; narrative+explicit collapses to member', () => {
  const cases = Object.fromEntries(membershipParityCases().map((c) => [c.id, c]));
  assert.equal(isReportIndicatorMember(cases.mode_a_body_mention_malicious.candidate), false);
  assert.equal(frontend.isReviewIndicator(cases.mode_a_body_mention_malicious.candidate), false);
  assert.equal(isReportIndicatorMember(cases.mode_a_body_mention_matched_existing.candidate), false);
  assert.equal(isReportIndicatorMember(cases.mode_b_narrative_malicious.candidate), true);
  assert.equal(frontend.isReviewIndicator(cases.mode_b_narrative_malicious.candidate), true);
  assert.equal(isReportIndicatorMember(cases.mode_a_narrative_plus_explicit_occurrence.candidate), true);
  assert.equal(isReportIndicatorMember(cases.member_approved_not_pending.candidate), true);
  assert.equal(isPendingReviewActionableIndicator(cases.member_approved_not_pending.candidate), false);
});

test('countCandidateBuckets separates All / Indicators / Context Only', () => {
  const list = membershipParityCases().map((c) => c.candidate);
  const buckets = countCandidateBuckets(list);
  assert.equal(buckets.all, list.length);
  assert.equal(buckets.indicators, list.filter((c) => isReportIndicatorMember(c)).length);
  assert.equal(buckets.context_only, list.filter((c) => isContextOnlyCandidate(c)).length);
  assert.ok(buckets.indicators < buckets.all, 'membership is a subset of All');
});

test('SQL predicates agree with JS on an ephemeral table (behavioural, not string compare)', async () => {
  const pool = new pg.Pool({
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 5432),
    database: process.env.DB_NAME || 'talonhound',
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD || process.env.POSTGRES_PASSWORD || 'talonhound'
  });
  let client;
  try {
    client = await pool.connect();
  } catch (err) {
    console.log(JSON.stringify({ skipped_sql_parity: true, reason: err.code || err.message }));
    await pool.end().catch(() => {});
    return;
  }
  try {
    await client.query('BEGIN');
    await client.query(`
      CREATE TEMP TABLE membership_parity_rows (
        id text PRIMARY KEY,
        candidate_type text,
        is_ioc boolean,
        assessment text,
        match_state text,
        review_status text,
        source_assertion text,
        has_original_document_occurrence boolean NOT NULL DEFAULT true,
        evidence jsonb
      ) ON COMMIT DROP`);

    for (const row of membershipParityCases()) {
      const c = row.candidate;
      await client.query(
        `INSERT INTO membership_parity_rows
           (id, candidate_type, is_ioc, assessment, match_state, review_status, source_assertion,
            has_original_document_occurrence, evidence)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          row.id,
          c.candidate_type,
          c.is_ioc !== false,
          c.assessment ?? null,
          c.match_state ?? null,
          c.review_status ?? 'pending',
          c.source_assertion ?? null,
          c.has_original_document_occurrence !== false,
          JSON.stringify({
            ...(c.evidence || {}),
            document_has_authoritative_scope: c.document_has_authoritative_scope === true
              || c.evidence?.document_has_authoritative_scope === true
          })
        ]
      );
    }

    const memberSql = reportIndicatorMembershipSql('c');
    const contextSql = isContextOnlySql('c');
    const { rows } = await client.query(`
      SELECT id,
             (${memberSql}) AS sql_member,
             (${contextSql}) AS sql_context
      FROM membership_parity_rows c
      ORDER BY id`);

    const byId = Object.fromEntries(membershipParityCases().map((c) => [c.id, c]));
    for (const r of rows) {
      const expect = byId[r.id].expect;
      const candidate = byId[r.id].candidate;
      assert.equal(r.sql_member, expect.member, `${r.id} SQL member vs expect`);
      assert.equal(r.sql_member, isReportIndicatorMember(candidate), `${r.id} SQL vs JS member`);
      assert.equal(r.sql_context, expect.context_only, `${r.id} SQL context vs expect`);
      assert.equal(r.sql_context, isContextOnlyCandidate(candidate), `${r.id} SQL vs JS context`);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
});

test('publisherAuthoritativeIocMembershipSql is composed into reportIndicatorMembershipSql', () => {
  const sql = reportIndicatorMembershipSql('c');
  assert.match(sql, /explicit_ioc/);
  assert.match(sql, /document_has_authoritative_scope/);
  assert.match(sql, /non_actionable_local/);
  assert.match(sql, /explicit_operational_infrastructure/);
  assert.match(sql, /jsonb_array_elements/);
  assert.equal(typeof publisherAuthoritativeIocMembershipSql('c'), 'string');
});

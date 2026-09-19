/**
 * Context Only != IOC candidate: backend safety rule for the review actions.
 *
 * The fake pool here is stateful: it applies the review UPDATEs to the
 * in-memory rows so that each test proves the resulting state, not just the
 * SQL text.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { applyCandidateReviewActions } from './reviewService.js';
import {
  classifyPromoteEligibility,
  isActionableReviewIndicator,
  isContextOnlyCandidate,
  NOT_CONTEXT_ONLY_SQL
} from './promotion.js';
import { buildReviewAuditEvent } from './audit.js';
import { AUDIT_ACTION } from '../auditConstants.js';

const REPORT = { id: 9, public_id: 'rep-1', title: 'Illegal Gambling Sites', analysis_status: 'review_required', source_url: null };

function isCtx(c) {
  return ['assessment', 'match_state', 'review_status'].some((k) => String(c[k] || '') === 'context_only');
}

/** Stateful fake: SELECTs read rows, review UPDATEs mutate them like the real SQL would. */
function statefulPool(report, candidates, { sourceId = 4 } = {}) {
  const rows = candidates.map((c) => ({ ...c, evidence: c.evidence || {} }));
  const writes = [];
  const byIds = (ids) => rows.filter((r) => ids.map(Number).includes(Number(r.id)));
  return {
    rows,
    writes,
    async query(sql, params) {
      if (/FROM threat_reports WHERE id = \$1/.test(sql) && /^\s*SELECT/i.test(sql)) {
        return { rows: report ? [report] : [] };
      }
      if (/^\s*SELECT/i.test(sql) && /FROM threat_report_candidates/.test(sql)) {
        if (/assessment = 'malicious'/.test(sql)) {
          // approve_high_confidence_malicious candidate set (mirrors the SQL predicates)
          const threshold = Number(params[1]);
          return {
            rows: rows.filter((r) => r.assessment === 'malicious'
              && r.confidence != null && Number(r.confidence) >= threshold
              && String(r.review_status || 'pending') === 'pending'
              && r.is_ioc !== false
              && !isCtx(r))
          };
        }
        const ids = Array.isArray(params?.[1]) ? params[1] : null;
        // Snapshots, like a real result set: later UPDATEs must not rewrite them.
        return { rows: (ids ? byIds(ids) : rows).map((r) => ({ ...r })) };
      }
      if (/FROM ioc_sources WHERE name/.test(sql)) return { rows: sourceId ? [{ id: sourceId }] : [] };
      writes.push({ sql, params });
      if (/^\s*UPDATE threat_report_candidates/.test(sql)) {
        if (/review_status = 'approved',\s*assessment = 'suspicious'/.test(sql)) {
          const row = rows.find((r) => Number(r.id) === Number(params[1]));
          if (!row) return { rows: [], rowCount: 0 };
          row.review_status = 'approved';
          row.assessment = 'suspicious';
          if (['reference', 'legitimate_service', 'hosting_platform'].includes(row.role)) row.role = 'unknown';
          row.is_ioc = true;
          row.match_state = row.matched_ioc_id ? 'existing' : 'new';
          row.evidence = { ...(row.evidence || {}), ...JSON.parse(params[2]) };
          return { rows: [row], rowCount: 1 };
        }
        if (/SET review_status = 'approved'/.test(sql)) {
          const guarded = sql.includes(NOT_CONTEXT_ONLY_SQL.trim().split('\n')[0].trim());
          const targets = byIds(params[1]).filter((r) => r.is_ioc !== false && (!guarded || !isCtx(r)));
          targets.forEach((r) => { r.review_status = 'approved'; });
          return { rows: [], rowCount: targets.length };
        }
        if (/review_status = 'context_only'/.test(sql)) {
          const targets = byIds(params[1]);
          targets.forEach((r) => { r.review_status = 'context_only'; r.assessment = 'context_only'; r.match_state = 'context_only'; });
          return { rows: [], rowCount: targets.length };
        }
        if (/review_status = 'ignored'/.test(sql)) {
          const targets = byIds(params[1]);
          targets.forEach((r) => { r.review_status = 'ignored'; });
          return { rows: [], rowCount: targets.length };
        }
        if (/promotion_outcome = \$3/.test(sql)) {
          const row = rows.find((r) => Number(r.id) === Number(params[1]));
          if (row) {
            row.promotion_outcome = params[2];
            row.promotion_detail = params[3];
            if (params[4] != null) { row.matched_ioc_id = params[4]; row.match_state = 'existing'; }
          }
          return { rows: [], rowCount: row ? 1 : 0 };
        }
      }
      return { rows: [], rowCount: 0 };
    }
  };
}

function iocCandidate(overrides) {
  return {
    id: 1,
    candidate_type: 'domain',
    original_value: 'evil.example',
    normalized_value: 'evil.example',
    assessment: 'malicious',
    review_status: 'pending',
    match_state: 'new',
    matched_ioc_id: null,
    confidence: 0.95,
    role: 'c2',
    is_ioc: true,
    section: 'report_body',
    evidence: {
      occurrences: [{ zone: 'explicit_ioc_section', section_kind: 'explicit_ioc_section', form: 'standalone' }],
      occurrence_count: 1,
      zones: ['explicit_ioc_section']
    },
    ...overrides
  };
}

/** Pipeline-shaped Context Only row (reference / legitimate service): review_status stays pending. */
function contextOnlyCandidate(overrides) {
  return iocCandidate({
    id: 2,
    normalized_value: 'amazon.com',
    original_value: 'amazon.com',
    assessment: 'context_only',
    match_state: 'context_only',
    review_status: 'pending',
    role: 'legitimate_service',
    confidence: 0.75,
    evidence: { policy_decision: 'context_only_provider_service', decision_source: 'deterministic', occurrences: [{ zone: 'report_body', form: 'standalone' }] },
    ...overrides
  });
}

function fakeAudit() {
  const events = [];
  return { events, auditLog: async (ev) => { events.push(ev); } };
}

test('isContextOnlyCandidate: any of the three review fields makes the row context-only', () => {
  assert.equal(isContextOnlyCandidate(contextOnlyCandidate()), true);
  assert.equal(isContextOnlyCandidate(iocCandidate({ review_status: 'context_only' })), true);
  assert.equal(isContextOnlyCandidate(iocCandidate({ match_state: 'context_only' })), true);
  assert.equal(isContextOnlyCandidate(iocCandidate({ assessment: 'context_only' })), true);
  assert.equal(isContextOnlyCandidate(iocCandidate()), false);
  assert.equal(isContextOnlyCandidate(iocCandidate({ review_status: 'approved' })), false);
  // Half-state left by the old Approve (review approved, assessment still context) stays context-only.
  assert.equal(isContextOnlyCandidate(contextOnlyCandidate({ review_status: 'approved' })), true);
  assert.equal(isActionableReviewIndicator(contextOnlyCandidate()), false);
});

test('Approve on a mixed selection approves only IOC candidates; context-only rows are skipped and reported', async () => {
  const pool = statefulPool(REPORT, [iocCandidate({ id: 1 }), contextOnlyCandidate({ id: 2 }), iocCandidate({ id: 3, candidate_type: 'ip', normalized_value: '1.2.3.4' })]);
  const audit = fakeAudit();
  const result = await applyCandidateReviewActions(pool, 9, { action: 'approve', candidateIds: [1, 2, 3], audit, user: { email: 'a@b' } });
  assert.equal(result.ok, true);
  assert.equal(result.updated, 2);
  assert.equal(result.skipped_context_only, 1);
  assert.equal(pool.rows.find((r) => r.id === 1).review_status, 'approved');
  assert.equal(pool.rows.find((r) => r.id === 3).review_status, 'approved');
  const ctx = pool.rows.find((r) => r.id === 2);
  assert.equal(ctx.review_status, 'pending', 'context-only row never becomes approved');
  assert.equal(ctx.assessment, 'context_only');
  assert.equal(ctx.match_state, 'context_only');
  const approveSql = pool.writes.find((w) => /review_status = 'approved'/.test(w.sql)).sql;
  assert.match(approveSql, /assessment, ''\) <> 'context_only'/, 'SQL guard, not only a JS filter');
  assert.match(approveSql, /match_state, ''\) <> 'context_only'/);
  assert.match(approveSql, /review_status, ''\) <> 'context_only'/);
  assert.equal(audit.events.length, 1);
  assert.equal(audit.events[0].action, AUDIT_ACTION.THREAT_LIBRARY_CANDIDATES_APPROVED);
  assert.equal(audit.events[0].metadata.changed, 2, 'skipped rows are not counted as changed');
  assert.equal(audit.events[0].metadata.already_in_state, 0);
  assert.equal(audit.events[0].metadata.skipped_context_only, 1);
  assert.equal(audit.events[0].metadata.matched, 3);
});

test('Approve with only context-only rows selected changes nothing (updated 0)', async () => {
  const pool = statefulPool(REPORT, [contextOnlyCandidate({ id: 2 }), contextOnlyCandidate({ id: 4, normalized_value: 'trustpilot.com', role: 'reference' })]);
  const result = await applyCandidateReviewActions(pool, 9, { action: 'approve', candidateIds: [2, 4] });
  assert.equal(result.ok, true);
  assert.equal(result.updated, 0);
  assert.equal(result.skipped_context_only, 2);
  assert.ok(pool.rows.every((r) => r.review_status === 'pending' && r.assessment === 'context_only'));
});

test('Create IOCs never materializes a context-only row, even when sent directly with confirm', async () => {
  const pool = statefulPool(REPORT, [contextOnlyCandidate({ id: 2 }), contextOnlyCandidate({ id: 4, normalized_value: 'trustpilot.com', role: 'reference', review_status: 'approved' })]);
  let created = 0;
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [2, 4],
    confirm: true,
    createIoc: async () => { created += 1; return { status: 201, body: { id: 1 } }; },
    findExistingIoc: async () => null
  });
  assert.equal(result.ok, false);
  assert.equal(result.status, 409);
  assert.equal(result.code, 'create_iocs_none_eligible');
  assert.equal(result.summary.not_applicable, 2);
  assert.equal(created, 0);
  assert.equal(pool.writes.length, 0, 'no promotion rows written');
});

test('Create IOCs on a mixed selection creates the IOC candidate only; context-only row is not_applicable', async () => {
  const pool = statefulPool(REPORT, [iocCandidate({ id: 1, review_status: 'approved' }), contextOnlyCandidate({ id: 2 })]);
  const createdValues = [];
  const preview = await applyCandidateReviewActions(pool, 9, { action: 'create_iocs', candidateIds: [1, 2], confirm: false });
  assert.equal(preview.ok, true);
  assert.equal(preview.summary.eligible, 1);
  assert.equal(preview.summary.not_applicable, 1);
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [1, 2],
    confirm: true,
    createIoc: async (_pool, body) => { createdValues.push(body.observable); return { status: 201, body: { id: 501, public_id: 'ioc-501', observable_type: 'domain' } }; },
    findExistingIoc: async () => null
  });
  assert.equal(result.ok, true);
  assert.deepEqual(createdValues, ['evil.example']);
  assert.equal(result.summary.created, 1);
  assert.equal(result.summary.not_applicable, 1);
  assert.equal(result.results.find((r) => r.candidate_id === 2).outcome, 'not_applicable');
  assert.equal(pool.rows.find((r) => r.id === 2).matched_ioc_id, null);
});

test('Approve high-confidence malicious never includes context-only or non-IOC rows (SQL + canonical filter)', async () => {
  const pool = statefulPool(REPORT, [
    iocCandidate({ id: 1 }),
    // context-only rows that still carry a malicious assessment / high confidence must be excluded by the other fields
    iocCandidate({ id: 2, normalized_value: 'amazon.com', match_state: 'context_only' }),
    iocCandidate({ id: 3, normalized_value: 'trustpilot.com', review_status: 'context_only' }),
    iocCandidate({ id: 4, normalized_value: 'mitre.org', assessment: 'context_only' }),
    iocCandidate({ id: 5, normalized_value: 'ref.example', is_ioc: false }),
    iocCandidate({ id: 6, normalized_value: 'low.example', confidence: 0.5 })
  ]);
  const result = await applyCandidateReviewActions(pool, 9, { action: 'approve_high_confidence_malicious' });
  assert.equal(result.ok, true);
  assert.equal(result.updated, 1);
  const selectSql = pool.writes.find((w) => /review_status = 'approved'/.test(w.sql));
  assert.deepEqual(selectSql.params[1], [1], 'only the real high-confidence IOC candidate is approved');
  assert.equal(pool.rows.find((r) => r.id === 1).review_status, 'approved');
  for (const id of [2, 3, 4, 5, 6]) assert.notEqual(pool.rows.find((r) => r.id === id).review_status, 'approved', `row ${id}`);
});

test('Approve high-confidence malicious with no eligible rows is a clean no-op', async () => {
  const pool = statefulPool(REPORT, [contextOnlyCandidate({ id: 2, assessment: 'malicious', confidence: 0.99 })]);
  const result = await applyCandidateReviewActions(pool, 9, { action: 'approve_high_confidence_malicious' });
  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.equal(pool.writes.length, 0);
  assert.equal(pool.rows[0].review_status, 'pending');
});

test('Ignore and Context only remain available for context-only rows', async () => {
  const pool = statefulPool(REPORT, [contextOnlyCandidate({ id: 2 }), iocCandidate({ id: 1 })]);
  const ignored = await applyCandidateReviewActions(pool, 9, { action: 'ignore', candidateIds: [2] });
  assert.equal(ignored.ok, true);
  assert.equal(ignored.updated, 1);
  assert.equal(pool.rows.find((r) => r.id === 2).review_status, 'ignored');
  const ctx = await applyCandidateReviewActions(pool, 9, { action: 'context_only', candidateIds: [1] });
  assert.equal(ctx.ok, true);
  const row = pool.rows.find((r) => r.id === 1);
  assert.equal(row.review_status, 'context_only');
  assert.equal(row.assessment, 'context_only');
  assert.equal(row.match_state, 'context_only');
});

test('Normal IOC candidate workflow is unchanged: approve then create', async () => {
  const pool = statefulPool(REPORT, [iocCandidate({ id: 1 })]);
  const approved = await applyCandidateReviewActions(pool, 9, { action: 'approve', candidateIds: [1] });
  assert.equal(approved.ok, true);
  assert.equal(approved.updated, 1);
  assert.equal(approved.skipped_context_only, 0);
  const createdValues = [];
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [1],
    confirm: true,
    createIoc: async (_pool, body) => { createdValues.push(body.observable); return { status: 201, body: { id: 501, public_id: 'ioc-501', observable_type: 'domain' } }; },
    findExistingIoc: async () => null
  });
  assert.equal(result.ok, true);
  assert.deepEqual(createdValues, ['evil.example']);
  assert.equal(result.summary.created, 1);
});

test('promote_to_ioc: single context-only row is re-classified and created through the normal Create IOCs path', async () => {
  const pool = statefulPool(REPORT, [contextOnlyCandidate({ id: 2 })]);
  const audit = fakeAudit();
  const createdBodies = [];
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'promote_to_ioc',
    candidateIds: [2],
    audit,
    user: { email: 'analyst@example.test' },
    createIoc: async (_pool, body) => { createdBodies.push(body); return { status: 201, body: { id: 777, public_id: 'ioc-777', observable_type: 'domain' } }; },
    findExistingIoc: async () => null
  });
  assert.equal(result.ok, true);
  assert.equal(result.promoted, true);
  assert.equal(result.candidate_id, 2);
  assert.equal(result.summary.created, 1);
  assert.equal(result.results[0].outcome, 'created');
  assert.equal(createdBodies.length, 1);
  assert.equal(createdBodies[0].observable, 'amazon.com');
  assert.equal(createdBodies[0].confidence, 'medium');
  const row = pool.rows[0];
  assert.equal(row.review_status, 'approved');
  assert.equal(row.assessment, 'suspicious');
  assert.equal(row.role, 'unknown');
  assert.equal(row.is_ioc, true);
  assert.equal(row.match_state, 'existing', 'linked to the created record');
  assert.equal(row.matched_ioc_id, 777);
  assert.equal(row.promotion_outcome, 'created');
  assert.equal(row.evidence.promoted_from.assessment, 'context_only');
  assert.equal(row.evidence.promoted_from.policy_decision, 'context_only_provider_service');
  assert.equal(row.evidence.promoted_from.promoted_by, 'analyst@example.test');
  assert.equal(row.evidence.policy_decision, 'analyst_promoted_from_context_only');
  assert.equal(isContextOnlyCandidate(row), false);
  assert.deepEqual(audit.events.map((e) => e.action), [
    AUDIT_ACTION.THREAT_LIBRARY_CANDIDATES_PROMOTED,
    AUDIT_ACTION.THREAT_LIBRARY_IOCS_CREATED
  ]);
  assert.equal(audit.events[0].metadata.target_state, 'approved');
  assert.deepEqual(audit.events[0].metadata.candidate_ids, [2]);
});

test('promote_to_ioc links an already existing IOC record instead of duplicating it', async () => {
  const pool = statefulPool(REPORT, [contextOnlyCandidate({ id: 2 })]);
  let created = 0;
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'promote_to_ioc',
    candidateIds: [2],
    createIoc: async () => { created += 1; return { status: 201, body: { id: 1 } }; },
    findExistingIoc: async () => ({ id: 55, public_id: 'ioc-55', observable_type: 'domain' })
  });
  assert.equal(result.ok, true);
  assert.equal(created, 0);
  assert.equal(result.summary.already_existing, 1);
  assert.equal(pool.rows[0].matched_ioc_id, 55);
  assert.equal(pool.rows[0].review_status, 'approved');
});

test('promote_to_ioc is single-row only and refuses non-context-only or unsupported rows', async () => {
  const pool = statefulPool(REPORT, [
    contextOnlyCandidate({ id: 2 }),
    contextOnlyCandidate({ id: 3, normalized_value: 'trustpilot.com' }),
    iocCandidate({ id: 1 }),
    contextOnlyCandidate({ id: 4, candidate_type: 'cidr', normalized_value: '10.0.0.0/8' }),
    contextOnlyCandidate({ id: 5, candidate_type: 'attack_technique', normalized_value: 'T1059', is_ioc: false })
  ]);
  const createIoc = async () => { throw new Error('must not be called'); };
  const bulk = await applyCandidateReviewActions(pool, 9, { action: 'promote_to_ioc', candidateIds: [2, 3], createIoc });
  assert.equal(bulk.ok, false);
  assert.equal(bulk.status, 400);
  assert.equal(bulk.code, 'promote_single_row_only');
  const notCtx = await applyCandidateReviewActions(pool, 9, { action: 'promote_to_ioc', candidateIds: [1], createIoc });
  assert.equal(notCtx.ok, false);
  assert.equal(notCtx.status, 409);
  assert.equal(notCtx.code, 'promote_not_context_only');
  const cidr = await applyCandidateReviewActions(pool, 9, { action: 'promote_to_ioc', candidateIds: [4], createIoc });
  assert.equal(cidr.code, 'promote_unsupported_type');
  const technique = await applyCandidateReviewActions(pool, 9, { action: 'promote_to_ioc', candidateIds: [5], createIoc });
  assert.equal(technique.code, 'promote_unsupported_type');
  const missing = await applyCandidateReviewActions(pool, 9, { action: 'promote_to_ioc', candidateIds: [99], createIoc });
  assert.equal(missing.status, 404);
  assert.equal(pool.writes.length, 0, 'refused promotions write nothing');
  assert.ok(pool.rows.every((r) => r.review_status === 'pending'));
  assert.deepEqual(classifyPromoteEligibility(contextOnlyCandidate()), { ok: true });
});

test('promote_to_ioc audit mapping is a distinct action with the approved target state', () => {
  const ev = buildReviewAuditEvent({ report: REPORT, action: 'promote_to_ioc', requestedIds: [2], candidates: [contextOnlyCandidate()], user: { email: 'a@b' } });
  assert.equal(ev.action, 'threat_library.candidates.promoted');
  assert.equal(ev.metadata.review_action, 'promote_to_ioc');
  assert.equal(ev.metadata.target_state, 'approved');
  assert.equal(ev.metadata.changed, 1);
});

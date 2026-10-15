/**
 * P1 hotfix: publisher membership vs analyst state vs global IOC links.
 *
 *   publisher membership  deterministic extraction (never pinned by history)
 *   analyst decisions     review_status, Context Only, Ignore / Reject — kept
 *   explicit override     promote_to_ioc (evidence.promoted_from) — re-applied
 *   global IOC identity   matched_ioc_id — kept when the lookup was skipped;
 *                         any change is a protected (admin) refresh change
 *
 * Shapes mirror the production cases verified on 2026-10-15: an approved,
 * IOC-created provider-service domain that the publisher only lists as a
 * legitimate service (NCSC), an approved, IOC-created incomplete URL prefix
 * (Raven), and approved IOC-linked body-table hashes (Huntress).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { candidateColumns } from './store.js';
import { applyAnalystState, preserveAnalystCandidates } from './candidateAnalystState.js';
import { preserveStoredIocLinks } from './iocMatch.js';
import {
  ADMIN_ACCEPTANCE_CATEGORIES,
  REFRESH_GUARD_DECISIONS,
  REFRESH_GUARD_REASONS,
  REFRESH_GUARD_VERSION,
  buildRefreshMembershipDiff,
  compactRefreshMembershipDiff,
  evaluateRefreshMembershipGuard
} from './refreshMembershipGuard.js';
import {
  QUALITY_CODES,
  assessReplayMembershipDivergence,
  withReplayMembershipDivergence
} from './extractionQuality.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isContextOnlyCandidate, isReportIndicatorMember } from './indicatorMembership.js';

const member = (c) => isReportIndicatorMember({ ...c, evidence: buildCandidateEvidenceRecord(c) });

/** Deterministic reading of a publisher IOC row (MODE A). */
function explicitRow(type, value, extra = {}) {
  return {
    candidate_type: type,
    normalized_value: value,
    original_value: value,
    is_ioc: true,
    assessment: 'malicious',
    role: 'command_and_control',
    match_state: 'new',
    review_status: 'pending',
    source_assertion: 'explicit_ioc',
    policy_decision: 'explicit_report_assertion',
    document_has_authoritative_scope: true,
    occurrences: [{ block_id: 'b1', zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row', row_shape: true }],
    ...extra
  };
}

/** Raven shape: an incomplete URL prefix, still inside the IOC section, read as non-IOC. */
const incompletePrefix = (value) => explicitRow('url', value, {
  is_ioc: false,
  assessment: 'context_only',
  match_state: 'context_only',
  source_assertion: 'non_ioc',
  policy_decision: 'ioc_excluded_incomplete_url_prefix'
});

/** NCSC shape: a provider service listed for log review (no authoritative scope, MODE B). */
const providerService = (value) => ({
  ...explicitRow('domain', value),
  document_has_authoritative_scope: false,
  assessment: 'context_only',
  match_state: 'context_only',
  role: 'legitimate_service',
  source_assertion: 'provider_service',
  policy_decision: 'context_only_legitimate_service_list',
  occurrences: [{ block_id: 'b70', zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }]
});

/** Huntress shape: a body-table hash outside the appendix (MODE A narrative). */
const bodyTableHash = (value) => explicitRow('sha256', value, {
  assessment: 'unknown',
  source_assertion: 'body_mention',
  policy_decision: 'ai_needed_prose_sample_hash',
  occurrences: [{ block_id: 'b38', zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }]
});

/** Stored row as bulk Create IOCs left it under the older contract. */
function createdRow(c, extra = {}) {
  return {
    ...candidateColumns({
      ...c,
      is_ioc: true,
      assessment: 'malicious',
      match_state: 'existing',
      source_assertion: c.candidate_type === 'url' ? 'explicit_c2' : 'explicit_ioc',
      policy_decision: 'explicit_report_assertion',
      document_has_authoritative_scope: true,
      occurrences: [{ block_id: 'b1', zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row', row_shape: true }],
      review_status: 'approved',
      matched_ioc_id: extra.matched_ioc_id ?? 3561785,
      matched_ioc_observable_type: c.candidate_type
    }),
    id: extra.id ?? '5679',
    promotion_outcome: extra.promotion_outcome ?? 'created',
    ...extra
  };
}

// --- 1. applyAnalystState: Create-IOC history no longer pins membership ------------

test('Raven shape: an approved, IOC-created incomplete URL prefix follows the deterministic reading', () => {
  const prior = createdRow(incompletePrefix('http://213.209.159.55:443/t/'));
  assert.equal(member(prior), true, 'stored row is an Indicator');
  const next = applyAnalystState(incompletePrefix('http://213.209.159.55:443/t/'), prior);
  assert.equal(next.is_ioc, false, 'not forced back to an IOC');
  assert.equal(next.assessment, 'context_only');
  assert.equal(next.match_state, 'context_only');
  assert.equal(next.source_assertion, 'non_ioc');
  assert.equal(next.review_status, 'approved', 'the analyst decision is history and is kept');
  assert.equal(member(next), false, 'leaves original Indicator membership');
});

test('NCSC shape: an approved, IOC-created provider-service domain stays Context Only (MODE B)', () => {
  const prior = createdRow(providerService('vultrobjects.com'), { id: '2344', matched_ioc_id: 3445487 });
  const fresh = { ...providerService('vultrobjects.com'), matched_ioc_id: 3445487 };
  const next = applyAnalystState(fresh, prior);
  assert.equal(next.assessment, 'context_only');
  assert.equal(next.role, 'legitimate_service');
  assert.equal(isContextOnlyCandidate(next), true);
  assert.equal(member(next), false);
  assert.equal(next.review_status, 'approved');
  assert.equal(next.matched_ioc_id, 3445487, 'the global IOC link survives');
});

test('Huntress shape (unchanged): approved IOC-linked body-table hashes leave MODE A membership with their decision', () => {
  const sha = 'a'.repeat(64);
  const next = applyAnalystState(bodyTableHash(sha), createdRow(bodyTableHash(sha), { promotion_outcome: 'already_existing', matched_ioc_id: 668913 }));
  assert.equal(member(next), false);
  assert.equal(next.review_status, 'approved');
  assert.equal(next.is_ioc, true);
});

test('explicit promote_to_ioc override is still re-applied (intentional manual promotion)', () => {
  const promoted = {
    ...createdRow(providerService('example-service.test'), { id: '9' }),
    evidence: {
      decision_source: 'analyst',
      policy_decision: 'analyst_promoted_from_context_only',
      promoted_from: { assessment: 'context_only', role: 'legitimate_service', match_state: 'context_only', is_ioc: true, promoted_by: 'analyst@example' }
    }
  };
  const next = applyAnalystState({ ...providerService('example-service.test'), matched_ioc_id: 3561785 }, promoted);
  assert.equal(next.assessment, 'suspicious');
  assert.equal(next.is_ioc, true);
  assert.equal(next.match_state, 'existing');
  assert.equal(next.role, 'unknown');
  assert.equal(next.policy_decision, 'analyst_promoted_from_context_only');
  assert.equal(next.promoted_from.promoted_by, 'analyst@example');
  assert.equal(member(next), true, 'MODE B: the analyst override keeps it an Indicator');
});

test('analyst exclusions stand; a pending row with a created outcome keeps its implied approval', () => {
  for (const review of ['context_only', 'ignored', 'rejected']) {
    const next = applyAnalystState(explicitRow('domain', 'c2.example'), createdRow(explicitRow('domain', 'c2.example'), { review_status: review }));
    assert.equal(next.review_status, review);
    if (review === 'context_only') assert.equal(member(next), false);
  }
  const pending = applyAnalystState(explicitRow('domain', 'c2.example'), createdRow(explicitRow('domain', 'c2.example'), { review_status: 'pending' }));
  assert.equal(pending.review_status, 'approved');
  assert.equal(pending.assessment, 'malicious', 'classification untouched');
});

test('a new identity starts pending; an unchanged Indicator keeps its state (non-destructive replay)', () => {
  const kept = applyAnalystState(explicitRow('ip', '198.51.100.7', { matched_ioc_id: 7 }), createdRow(explicitRow('ip', '198.51.100.7'), { matched_ioc_id: 7 }));
  assert.equal(member(kept), true);
  assert.equal(kept.review_status, 'approved');
  assert.equal(applyAnalystState(explicitRow('ip', '198.51.100.8'), null).review_status, 'pending');
});

// --- 2. preserveStoredIocLinks ------------------------------------------------------

function fakePool(liveIds) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      assert.match(sql, /^SELECT id, observable_type FROM ioc_items WHERE id = ANY/);
      return { rows: params[0].filter((id) => liveIds.includes(Number(id))).map((id) => ({ id, observable_type: 'url' })) };
    }
  };
}

test('a skipped catalog lookup keeps the stored global-IOC link when the IOC still exists', async () => {
  const prior = createdRow(incompletePrefix('http://213.209.159.55:443/t/'));
  const fresh = { ...incompletePrefix('http://213.209.159.55:443/t/'), matched_ioc_id: null };
  const pool = fakePool([3561785]);
  const { candidates, preserved } = await preserveStoredIocLinks(pool, [fresh], [prior]);
  assert.equal(candidates[0].matched_ioc_id, 3561785);
  assert.equal(candidates[0].matched_ioc_observable_type, 'url');
  assert.equal(candidates[0].match_state, 'context_only', 'match_state recomputed with the link; context wins');
  assert.deepEqual(preserved, [{ identity: 'url:http://213.209.159.55:443/t/', matched_ioc_id: 3561785 }]);
  assert.equal(fresh.matched_ioc_id, null, 'input not mutated');
});

test('a deleted IOC record is not resurrected, a lookup that ran and missed is not overridden, nothing to do = no query', async () => {
  const prior = createdRow(incompletePrefix('http://x.example/t/'));
  const gone = await preserveStoredIocLinks(fakePool([]), [{ ...incompletePrefix('http://x.example/t/'), matched_ioc_id: null }], [prior]);
  assert.equal(gone.candidates[0].matched_ioc_id, null);
  assert.deepEqual(gone.preserved, []);

  const ranPool = fakePool([3561785]);
  const ran = await preserveStoredIocLinks(ranPool, [{ ...explicitRow('url', 'http://x.example/t/'), matched_ioc_id: null }], [prior]);
  assert.equal(ran.candidates[0].matched_ioc_id, null, 'is_ioc lookup ran: a real catalog miss stays a miss');
  assert.equal(ranPool.calls.length, 0);

  const nonePool = fakePool([1]);
  await preserveStoredIocLinks(nonePool, [explicitRow('ip', '198.51.100.9', { matched_ioc_id: 1 })], [createdRow(explicitRow('ip', '198.51.100.9'), { matched_ioc_id: 1 })]);
  assert.equal(nonePool.calls.length, 0);
});

// --- 3. Guard: IOC link changes are protected --------------------------------------

function guard(previousRows, nextCandidates, policy, acceptorRole = 'admin') {
  const diff = buildRefreshMembershipDiff({ previousRows, nextCandidates });
  return { diff, verdict: evaluateRefreshMembershipGuard(diff, policy, { acceptorRole }) };
}
const reasons = (v) => v.reasons.map((r) => r.code).sort();

test('guard version is v2', () => {
  assert.equal(REFRESH_GUARD_VERSION, 'tl-refresh-guard-v2');
});

test('a cleared IOC link on an unchanged Indicator is a material, admin-only change (counts unchanged)', () => {
  const c = explicitRow('domain', 'c2.example', { review_status: 'approved' });
  const prior = { ...candidateColumns({ ...c, matched_ioc_id: 77, match_state: 'existing' }), id: '1', promotion_outcome: 'created' };
  const { diff, verdict } = guard([prior], [{ ...c, matched_ioc_id: null }]);
  assert.deepEqual(diff.indicators, { before: 1, after: 1 });
  assert.equal(diff.counts.ioc_link_changes, 1);
  assert.deepEqual(diff.ioc_link_changes[0], {
    identity: 'domain:c2.example', from_ioc_id: 77, to_ioc_id: null, change: 'cleared', reviewed: true,
    review_status: 'approved', promotion_outcome: 'created', member_before: true, member_after: true
  });
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.deepEqual(reasons(verdict), [REFRESH_GUARD_REASONS.IOC_LINK_CHANGED]);
  assert.equal(verdict.authorization.required_role, 'admin');
  assert.ok(verdict.authorization.categories.some((x) => x.code === ADMIN_ACCEPTANCE_CATEGORIES.IOC_LINK_CHANGED));
  assert.equal(compactRefreshMembershipDiff(diff).ioc_link_changes[0].from_ioc_id, 77);
});

test('a moved IOC link is protected; the fingerprint binds the exact link change', () => {
  const c = explicitRow('domain', 'c2.example');
  const prior = { ...candidateColumns({ ...c, matched_ioc_id: 77 }), id: '1' };
  const moved = guard([prior], [{ ...c, matched_ioc_id: 78 }]);
  const cleared = guard([prior], [{ ...c, matched_ioc_id: null }]);
  const same = guard([prior], [{ ...c, matched_ioc_id: 77 }]);
  assert.equal(moved.diff.ioc_link_changes[0].change, 'moved');
  assert.notEqual(moved.diff.material_fingerprint, cleared.diff.material_fingerprint);
  assert.notEqual(moved.diff.material_fingerprint, same.diff.material_fingerprint);
  assert.equal(same.verdict.decision, REFRESH_GUARD_DECISIONS.APPLY);
});

test('harmless metadata (match_state, evidence) on a kept link does not block', () => {
  const c = explicitRow('domain', 'c2.example', { review_status: 'approved' });
  const prior = { ...candidateColumns({ ...c, matched_ioc_id: 77, match_state: 'existing' }), id: '1', promotion_outcome: 'created' };
  const { diff, verdict } = guard([prior], [{ ...c, matched_ioc_id: 77, match_state: 'existing', evidence_text: 'new excerpt' }]);
  assert.equal(diff.counts.ioc_link_changes, 0);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.APPLY);
});

test('acceptance of an IOC link change: analyst denied, admin with the preview fingerprint accepted, stale refused', () => {
  const c = explicitRow('domain', 'c2.example');
  const prior = { ...candidateColumns({ ...c, matched_ioc_id: 77 }), id: '1' };
  const next = [{ ...c, matched_ioc_id: null }];
  const { diff } = guard([prior], next);
  const accept = { mode: 'accept', reason: 'Reviewed the preview: link change expected', preview_fingerprint: diff.material_fingerprint };
  assert.ok(reasons(guard([prior], next, accept, 'analyst').verdict).includes(REFRESH_GUARD_REASONS.ACCEPTANCE_REQUIRES_ADMIN));
  assert.equal(guard([prior], next, accept, 'analyst').verdict.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.equal(guard([prior], next, accept, 'admin').verdict.decision, REFRESH_GUARD_DECISIONS.APPLY_ACCEPTED);
  const stale = { ...accept, preview_fingerprint: 'f'.repeat(64) };
  assert.ok(reasons(guard([prior], next, stale, 'admin').verdict).includes(REFRESH_GUARD_REASONS.PREVIEW_STALE));
});

test('end to end (pure): the Raven and NCSC shapes now leave membership as protected, reviewed, IOC-linked losses with links kept', async () => {
  const ravenPrior = createdRow(incompletePrefix('http://213.209.159.55:443/t/'));
  const ncscPrior = createdRow(providerService('iproyal.com'), { id: '2346', matched_ioc_id: 3445489 });
  const prev = [ravenPrior, ncscPrior];
  const matched = [
    { ...incompletePrefix('http://213.209.159.55:443/t/'), matched_ioc_id: null },
    { ...providerService('iproyal.com'), matched_ioc_id: 3445489 }
  ];
  const linked = await preserveStoredIocLinks(fakePool([3561785, 3445489]), matched, prev);
  const final = preserveAnalystCandidates(linked.candidates, prev);
  const { diff, verdict } = guard(prev, final);
  assert.deepEqual(diff.indicators, { before: 2, after: 0 });
  assert.equal(diff.counts.ioc_link_changes, 0, 'no global IOC link lost');
  assert.equal(diff.counts.removed_reviewed_indicators, 2);
  assert.equal(diff.counts.ioc_linked_losses, 2);
  assert.deepEqual(diff.removed_indicators.map((r) => [r.identity, r.reason_code, r.row_outcome, r.matched_ioc_id]), [
    ['domain:iproyal.com', 'publisher_assertion_lost', 'kept', 3445489],
    ['url:http://213.209.159.55:443/t/', 'publisher_assertion_lost', 'kept', 3561785]
  ]);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.equal(verdict.authorization.required_role, 'admin');
  assert.equal(final.every((x) => x.review_status === 'approved'), true);
});

// --- 4. Quality check 9: replay divergence -----------------------------------------

test('quality check 9: no divergence = no warning; explicit overrides are notes; anything else warns', () => {
  const det = [explicitRow('domain', 'a.example'), providerService('svc.example')];
  assert.equal(assessReplayMembershipDivergence({ deterministic: det, final: det, previousRows: [] }), null);

  const promotedPrior = { candidate_type: 'domain', normalized_value: 'svc.example', review_status: 'approved', evidence: { promoted_from: { assessment: 'context_only' } } };
  const promotedFinal = [det[0], { ...providerService('svc.example'), assessment: 'suspicious', match_state: 'new', role: 'unknown' }];
  const note = assessReplayMembershipDivergence({ deterministic: det, final: promotedFinal, previousRows: [promotedPrior] });
  assert.equal(note.code, QUALITY_CODES.ANALYST_STATE_MEMBERSHIP_DIVERGENCE);
  assert.equal(note.severity, 'info');
  assert.deepEqual(note.divergence, { added_by_replay: 1, removed_by_replay: 0, causes: { analyst_promotion: 1, analyst_exclusion: 0, unexplained: 0 } });

  const excludedPrior = { candidate_type: 'domain', normalized_value: 'a.example', review_status: 'context_only', evidence: {} };
  const excluded = assessReplayMembershipDivergence({
    deterministic: det,
    final: [{ ...det[0], assessment: 'context_only', match_state: 'context_only', review_status: 'context_only' }, det[1]],
    previousRows: [excludedPrior]
  });
  assert.equal(excluded.severity, 'info');
  assert.equal(excluded.divergence.causes.analyst_exclusion, 1);

  const unexplained = assessReplayMembershipDivergence({
    deterministic: det,
    final: [det[0], { ...providerService('svc.example'), assessment: 'suspicious', match_state: 'existing' }],
    previousRows: [{ candidate_type: 'domain', normalized_value: 'svc.example', review_status: 'approved', promotion_outcome: 'created', evidence: {} }]
  });
  assert.equal(unexplained.severity, 'warning');
  assert.deepEqual(unexplained.candidates, ['domain:svc.example']);
});

test('withReplayMembershipDivergence merges additively and recomputes status / counts', () => {
  const base = { version: 'tl-quality-v5', mode: 'B', status: 'clean', counts: { high: 0, warning: 0, info: 0 }, warnings: [], warnings_total: 0, extractor_versions: { quality: 'tl-quality-v5' } };
  const det = [providerService('svc.example')];
  assert.equal(withReplayMembershipDivergence(base, { deterministic: det, final: det }), base);
  const merged = withReplayMembershipDivergence(base, {
    deterministic: det,
    final: [{ ...det[0], assessment: 'suspicious', match_state: 'existing' }],
    previousRows: [{ candidate_type: 'domain', normalized_value: 'svc.example', review_status: 'approved', evidence: {} }]
  });
  assert.equal(merged.status, 'warning');
  assert.deepEqual(merged.counts, { high: 0, warning: 1, info: 0 });
  assert.equal(merged.warnings_total, 1);
  assert.equal(merged.warnings[0].code, 'analyst_state_membership_divergence');
  assert.equal(base.warnings.length, 0, 'input not mutated');
  assert.equal(withReplayMembershipDivergence(null, { deterministic: det, final: det }), null);
});

/**
 * Refresh membership guard (tl-refresh-guard-v1): diff contents, material vs
 * advisory reasons, the explicit acceptance path and policy normalization.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { candidateColumns } from './store.js';
import {
  REFRESH_GUARD_DECISIONS,
  REFRESH_GUARD_REASONS,
  REFRESH_GUARD_THRESHOLDS,
  buildRefreshMembershipDiff,
  compactRefreshMembershipDiff,
  evaluateRefreshMembershipGuard,
  normalizeRefreshMembershipPolicy
} from './refreshMembershipGuard.js';

const H = (c) => c.repeat(32);

/** Extracted candidate (pre-persistence shape). */
function cand(type, value, opts = {}) {
  const explicit = opts.explicit !== false;
  return {
    candidate_type: type,
    normalized_value: value,
    original_value: value,
    is_ioc: opts.is_ioc ?? true,
    assessment: opts.assessment || (explicit ? 'malicious' : 'unknown'),
    match_state: opts.match_state || 'new',
    role: 'malicious_infrastructure',
    review_status: opts.review_status || 'pending',
    source_assertion: opts.source_assertion || (explicit ? 'explicit_ioc' : 'body_mention'),
    policy_decision: opts.policy_decision || (explicit ? 'explicit_report_assertion' : 'pass'),
    document_has_authoritative_scope: opts.modeA ?? true,
    occurrences: [
      explicit
        ? { block_id: 'b1', zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row', row_shape: true }
        : { block_id: 'b2', zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention', row_shape: false }
    ]
  };
}

/** Persisted row for a candidate (as reconcile stored it). */
const row = (c, extra = {}) => ({ ...candidateColumns(c), id: 1, promotion_outcome: null, ...extra });
const contextOnly = (c) => ({ ...c, assessment: 'context_only', match_state: 'context_only', policy_decision: 'context_only_negative_zone', source_assertion: 'reference_only' });

function guard(previousRows, nextCandidates, policy, quality = {}) {
  const diff = buildRefreshMembershipDiff({ previousRows, nextCandidates, ...quality });
  return { diff, verdict: evaluateRefreshMembershipGuard(diff, policy) };
}

const codes = (verdict) => verdict.reasons.map((r) => r.code).sort();

test('identical sets apply with an empty diff', () => {
  const set = [cand('md5', H('a')), cand('domain', 'evil.example')];
  const { diff, verdict } = guard(set.map((c) => row(c)), set);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.APPLY);
  assert.deepEqual(verdict.reasons, []);
  assert.deepEqual(diff.indicators, { before: 2, after: 2 });
  assert.equal(diff.counts.removed_indicators + diff.counts.added_indicators + diff.counts.classification_changes, 0);
});

test('additions alone apply (no material loss) and are recorded', () => {
  const before = [cand('md5', H('a'))];
  const after = [...before, cand('md5', H('b'))];
  const { diff, verdict } = guard(before.map((c) => row(c)), after);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.APPLY);
  assert.deepEqual(diff.added_indicators.map((x) => x.identity), [`md5:${H('b')}`]);
  assert.equal(diff.added_indicators[0].new_identity, true);
});

test('losing a publisher-asserted Indicator blocks under protect, with reason codes per row', () => {
  const kept = cand('domain', 'evil.example');
  const lost = cand('md5', H('a'));
  const relabeled = { ...lost, ...cand('md5', H('a'), { explicit: false, policy_decision: 'ai_needed_prose_sample_hash' }) };
  const { diff, verdict } = guard([row(kept), row(lost)], [kept, relabeled]);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.deepEqual(codes(verdict), [REFRESH_GUARD_REASONS.PUBLISHER_ASSERTION_LOST]);
  assert.equal(verdict.material, true);
  assert.match(verdict.message, /publisher_assertion_lost \(1\)/);
  const removed = diff.removed_indicators[0];
  assert.equal(removed.identity, `md5:${H('a')}`);
  assert.equal(removed.reason_code, 'publisher_assertion_lost');
  assert.equal(removed.next.policy_decision, 'ai_needed_prose_sample_hash');
  assert.deepEqual(diff.classification_changes[0].fields, ['source_assertion', 'policy_decision', 'assessment']);
});

test('explicit acceptance with a reason applies the same diff and records who and why', () => {
  const lost = cand('md5', H('a'));
  const preview = buildRefreshMembershipDiff({ previousRows: [row(lost)], nextCandidates: [] });
  const policy = {
    mode: 'accept',
    reason: 'Parser fix: hash rows were an analysis table',
    preview_fingerprint: preview.material_fingerprint,
    requested_by: 'user-1',
    requested_at: '2026-10-14T00:00:00Z'
  };
  const { verdict } = guard([row(lost)], [], policy);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.APPLY_ACCEPTED);
  assert.deepEqual(verdict.accepted, {
    reason: policy.reason,
    requested_by: 'user-1',
    requested_at: policy.requested_at,
    preview_fingerprint: preview.material_fingerprint
  });
  assert.ok(codes(verdict).includes(REFRESH_GUARD_REASONS.PUBLISHER_ASSERTION_LOST), 'reasons stay recorded');
});

test('acceptance without a sufficient reason still blocks', () => {
  const { verdict } = guard([row(cand('md5', H('a')))], [], { mode: 'accept', reason: 'ok' });
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.ok(codes(verdict).includes(REFRESH_GUARD_REASONS.ACCEPTANCE_REASON_MISSING));
});

test('an analyst-reviewed Indicator leaving the set is material even when it was a body mention', () => {
  const approved = cand('domain', 'c2.example', { explicit: false, modeA: false, review_status: 'approved' });
  const demoted = contextOnly(cand('domain', 'c2.example', { explicit: false, modeA: false, review_status: 'approved' }));
  const { diff, verdict } = guard([row(approved)], [demoted]);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.deepEqual(codes(verdict), [REFRESH_GUARD_REASONS.REVIEWED_INDICATOR_REMOVED]);
  assert.equal(diff.removed_indicators[0].reason_code, 'became_context_only');
  assert.equal(diff.removed_indicators[0].reviewed, true);
});

test('deleting a reviewed non-Indicator row (analyst decision) is material', () => {
  const ignored = contextOnly(cand('domain', 'cs.append', { review_status: 'ignored' }));
  const keep = cand('domain', 'evil.example');
  const { diff, verdict } = guard([row(ignored), row(keep)], [keep]);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.deepEqual(codes(verdict), [REFRESH_GUARD_REASONS.REVIEWED_CANDIDATE_DELETED]);
  assert.deepEqual(diff.reviewed_candidates_deleted, [{ identity: 'domain:cs.append', review_status: 'ignored', promotion_outcome: null, matched_ioc_id: null }]);
});

test('a created-IOC outcome counts as analyst state', () => {
  const created = cand('domain', 'evil.example', { review_status: 'pending' });
  const { verdict } = guard([row(created, { promotion_outcome: 'created' })], []);
  assert.ok(codes(verdict).includes(REFRESH_GUARD_REASONS.REVIEWED_INDICATOR_REMOVED));
  assert.ok(codes(verdict).includes(REFRESH_GUARD_REASONS.REVIEWED_CANDIDATE_DELETED));
});

test('ordinary reclassification of a pending narrative row applies (legitimate change, recorded)', () => {
  const before = cand('url', 'https://learn.example/docs', { explicit: false, modeA: false });
  const after = contextOnly(cand('url', 'https://learn.example/docs', { explicit: false, modeA: false }));
  const { diff, verdict } = guard([row(before)], [after]);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.APPLY);
  assert.equal(diff.counts.removed_indicators, 1);
  assert.equal(diff.removed_indicators[0].reason_code, 'became_context_only');
  assert.deepEqual(diff.newly_context_only.map((x) => x.identity), ['url:https://learn.example/docs']);
});

test('bulk loss of pending non-explicit Indicators: threshold is count AND fraction', () => {
  const T = REFRESH_GUARD_THRESHOLDS;
  const narrative = (i) => cand('domain', `n${i}.example`, { explicit: false, modeA: false });
  const ten = Array.from({ length: 10 }, (_, i) => narrative(i));
  const drop = (n) => guard(ten.map((c) => row(c)), ten.map((c, i) => (i < n ? contextOnly(c) : c)));
  assert.equal(T.bulkLossMinCount, 5);
  assert.equal(drop(T.bulkLossMinCount - 1).verdict.decision, REFRESH_GUARD_DECISIONS.APPLY);
  const bulk = drop(T.bulkLossMinCount).verdict;
  assert.equal(bulk.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.deepEqual(codes(bulk), [REFRESH_GUARD_REASONS.BULK_MEMBERSHIP_LOSS]);
  // 5 of 100 is below the fraction: not bulk.
  const hundred = Array.from({ length: 100 }, (_, i) => narrative(i));
  const small = guard(hundred.map((c) => row(c)), hundred.map((c, i) => (i < 5 ? contextOnly(c) : c))).verdict;
  assert.equal(small.decision, REFRESH_GUARD_DECISIONS.APPLY);
});

test('MODE change and new quality warnings are advisory, never blocking on their own', () => {
  const b = cand('domain', 'n.example', { explicit: false, modeA: false });
  const a = cand('domain', 'n.example', { explicit: false, modeA: true });
  const { diff, verdict } = guard([row(b)], [{ ...a, assessment: 'unknown', source_assertion: 'body_mention' }, cand('md5', H('a'))], undefined, {
    previousQuality: { status: 'clean', warnings: [] },
    nextQuality: { status: 'warning', warnings: [{ code: 'indicator_rows_adjacent_to_authoritative_scope', severity: 'warning' }, { code: 'authoritative_section_empty', severity: 'info' }] }
  });
  assert.deepEqual(diff.mode, { before: 'B', after: 'A' });
  assert.deepEqual(diff.quality.new_warning_codes, ['indicator_rows_adjacent_to_authoritative_scope'], 'info codes are not counted');
  assert.equal(diff.removed_indicators[0].reason_code, 'mode_changed');
  assert.deepEqual(codes(verdict), [REFRESH_GUARD_REASONS.MEMBERSHIP_MODE_CHANGED, REFRESH_GUARD_REASONS.NEW_QUALITY_WARNINGS].sort());
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.APPLY);
  assert.ok(verdict.reasons.every((r) => r.material === false));
});

test('linked-only rows are outside the refresh scope and never counted as losses', () => {
  const linked = row(cand('domain', 'linked.example'), { has_original_document_occurrence: false });
  const { diff, verdict } = guard([linked], []);
  assert.equal(diff.indicators.before, 0);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.APPLY);
});

test('policy normalization: unknown input is protect; accept keeps a trimmed reason', () => {
  assert.deepEqual(normalizeRefreshMembershipPolicy(undefined), { mode: 'protect' });
  assert.deepEqual(normalizeRefreshMembershipPolicy({ mode: 'force' }), { mode: 'protect' });
  assert.deepEqual(normalizeRefreshMembershipPolicy({ mode: 'accept', reason: '  why  ' }), {
    mode: 'accept', reason: 'why', preview_fingerprint: null, requested_by: null, requested_at: null
  });
  assert.equal(normalizeRefreshMembershipPolicy({ mode: 'accept', preview_fingerprint: 'not-hex' }).preview_fingerprint, null);
});

test('compact diff is bounded and identity-keyed', () => {
  const many = Array.from({ length: 60 }, (_, i) => cand('domain', `x${i}.example`));
  const diff = buildRefreshMembershipDiff({ previousRows: [], nextCandidates: many });
  const compact = compactRefreshMembershipDiff(diff);
  assert.equal(compact.counts.added_indicators, 60);
  assert.equal(compact.added_indicators.length, 40);
  assert.ok(compact.added_indicators.every((x) => typeof x === 'string'));
});

// --- Linked-source / deletion / global IOC distinctions ----------------------

test('a reviewed non-member row that leaves the document is deleted unless an IOC Source links it', () => {
  const approved = { ...row(cand('domain', 'kept.example', { explicit: false, review_status: 'approved' })), id: 41 };
  const unlinked = buildRefreshMembershipDiff({ previousRows: [approved], nextCandidates: [] });
  assert.equal(unlinked.reviewed_candidates_deleted.length, 1, 'unlinked row is deleted with its decision');
  assert.equal(evaluateRefreshMembershipGuard(unlinked, null).decision, REFRESH_GUARD_DECISIONS.BLOCK);
  const linked = buildRefreshMembershipDiff({ previousRows: [approved], nextCandidates: [], linkedCandidateIds: new Set(['41']) });
  assert.deepEqual(linked.reviewed_candidates_deleted, [], 'a linked row is kept, not deleted');
  assert.equal(evaluateRefreshMembershipGuard(linked, null).decision, REFRESH_GUARD_DECISIONS.APPLY);
});

test('reviewed original Indicator leaving the document but kept via linked source is not a lost decision', () => {
  const approved = { ...row(cand('domain', 'c2.example', { explicit: false, modeA: false, review_status: 'approved' })), id: 7 };
  const linked = buildRefreshMembershipDiff({ previousRows: [approved], nextCandidates: [], linkedCandidateIds: [7] });
  const removed = linked.removed_indicators[0];
  assert.equal(removed.row_outcome, 'original_occurrence_cleared');
  assert.equal(removed.reason_code, 'left_document_linked_source_kept');
  assert.equal(removed.union_member_after, true);
  assert.equal(linked.counts.removed_reviewed_indicators, 0);
  assert.equal(linked.counts.removed_reviewed_kept_by_linked_source, 1);
  assert.equal(linked.counts.original_occurrences_cleared, 1);
  assert.equal(linked.counts.reviewed_candidates_deleted, 0);
  assert.equal(evaluateRefreshMembershipGuard(linked, null).decision, REFRESH_GUARD_DECISIONS.APPLY);

  const deleted = buildRefreshMembershipDiff({ previousRows: [approved], nextCandidates: [] });
  assert.equal(deleted.removed_indicators[0].row_outcome, 'deleted');
  assert.equal(deleted.removed_indicators[0].reason_code, 'identity_left_document');
  const verdict = evaluateRefreshMembershipGuard(deleted, null);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.deepEqual(codes(verdict), [REFRESH_GUARD_REASONS.REVIEWED_CANDIDATE_DELETED, REFRESH_GUARD_REASONS.REVIEWED_INDICATOR_REMOVED].sort());
});

test('a publisher-asserted Indicator leaving the original document stays material even when a linked source keeps the row', () => {
  const explicit = { ...row(cand('md5', H('e'))), id: 9 };
  const diff = buildRefreshMembershipDiff({ previousRows: [explicit], nextCandidates: [], linkedCandidateIds: [9] });
  assert.equal(diff.removed_indicators[0].row_outcome, 'original_occurrence_cleared');
  assert.equal(diff.removed_indicators[0].publisher_asserted, true);
  const verdict = evaluateRefreshMembershipGuard(diff, null);
  assert.equal(verdict.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.deepEqual(codes(verdict), [REFRESH_GUARD_REASONS.PUBLISHER_ASSERTION_LOST]);
});

test('a kept linked row is a union member exactly when its own gates pass (they are unchanged by the refresh)', () => {
  const approved = { ...row(cand('domain', 'c2.example', { explicit: false, modeA: false, review_status: 'approved' })), id: 8 };
  // The kept row is not rewritten, so its gates after equal its gates before.
  const gated = { ...approved };
  const diff = buildRefreshMembershipDiff({ previousRows: [gated], nextCandidates: [], linkedCandidateIds: [8] });
  assert.equal(diff.removed_indicators[0].union_member_after, true);
  const parserDerived = { ...approved, evidence: { ...approved.evidence, is_parser_derived_metadata: true } };
  const none = buildRefreshMembershipDiff({ previousRows: [parserDerived], nextCandidates: [], linkedCandidateIds: [8] });
  assert.equal(none.removed_indicators.length, 0, 'never an Indicator, so nothing leaves the set');
});

test('global IOC identity: a deleted Create-IOC row reports the IOC record it was linked to (refresh never deletes the IOC)', () => {
  const created = { ...row(cand('domain', 'created.example'), { promotion_outcome: 'created' }), id: 5, matched_ioc_id: 9001 };
  const diff = buildRefreshMembershipDiff({ previousRows: [created], nextCandidates: [] });
  assert.equal(diff.removed_indicators[0].matched_ioc_id, 9001);
  assert.equal(diff.removed_indicators[0].promotion_outcome, 'created');
  assert.equal(diff.reviewed_candidates_deleted[0].matched_ioc_id, 9001);
  assert.equal(evaluateRefreshMembershipGuard(diff, null).decision, REFRESH_GUARD_DECISIONS.BLOCK);
  const compact = compactRefreshMembershipDiff(diff);
  assert.equal(compact.removed_indicators[0].matched_ioc_id, 9001);
  assert.equal(compact.removed_indicators[0].row_outcome, 'deleted');
});

// --- Preview binding (stale previews never authorize) ------------------------

test('material fingerprint: order-independent, ignores additions, changes with the losses', () => {
  const a = row(cand('md5', H('a')));
  const b = row(cand('md5', H('b')));
  const base = buildRefreshMembershipDiff({ previousRows: [a, b], nextCandidates: [] }).material_fingerprint;
  assert.match(base, /^[a-f0-9]{64}$/);
  assert.equal(buildRefreshMembershipDiff({ previousRows: [b, a], nextCandidates: [] }).material_fingerprint, base);
  assert.equal(
    buildRefreshMembershipDiff({ previousRows: [a, b], nextCandidates: [cand('md5', H('c'))] }).material_fingerprint,
    base,
    'an added Indicator does not change what is being given up'
  );
  assert.notEqual(buildRefreshMembershipDiff({ previousRows: [a], nextCandidates: [] }).material_fingerprint, base);
  assert.notEqual(
    buildRefreshMembershipDiff({ previousRows: [a, { ...b, review_status: 'approved' }], nextCandidates: [] }).material_fingerprint,
    base,
    'a newly reviewed row changes the losses'
  );
});

test('acceptance of a stale preview is refused; acceptance without a preview is refused', () => {
  const a = row(cand('md5', H('a')));
  const b = row(cand('md5', H('b')));
  const preview = buildRefreshMembershipDiff({ previousRows: [a], nextCandidates: [] });
  const now = buildRefreshMembershipDiff({ previousRows: [a, b], nextCandidates: [] });
  const reason = 'Reviewed the preview: intended parser change';
  const stale = evaluateRefreshMembershipGuard(now, { mode: 'accept', reason, preview_fingerprint: preview.material_fingerprint });
  assert.equal(stale.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.ok(codes(stale).includes(REFRESH_GUARD_REASONS.PREVIEW_STALE));
  const missing = evaluateRefreshMembershipGuard(now, { mode: 'accept', reason });
  assert.equal(missing.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.ok(codes(missing).includes(REFRESH_GUARD_REASONS.PREVIEW_FINGERPRINT_MISSING));
  const current = evaluateRefreshMembershipGuard(now, { mode: 'accept', reason, preview_fingerprint: now.material_fingerprint });
  assert.equal(current.decision, REFRESH_GUARD_DECISIONS.APPLY_ACCEPTED);
});

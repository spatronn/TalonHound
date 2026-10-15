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

/** Acceptances here come from an admin unless a test says otherwise (role matrix below). */
function guard(previousRows, nextCandidates, policy, quality = {}, acceptorRole = 'admin') {
  const diff = buildRefreshMembershipDiff({ previousRows, nextCandidates, ...quality });
  return { diff, verdict: evaluateRefreshMembershipGuard(diff, policy, { acceptorRole }) };
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
    acceptor_role: 'admin',
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
  const stale = evaluateRefreshMembershipGuard(now, { mode: 'accept', reason, preview_fingerprint: preview.material_fingerprint }, { acceptorRole: 'admin' });
  assert.equal(stale.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.ok(codes(stale).includes(REFRESH_GUARD_REASONS.PREVIEW_STALE));
  const missing = evaluateRefreshMembershipGuard(now, { mode: 'accept', reason }, { acceptorRole: 'admin' });
  assert.equal(missing.decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.ok(codes(missing).includes(REFRESH_GUARD_REASONS.PREVIEW_FINGERPRINT_MISSING));
  const current = evaluateRefreshMembershipGuard(now, { mode: 'accept', reason, preview_fingerprint: now.material_fingerprint }, { acceptorRole: 'admin' });
  assert.equal(current.decision, REFRESH_GUARD_DECISIONS.APPLY_ACCEPTED);
});

// ---------------------------------------------------------------- RBAC (guard role matrix)

/** Synthetic diff with only the given loss counts (everything else zero). */
function lossDiff(counts) {
  return {
    material_fingerprint: 'f'.repeat(64),
    indicators: { before: 10, after: 10 - (counts.removed_indicators || 0) },
    mode: { before: 'A', after: 'A' },
    quality: { new_warning_codes: [] },
    counts: {
      removed_indicators: 0,
      removed_reviewed_indicators: 0,
      removed_reviewed_any: 0,
      removed_publisher_asserted: 0,
      reviewed_candidates_deleted: 0,
      ioc_linked_losses: 0,
      ...counts
    }
  };
}
const ACCEPT = { mode: 'accept', reason: 'Reviewed the preview carefully', preview_fingerprint: 'f'.repeat(64), requested_by: 'u' };

test('RBAC role matrix: admin-only loss categories × acceptor roles', async () => {
  const { ADMIN_ACCEPTANCE_CATEGORIES: C } = await import('./refreshMembershipGuard.js');
  const categories = [
    [C.REVIEWED_INDICATOR_REMOVED, { removed_indicators: 1, removed_reviewed_indicators: 1, removed_reviewed_any: 1 }],
    [C.PUBLISHER_ASSERTED_REMOVED, { removed_indicators: 1, removed_publisher_asserted: 1 }],
    [C.REVIEWED_CANDIDATE_DELETED, { reviewed_candidates_deleted: 1 }],
    [C.IOC_LINKED_CANDIDATE_REMOVED, { removed_indicators: 6, ioc_linked_losses: 1 }]
  ];
  const roles = [
    ['admin', 'apply_accepted', null],
    ['system', 'apply_accepted', null],
    ['analyst', 'block', 'acceptance_requires_admin'],
    ['readonly', 'block', 'acceptance_not_authorized'],
    [null, 'block', 'acceptance_not_authorized'],
    ['superadmin', 'block', 'acceptance_not_authorized']
  ];
  for (const [category, counts] of categories) {
    const diff = lossDiff(counts);
    for (const [role, decision, code] of roles) {
      const v = evaluateRefreshMembershipGuard(diff, ACCEPT, { acceptorRole: role });
      assert.equal(v.decision, decision, `${category} × ${role}`);
      assert.equal(v.authorization.required_role, 'admin', category);
      assert.ok(v.authorization.categories.some((x) => x.code === category), category);
      if (code) assert.ok(v.reasons.some((r) => r.code === code), `${category} × ${role}: ${JSON.stringify(v.reasons)}`);
    }
  }
});

test('RBAC: an analyst may accept losses limited to unreviewed, non-publisher, IOC-free candidates', () => {
  const diff = lossDiff({ removed_indicators: 6 }); // bulk loss of model-only rows
  const analyst = evaluateRefreshMembershipGuard(diff, ACCEPT, { acceptorRole: 'analyst' });
  assert.equal(analyst.decision, REFRESH_GUARD_DECISIONS.APPLY_ACCEPTED);
  assert.equal(analyst.authorization.required_role, 'analyst');
  assert.equal(analyst.accepted.acceptor_role, 'analyst');
  assert.equal(evaluateRefreshMembershipGuard(diff, ACCEPT, { acceptorRole: 'readonly' }).decision, REFRESH_GUARD_DECISIONS.BLOCK);
  assert.equal(evaluateRefreshMembershipGuard(diff, ACCEPT).decision, REFRESH_GUARD_DECISIONS.BLOCK, 'no resolved role: fail closed');
});

test('RBAC: a non-material refresh needs no acceptance and no role; a protected material refresh still blocks for an admin', () => {
  const none = evaluateRefreshMembershipGuard(lossDiff({}), null);
  assert.equal(none.decision, REFRESH_GUARD_DECISIONS.APPLY);
  assert.equal(none.authorization.required_role, null);
  const protectedAdmin = evaluateRefreshMembershipGuard(lossDiff({ reviewed_candidates_deleted: 1 }), null, { acceptorRole: 'admin' });
  assert.equal(protectedAdmin.decision, REFRESH_GUARD_DECISIONS.BLOCK, 'being admin is not an acceptance');
});

test('RBAC: the admin requirement is derived from real diffs (reviewed / publisher / IOC-linked / deletion)', () => {
  const md5 = cand('md5', H('a'));
  const roleOf = (prev) => {
    const diff = buildRefreshMembershipDiff({ previousRows: prev, nextCandidates: [] });
    return evaluateRefreshMembershipGuard(diff, null).authorization;
  };
  assert.equal(roleOf([row(md5)]).required_role, 'admin', 'publisher-asserted Indicator');
  assert.equal(roleOf([row(md5, { review_status: 'approved' })]).required_role, 'admin', 'reviewed');
  assert.ok(roleOf([row(md5, { matched_ioc_id: 42 })]).categories.some((c) => c.code === 'ioc_linked_candidate_removed'), 'IOC-linked');
  // Fingerprint contract unchanged by the authorization fields.
  const d = buildRefreshMembershipDiff({ previousRows: [row(md5)], nextCandidates: [] });
  assert.match(d.material_fingerprint, /^[a-f0-9]{64}$/);
});

test('RBAC: a diff without the IOC-linked count (older payload) fails closed to admin', () => {
  const diff = lossDiff({ removed_indicators: 6 });
  delete diff.counts.ioc_linked_losses;
  assert.equal(evaluateRefreshMembershipGuard(diff, ACCEPT, { acceptorRole: 'analyst' }).decision, REFRESH_GUARD_DECISIONS.BLOCK);
});

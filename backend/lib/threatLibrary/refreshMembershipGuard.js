/**
 * Refresh extraction membership guard (tl-refresh-guard-v1).
 *
 * Before a Refresh extraction reconciles a new candidate set, the report
 * Indicator membership it would produce is compared with the stored one. The
 * diff (added / removed Indicators, newly Context Only rows, classification
 * changes with reason codes, analyst-reviewed rows that would be deleted, MODE
 * change, new quality warnings) is recorded with every refresh.
 *
 * Material unexpected losses are PROTECTED: the refresh is not applied unless
 * the request carries an explicit, audited acceptance (policy `accept` with a
 * reason). Everything else — additions, ordinary reclassification, newly
 * contextual rows — applies as before. The guard only decides whether to
 * apply; it never edits candidates, membership rules or analyst decisions.
 */

import { candidateColumns } from './store.js';
import { isContextOnlyCandidate, isReportIndicatorMember } from './indicatorMembership.js';

export const REFRESH_GUARD_VERSION = 'tl-refresh-guard-v1';

export const REFRESH_MEMBERSHIP_POLICIES = Object.freeze({
  /** Default: material membership losses block the refresh. */
  PROTECT: 'protect',
  /** Explicit, audited acceptance of the previewed changes (requires a reason). */
  ACCEPT: 'accept'
});

export const REFRESH_GUARD_DECISIONS = Object.freeze({
  APPLY: 'apply',
  APPLY_ACCEPTED: 'apply_accepted',
  BLOCK: 'block'
});

/** Stable reason codes. `material` reasons block under `protect`. */
export const REFRESH_GUARD_REASONS = Object.freeze({
  REVIEWED_INDICATOR_REMOVED: 'reviewed_indicator_removed',
  REVIEWED_CANDIDATE_DELETED: 'reviewed_candidate_deleted',
  PUBLISHER_ASSERTION_LOST: 'publisher_assertion_lost',
  BULK_MEMBERSHIP_LOSS: 'bulk_membership_loss',
  MEMBERSHIP_MODE_CHANGED: 'membership_mode_changed',
  NEW_QUALITY_WARNINGS: 'new_quality_warnings',
  ACCEPTANCE_REASON_MISSING: 'acceptance_reason_missing'
});

const MATERIAL_REASONS = new Set([
  REFRESH_GUARD_REASONS.REVIEWED_INDICATOR_REMOVED,
  REFRESH_GUARD_REASONS.REVIEWED_CANDIDATE_DELETED,
  REFRESH_GUARD_REASONS.PUBLISHER_ASSERTION_LOST,
  REFRESH_GUARD_REASONS.BULK_MEMBERSHIP_LOSS
]);

export const REFRESH_GUARD_THRESHOLDS = Object.freeze({
  /** A loss of at least this many Indicators AND this fraction of the prior set is a bulk loss. */
  bulkLossMinCount: 5,
  bulkLossMinFraction: 0.2,
  /** Bounded lists in the recorded diff. */
  maxListed: 100,
  /** Minimum characters of an acceptance reason. */
  acceptanceReasonMinChars: 8
});

const EXPLICIT = new Set(['explicit_ioc', 'explicit_c2', 'explicit_operational_infrastructure']);
const CREATED_OUTCOMES = new Set(['created', 'already_existing']);

const key = (c) => `${c.candidate_type}:${c.normalized_value}`;
const evidenceOf = (row) => (row?.evidence && typeof row.evidence === 'object' ? row.evidence : {});

/** Analyst-owned state: any review decision or a Create IOCs outcome. */
function isReviewed(row) {
  const review = String(row?.review_status || 'pending').toLowerCase();
  return review !== 'pending' || CREATED_OUTCOMES.has(String(row?.promotion_outcome || ''));
}

/** Persisted shape of a refreshed (not yet reconciled) candidate. */
function persistedShape(candidate) {
  const col = candidateColumns(candidate);
  return { ...col, promotion_outcome: candidate.promotion_outcome ?? null };
}

function stateOf(row) {
  if (!row) return null;
  const ev = evidenceOf(row);
  return {
    member: isReportIndicatorMember(row),
    context_only: isContextOnlyCandidate(row),
    source_assertion: row.source_assertion || ev.source_assertion || null,
    policy_decision: ev.policy_decision || null,
    assessment: row.assessment || null,
    is_ioc: row.is_ioc !== false,
    review_status: row.review_status || 'pending',
    mode: ev.document_has_authoritative_scope === true ? 'A' : 'B'
  };
}

function removalReason(before, after) {
  if (!after) return 'identity_left_document';
  if (EXPLICIT.has(String(before.source_assertion)) && !EXPLICIT.has(String(after.source_assertion))) return 'publisher_assertion_lost';
  if (after.context_only) return 'became_context_only';
  if (!after.is_ioc || after.assessment === 'invalid') return 'excluded_by_type_gate';
  if (before.mode === 'B' && after.mode === 'A') return 'mode_changed';
  return 'membership_rule';
}

function documentMode(states) {
  const list = states.filter(Boolean);
  if (!list.length) return null;
  return list.some((s) => s.mode === 'A') ? 'A' : 'B';
}

/**
 * Membership diff between the stored candidate rows and a refreshed set.
 * Linked-only rows (no original-document occurrence) are outside the refresh
 * scope: reconcile never deletes them, so they are not compared.
 * @param {{
 *   previousRows: object[],
 *   nextCandidates: object[],
 *   previousQuality?: object|null,
 *   nextQuality?: object|null
 * }} input
 */
export function buildRefreshMembershipDiff({ previousRows, nextCandidates, previousQuality = null, nextQuality = null }) {
  const L = REFRESH_GUARD_THRESHOLDS.maxListed;
  const prior = new Map(
    (previousRows || []).filter((r) => r.has_original_document_occurrence !== false).map((r) => [key(r), r])
  );
  const next = new Map((nextCandidates || []).map((c) => [key(c), persistedShape(c)]));
  const priorStates = new Map([...prior].map(([k, r]) => [k, stateOf(r)]));
  const nextStates = new Map([...next].map(([k, r]) => [k, stateOf(r)]));

  const added = [];
  const removed = [];
  const newlyContext = [];
  const changes = [];
  const reviewedDeleted = [];

  for (const [k, after] of nextStates) {
    const before = priorStates.get(k) || null;
    if (after.member && !before?.member) {
      added.push({ identity: k, previous: before, next: after, new_identity: !before });
    }
    if (before && after.context_only && !before.context_only) {
      newlyContext.push({ identity: k, policy_decision: after.policy_decision, previous_policy_decision: before.policy_decision });
    }
    if (before) {
      const fields = ['source_assertion', 'policy_decision', 'assessment', 'is_ioc'].filter((f) => before[f] !== after[f]);
      if (fields.length) {
        changes.push({
          identity: k,
          fields,
          from: Object.fromEntries(fields.map((f) => [f, before[f]])),
          to: Object.fromEntries(fields.map((f) => [f, after[f]])),
          reason_code: after.policy_decision || null
        });
      }
    }
  }
  for (const [k, before] of priorStates) {
    const row = prior.get(k);
    const after = nextStates.get(k) || null;
    if (!after && isReviewed(row)) {
      reviewedDeleted.push({ identity: k, review_status: row.review_status || 'pending', promotion_outcome: row.promotion_outcome || null });
    }
    if (before.member && !after?.member) {
      removed.push({
        identity: k,
        reason_code: removalReason(before, after),
        reviewed: isReviewed(row),
        review_status: row.review_status || 'pending',
        previous: { source_assertion: before.source_assertion, policy_decision: before.policy_decision },
        next: after ? { source_assertion: after.source_assertion, policy_decision: after.policy_decision, assessment: after.assessment } : null
      });
    }
  }

  const priorMembers = [...priorStates.values()].filter((s) => s.member).length;
  const nextMembers = [...nextStates.values()].filter((s) => s.member).length;
  const codesOf = (q) => new Set((q?.warnings || []).filter((w) => w.severity !== 'info').map((w) => w.code));
  const beforeCodes = codesOf(previousQuality);
  const afterCodes = codesOf(nextQuality);
  const sortById = (a, b) => a.identity.localeCompare(b.identity);
  return {
    version: REFRESH_GUARD_VERSION,
    indicators: { before: priorMembers, after: nextMembers },
    mode: { before: documentMode([...priorStates.values()]), after: documentMode([...nextStates.values()]) },
    added_indicators: added.sort(sortById).slice(0, L),
    removed_indicators: removed.sort(sortById).slice(0, L),
    newly_context_only: newlyContext.sort(sortById).slice(0, L),
    classification_changes: changes.sort(sortById).slice(0, L),
    reviewed_candidates_deleted: reviewedDeleted.sort(sortById).slice(0, L),
    quality: {
      before_status: previousQuality?.status || null,
      after_status: nextQuality?.status || null,
      new_warning_codes: [...afterCodes].filter((c) => !beforeCodes.has(c)).sort(),
      resolved_warning_codes: previousQuality ? [...beforeCodes].filter((c) => !afterCodes.has(c)).sort() : []
    },
    counts: {
      added_indicators: added.length,
      removed_indicators: removed.length,
      removed_reviewed_indicators: removed.filter((r) => r.reviewed).length,
      removed_publisher_asserted: removed.filter((r) => EXPLICIT.has(String(r.previous.source_assertion))).length,
      newly_context_only: newlyContext.length,
      classification_changes: changes.length,
      reviewed_candidates_deleted: reviewedDeleted.length
    }
  };
}

/**
 * Normalize a request / dispatch policy. Unknown input is `protect`.
 * @param {unknown} raw
 */
export function normalizeRefreshMembershipPolicy(raw) {
  const p = raw && typeof raw === 'object' ? raw : {};
  if (p.mode === REFRESH_MEMBERSHIP_POLICIES.ACCEPT) {
    return {
      mode: REFRESH_MEMBERSHIP_POLICIES.ACCEPT,
      reason: typeof p.reason === 'string' ? p.reason.trim().slice(0, 2000) : '',
      requested_by: p.requested_by || null,
      requested_at: p.requested_at || null
    };
  }
  return { mode: REFRESH_MEMBERSHIP_POLICIES.PROTECT };
}

/**
 * Decide whether a refresh may apply its diff.
 * @param {ReturnType<typeof buildRefreshMembershipDiff>} diff
 * @param {unknown} rawPolicy
 */
export function evaluateRefreshMembershipGuard(diff, rawPolicy) {
  const policy = normalizeRefreshMembershipPolicy(rawPolicy);
  const T = REFRESH_GUARD_THRESHOLDS;
  const reasons = [];
  const c = diff.counts;
  if (c.removed_reviewed_indicators > 0) {
    reasons.push({
      code: REFRESH_GUARD_REASONS.REVIEWED_INDICATOR_REMOVED,
      count: c.removed_reviewed_indicators,
      detail: 'Indicators an analyst already reviewed (approved / created / decided) would leave the Indicators set.'
    });
  }
  if (c.reviewed_candidates_deleted > 0) {
    reasons.push({
      code: REFRESH_GUARD_REASONS.REVIEWED_CANDIDATE_DELETED,
      count: c.reviewed_candidates_deleted,
      detail: 'Candidates with an analyst decision would no longer be extracted, and the row with that decision would be removed.'
    });
  }
  if (c.removed_publisher_asserted > 0) {
    reasons.push({
      code: REFRESH_GUARD_REASONS.PUBLISHER_ASSERTION_LOST,
      count: c.removed_publisher_asserted,
      detail: 'Publisher-asserted Indicators (explicit IOC / C2 / operational rows) would leave the Indicators set.'
    });
  }
  if (c.removed_indicators >= T.bulkLossMinCount && diff.indicators.before > 0 && c.removed_indicators / diff.indicators.before >= T.bulkLossMinFraction) {
    reasons.push({
      code: REFRESH_GUARD_REASONS.BULK_MEMBERSHIP_LOSS,
      count: c.removed_indicators,
      detail: `${c.removed_indicators} of ${diff.indicators.before} Indicators would be removed.`
    });
  }
  if (diff.mode.before && diff.mode.after && diff.mode.before !== diff.mode.after) {
    reasons.push({
      code: REFRESH_GUARD_REASONS.MEMBERSHIP_MODE_CHANGED,
      count: 1,
      detail: `Membership mode would change from ${diff.mode.before} to ${diff.mode.after}.`
    });
  }
  if (diff.quality.new_warning_codes.length) {
    reasons.push({
      code: REFRESH_GUARD_REASONS.NEW_QUALITY_WARNINGS,
      count: diff.quality.new_warning_codes.length,
      detail: `New extraction quality warnings: ${diff.quality.new_warning_codes.join(', ')}.`
    });
  }
  const material = reasons.filter((r) => MATERIAL_REASONS.has(r.code));
  const tagged = reasons.map((r) => ({ ...r, material: MATERIAL_REASONS.has(r.code) }));
  let decision = REFRESH_GUARD_DECISIONS.APPLY;
  if (material.length) {
    if (policy.mode === REFRESH_MEMBERSHIP_POLICIES.ACCEPT && policy.reason.length >= T.acceptanceReasonMinChars) {
      decision = REFRESH_GUARD_DECISIONS.APPLY_ACCEPTED;
    } else {
      decision = REFRESH_GUARD_DECISIONS.BLOCK;
      if (policy.mode === REFRESH_MEMBERSHIP_POLICIES.ACCEPT) {
        tagged.push({
          code: REFRESH_GUARD_REASONS.ACCEPTANCE_REASON_MISSING,
          count: 1,
          material: true,
          detail: `Accepting membership changes needs a reason of at least ${T.acceptanceReasonMinChars} characters.`
        });
      }
    }
  }
  return {
    version: REFRESH_GUARD_VERSION,
    decision,
    policy: policy.mode,
    ...(decision === REFRESH_GUARD_DECISIONS.APPLY_ACCEPTED
      ? { accepted: { reason: policy.reason, requested_by: policy.requested_by, requested_at: policy.requested_at } }
      : {}),
    reasons: tagged,
    material: material.length > 0,
    message:
      decision === REFRESH_GUARD_DECISIONS.BLOCK
        ? `Refresh blocked: ${material.map((r) => `${r.code} (${r.count})`).join(', ')}. Review the preview and re-run with an explicit acceptance and reason to apply.`
        : decision === REFRESH_GUARD_DECISIONS.APPLY_ACCEPTED
          ? 'Membership changes accepted explicitly.'
          : 'No material membership loss.'
  };
}

/**
 * Bounded record for analysis_progress.last_refresh / job progress / audit.
 * @param {ReturnType<typeof buildRefreshMembershipDiff>} diff
 * @param {number} [limit]
 */
export function compactRefreshMembershipDiff(diff, limit = 40) {
  if (!diff) return null;
  const cut = (list) => (list || []).slice(0, limit);
  return {
    version: diff.version,
    indicators: diff.indicators,
    mode: diff.mode,
    counts: diff.counts,
    quality: diff.quality,
    added_indicators: cut(diff.added_indicators).map((x) => x.identity),
    removed_indicators: cut(diff.removed_indicators).map((x) => ({
      identity: x.identity,
      reason_code: x.reason_code,
      reviewed: x.reviewed,
      review_status: x.review_status,
      previous_source_assertion: x.previous.source_assertion
    })),
    newly_context_only: cut(diff.newly_context_only).map((x) => ({ identity: x.identity, policy_decision: x.policy_decision })),
    classification_changes: cut(diff.classification_changes),
    reviewed_candidates_deleted: cut(diff.reviewed_candidates_deleted)
  };
}

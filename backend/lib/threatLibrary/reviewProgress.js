/**
 * Canonical Threat Library report review progress (tl-review-progress-v1).
 *
 * Scope = the report's effective Indicator inventory U = A ∪ B, where
 *   A = original publisher-document Indicators (isReportIndicatorMember)
 *   B = linked IOC Source Indicators            (isLinkedSourceIndicatorMember)
 * counted once per canonical identity (candidate_type, normalized_value) —
 * the same set as `total_unique_indicator_count`. Context-only, non-IOC,
 * reserved and other non-members never enter the denominator.
 *
 * Reviewed = a completed analyst decision persisted on the candidate row
 * (review_status approved / created_ioc / ignored / rejected). That per-IOC
 * row is the most granular decision TalonHound stores: approving an IOC Source
 * only attaches it and authorizes extraction ("it does not approve IOCs into
 * inventory", migration 041), so source state alone never marks an Indicator
 * reviewed. In addition, a linked-only Indicator counts as reviewed only when
 * at least one of its IOC Sources carries a persisted analyst acceptance
 * (`approved_at`). An identity that is also an original Indicator follows the
 * original review workflow (its own decision is enough). Neither a global IOC
 * match (`matched_ioc_id` / match_state) nor the mere existence of a source
 * link is a decision.
 *
 *   total    = |U|
 *   reviewed = |{ u ∈ U : decided(u) ∧ (u ∈ A ∨ acceptedSource(u)) }|
 *   pending  = total − reviewed          (0 ≤ reviewed ≤ total)
 */

import {
  isLinkedSourceIndicatorMember,
  isReportIndicatorMember,
  linkedSourceIndicatorMembershipSql,
  reportIndicatorMembershipSql
} from './indicatorMembership.js';

export const REVIEW_PROGRESS_CONTRACT = 'tl-review-progress-v1';

/**
 * review_status values that record a completed analyst decision on an
 * Indicator. `context_only` is a decision too, but it removes the row from
 * Indicator membership, so it never reaches this predicate.
 */
export const COMPLETED_REVIEW_STATUSES = Object.freeze(['approved', 'created_ioc', 'ignored', 'rejected']);

const COMPLETED_SET = new Set(COMPLETED_REVIEW_STATUSES);

export function isCompletedReviewDecision(candidate) {
  return COMPLETED_SET.has(String(candidate?.review_status || 'pending').toLowerCase());
}

/** Persisted analyst acceptance of an IOC Source (approve → attached). */
export function isAcceptedIocSource(source) {
  if (!source) return false;
  if (source.accepted === true) return true;
  return source.approved_at != null && source.approved_at !== '';
}

function identityKey(candidate) {
  return `${String(candidate?.candidate_type || '').toLowerCase()}\0${String(candidate?.normalized_value || '')}`;
}

function emptyBucket() {
  return { total: 0, reviewed: 0, pending: 0 };
}

/**
 * Pure mirror of the SQL in loadReportReviewProgress (tests / parity).
 * Each candidate may carry `sources: [{ approved_at | accepted }]`.
 * @param {object[]} candidates
 */
export function summarizeReviewProgress(candidates) {
  const byIdentity = new Map();
  for (const c of Array.isArray(candidates) ? candidates : []) {
    const original = isReportIndicatorMember(c);
    const linked = isLinkedSourceIndicatorMember(c);
    if (!original && !linked) continue;
    const key = identityKey(c);
    const prev = byIdentity.get(key) || { original: false, linked: false, decided: false, accepted: false, reviewed: false };
    const decided = isCompletedReviewDecision(c);
    const accepted = (Array.isArray(c.sources) ? c.sources : []).some(isAcceptedIocSource);
    const next = {
      original: prev.original || original,
      linked: prev.linked || linked,
      decided: prev.decided || decided,
      accepted: prev.accepted || accepted,
      reviewed: prev.reviewed || (decided && (original || accepted))
    };
    byIdentity.set(key, next);
  }
  return finalizeProgress([...byIdentity.values()].map((i) => ({
    is_original: i.original,
    is_linked: i.linked,
    decided: i.decided,
    reviewed: i.reviewed,
    n: 1
  })));
}

/** @param {{ is_original: boolean, is_linked: boolean, decided: boolean, reviewed: boolean, n?: number }[]} identities */
function finalizeProgress(identities) {
  const out = {
    contract: REVIEW_PROGRESS_CONTRACT,
    total: 0,
    reviewed: 0,
    pending: 0,
    original: emptyBucket(),
    linked_only: { ...emptyBucket(), decided_without_accepted_source: 0 },
    overlap: 0
  };
  for (const i of identities) {
    const n = Number(i?.n) || 0;
    out.total += n;
    if (i.reviewed) out.reviewed += n;
    const bucket = i.is_original ? out.original : out.linked_only;
    bucket.total += n;
    if (i.reviewed) bucket.reviewed += n;
    if (i.is_original && i.is_linked) out.overlap += n;
    if (!i.is_original && i.decided && !i.reviewed) out.linked_only.decided_without_accepted_source += n;
  }
  out.pending = out.total - out.reviewed;
  out.original.pending = out.original.total - out.original.reviewed;
  out.linked_only.pending = out.linked_only.total - out.linked_only.reviewed;
  return out;
}

/**
 * One grouped query over the report's candidate rows (idx_threat_report_candidates_report)
 * plus an EXISTS over that report's link rows / sources only (never other reports'
 * links). No global IOC table access, no per-Indicator round trips.
 */
export function reviewProgressSql() {
  const completed = COMPLETED_REVIEW_STATUSES.map((s) => `'${s}'`).join(', ');
  return `
    WITH m AS (
      SELECT
        c.candidate_type,
        c.normalized_value,
        (${reportIndicatorMembershipSql('c')}) AS is_original,
        (${linkedSourceIndicatorMembershipSql('c')}) AS is_linked,
        (c.review_status IN (${completed})) AS decided,
        EXISTS (
          SELECT 1
          FROM threat_report_candidate_source_links al
          JOIN threat_report_ioc_sources s ON s.id = al.source_id
          WHERE al.candidate_id = c.id AND s.report_id = $1 AND s.approved_at IS NOT NULL
        ) AS accepted_source
      FROM threat_report_candidates c
      WHERE c.report_id = $1
    ),
    ident AS (
      SELECT
        candidate_type,
        normalized_value,
        bool_or(is_original) AS is_original,
        bool_or(is_linked) AS is_linked,
        bool_or(decided) AS decided,
        bool_or(decided AND (is_original OR accepted_source)) AS reviewed
      FROM m
      WHERE is_original OR is_linked
      GROUP BY candidate_type, normalized_value
    )
    SELECT is_original, is_linked, decided, reviewed, COUNT(*)::int AS n
    FROM ident
    GROUP BY is_original, is_linked, decided, reviewed`;
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} pool
 * @param {number} reportId
 */
export async function loadReportReviewProgress(pool, reportId) {
  const { rows } = await pool.query(reviewProgressSql(), [reportId]);
  return finalizeProgress(Array.isArray(rows) ? rows : []);
}

/**
 * Guarded finalization (tl-finalize-guard-v1).
 *
 * A finalized report is the analyst's statement that its Indicator inventory
 * is complete. A publisher that delegates indicators to a linked IOC Source
 * (STIX / CSV / repository pack) has an incomplete Union until that pack is
 * extracted, so every linked source that is not explicitly disposed blocks
 * finalization:
 *
 *   resolved   extracted, or dismissed (audited analyst disposition: the
 *              pack is intentionally omitted)
 *   pending    discovered / inspecting / inspected / attached / extracting
 *   unresolved failed / unsupported / blocked / stale
 *
 * Discovery records only scored IOC-pack links (never every reference link),
 * so a recorded source is a required one; a wrongly discovered link is
 * resolved by dismissing it. A finalized report is never reopened: a pack
 * attached after finalization stays reviewable, and these rules only gate the
 * act of finalizing.
 *
 * The guard is enforced in the single write path (reviewService.finalizeReport
 * — HTTP and MCP) by one conditional UPDATE, so a concurrent candidate or
 * source change can never slip between check and write. An administrator may
 * override the source rule with a written reason; the override is audited and
 * never available to MCP.
 */

import { ROLES } from '../rbac.js';
import { reviewActionableIndicatorSql } from './indicatorMembership.js';

export const FINALIZE_GUARD_VERSION = 'tl-finalize-guard-v1';

export const FINALIZE_BLOCKER_CODES = Object.freeze({
  PENDING_REVIEW: 'pending_review_remaining',
  LINKED_SOURCES: 'linked_ioc_sources_unresolved',
  STATE_CHANGED: 'finalize_state_changed'
});

export const LINKED_SOURCE_PENDING_STATUSES = Object.freeze(['discovered', 'inspecting', 'inspected', 'attached', 'extracting']);
export const LINKED_SOURCE_UNRESOLVED_STATUSES = Object.freeze(['failed', 'unsupported', 'blocked', 'stale']);
export const LINKED_SOURCE_OPEN_STATUSES = Object.freeze([...LINKED_SOURCE_PENDING_STATUSES, ...LINKED_SOURCE_UNRESOLVED_STATUSES]);

const PENDING = new Set(LINKED_SOURCE_PENDING_STATUSES);
const UNRESOLVED = new Set(LINKED_SOURCE_UNRESOLVED_STATUSES);

/** Minimum length of an administrator's written override reason. */
export const OVERRIDE_REASON_MIN_LENGTH = 12;

/**
 * Open linked sources of a report (pure).
 * @param {Array<{ public_id?: string, lifecycle_status?: string, original_url?: string, canonical_url?: string, error_code?: string|null }>} sources
 */
export function openLinkedSources(sources) {
  const out = [];
  for (const s of Array.isArray(sources) ? sources : []) {
    const status = String(s?.lifecycle_status || '').toLowerCase();
    if (!PENDING.has(status) && !UNRESOLVED.has(status)) continue;
    out.push({
      public_id: s.public_id || null,
      lifecycle_status: status,
      state: PENDING.has(status) ? 'pending' : 'unresolved',
      url: s.canonical_url || s.original_url || null,
      error_code: s.error_code || null
    });
  }
  return out;
}

/**
 * Finalize blockers for a candidate pending count and the report's sources (pure).
 * @param {{ pendingCount: number, sources: object[], sourceOverride?: boolean }} input
 * @returns {Array<{ code: string, message: string, pending_count?: number, sources?: object[] }>}
 */
export function finalizeBlockers({ pendingCount = 0, sources = [], sourceOverride = false } = {}) {
  const blockers = [];
  if (pendingCount > 0) {
    blockers.push({
      code: FINALIZE_BLOCKER_CODES.PENDING_REVIEW,
      message: `${pendingCount} indicator${pendingCount === 1 ? '' : 's'} still need review.`,
      pending_count: pendingCount
    });
  }
  const open = openLinkedSources(sources);
  if (open.length && !sourceOverride) {
    const pending = open.filter((s) => s.state === 'pending').length;
    blockers.push({ ...linkedSourceBlocker({ pending, unresolved: open.length - pending }), sources: open });
  }
  return blockers;
}

/**
 * The linked-source blocker from counts (summarizeLinkedIocSources shape), so
 * read-only gate previews (MCP workflow status) state exactly what the write
 * path enforces. Null when nothing is open.
 * @param {{ pending?: number, unresolved?: number }|null|undefined} counts
 */
export function linkedSourceBlocker(counts) {
  const pending = Number(counts?.pending || 0);
  const unresolved = Number(counts?.unresolved || 0);
  const open = pending + unresolved;
  if (!open) return null;
  const them = open === 1 ? 'it' : 'them';
  return {
    code: FINALIZE_BLOCKER_CODES.LINKED_SOURCES,
    message: `${open} linked IOC Source${open === 1 ? ' is' : 's are'} not resolved ` +
      `(${pending} pending, ${unresolved} failed or unsupported): extract ${them}, or dismiss ${them} ` +
      'to record that the pack is intentionally omitted.',
    pending_count_sources: pending,
    unresolved_count_sources: unresolved
  };
}

/**
 * Validate an administrator override request (pure).
 * @param {{ reason?: string }|null|undefined} override
 * @param {{ role?: string }|null|undefined} actor
 * @returns {{ ok: true, reason: string } | { ok: false, status: number, code: string, error: string } | null}
 */
export function validateSourceOverride(override, actor) {
  if (!override) return null;
  const role = String(actor?.role || '').toLowerCase();
  if (role !== ROLES.ADMIN) {
    return { ok: false, status: 403, code: 'finalize_override_forbidden', error: 'Only an administrator can finalize over unresolved IOC Sources.' };
  }
  const reason = String(override.reason || '').trim();
  if (reason.length < OVERRIDE_REASON_MIN_LENGTH) {
    return {
      ok: false,
      status: 400,
      code: 'finalize_override_reason_required',
      error: `An override needs a written reason (at least ${OVERRIDE_REASON_MIN_LENGTH} characters).`
    };
  }
  return { ok: true, reason: reason.slice(0, 1000) };
}

/**
 * The finalize write: one statement that re-checks both rules against the
 * committed state and finalizes only when they hold. $1 report id,
 * $2 source override (boolean), $3 open source statuses (text[]).
 */
export const GUARDED_FINALIZE_SQL = `UPDATE threat_reports r
   SET import_status = 'ready',
       analysis_status = 'ready',
       updated_at = NOW(),
       finalized_at = NOW()
 WHERE r.id = $1
   AND NOT EXISTS (
     SELECT 1 FROM threat_report_candidates c
      WHERE c.report_id = r.id
        AND COALESCE(c.review_status, 'pending') = 'pending'
        AND ${reviewActionableIndicatorSql('c')}
   )
   AND ($2::boolean OR NOT EXISTS (
     SELECT 1 FROM threat_report_ioc_sources s
      WHERE s.report_id = r.id
        AND s.lifecycle_status = ANY($3::text[])
   ))
 RETURNING r.*`;

/**
 * Load the report's linked sources for blocker messages.
 * @param {{ query: Function }} pool
 * @param {number} reportId
 */
export async function loadReportSources(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT public_id, lifecycle_status, original_url, canonical_url, error_code
       FROM threat_report_ioc_sources WHERE report_id = $1 ORDER BY id`,
    [reportId]
  );
  return rows;
}

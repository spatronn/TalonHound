/**
 * Linked IOC Source assertion over a body "deferral" (tl-linked-overlay-v1).
 *
 * A report whose IOC section points at an external pack ("IOCs for this
 * research can be found in our GitHub repository") delegates its inventory:
 * body mentions of those values stay Context Only with
 * `context_only_narrative_with_authoritative_scope` — "not asserted here",
 * not a stance about the value. When the delegated pack then lists the same
 * identity, the pack's assertion is the publisher's, so the overlap row takes
 * the linked assessment. Any other Context Only reading (benign component,
 * provider, reference, negative zone) and every analyst decision still win.
 */

/** Body policies that only mean "the publisher listed its IOCs elsewhere". */
export const DEFERRED_CONTEXT_POLICIES = Object.freeze(new Set(['context_only_narrative_with_authoritative_scope']));

function evidenceOf(row) {
  const ev = row?.evidence;
  if (ev && typeof ev === 'object') return ev;
  if (typeof ev === 'string') {
    try {
      return JSON.parse(ev) || {};
    } catch {
      return {};
    }
  }
  return {};
}

/**
 * True when a linked pack's assertion replaces this body row's Context Only
 * reading: the row is still pending, its only Context Only reason is the
 * deferral policy, and the linked candidate itself asserts the value.
 * @param {object} prior persisted original-document candidate row
 * @param {object} linked linked-source candidate columns for the same identity
 */
export function linkedAssertionOverridesDeferral(prior, linked) {
  if (!prior || !linked) return false;
  if (String(prior.review_status || 'pending') !== 'pending') return false;
  if (prior.assessment !== 'context_only') return false;
  const policy = String(evidenceOf(prior).policy_decision || '');
  if (!DEFERRED_CONTEXT_POLICIES.has(policy)) return false;
  return linked.assessment !== 'context_only' && linked.assessment !== 'invalid' && linked.is_ioc !== false;
}

/**
 * The overlap row's evidence with the override recorded (provenance only).
 * @param {object} prior
 * @param {{ sourceId?: number|null }} meta
 */
export function overlayEvidence(prior, meta = {}) {
  const ev = evidenceOf(prior);
  return {
    ...ev,
    linked_assertion_over_deferral: {
      source_id: meta.sourceId ?? null,
      prior_assessment: prior.assessment,
      prior_role: prior.role || null,
      prior_policy_decision: ev.policy_decision || null
    }
  };
}

/**
 * Refresh: a recomputed body candidate falls back to the deferral reading; a
 * prior row that carried the linked override keeps it (the pack still asserts
 * the identity — its links are untouched by a document refresh).
 * @param {object[]} candidates refreshed candidates
 * @param {object[]} previousRows persisted rows before the refresh
 */
export function reapplyLinkedOverlay(candidates, previousRows) {
  const prior = new Map();
  for (const row of previousRows || []) {
    const ev = evidenceOf(row);
    if (ev.linked_assertion_over_deferral) prior.set(`${row.candidate_type}\0${row.normalized_value}`, row);
  }
  if (!prior.size) return candidates;
  return candidates.map((c) => {
    const row = prior.get(`${c.candidate_type}\0${c.normalized_value}`);
    if (!row) return c;
    const pending = String(c.review_status || 'pending') === 'pending';
    if (!pending || c.assessment !== 'context_only' || !DEFERRED_CONTEXT_POLICIES.has(String(c.policy_decision || evidenceOf(c).policy_decision || ''))) {
      return c;
    }
    const marker = evidenceOf(row).linked_assertion_over_deferral;
    return {
      ...c,
      assessment: row.assessment,
      role: row.role,
      match_state: row.match_state === 'context_only' ? 'new' : row.match_state,
      is_ioc: true,
      linked_assertion_over_deferral: marker,
      evidence: c.evidence && typeof c.evidence === 'object' ? { ...c.evidence, linked_assertion_over_deferral: marker } : c.evidence
    };
  });
}

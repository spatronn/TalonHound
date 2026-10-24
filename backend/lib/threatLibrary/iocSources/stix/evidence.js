/**
 * Shared structured evidence model for STIX XML / STIX JSON IOC Source parsing.
 * Parsing success ≠ Indicator authority.
 */

export const EVIDENCE_MEMBERSHIP = Object.freeze({
  INDICATOR: 'indicator',
  CONTEXT_ONLY: 'context_only',
  EXCLUDED: 'excluded',
  UNCERTAIN: 'uncertain',
  UNSUPPORTED: 'unsupported'
});

/**
 * @typedef {object} StixEvidence
 * @property {string} original_value
 * @property {string} normalized_value
 * @property {string} observable_type
 * @property {string} source_format  stix_json | stix_xml
 * @property {string|null} stix_object_id
 * @property {string|null} evidence_locator
 * @property {string} object_semantics  indicator | observed_data | sco | relationship | metadata | cybox_observable
 * @property {string} evidence_role
 * @property {string} membership  EVIDENCE_MEMBERSHIP
 * @property {string[]} diagnostics
 * @property {object} [meta]
 */

/**
 * @param {Partial<StixEvidence> & { original_value: string, normalized_value: string, observable_type: string, membership: string }} partial
 * @returns {StixEvidence}
 */
export function createStixEvidence(partial) {
  return {
    original_value: partial.original_value,
    normalized_value: partial.normalized_value,
    observable_type: partial.observable_type,
    source_format: partial.source_format || 'stix_json',
    stix_object_id: partial.stix_object_id ?? null,
    evidence_locator: partial.evidence_locator ?? null,
    object_semantics: partial.object_semantics || 'indicator',
    evidence_role: partial.evidence_role || 'malicious_infrastructure',
    membership: partial.membership,
    diagnostics: Array.isArray(partial.diagnostics) ? partial.diagnostics.slice(0, 20) : [],
    meta: partial.meta && typeof partial.meta === 'object' ? partial.meta : {}
  };
}

/**
 * Summarize evidence rows into classification buckets (unique by type+value per membership).
 * @param {StixEvidence[]} evidence
 */
export function summarizeEvidence(evidence) {
  const buckets = {
    indicator: 0,
    context_only: 0,
    excluded: 0,
    uncertain: 0,
    unsupported: 0
  };
  const seen = new Set();
  const diagnostics = [];
  for (const e of evidence || []) {
    const m = e.membership || EVIDENCE_MEMBERSHIP.UNSUPPORTED;
    if (buckets[m] != null) {
      const key = `${m}\0${e.observable_type}\0${e.normalized_value}`;
      if (!seen.has(key)) {
        seen.add(key);
        buckets[m] += 1;
      }
    }
    for (const d of e.diagnostics || []) {
      if (diagnostics.length < 40) diagnostics.push({ code: d, stix_object_id: e.stix_object_id, value: e.normalized_value });
    }
  }
  return { classification: buckets, diagnostics };
}

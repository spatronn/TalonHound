/**
 * Evidence tiers + promotion policy for Threat Library candidates.
 *
 * Deterministic decisions (no AI needed):
 *  - explicit IOC / C2 section occurrence → malicious, strong source assertion
 *  - only reference / source / footer occurrences → context_only
 *  - filename / code identifier / non-network → excluded from IOC review
 * Everything else is a body mention the model must classify (ai_needed).
 *
 * Confidence alone is never sufficient for malicious batch approval.
 */

import { NEGATIVE_ZONES, STRONG_IOC_ZONES, evidenceTierForZone } from './documentZones.js';
import { CONFIDENCE_POLICY } from './constants.js';

export const EVIDENCE_TIERS = Object.freeze({
  A: 'explicit_ioc_assertion',
  B: 'direct_malicious_behavior',
  C: 'contextual_mention',
  D: 'negative_context_only'
});

export const SOURCE_ASSERTIONS = Object.freeze({
  EXPLICIT_IOC: 'explicit_ioc',
  EXPLICIT_C2: 'explicit_c2',
  BODY_MENTION: 'body_mention',
  REFERENCE_ONLY: 'reference_only',
  SOURCE_METADATA: 'source_metadata',
  NON_IOC: 'non_ioc'
});

/** Confidence assigned to an explicit report assertion (report says it is an IOC). */
export const EXPLICIT_ASSERTION_CONFIDENCE = 0.9;

const MALICIOUS_ROLES = new Set([
  'command_and_control',
  'redirector',
  'payload_hosting',
  'malware_download',
  'phishing',
  'tracking',
  'malicious_infrastructure',
  'delivery',
  'malware_sample'
]);

const HASH_TYPES = new Set(['md5', 'sha1', 'sha256']);

/**
 * @param {object} candidate
 * @returns {'A'|'B'|'C'|'D'}
 */
export function strongestEvidenceTier(candidate) {
  const occ = Array.isArray(candidate.occurrences) ? candidate.occurrences : [];
  if (!occ.length) {
    return evidenceTierForZone(candidate.zone || candidate.section);
  }
  let best = 'D';
  const rank = { A: 4, B: 3, C: 2, D: 1 };
  for (const o of occ) {
    const t = evidenceTierForZone(o.zone || o.section_kind);
    if (rank[t] > rank[best]) best = t;
  }
  return best;
}

/**
 * Aggregate occurrence zones into promotion flags.
 * @param {object} candidate
 */
export function summarizeOccurrenceEvidence(candidate) {
  const occ = Array.isArray(candidate.occurrences) ? candidate.occurrences : [];
  const zones = occ.map((o) => o.zone || o.section_kind).filter(Boolean);
  if (!zones.length && candidate.zone) zones.push(candidate.zone);

  const hasStrong = zones.some((z) => STRONG_IOC_ZONES.has(z));
  const hasC2 = zones.some((z) => z === 'c2_section');
  const hasBody = zones.some((z) => z === 'report_body' || z === 'unknown' || z === 'code');
  const onlyNegative = zones.length > 0 && zones.every((z) => NEGATIVE_ZONES.has(z));
  const hasEndpoint = occ.some((o) => o.form === 'ip_port' || o.port != null);

  return {
    zones,
    hasStrong,
    hasC2,
    hasBody,
    hasEndpoint,
    onlyNegative,
    tier: strongestEvidenceTier({ ...candidate, occurrences: occ.length ? occ : [{ zone: candidate.zone }] })
  };
}

function deterministicRole(candidate, summary) {
  if (HASH_TYPES.has(String(candidate.candidate_type))) return 'malware_sample';
  if (summary.hasC2 || summary.hasEndpoint) return 'command_and_control';
  return 'malicious_infrastructure';
}

/**
 * Apply structural evidence constraints (optionally merging an AI update).
 * @param {object} candidate — mutable candidate record
 * @param {object} [aiUpdate]
 */
export function applyEvidencePolicy(candidate, aiUpdate = null) {
  const summary = summarizeOccurrenceEvidence(candidate);
  const resolvedType = candidate.resolved_type || candidate.candidate_type;
  candidate.occurrence_count = Array.isArray(candidate.occurrences)
    ? candidate.occurrences.length
    : candidate.occurrence_count || 0;

  // Non-network artifacts never promote as IOC
  if (resolvedType === 'file_artifact' || resolvedType === 'code_identifier' || candidate.is_ioc === false) {
    candidate.assessment = 'context_only';
    candidate.role = resolvedType === 'code_identifier' ? 'tool' : 'reference';
    candidate.match_state = 'context_only';
    candidate.is_ioc = false;
    candidate.evidence_tier = summary.tier;
    candidate.evidence_summary = summary;
    candidate.policy_decision = 'ioc_excluded_non_network';
    candidate.source_assertion = SOURCE_ASSERTIONS.NON_IOC;
    candidate.evidence_strength = 'none';
    candidate.ai_needed = false;
    candidate.decision_source = 'deterministic';
    return candidate;
  }

  // Filename/code mis-typed as domain that slipped through
  if (
    candidate.candidate_type === 'domain' &&
    (candidate.typing_reason === 'file_extension' ||
      candidate.typing_reason === 'url_path_basename' ||
      candidate.typing_reason === 'camel_method' ||
      candidate.typing_reason === 'method_suffix')
  ) {
    candidate.assessment = 'context_only';
    candidate.is_ioc = false;
    candidate.match_state = 'context_only';
    candidate.policy_decision = 'ioc_excluded_typing';
    candidate.source_assertion = SOURCE_ASSERTIONS.NON_IOC;
    candidate.evidence_strength = 'none';
    candidate.ai_needed = false;
    candidate.decision_source = 'deterministic';
    candidate.evidence_tier = summary.tier;
    candidate.evidence_summary = summary;
    return candidate;
  }

  const explicit = summary.hasStrong;
  const reportSource = candidate.is_report_source === true;

  if (aiUpdate) {
    if (explicit) {
      // The report already asserts this observable; the model may only refine role.
      if (aiUpdate.role && MALICIOUS_ROLES.has(String(aiUpdate.role))) candidate.role = aiUpdate.role;
      if (aiUpdate.confidence != null) {
        candidate.confidence = Math.max(Number(aiUpdate.confidence) || 0, EXPLICIT_ASSERTION_CONFIDENCE);
      }
      candidate.ai_role_suggestion = aiUpdate.role || null;
    } else {
      if (aiUpdate.assessment) candidate.assessment = aiUpdate.assessment;
      if (aiUpdate.role) candidate.role = aiUpdate.role;
      if (aiUpdate.confidence != null) candidate.confidence = aiUpdate.confidence;
      candidate.decision_source = 'ai';
    }
  }

  if (explicit && !reportSource) {
    candidate.assessment = 'malicious';
    if (!candidate.role || candidate.role === 'unknown' || !MALICIOUS_ROLES.has(String(candidate.role))) {
      candidate.role = deterministicRole(candidate, summary);
    }
    if (candidate.confidence == null || Number(candidate.confidence) < EXPLICIT_ASSERTION_CONFIDENCE) {
      candidate.confidence = EXPLICIT_ASSERTION_CONFIDENCE;
    }
    candidate.source_assertion = summary.hasC2 || summary.hasEndpoint
      ? SOURCE_ASSERTIONS.EXPLICIT_C2
      : SOURCE_ASSERTIONS.EXPLICIT_IOC;
    candidate.evidence_strength = 'strong';
    candidate.policy_decision = 'explicit_report_assertion';
    candidate.ai_needed = false;
    candidate.decision_source = candidate.decision_source === 'ai' ? 'deterministic' : (candidate.decision_source || 'deterministic');
    candidate.match_state = undefined;
  } else if (reportSource || summary.onlyNegative || candidate.rfc_example === true || candidate.reserved_address === true) {
    // Only negative zones (references / source / footer), RFC example names and
    // private / reserved address space → context_only
    candidate.assessment = 'context_only';
    if (!candidate.role || candidate.role === 'unknown' || MALICIOUS_ROLES.has(String(candidate.role))) {
      const onlyVendorNav = summary.zones.length > 0 && summary.zones.every((z) => z === 'vendor_about' || z === 'navigation');
      candidate.role = onlyVendorNav && !reportSource ? 'legitimate_service' : 'reference';
    }
    candidate.match_state = 'context_only';
    candidate.policy_decision = reportSource
      ? 'context_only_report_source'
      : candidate.reserved_address === true
        ? 'context_only_reserved_address'
        : candidate.rfc_example === true
          ? 'context_only_rfc_example'
          : 'context_only_negative_zone';
    candidate.source_assertion = reportSource || summary.zones.every((z) => z === 'source_metadata' || z === 'header_footer')
      ? SOURCE_ASSERTIONS.SOURCE_METADATA
      : SOURCE_ASSERTIONS.REFERENCE_ONLY;
    candidate.evidence_strength = 'none';
    candidate.ai_needed = false;
    candidate.decision_source = 'deterministic';
    if (candidate.confidence == null) candidate.confidence = 0.75;
  } else {
    // Body mention: semantic classification required unless the model already decided.
    candidate.source_assertion = SOURCE_ASSERTIONS.BODY_MENTION;
    candidate.evidence_strength = summary.hasEndpoint ? 'medium' : 'weak';
    candidate.policy_decision = 'pass';
    const decided = candidate.decision_source === 'ai' && candidate.assessment && candidate.assessment !== 'unknown';
    candidate.ai_needed = !decided;
    if (!candidate.decision_source) candidate.decision_source = 'pending';

    // AI said malicious but evidence is only Tier D → demote
    if (
      (candidate.assessment === 'malicious' || candidate.assessment === 'suspicious') &&
      summary.tier === 'D' &&
      !summary.hasStrong &&
      !summary.hasBody
    ) {
      candidate.assessment = 'context_only';
      candidate.role = 'reference';
      candidate.match_state = 'context_only';
      candidate.policy_decision = 'demoted_weak_evidence';
      candidate.ai_needed = false;
    }
  }

  candidate.evidence_tier = summary.tier;
  candidate.evidence_summary = summary;
  if (!candidate.policy_decision) candidate.policy_decision = 'pass';
  return candidate;
}

function isMaliciousRole(role) {
  return MALICIOUS_ROLES.has(String(role || ''));
}

export { isMaliciousRole };

/**
 * High-confidence batch approval eligibility.
 * @param {object} candidate
 */
export function isEligibleForHighConfidenceMalicious(candidate) {
  if (String(candidate.assessment) !== 'malicious') return false;
  if (candidate.is_ioc === false) return false;
  if (!['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'].includes(String(candidate.candidate_type))) {
    return false;
  }
  const conf = Number(candidate.confidence);
  if (!Number.isFinite(conf) || conf < CONFIDENCE_POLICY.AUTO_APPROVE_SUGGEST) return false;

  const summary = candidate.evidence_summary || summarizeOccurrenceEvidence(candidate);
  if (summary.onlyNegative || summary.tier === 'D') return false;
  // Require Tier A/B or body+malicious with confidence
  if (!(summary.hasStrong || summary.tier === 'A' || summary.tier === 'B' || summary.hasBody)) {
    return false;
  }
  if (candidate.policy_decision && String(candidate.policy_decision).startsWith('ioc_excluded')) {
    return false;
  }
  if (candidate.policy_decision === 'demoted_weak_evidence' || candidate.policy_decision === 'context_only_negative_zone') {
    return false;
  }
  return true;
}

/**
 * Compact, JSON-safe evidence record persisted with each candidate row.
 * @param {object} c
 */
export function buildCandidateEvidenceRecord(c) {
  const occurrences = (Array.isArray(c.occurrences) ? c.occurrences : []).slice(0, 40).map((o) => ({
    block_id: o.block_id || null,
    page: o.page ?? null,
    zone: o.zone || o.section_kind || null,
    section_heading: o.section_heading || null,
    form: o.form || 'standalone',
    port: o.port ?? null,
    table_row: o.table_row ?? null,
    surrounding_text: o.surrounding_text ? String(o.surrounding_text).slice(0, 200) : null
  }));
  const tableRows = (Array.isArray(c.table_rows) ? c.table_rows : []).slice(0, 20).map((r) => ({
    table_id: r.table_id || null,
    page: r.page ?? null,
    row_index: r.row_index ?? null,
    column_index: r.column_index ?? null,
    declared_type: r.declared_type || null,
    type_cell: r.type_cell ? String(r.type_cell).slice(0, 80) : null,
    indicator_cell: r.indicator_cell ? String(r.indicator_cell).slice(0, 300) : null,
    raw_value: r.raw_value ? String(r.raw_value).slice(0, 300) : null,
    description: r.description ? String(r.description).slice(0, 300) : null,
    explicit: r.explicit === true,
    declared_type_mismatch: r.declared_type_mismatch === true || undefined,
    related_values: Array.isArray(r.related_values) ? r.related_values.slice(0, 8) : undefined
  }));
  return {
    source_assertion: c.source_assertion || null,
    evidence_strength: c.evidence_strength || null,
    evidence_tier: c.evidence_tier || null,
    policy_decision: c.policy_decision || null,
    decision_source: c.decision_source || null,
    ai_needed: c.ai_needed === true,
    is_direct_source_observable: c.is_direct_source_observable !== false,
    is_parser_derived_metadata: c.is_parser_derived_metadata === true,
    derived_from: c.derived_from || null,
    resolved_type: c.resolved_type || c.candidate_type,
    typing_reason: c.typing_reason || null,
    occurrence_count: occurrences.length || c.occurrence_count || 0,
    zones: [...new Set(occurrences.map((o) => o.zone).filter(Boolean))],
    parsed: c.parsed && typeof c.parsed === 'object' ? c.parsed : {},
    ai_role_suggestion: c.ai_role_suggestion || null,
    table_rows: tableRows,
    occurrences
  };
}

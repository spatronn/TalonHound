/**
 * Evidence tiers + promotion policy for Threat Library candidates.
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
  // Body mention with malicious AI role can elevate to B later; structural max here
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
  const hasBody = zones.some((z) => z === 'report_body' || z === 'unknown' || z === 'code');
  const onlyNegative =
    zones.length > 0 && zones.every((z) => NEGATIVE_ZONES.has(z));

  return {
    zones,
    hasStrong,
    hasBody,
    onlyNegative,
    tier: strongestEvidenceTier({ ...candidate, occurrences: occ.length ? occ : [{ zone: candidate.zone }] })
  };
}

/**
 * Apply structural evidence constraints after AI assessment merge.
 * @param {object} candidate — mutable candidate record
 * @param {object} [aiUpdate]
 */
export function applyEvidencePolicy(candidate, aiUpdate = null) {
  const summary = summarizeOccurrenceEvidence(candidate);
  const resolvedType = candidate.resolved_type || candidate.candidate_type;

  // Non-network artifacts never promote as IOC
  if (resolvedType === 'file_artifact' || resolvedType === 'code_identifier' || candidate.is_ioc === false) {
    candidate.assessment = 'context_only';
    candidate.role = resolvedType === 'code_identifier' ? 'tool' : 'reference';
    candidate.match_state = 'context_only';
    candidate.is_ioc = false;
    candidate.evidence_tier = summary.tier;
    candidate.policy_decision = 'ioc_excluded_non_network';
    return candidate;
  }

  if (aiUpdate) {
    if (aiUpdate.assessment) candidate.assessment = aiUpdate.assessment;
    if (aiUpdate.role) candidate.role = aiUpdate.role;
    if (aiUpdate.confidence != null) candidate.confidence = aiUpdate.confidence;
  }

  // Only negative zones → force context_only / reference
  if (summary.onlyNegative) {
    candidate.assessment = 'context_only';
    if (!candidate.role || candidate.role === 'unknown' || isMaliciousRole(candidate.role)) {
      candidate.role = summary.zones.includes('reference_section') ? 'reference' : 'legitimate_service';
    }
    candidate.match_state = 'context_only';
    candidate.policy_decision = 'context_only_negative_zone';
  }

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
  }

  candidate.evidence_tier = summary.tier;
  candidate.evidence_summary = summary;
  if (!candidate.policy_decision) candidate.policy_decision = 'pass';
  return candidate;
}

function isMaliciousRole(role) {
  return [
    'command_and_control',
    'redirector',
    'payload_hosting',
    'malware_download',
    'phishing',
    'tracking',
    'malicious_infrastructure',
    'delivery'
  ].includes(String(role || ''));
}

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

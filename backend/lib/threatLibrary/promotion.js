/**
 * Threat Library IOC promotion eligibility.
 *
 * Approve = analyst accepts the candidate.
 * Create IOCs = materialize only approved, supported, new observables.
 * A CIDR Indicator is an `ip` / `ipv6` IOC record whose observable keeps the
 * canonical network and prefix (the ioc_items contract the EmergingThreats
 * network rows already use): never exploded into host IPs, never truncated to
 * a single address, never the same identity as a host IP.
 */

import {
  publisherAuthoritativeIocMembershipSql,
  isReportIndicatorMember,
  isUnionReportIndicatorMember,
  isPendingReviewActionableIndicator,
  isContextOnlyCandidate as isContextOnlyFromContract,
  notContextOnlySql,
  reviewActionableIndicatorSql,
  hasAuthoritativePublisherIocScope as hasPublisherScope,
  isPublisherAssertedReportIoc as isPublisherAsserted,
  isLinkedSourceAssertedIoc,
  NON_IOC_CANDIDATE_TYPES
} from './indicatorMembership.js';
import { parseNetworkObservable } from '../networkObservable.js';
import { refangTextForExtraction } from './defang.js';

export {
  hasAuthoritativePublisherIocScope,
  isPublisherAssertedReportIoc,
  isPublisherAuthoritativeReportIocMember,
  publisherAuthoritativeIocMembershipSql,
  isReportIndicatorMember,
  isReviewActionableIndicator,
  isUnionReportIndicatorMember,
  isPendingReviewActionableIndicator,
  reviewActionableIndicatorSql
} from './indicatorMembership.js';

export const PUBLISHER_AUTHORITATIVE_IOC_MEMBERSHIP_SQL = publisherAuthoritativeIocMembershipSql('c');

export const CREATABLE_IOC_TYPES = Object.freeze([
  'ip',
  'ipv6',
  'domain',
  'url',
  'md5',
  'sha1',
  'sha256',
  'cidr'
]);

const CREATABLE = new Set(CREATABLE_IOC_TYPES);
const NON_IOC_TYPES = new Set(NON_IOC_CANDIDATE_TYPES);

export const INVALID_NETWORK_DETAIL =
  'The value is not a valid IP address or network, so it cannot be stored as an IOC record.';

const NETWORK_CANDIDATE_TYPES = new Set(['ip', 'ipv6', 'cidr']);

/**
 * ioc_items identity (observable_type + canonical observable) of a creatable
 * candidate. Network values (ip / ipv6 / cidr) go through the IOC layer's
 * canonicalizer, so an IPv6 address is an `ipv6` IOC and a CIDR is an `ip` /
 * `ipv6` network IOC with its prefix; other types keep their stored value.
 * @returns {{ type: string, value: string } | null} null for an invalid network
 */
export function iocStorageIdentity(candidate) {
  const type = typeOf(candidate);
  const value = String(candidate?.normalized_value || '');
  if (!NETWORK_CANDIDATE_TYPES.has(type)) return { type, value };
  const network = parseNetworkObservable(value);
  if (!network || !network.ok) return null;
  // A cidr candidate must stay a network, a host candidate must stay a host.
  if ((type === 'cidr') !== (network.kind === 'cidr')) return null;
  return { type: network.type, value: network.value };
}

export const PROMOTION_OUTCOMES = Object.freeze({
  WILL_CREATE: 'will_create',
  CREATED: 'created',
  ALREADY_EXISTING: 'already_existing',
  UNSUPPORTED: 'unsupported',
  NOT_APPROVED: 'not_approved',
  NOT_APPLICABLE: 'not_applicable',
  FAILED: 'failed'
});

function reviewOf(candidate) {
  return String(candidate?.review_status || 'pending').toLowerCase();
}

function typeOf(candidate) {
  return String(candidate?.candidate_type || '').toLowerCase();
}

function evidenceOf(candidate) {
  return candidate?.evidence && typeof candidate.evidence === 'object' ? candidate.evidence : {};
}

export function isAnalystApproved(candidate) {
  const review = reviewOf(candidate);
  return review === 'approved' || review === 'created_ioc';
}

/**
 * Original-document Indicator membership (Indicators / Original filter).
 * Canonical implementation: indicatorMembership.isReportIndicatorMember.
 * For Approve / Create eligibility use isReviewActionableIndicator (union).
 */
export function isActionableReviewIndicator(candidate) {
  return isReportIndicatorMember(candidate);
}

export function isPendingActionableCandidate(candidate) {
  return isPendingReviewActionableIndicator(candidate);
}

/**
 * Context Only != IOC candidate. Canonical: indicatorMembership.isContextOnlyCandidate.
 */
export function isContextOnlyCandidate(candidate) {
  return isContextOnlyFromContract(candidate);
}

/** SQL predicate equivalent of isContextOnlyCandidate (negated) for `threat_report_candidates` rows. */
export const NOT_CONTEXT_ONLY_SQL = notContextOnlySql();

/**
 * Minimum length of an analyst corroboration that may stand in for a publisher
 * IOC-list assertion. The promote action stores and audits this text.
 */
export const PROMOTION_CORROBORATION_MIN = 12;

/**
 * Publisher policies that already say the value is not an IOC. Appearing in a
 * list does not override them unless the same evidence shows operational abuse
 * of this exact observable.
 */
const NEGATIVE_PUBLISHER_POLICIES = new Set([
  'context_only_provider_service',
  'context_only_legitimate_service_list',
  'demoted_provider_service',
  'context_only_reference_relation',
  'context_only_benign_component',
  'context_only_report_source',
  'context_only_rfc_example',
  'context_only_negative_zone',
  'context_only_truncated_duplicate',
  'context_only_hosts_file_entry',
  'context_only_email_domain',
  'context_only_reserved_address',
  'context_only_non_actionable_local',
  'context_only_reference_column',
  'context_only_table_description',
  'context_only_resolution_column'
]);

const PROVIDER_POLICIES = new Set([
  'context_only_provider_service',
  'context_only_legitimate_service_list',
  'demoted_provider_service'
]);

/**
 * The clause uses this observable as attacker infrastructure, a payload, a
 * phishing destination, or a service abused for that purpose. "Connects to"
 * is intentionally absent: a connectivity check uses the same verb.
 */
const POSITIVE_USE_RE =
  /\b(?:c2|c&c|c\s*&\s*c|command\s*(?:and|&)\s*control|beacon(?:s|ing|ed)?|payloads?|phish(?:ing|es|ed)?|malware\s+download|downloaded?\s+from|drops?\s+from|attacker[- ]controlled|malicious\s+(?:server|host|domain|url|ip|infrastructure|endpoint)|staging\s+server|(?:used|abused|leveraged)\s+to\s+(?:host|deliver|stage|phish|serve))\b/i;

/** A probe of whether the host is online, not a claim the destination is malicious. */
const CONNECTIVITY_RE =
  /\b(?:internet|network|outbound|external|online)\s+connectivity\b|\bconnectivity\s+(?:check|test)\b|\bby\s+resolving\b|\bresolv(?:e|es|ed|ing)\b[^.]{0,80}\b(?:connectivity|before\s+execut)/i;

/** C2 / payload / phishing in the same clause overrides a connectivity reading. */
const ABUSE_OVERRIDE_RE =
  /\b(?:c2|c&c|command\s+and\s+control|payload|phish\w*|attacker[- ]controlled|malicious\s+(?:server|host|domain|url|infrastructure))\b/i;

const DOCUMENTATION_RE =
  /\bdocumentation\s+(?:address|range|prefix|network)\b|\b(?:rfc\s+5737|rfc\s+3849|rfc\s+2606)\b/i;

const PLACEHOLDER_RE =
  /\{[^{}\s]{1,40}\}|\$[A-Z][A-Z0-9_]{1,40}\$|<(?:token|name|id|campaign|redacted)[^>\s]*>|%[0-9A-Za-z_]{2,40}%/i;

function occurrencesOf(candidate) {
  const ev = evidenceOf(candidate);
  if (Array.isArray(candidate?.occurrences) && candidate.occurrences.length) return candidate.occurrences;
  return Array.isArray(ev.occurrences) ? ev.occurrences : [];
}

function policyOf(candidate) {
  const ev = evidenceOf(candidate);
  return String(candidate?.policy_decision || ev.policy_decision || '').toLowerCase();
}

function relationOf(candidate) {
  const ev = evidenceOf(candidate);
  const top = String(candidate?.source_relation || ev.source_relation || '').toLowerCase();
  if (top) return top;
  for (const occ of occurrencesOf(candidate)) {
    const rel = String(occ?.source_relation || '').toLowerCase();
    if (rel === 'operational_malicious') return rel;
  }
  for (const occ of occurrencesOf(candidate)) {
    const rel = String(occ?.source_relation || '').toLowerCase();
    if (rel) return rel;
  }
  return '';
}

function clauseTexts(candidate) {
  const texts = [];
  for (const occ of occurrencesOf(candidate)) {
    const raw = occ?.surrounding_text || occ?.section_heading || '';
    if (raw) texts.push(refangTextForExtraction(String(raw)));
  }
  if (!texts.length && candidate?.evidence_text) {
    texts.push(refangTextForExtraction(String(candidate.evidence_text)));
  }
  return texts;
}

function hasOperationalEvidence(candidate) {
  if (relationOf(candidate) === 'operational_malicious') return true;
  if (occurrencesOf(candidate).some((occ) => String(occ?.relation_marker || '') === 'operational')) return true;
  return clauseTexts(candidate).some((text) => POSITIVE_USE_RE.test(text));
}

/** A column header / list name that labels its values as attacker infrastructure. */
const ROLE_COLUMN_HEADER_RE =
  /\b(?:spoof\w*|look-?alike|typo-?squat\w*|impersonat\w*|malicious|c2|c&c|command\s*(?:and|&)\s*control|phishing|attacker|actor[- ]controlled)\b/i;
const ROLE_LIST_NAME_RE = /(?:c2|cnc|payload|delivery|malicious|campaign|attacker|phish|exfil|beacon)/i;

/**
 * The publisher labelled the value's role outside its own sentence: the
 * column of a body table ("Spoofed domain (defanged)") or the name of a
 * hunting-query list (`let c2ip = dynamic([…])`, `deliveryHosts`,
 * `campaignSha256`). Evidence for an analyst promotion only — never
 * membership (tl-candidates-v48).
 */
function hasPublisherRoleLabel(candidate) {
  const ev = evidenceOf(candidate);
  const rows = Array.isArray(ev.table_rows) ? ev.table_rows : [];
  if (rows.some((r) => ROLE_COLUMN_HEADER_RE.test(String(r?.column_header || '')))) return true;
  return occurrencesOf(candidate).some((occ) => ROLE_LIST_NAME_RE.test(String(occ?.code_list_name || '')));
}

function isConnectivityCheck(candidate) {
  return clauseTexts(candidate).some((text) => CONNECTIVITY_RE.test(text) && !ABUSE_OVERRIDE_RE.test(text));
}

function isDocumentationContext(candidate) {
  const ev = evidenceOf(candidate);
  if (candidate?.rfc_example === true || ev.rfc_example === true) return true;
  if (policyOf(candidate).includes('documentation')) return true;
  return clauseTexts(candidate).some((text) => DOCUMENTATION_RE.test(text));
}

function isPlaceholderValue(candidate) {
  const policy = policyOf(candidate);
  if (policy.includes('template_placeholder') || policy.includes('placeholder')) return true;
  const value = String(candidate?.normalized_value || '');
  if (PLACEHOLDER_RE.test(value)) return true;
  return clauseTexts(candidate).some((text) => /template\s+placeholder|unfilled\s+placeholder/i.test(text) && PLACEHOLDER_RE.test(text));
}

/**
 * A domain or address whose every mention is only the host of a more specific
 * URL. The promotable identity is that URL, not the provider's whole name.
 * A structural publisher row of the bare host is its own identity.
 */
function evidenceSupportsOnlyNarrowerUrl(candidate) {
  const type = typeOf(candidate);
  if (type !== 'domain' && type !== 'ip' && type !== 'ipv6') return false;
  const host = String(candidate?.normalized_value || '').trim().toLowerCase();
  if (!host || host.includes('/')) return false;
  const occs = occurrencesOf(candidate);
  if (!occs.length) return false;
  if (occs.some((occ) => occ?.asserted === true && (occ?.structural_row === true || occ?.row_shape === true || occ?.form === 'list_row' || occ?.form === 'table_row'))) {
    return false;
  }
  const texts = clauseTexts(candidate);
  if (!texts.length) return false;
  return texts.every((text) => mentionsNarrowerUrl(text, host));
}

function mentionsNarrowerUrl(text, host) {
  const t = String(text || '').toLowerCase();
  const markers = [`https://${host}/`, `http://${host}/`, `https://www.${host}/`, `http://www.${host}/`];
  for (const marker of markers) {
    let from = 0;
    while (from < t.length) {
      const at = t.indexOf(marker, from);
      if (at < 0) break;
      const rest = t.slice(at + marker.length);
      if (rest.length && !/^[\s)\]>"']/.test(rest)) return true;
      from = at + marker.length;
    }
  }
  return false;
}

function publisherEvidenceSummary(candidate) {
  const ev = evidenceOf(candidate);
  const occ = occurrencesOf(candidate).find((row) => row?.surrounding_text) || occurrencesOf(candidate)[0] || null;
  const lines = [];
  const assertion = String(candidate?.source_assertion || ev.source_assertion || '').trim();
  if (assertion) lines.push(`Publisher assertion: ${assertion}`);
  const relation = relationOf(candidate);
  if (relation) lines.push(`Relation: ${relation}`);
  const policy = policyOf(candidate);
  if (policy) lines.push(`Policy: ${policy}`);
  if (occ?.section_heading) lines.push(`Section: ${occ.section_heading}`);
  if (occ?.zone) lines.push(`Zone: ${occ.zone}`);
  if (occ?.surrounding_text) lines.push(`Evidence: ${String(occ.surrounding_text).replace(/\s+/g, ' ').slice(0, 280)}`);
  return lines.join('\n');
}

function blocked(code, detail, blockedClass, candidate, extra = {}) {
  return {
    ok: false,
    promotable: false,
    requires_corroboration: false,
    corroboration_min_length: PROMOTION_CORROBORATION_MIN,
    code,
    detail,
    reason: detail,
    basis: null,
    observable_role: String(candidate?.role || '').trim() || null,
    publisher_evidence: publisherEvidenceSummary(candidate),
    blocked_class: blockedClass,
    accepted_corroboration: null,
    ...extra
  };
}

function acceptedCorroboration(opts) {
  const text = String(opts?.corroboration || '').replace(/\s+/g, ' ').trim();
  if (text.length < PROMOTION_CORROBORATION_MIN) return null;
  return text.slice(0, 500);
}

/**
 * Row-level Context Only / narrative → IOC override eligibility.
 *
 * Lacking a negative publisher stance is not enough. A narrative value becomes
 * an IOC only with positive publisher evidence (this exact observable asserted
 * as infrastructure) or with operational evidence of attacker use plus an
 * explicit corroboration the promote action stores and audits.
 *
 * Connectivity checks, generic references, documentation addresses,
 * placeholders, and provider infrastructure that is merely mentioned stay
 * blocked. Corroboration does not override those classes.
 *
 * @param {object} candidate
 * @param {{ corroboration?: string }} [opts]
 * @returns {{
 *   ok: boolean,
 *   promotable: boolean,
 *   requires_corroboration: boolean,
 *   corroboration_min_length: number,
 *   code: string|null,
 *   detail: string|null,
 *   reason: string|null,
 *   basis: string|null,
 *   observable_role: string|null,
 *   publisher_evidence: string|null,
 *   blocked_class: string|null,
 *   accepted_corroboration: string|null
 * }}
 */
export function classifyPromoteEligibility(candidate, opts = {}) {
  if (!candidate) return blocked('promote_not_found', 'Candidate not found.', null, candidate);
  // A MODE A narrative value outside the curated IOC set is not an IOC
  // candidate whatever its assessment, so Approve can never reach it.
  if (!isContextOnlyCandidate(candidate) && !isMissingFromPublisherScope(candidate)) {
    return blocked(
      'promote_not_context_only',
      'Only Context Only indicators can be promoted; use Approve for IOC candidates.',
      null,
      candidate
    );
  }
  const type = typeOf(candidate);
  if (!CREATABLE.has(type)) {
    return blocked(
      'promote_unsupported_type',
      `Type ${type || 'unknown'} cannot be stored as an IOC record.`,
      'unsupported_type',
      candidate
    );
  }
  if (!iocStorageIdentity(candidate)) {
    return blocked('promote_unsupported_type', INVALID_NETWORK_DETAIL, 'unsupported_type', candidate);
  }
  if (candidate.has_original_document_occurrence === false && !isLinkedSourceAssertedIoc(candidate)) {
    return blocked(
      'promote_outside_publisher_scope',
      'This value has no occurrence in the original document, so it cannot be promoted from the report narrative.',
      'outside_document',
      candidate
    );
  }
  if (isPlaceholderValue(candidate)) {
    return blocked(
      'promote_placeholder',
      'This value is a placeholder or template, not an observable the publisher reported as infrastructure.',
      'placeholder',
      candidate
    );
  }
  if (isDocumentationContext(candidate)) {
    return blocked(
      'promote_documentation',
      'The publisher uses this value as a documentation or example address, not as attacker infrastructure.',
      'documentation',
      candidate
    );
  }
  if (isConnectivityCheck(candidate)) {
    return blocked(
      'promote_connectivity_check',
      'The publisher uses this value as a connectivity check, not as attacker infrastructure.',
      'connectivity_check',
      candidate
    );
  }

  const policy = policyOf(candidate);
  const providerPolicy = PROVIDER_POLICIES.has(policy) || relationOf(candidate) === 'provider_service';
  const negativePolicy = NEGATIVE_PUBLISHER_POLICIES.has(policy) || policy.startsWith('ioc_excluded');
  // A role label never outweighs a provider / benign reading of the value itself.
  const operational = hasOperationalEvidence(candidate) ||
    (!providerPolicy && !negativePolicy && hasPublisherRoleLabel(candidate));

  if (providerPolicy && !operational) {
    return blocked(
      'promote_outside_publisher_scope',
      'The publisher describes this value as provider or service infrastructure. Promotion needs evidence this exact observable was abused, not the provider name alone.',
      'provider_infrastructure',
      candidate
    );
  }
  if (negativePolicy && !operational) {
    return blocked(
      'promote_outside_publisher_scope',
      'The publisher describes this value as non-malicious context (reference, example, or benign). It cannot be promoted.',
      'publisher_negative',
      candidate
    );
  }
  if (evidenceSupportsOnlyNarrowerUrl(candidate)) {
    return blocked(
      'promote_narrower_identity',
      'The evidence supports a specific URL, not this whole domain or address. Promote that URL instead.',
      'narrower_identity',
      candidate
    );
  }

  const role = String(candidate?.role || '').trim() || null;
  const evidenceSummary = publisherEvidenceSummary(candidate);
  // Publisher assertion of this exact observable (IOC / C2 / operational row,
  // or an approved linked IOC source). Not "the report never called it benign".
  const publisherAsserted = isPublisherAsserted(candidate) || isLinkedSourceAssertedIoc(candidate);
  if (publisherAsserted && !providerPolicy) {
    const reason = 'The publisher asserted this exact observable as report infrastructure.';
    if (!isUnionReportIndicatorMember(asPromotedRow(candidate))) {
      return blocked(
        'promote_outside_publisher_scope',
        'Promotion cannot create an IOC for this value under the current membership contract.',
        null,
        candidate
      );
    }
    return {
      ok: true,
      promotable: true,
      requires_corroboration: false,
      corroboration_min_length: PROMOTION_CORROBORATION_MIN,
      code: null,
      detail: null,
      reason,
      basis: 'publisher_assertion',
      observable_role: role,
      publisher_evidence: evidenceSummary,
      blocked_class: null,
      accepted_corroboration: null
    };
  }

  if (operational) {
    const reason = providerPolicy
      ? 'The publisher shows this exact service observable being abused for attacker operations.'
      : 'The narrative describes operational use of this exact observable (command and control, payload, phishing, or attacker infrastructure).';
    const note = acceptedCorroboration(opts);
    if (!note) {
      return {
        ok: false,
        promotable: true,
        requires_corroboration: true,
        corroboration_min_length: PROMOTION_CORROBORATION_MIN,
        code: 'promote_corroboration_required',
        detail: `Record why this exact observable is attacker infrastructure (at least ${PROMOTION_CORROBORATION_MIN} characters). The reason is stored with the promotion and audited.`,
        reason,
        basis: 'operational_evidence',
        observable_role: role,
        publisher_evidence: evidenceSummary,
        blocked_class: null,
        accepted_corroboration: null
      };
    }
    if (!isUnionReportIndicatorMember(asPromotedRow(candidate))) {
      return blocked(
        'promote_outside_publisher_scope',
        'Promotion cannot create an IOC for this value under the current membership contract.',
        null,
        candidate
      );
    }
    return {
      ok: true,
      promotable: true,
      requires_corroboration: true,
      corroboration_min_length: PROMOTION_CORROBORATION_MIN,
      code: null,
      detail: null,
      reason,
      basis: providerPolicy ? 'abused_service' : 'operational_evidence',
      observable_role: role,
      publisher_evidence: evidenceSummary,
      blocked_class: null,
      accepted_corroboration: note
    };
  }

  return blocked(
    'promote_insufficient_evidence',
    'A narrative mention is not enough to promote this value. Promotion needs publisher evidence that this exact observable is infrastructure, or operational evidence of attacker use.',
    'insufficient_evidence',
    candidate
  );
}

/**
 * API / MCP view of a promotion decision. Omits the accepted corroboration
 * text; the write path reads that from classifyPromoteEligibility.
 * @param {object} candidate
 * @param {{ corroboration?: string }} [opts]
 */
export function publicPromoteEligibility(candidate, opts = {}) {
  const decision = classifyPromoteEligibility(candidate, opts);
  return {
    promotable: decision.promotable === true,
    ok: decision.ok === true,
    requires_corroboration: decision.requires_corroboration === true,
    corroboration_min_length: decision.corroboration_min_length || PROMOTION_CORROBORATION_MIN,
    code: decision.code || null,
    detail: decision.detail || null,
    reason: decision.reason || null,
    basis: decision.basis || null,
    observable_role: decision.observable_role || null,
    publisher_evidence: decision.publisher_evidence || null,
    blocked_class: decision.blocked_class || null
  };
}

/** MODE A: a value neither the publisher's IOC set nor a linked IOC Source asserts. */
function isMissingFromPublisherScope(candidate) {
  return hasPublisherScope(candidate) && !isPublisherAsserted(candidate) && !isLinkedSourceAssertedIoc(candidate);
}

/** The review fields promote_to_ioc writes, applied to a copy (never persisted). */
export function asPromotedRow(candidate) {
  const ev = candidate.evidence && typeof candidate.evidence === 'object' ? candidate.evidence : {};
  return {
    ...candidate,
    review_status: 'approved',
    assessment: ['malicious', 'suspicious'].includes(String(candidate.assessment)) ? candidate.assessment : 'suspicious',
    is_ioc: true,
    match_state: candidate.matched_ioc_id ? 'existing' : 'new',
    evidence: { ...ev, promoted_from: ev.promoted_from || {} }
  };
}

export function isContextOrIgnored(candidate) {
  if (!candidate || candidate.is_ioc === false) return true;
  const review = reviewOf(candidate);
  const assessment = String(candidate.assessment || '').toLowerCase();
  const state = String(candidate.match_state || '').toLowerCase();
  if (review === 'ignored' || review === 'context_only') return true;
  if (assessment === 'context_only' || assessment === 'invalid') return true;
  if (state === 'context_only' || state === 'invalid') return true;
  return false;
}

function alreadyHasIocRecord(candidate) {
  if (candidate?.matched_ioc_id) return true;
  if (reviewOf(candidate) === 'created_ioc') return true;
  return String(candidate?.match_state || '').toLowerCase() === 'existing';
}

/**
 * Classify one candidate for Create IOCs. Never mutates, never explodes CIDR.
 * @returns {{
 *   eligible: boolean,
 *   outcome: string,
 *   detail?: string,
 *   ioc_id?: number|null
 * }}
 */
export function classifyCreateEligibility(candidate) {
  const type = typeOf(candidate);

  if (isContextOrIgnored(candidate)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.NOT_APPLICABLE,
      detail: 'No IOC creation expected for context-only or ignored indicators.'
    };
  }

  // Original publisher Indicators or authoritative linked-source Indicators.
  if (!isUnionReportIndicatorMember(candidate)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.NOT_APPLICABLE,
      detail: 'Not an actionable report Indicator (original publisher or linked IOC source).'
    };
  }

  if (!CREATABLE.has(type)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.UNSUPPORTED,
      detail: `Type ${type || 'unknown'} cannot be stored as an IOC record.`
    };
  }

  if (!isAnalystApproved(candidate)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.NOT_APPROVED,
      detail: 'Only approved indicators can be created as IOCs.'
    };
  }

  // Approve is the creation gate. `unknown` means the model did not decide —
  // analyst approval still materializes the IOC. `benign` stays blocked even
  // when approved; context_only / invalid are already excluded above.
  const assessment = String(candidate.assessment || '').toLowerCase();
  if (assessment === 'benign') {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.NOT_APPLICABLE,
      detail: 'Benign indicators are not created as IOC records.'
    };
  }

  if (alreadyHasIocRecord(candidate)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.ALREADY_EXISTING,
      ioc_id: candidate.matched_ioc_id ? Number(candidate.matched_ioc_id) : null,
      detail: 'An IOC record already exists for this indicator.'
    };
  }

  // Only a value with a valid ioc_items identity can be created: a malformed
  // network is reported, never truncated to a host or stored as written.
  if (!iocStorageIdentity(candidate)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.UNSUPPORTED,
      detail: INVALID_NETWORK_DETAIL
    };
  }

  return {
    eligible: true,
    outcome: PROMOTION_OUTCOMES.WILL_CREATE
  };
}

/**
 * @param {object[]} candidates
 */
export function previewCreateIocPromotion(candidates) {
  const results = (Array.isArray(candidates) ? candidates : []).map((c) => {
    const classified = classifyCreateEligibility(c);
    return {
      candidate_id: Number(c.id),
      outcome: classified.outcome,
      eligible: classified.eligible === true,
      detail: classified.detail || null,
      ioc_id: classified.ioc_id ?? null
    };
  });
  return { summary: summarizePromotionResults(results), results };
}

export function summarizePromotionResults(results) {
  const summary = {
    selected: results.length,
    eligible: 0,
    created: 0,
    already_existing: 0,
    not_approved: 0,
    unsupported: 0,
    not_applicable: 0,
    failed: 0
  };
  for (const row of results) {
    const outcome = String(row.outcome || '');
    if (outcome === PROMOTION_OUTCOMES.WILL_CREATE || row.eligible === true) summary.eligible += 1;
    if (outcome === PROMOTION_OUTCOMES.CREATED) {
      summary.created += 1;
    }
    if (outcome === PROMOTION_OUTCOMES.ALREADY_EXISTING) summary.already_existing += 1;
    if (outcome === PROMOTION_OUTCOMES.NOT_APPROVED) summary.not_approved += 1;
    if (outcome === PROMOTION_OUTCOMES.UNSUPPORTED) summary.unsupported += 1;
    if (outcome === PROMOTION_OUTCOMES.NOT_APPLICABLE) summary.not_applicable += 1;
    if (outcome === PROMOTION_OUTCOMES.FAILED) summary.failed += 1;
  }
  return summary;
}

/**
 * True when Create IOCs may run (after confirm): at least one row will be
 * created, linked as already-existing, or recorded as unsupported.
 * All-pending / all-ignored selections are blocked.
 */
export function canExecutePromotion(summary) {
  if (!summary) return false;
  return (summary.eligible || 0) > 0
    || (summary.already_existing || 0) > 0
    || (summary.unsupported || 0) > 0;
}

export function isNoneEligibleBlock(summary) {
  if (!summary || summary.selected <= 0) return true;
  return !canExecutePromotion(summary) && (summary.not_approved || 0) + (summary.not_applicable || 0) >= summary.selected;
}

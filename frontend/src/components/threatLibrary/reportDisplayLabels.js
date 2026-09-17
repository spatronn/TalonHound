/**
 * Display-only labels for Threat Library enum values.
 *
 * Every function here maps a canonical backend value (snake_case, stored and
 * sent unchanged) to a human label for rendering. Nothing in this module may
 * be used to build a request body or compare against API state: the canonical
 * value stays the source of truth, the label is presentation.
 */

const CANDIDATE_TYPE_LABELS = Object.freeze({
  ip: 'IP',
  ipv6: 'IPv6',
  domain: 'Domain',
  url: 'URL',
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  cidr: 'CIDR',
  cve: 'CVE',
  email: 'Email',
  attack_technique: 'ATT&CK technique',
  technical_artifact: 'Technical artifact',
  relative_path: 'Relative path',
  file_path: 'File path'
});

const ASSESSMENT_LABELS = Object.freeze({
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  context_only: 'Context only',
  unknown: 'Unknown',
  invalid: 'Invalid'
});

const ROLE_LABELS = Object.freeze({
  command_and_control: 'Command & Control',
  redirector: 'Redirector',
  payload_hosting: 'Payload hosting',
  malware_download: 'Malware download',
  phishing: 'Phishing',
  tracking: 'Tracking',
  malicious_infrastructure: 'Malicious infrastructure',
  delivery: 'Delivery',
  malware_sample: 'Malware sample',
  legitimate_service: 'Legitimate service',
  hosting_platform: 'Hosting platform',
  victim: 'Victim',
  reference: 'Reference',
  security_tool: 'Security tool',
  unknown: 'Unknown'
});

const REVIEW_STATUS_LABELS = Object.freeze({
  pending: 'Pending',
  approved: 'Approved',
  ignored: 'Ignored',
  context_only: 'Context only',
  created_ioc: 'Approved'
});

const MATCH_STATE_LABELS = Object.freeze({
  new: 'New',
  existing: 'Existing',
  needs_review: 'Needs review',
  context_only: 'Context only',
  invalid: 'Invalid'
});

const ENTITY_TYPE_LABELS = Object.freeze({
  threat_actor: { singular: 'Threat actor', plural: 'Threat actors' },
  malware: { singular: 'Malware', plural: 'Malware' },
  campaign: { singular: 'Campaign', plural: 'Campaigns' },
  tool: { singular: 'Tool', plural: 'Tools' },
  vulnerability: { singular: 'Vulnerability', plural: 'Vulnerabilities' },
  infrastructure: { singular: 'Infrastructure', plural: 'Infrastructure' },
  organization: { singular: 'Organization', plural: 'Organizations' },
  attack_pattern: { singular: 'Attack pattern', plural: 'Attack patterns' }
});

const ARTIFACT_TYPE_LABELS = Object.freeze({
  url_fetch: 'Fetched source',
  pdf_upload: 'Uploaded PDF',
  canonical_document: 'Canonical document',
  thib_bundle: 'THIB bundle'
});

const SOURCE_TYPE_LABELS = Object.freeze({
  url: 'URL',
  pdf: 'PDF',
  thib: 'THIB bundle'
});

/** Generic fallback: `some_snake_value` -> `Some snake value`. Never returns the raw value with underscores. */
export function humanizeEnum(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return '';
  const spaced = raw.replace(/[_\-]+/g, ' ').replace(/\s+/g, ' ').trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

function lookup(table, value, fallback = '') {
  const key = String(value ?? '').trim().toLowerCase();
  if (!key) return fallback;
  return table[key] || humanizeEnum(key);
}

export function candidateTypeLabel(value) {
  const key = String(value ?? '').trim().toLowerCase();
  if (!key) return '';
  return CANDIDATE_TYPE_LABELS[key] || key.toUpperCase();
}

export function assessmentLabel(value) {
  return lookup(ASSESSMENT_LABELS, value);
}

export function roleLabel(value) {
  return lookup(ROLE_LABELS, value);
}

export function reviewStatusLabel(value) {
  return lookup(REVIEW_STATUS_LABELS, value);
}

export function matchStateLabel(value) {
  return lookup(MATCH_STATE_LABELS, value);
}

export function entityTypeLabel(value, { plural = false } = {}) {
  const key = String(value ?? '').trim().toLowerCase();
  if (!key) return plural ? 'Other' : '';
  const entry = ENTITY_TYPE_LABELS[key];
  if (entry) return plural ? entry.plural : entry.singular;
  const base = humanizeEnum(key);
  return plural ? `${base}s` : base;
}

export function artifactTypeLabel(value) {
  return lookup(ARTIFACT_TYPE_LABELS, value);
}

export function sourceTypeLabel(value) {
  return lookup(SOURCE_TYPE_LABELS, value);
}

/**
 * Badge tone for an assessment: only Malicious / Suspicious carry colour so the
 * table stays scannable rather than uniformly tinted.
 */
export function assessmentTone(value) {
  const key = String(value ?? '').trim().toLowerCase();
  if (key === 'malicious') return 'danger';
  if (key === 'suspicious') return 'warning';
  if (key === 'invalid') return 'muted';
  return 'neutral';
}

export function reviewStatusTone(value) {
  const key = String(value ?? '').trim().toLowerCase();
  if (key === 'approved' || key === 'created_ioc') return 'success';
  if (key === 'pending') return 'warning';
  if (key === 'ignored') return 'muted';
  return 'neutral';
}

export function matchStateTone(value) {
  const key = String(value ?? '').trim().toLowerCase();
  if (key === 'new') return 'info';
  if (key === 'existing') return 'neutral';
  if (key === 'needs_review') return 'warning';
  return 'muted';
}

/** IOC promotion outcome tone (input is the canonical `promotion_outcome`). */
export function promotionOutcomeTone(value) {
  const key = String(value ?? '').trim().toLowerCase();
  if (key === 'created') return 'success';
  if (key === 'already_existing') return 'neutral';
  if (key === 'failed') return 'danger';
  if (!key || key === 'will_create') return 'none';
  return 'muted';
}

/**
 * Cell text for the Match column: an actual IOC match names the matched
 * observable type; otherwise the humanised match state.
 */
export function matchCellLabel(candidate) {
  if (!candidate) return '';
  if (candidate.matched_ioc_id) {
    const type = candidate.matched_ioc_observable_type || candidate.candidate_type;
    return `Matched (${candidateTypeLabel(type) || type})`;
  }
  return matchStateLabel(candidate.match_state);
}

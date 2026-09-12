/**
 * Deterministic IOC / identifier candidate extraction from canonical documents.
 * Reuses TalonHound observable normalization; adds defang prep only.
 */

import { normalizeObservable } from '../observable-normalization.js';
import { normalizeIpAddress, isValidIpAddress } from '../publicIp.js';
import { inferExactHashType, normalizeHashValue } from '../fileArtifacts/hashNormalize.js';
import { resolveStorageObservableType, inferObservableType } from '../manualIocCreate.js';
import { refangObservable, refangTextForExtraction } from './defang.js';

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(?:3[0-2]|[12]?\d))?\b/g;
const IPV6_RE = /\b(?:(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:)\b/g;
const URL_RE = /\bhttps?:\/\/[^\s<>"'`)\]]+/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b/gi;
const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const ATTACK_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

const COMMON_FALSE_POSITIVE_DOMAINS = new Set([
  'example.com',
  'example.org',
  'example.net',
  'localhost',
  'github.com',
  'gitlab.com',
  'microsoft.com',
  'google.com',
  'googleapis.com',
  'wikipedia.org',
  'w3.org',
  'schema.org',
  'pages.dev',
  'cloudflare.com',
  'amazonaws.com'
]);

/**
 * @param {string} domain
 */
function isLikelyFalsePositiveDomain(domain) {
  const d = String(domain || '').toLowerCase();
  if (COMMON_FALSE_POSITIVE_DOMAINS.has(d)) return true;
  for (const fp of COMMON_FALSE_POSITIVE_DOMAINS) {
    if (d.endsWith(`.${fp}`)) return true;
  }
  return false;
}

/**
 * @param {string} urlish
 */
function stripUrlTrailingPunct(urlish) {
  return String(urlish || '').replace(/[),.;:!?\]]+$/g, '');
}

/**
 * Normalize a candidate value into a TalonHound storage type + value.
 * @param {string} raw
 * @param {string} [hintType]
 */
export function normalizeCandidateValue(raw, hintType = null) {
  const refanged = refangObservable(raw);
  if (!refanged) return { ok: false, error: 'empty' };

  if (hintType === 'cve' || /^CVE-\d{4}-\d{4,7}$/i.test(refanged)) {
    return {
      ok: true,
      candidateType: 'cve',
      originalValue: String(raw).trim(),
      normalizedValue: refanged.toUpperCase(),
      isIoc: false
    };
  }
  if (hintType === 'attack_technique' || /^T\d{4}(?:\.\d{3})?$/i.test(refanged)) {
    return {
      ok: true,
      candidateType: 'attack_technique',
      originalValue: String(raw).trim(),
      normalizedValue: refanged.toUpperCase(),
      isIoc: false
    };
  }

  let inferred = hintType || inferObservableType(refanged);
  if (hintType === 'ipv6') inferred = 'ip';
  if (!inferred) return { ok: false, error: 'unrecognized' };

  if (inferred === 'ip' || inferred === 'ipv6') {
    if (!isValidIpAddress(refanged.split('/')[0])) {
      return { ok: false, error: 'invalid_ip' };
    }
    const norm = normalizeIpAddress(refanged.split('/')[0]);
    const isV6 = norm.includes(':');
    return {
      ok: true,
      candidateType: isV6 ? 'ipv6' : 'ip',
      originalValue: String(raw).trim(),
      normalizedValue: norm,
      isIoc: true
    };
  }

  if (inferred === 'url' || /^https?:\/\//i.test(refanged)) {
    const storage = resolveStorageObservableType(refanged, 'url');
    if (!storage.ok) return { ok: false, error: storage.error };
    return {
      ok: true,
      candidateType: 'url',
      originalValue: String(raw).trim(),
      normalizedValue: normalizeObservable('url', storage.value),
      isIoc: true
    };
  }

  if (inferred === 'hash' || hintType === 'md5' || hintType === 'sha1' || hintType === 'sha256') {
    const normalized = normalizeHashValue(refanged);
    const exact = inferExactHashType(normalized) || (hintType && ['md5', 'sha1', 'sha256'].includes(hintType) ? hintType : null);
    if (!exact) return { ok: false, error: 'invalid_hash' };
    return {
      ok: true,
      candidateType: exact,
      originalValue: String(raw).trim(),
      normalizedValue: normalized,
      isIoc: true
    };
  }

  // domain
  const domain = normalizeObservable('domain', refanged.replace(/\.$/, ''));
  if (!domain || !domain.includes('.')) return { ok: false, error: 'invalid_domain' };
  return {
    ok: true,
    candidateType: 'domain',
    originalValue: String(raw).trim(),
    normalizedValue: domain,
    isIoc: true,
    likelyContextOnly: isLikelyFalsePositiveDomain(domain)
  };
}

/**
 * Extract candidates from a canonical document.
 * @param {import('./canonicalDocument.js').CanonicalDocument} doc
 */
export function extractCandidatesFromDocument(doc) {
  /** @type {Map<string, object>} */
  const byKey = new Map();

  function add(raw, hintType, block) {
    const n = normalizeCandidateValue(raw, hintType);
    if (!n.ok) return;
    const key = `${n.candidateType}\0${n.normalizedValue}`;
    const existing = byKey.get(key);
    if (existing) {
      if (!existing.evidence_text && block?.text) {
        existing.evidence_text = String(block.text).slice(0, 500);
        existing.block_id = block.id;
        existing.page_number = block.page ?? null;
        existing.section = block.section || null;
      }
      return;
    }
    byKey.set(key, {
      candidate_type: n.candidateType,
      original_value: n.originalValue,
      normalized_value: n.normalizedValue,
      assessment: n.isIoc === false ? 'context_only' : n.likelyContextOnly ? 'context_only' : 'unknown',
      role: n.likelyContextOnly ? 'legitimate_service' : n.isIoc === false ? 'reference' : 'unknown',
      confidence: n.likelyContextOnly || n.isIoc === false ? 0.7 : null,
      evidence_text: block?.text ? String(block.text).slice(0, 500) : null,
      block_id: block?.id || null,
      page_number: block?.page ?? null,
      section: block?.section || null,
      is_ioc: n.isIoc !== false && n.candidateType !== 'cve' && n.candidateType !== 'attack_technique'
    });
  }

  for (const block of doc.blocks || []) {
    const text = refangTextForExtraction(block.text || '');
    if (!text.trim()) continue;

    for (const m of text.matchAll(URL_RE)) {
      add(stripUrlTrailingPunct(m[0]), 'url', block);
    }
    for (const m of text.matchAll(IPV4_RE)) {
      add(m[0], 'ip', block);
    }
    for (const m of text.matchAll(IPV6_RE)) {
      add(m[0], 'ipv6', block);
    }
    for (const m of text.matchAll(SHA256_RE)) {
      add(m[0], 'sha256', block);
    }
    for (const m of text.matchAll(SHA1_RE)) {
      add(m[0], 'sha1', block);
    }
    for (const m of text.matchAll(MD5_RE)) {
      add(m[0], 'md5', block);
    }
    for (const m of text.matchAll(CVE_RE)) {
      add(m[0], 'cve', block);
    }
    for (const m of text.matchAll(ATTACK_RE)) {
      // Avoid matching lone "T1234" noise in prose when not ATT&CK-like context — still useful
      if (/^T1\d{3}/.test(m[0]) || /^T10\d{2}/.test(m[0]) || /^T11\d{2}/.test(m[0]) || /^T12\d{2}/.test(m[0]) || /^T15\d{2}/.test(m[0]) || /^T16\d{2}/.test(m[0])) {
        add(m[0], 'attack_technique', block);
      }
    }
    for (const m of text.matchAll(DOMAIN_RE)) {
      const d = m[0].toLowerCase();
      // Skip if already captured as URL host noise-heavy TLDs from file extensions
      if (/\.(png|jpg|jpeg|gif|css|js|html|htm|exe|dll|zip|pdf)$/i.test(d)) continue;
      add(d, 'domain', block);
    }
  }

  return [...byKey.values()];
}

/**
 * Deterministic IOC / identifier candidate extraction from canonical documents.
 * Discovery stays broad; typing + zones prevent non-IOC promotion.
 */

import { normalizeObservable } from '../observable-normalization.js';
import { normalizeIpAddress, isValidIpAddress } from '../publicIp.js';
import { inferExactHashType, normalizeHashValue } from '../fileArtifacts/hashNormalize.js';
import { resolveStorageObservableType, inferObservableType } from '../manualIocCreate.js';
import { refangObservable, refangTextForExtraction } from './defang.js';
import { annotateDocumentZones, NEGATIVE_ZONES, STRONG_IOC_ZONES } from './documentZones.js';
import {
  resolveDottedTokenType,
  hostnameFromUrl,
  pathBasenameFromUrl
} from './candidateTyping.js';
import { applyEvidencePolicy } from './evidencePolicy.js';

export const THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION = 'tl-candidates-v2';

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(?:3[0-2]|[12]?\d))?\b/g;
const IPV6_RE = /\b(?:(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:)\b/g;
const URL_RE = /\bhttps?:\/\/[^\s<>"'`)\]]+/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b/gi;
const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const ATTACK_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

/** RFC documentation / loopback only — not vendor safety allowlists. */
const RFC_EXAMPLE_DOMAINS = new Set(['example.com', 'example.org', 'example.net', 'localhost', 'invalid', 'test']);

function isRfcExampleDomain(domain) {
  const d = String(domain || '').toLowerCase();
  if (RFC_EXAMPLE_DOMAINS.has(d)) return true;
  for (const fp of RFC_EXAMPLE_DOMAINS) {
    if (d.endsWith(`.${fp}`)) return true;
  }
  return false;
}

function stripUrlTrailingPunct(urlish) {
  return String(urlish || '').replace(/[),.;:!?\]]+$/g, '');
}

/**
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

  const domain = normalizeObservable('domain', refanged.replace(/\.$/, ''));
  if (!domain || !domain.includes('.')) return { ok: false, error: 'invalid_domain' };
  return {
    ok: true,
    candidateType: 'domain',
    originalValue: String(raw).trim(),
    normalizedValue: domain,
    isIoc: true,
    likelyContextOnly: isRfcExampleDomain(domain)
  };
}

/**
 * @param {import('./canonicalDocument.js').CanonicalDocument} doc
 * @param {{ sourceUrl?: string|null }} [opts]
 */
export function extractCandidatesFromDocument(doc, opts = {}) {
  const sourceUrl = opts.sourceUrl || doc.meta?.source_url || doc.meta?.sourceUrl || null;
  let sourceHost = '';
  try {
    if (sourceUrl) sourceHost = hostnameFromUrl(sourceUrl);
  } catch {
    sourceHost = '';
  }

  const annotated = annotateDocumentZones(doc, { sourceUrl, sourceHost });
  /** @type {Map<string, object>} */
  const byKey = new Map();
  const urlPathBasenames = new Set();
  const knownUrlHosts = new Set();
  if (sourceHost) knownUrlHosts.add(sourceHost.toLowerCase());

  function pushOccurrence(entry, block, extra = {}) {
    const occ = {
      block_id: block?.id || null,
      page: block?.page ?? null,
      section_kind: block?.zone || block?.section || 'unknown',
      zone: block?.zone || 'unknown',
      surrounding_text: block?.text ? String(block.text).slice(0, 280) : null,
      ...extra
    };
    if (!Array.isArray(entry.occurrences)) entry.occurrences = [];
    // Dedup same block
    if (!entry.occurrences.some((o) => o.block_id && o.block_id === occ.block_id)) {
      entry.occurrences.push(occ);
    }
  }

  function add(raw, hintType, block, typingMeta = {}) {
    const n = normalizeCandidateValue(raw, hintType);
    if (!n.ok) return;

    // Domain typing gate
    if (n.candidateType === 'domain') {
      const typed = resolveDottedTokenType(n.normalizedValue, {
        surroundingText: block?.text || '',
        urlPathBasenames,
        knownUrlHosts
      });
      if (typed.kind === 'file_artifact' || typed.kind === 'code_identifier' || typed.kind === 'skip') {
        // Do not promote as network IOC candidate
        return;
      }
      typingMeta.typing_reason = typed.reason;
      typingMeta.resolved_type = 'domain';
    }

    const key = `${n.candidateType}\0${n.normalizedValue}`;
    let entry = byKey.get(key);
    if (!entry) {
      const zone = block?.zone || 'unknown';
      const negativeOnlySeed = NEGATIVE_ZONES.has(zone);
      const strongSeed = STRONG_IOC_ZONES.has(zone);
      entry = {
        candidate_type: n.candidateType,
        original_value: n.originalValue,
        normalized_value: n.normalizedValue,
        assessment:
          n.isIoc === false || n.likelyContextOnly || negativeOnlySeed
            ? 'context_only'
            : strongSeed
              ? 'unknown'
              : 'unknown',
        role: n.likelyContextOnly
          ? 'legitimate_service'
          : negativeOnlySeed
            ? zone === 'reference_section'
              ? 'reference'
              : 'legitimate_service'
            : n.isIoc === false
              ? 'reference'
              : 'unknown',
        confidence: n.likelyContextOnly || negativeOnlySeed ? 0.75 : null,
        evidence_text: block?.text ? String(block.text).slice(0, 500) : null,
        block_id: block?.id || null,
        page_number: block?.page ?? null,
        section: zone,
        zone,
        is_ioc: n.isIoc !== false && n.candidateType !== 'cve' && n.candidateType !== 'attack_technique',
        resolved_type: typingMeta.resolved_type || n.candidateType,
        typing_reason: typingMeta.typing_reason || null,
        occurrences: [],
        extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
      };
      // Source host / URL provenance
      if (
        (n.candidateType === 'domain' && sourceHost && n.normalizedValue === sourceHost) ||
        (n.candidateType === 'url' && sourceUrl && n.normalizedValue === normalizeObservable('url', sourceUrl))
      ) {
        entry.assessment = 'context_only';
        entry.role = 'reference';
        entry.zone = 'source_metadata';
      }
      byKey.set(key, entry);
    }
    pushOccurrence(entry, block, typingMeta);
    // Prefer strong-zone evidence text
    if (STRONG_IOC_ZONES.has(block?.zone) && block?.text) {
      entry.evidence_text = String(block.text).slice(0, 500);
      entry.block_id = block.id;
      entry.page_number = block.page ?? null;
      entry.section = block.zone;
      entry.zone = block.zone;
    }
  }

  // Pass 1: URLs — record hosts + path basenames before domain scan
  for (const block of annotated.blocks || []) {
    const text = refangTextForExtraction(block.text || '');
    if (!text.trim()) continue;
    for (const m of text.matchAll(URL_RE)) {
      const url = stripUrlTrailingPunct(m[0]);
      const host = hostnameFromUrl(url);
      const base = pathBasenameFromUrl(url);
      if (host) knownUrlHosts.add(host);
      if (base && base.includes('.')) urlPathBasenames.add(base.toLowerCase());
      add(url, 'url', block);
      // Host from URL is a real domain signal
      if (host && isValidIpAddress(host)) {
        add(host, 'ip', block);
      } else if (host && host.includes('.')) {
        add(host, 'domain', block, { resolved_type: 'domain', typing_reason: 'url_host' });
      }
    }
  }

  // Pass 2: other observables + domains
  for (const block of annotated.blocks || []) {
    const text = refangTextForExtraction(block.text || '');
    if (!text.trim()) continue;

    for (const m of text.matchAll(IPV4_RE)) add(m[0], 'ip', block);
    for (const m of text.matchAll(IPV6_RE)) add(m[0], 'ipv6', block);
    for (const m of text.matchAll(SHA256_RE)) add(m[0], 'sha256', block);
    for (const m of text.matchAll(SHA1_RE)) add(m[0], 'sha1', block);
    for (const m of text.matchAll(MD5_RE)) add(m[0], 'md5', block);
    for (const m of text.matchAll(CVE_RE)) add(m[0], 'cve', block);
    for (const m of text.matchAll(ATTACK_RE)) {
      if (/^T(1\d{3}|10\d{2}|11\d{2}|12\d{2}|15\d{2}|16\d{2})/.test(m[0])) {
        add(m[0], 'attack_technique', block);
      }
    }
    for (const m of text.matchAll(DOMAIN_RE)) {
      const d = m[0].toLowerCase();
      add(d, 'domain', block);
    }
  }

  const out = [];
  for (const entry of byKey.values()) {
    applyEvidencePolicy(entry);
    out.push(entry);
  }
  return out;
}

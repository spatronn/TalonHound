/**
 * Deterministic IOC / identifier candidate extraction from canonical documents.
 *
 * Model: a candidate is an observable identity (type + normalized value) that
 * aggregates source OCCURRENCES. Every occurrence points at a real text span in
 * a canonical block. Parser-derived facts about a value (the host of a URL, the
 * port of an IP:port endpoint) are kept as `parsed` metadata on that candidate
 * and never become occurrences of another candidate. A standalone host
 * candidate therefore only exists when the report itself mentions the host
 * outside URL syntax (independent evidence).
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
import { isObservableOnlyLine } from './pdfLayout.js';

/**
 * Bump when derivation / evidence semantics change. Older candidate sets are
 * rebuilt from the canonical document on the next analysis run.
 */
export const THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION = 'tl-candidates-v3';

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(?:3[0-2]|[12]?\d))?\b/g;
const IPV4_PORT_RE = /\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))[:：](\d{1,5})\b/g;
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

export const OCCURRENCE_FORMS = Object.freeze({
  STANDALONE: 'standalone',
  URL: 'url',
  IP_PORT: 'ip_port',
  LIST_ROW: 'list_row'
});

function isRfcExampleDomain(domain) {
  const d = String(domain || '').toLowerCase();
  if (RFC_EXAMPLE_DOMAINS.has(d)) return true;
  for (const fp of RFC_EXAMPLE_DOMAINS) {
    if (d.endsWith(`.${fp}`)) return true;
  }
  return false;
}

function stripUrlTrailingPunct(urlish) {
  return String(urlish || '').replace(/[),.;:!?\]。，；]+$/g, '');
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
 * Parse port from an http(s) URL when explicitly present.
 * @param {string} url
 */
function portFromUrl(url) {
  try {
    const u = new URL(String(url));
    return u.port ? Number(u.port) : null;
  } catch {
    return null;
  }
}

/**
 * @param {Array<[number, number]>} spans
 * @param {number} start
 * @param {number} end
 */
function insideAnySpan(spans, start, end) {
  for (const [s, e] of spans) {
    if (start >= s && end <= e) return true;
  }
  return false;
}

/**
 * Candidate key used everywhere (DB unique constraint mirrors it).
 * @param {string} type
 * @param {string} value
 */
export function candidateKey(type, value) {
  return `${type}\0${value}`;
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
  const normalizedSourceUrl = sourceUrl ? normalizeObservable('url', refangObservable(sourceUrl)) : null;

  const annotated = annotateDocumentZones(doc, { sourceUrl, sourceHost });
  /** @type {Map<string, object>} */
  const byKey = new Map();
  const urlPathBasenames = new Set();
  const knownUrlHosts = new Set();
  /** host → Set<url candidate key> (parser-derived metadata index, not occurrences) */
  const urlHostIndex = new Map();
  if (sourceHost) knownUrlHosts.add(sourceHost.toLowerCase());

  function occurrenceFor(block, extra = {}) {
    const zone = block?.zone || 'unknown';
    return {
      block_id: block?.id || null,
      page: block?.page ?? null,
      zone,
      section_kind: zone,
      section_heading: block?.section_heading || null,
      block_type: block?.type || null,
      form: extra.form || OCCURRENCE_FORMS.STANDALONE,
      port: extra.port ?? null,
      surrounding_text: block?.text ? String(block.text).slice(0, 280) : null
    };
  }

  function pushOccurrence(entry, block, extra = {}) {
    const occ = occurrenceFor(block, extra);
    if (!Array.isArray(entry.occurrences)) entry.occurrences = [];
    const dup = entry.occurrences.find((o) => o.block_id && o.block_id === occ.block_id);
    if (dup) {
      // Same block: keep one occurrence but remember a stronger assertion form / port.
      if (occ.port != null && dup.port == null) dup.port = occ.port;
      if (dup.form === OCCURRENCE_FORMS.STANDALONE && occ.form !== OCCURRENCE_FORMS.STANDALONE) dup.form = occ.form;
      return;
    }
    entry.occurrences.push(occ);
    if (occ.port != null) {
      if (!Array.isArray(entry.parsed.ports)) entry.parsed.ports = [];
      if (!entry.parsed.ports.includes(occ.port)) entry.parsed.ports.push(occ.port);
    }
  }

  function evidenceTextFor(block) {
    if (!block?.text) return null;
    const text = String(block.text).slice(0, 500);
    if ((block.type === 'list_item' || block.layout === 'observable_row') && block.section_heading) {
      return `${String(block.section_heading).slice(0, 80)}: ${text}`.slice(0, 500);
    }
    return text;
  }

  /**
   * @param {string} raw
   * @param {string|null} hintType
   * @param {object} block
   * @param {{ form?: string, port?: number|null, typing?: object }} [extra]
   */
  function add(raw, hintType, block, extra = {}) {
    const n = normalizeCandidateValue(raw, hintType);
    if (!n.ok) return null;
    const typingMeta = { ...(extra.typing || {}) };

    // Domain typing gate (filename / code identifier / hostname shape)
    if (n.candidateType === 'domain') {
      const typed = resolveDottedTokenType(n.normalizedValue, {
        surroundingText: block?.text || '',
        urlPathBasenames,
        knownUrlHosts
      });
      if (typed.kind === 'file_artifact' || typed.kind === 'code_identifier' || typed.kind === 'skip') {
        return null; // never a network IOC candidate
      }
      typingMeta.typing_reason = typed.reason;
      typingMeta.resolved_type = 'domain';
    }

    const key = candidateKey(n.candidateType, n.normalizedValue);
    let entry = byKey.get(key);
    if (!entry) {
      const zone = block?.zone || 'unknown';
      const isIoc = n.isIoc !== false && n.candidateType !== 'cve' && n.candidateType !== 'attack_technique';
      entry = {
        candidate_type: n.candidateType,
        original_value: n.originalValue,
        normalized_value: n.normalizedValue,
        assessment: isIoc && !n.likelyContextOnly ? 'unknown' : 'context_only',
        role: n.likelyContextOnly ? 'legitimate_service' : isIoc ? 'unknown' : 'reference',
        confidence: n.likelyContextOnly ? 0.75 : null,
        evidence_text: evidenceTextFor(block),
        block_id: block?.id || null,
        page_number: block?.page ?? null,
        section: zone,
        zone,
        is_ioc: isIoc,
        resolved_type: typingMeta.resolved_type || n.candidateType,
        typing_reason: typingMeta.typing_reason || null,
        occurrences: [],
        parsed: {},
        derived_from: null,
        is_direct_source_observable: true,
        is_parser_derived_metadata: false,
        extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
      };
      if (n.likelyContextOnly) entry.rfc_example = true;
      // Report's own source URL / host is provenance, never a finding.
      if (
        (n.candidateType === 'domain' && sourceHost && n.normalizedValue === sourceHost) ||
        (n.candidateType === 'url' && normalizedSourceUrl && n.normalizedValue === normalizedSourceUrl)
      ) {
        entry.is_report_source = true;
      }
      byKey.set(key, entry);
    }
    pushOccurrence(entry, block, extra);
    // Prefer strong-zone evidence text / anchor block
    const anchorIsStrong = STRONG_IOC_ZONES.has(entry.zone);
    if (STRONG_IOC_ZONES.has(block?.zone) && block?.text && !anchorIsStrong) {
      entry.evidence_text = evidenceTextFor(block);
      entry.block_id = block.id;
      entry.page_number = block.page ?? null;
      entry.section = block.zone;
      entry.zone = block.zone;
    } else if (NEGATIVE_ZONES.has(entry.zone) && !NEGATIVE_ZONES.has(block?.zone) && block?.text) {
      // Body mention beats a footer/reference anchor for display purposes
      entry.evidence_text = evidenceTextFor(block);
      entry.block_id = block.id;
      entry.page_number = block.page ?? null;
      entry.section = block.zone || 'unknown';
      entry.zone = block.zone || 'unknown';
    }
    return entry;
  }

  const blocks = annotated.blocks || [];
  // Format-agnostic "indicator row": PDF list rows, HTML <li>/<td>, or any line that is a single observable.
  const isObservableRow = (block) =>
    block.type === 'list_item' ||
    block.layout === 'observable_row' ||
    ((block.type === 'list' || block.type === 'table') && isObservableOnlyLine(block.text || ''));

  // Pass 1: URLs — one candidate per URL; host/port/basename are parsed metadata only.
  /** @type {Map<string, Array<[number, number]>>} block id → URL spans */
  const urlSpansByBlock = new Map();
  for (const block of blocks) {
    const text = refangTextForExtraction(block.text || '');
    if (!text.trim()) continue;
    const spans = [];
    for (const m of text.matchAll(URL_RE)) {
      const url = stripUrlTrailingPunct(m[0]);
      if (!url) continue;
      spans.push([m.index, m.index + url.length]);
      const host = hostnameFromUrl(url);
      const base = pathBasenameFromUrl(url);
      if (host) knownUrlHosts.add(host);
      if (base && base.includes('.')) urlPathBasenames.add(base.toLowerCase());
      const isRow = isObservableRow(block);
      const entry = add(url, 'url', block, { form: isRow ? OCCURRENCE_FORMS.LIST_ROW : OCCURRENCE_FORMS.URL });
      if (entry) {
        if (host && !entry.parsed.host) {
          entry.parsed.host = host;
          entry.parsed.host_kind = isValidIpAddress(host) ? 'ip' : 'domain';
        }
        const port = portFromUrl(url);
        if (port != null) {
          if (!Array.isArray(entry.parsed.ports)) entry.parsed.ports = [];
          if (!entry.parsed.ports.includes(port)) entry.parsed.ports.push(port);
        }
        if (base && !entry.parsed.path_basename) entry.parsed.path_basename = base;
        if (host) {
          if (!urlHostIndex.has(host)) urlHostIndex.set(host, new Set());
          urlHostIndex.get(host).add(candidateKey('url', entry.normalized_value));
        }
      }
    }
    if (spans.length) urlSpansByBlock.set(block.id, spans);
  }

  // Pass 2: other observables. Host-like matches inside a URL span are the URL's
  // own host component — not an independent assertion — and are skipped.
  for (const block of blocks) {
    const text = refangTextForExtraction(block.text || '');
    if (!text.trim()) continue;
    const urlSpans = urlSpansByBlock.get(block.id) || [];
    const isRow = isObservableRow(block);
    const standaloneForm = isRow ? OCCURRENCE_FORMS.LIST_ROW : OCCURRENCE_FORMS.STANDALONE;
    /** @type {Array<[number, number]>} */
    const consumed = [];

    // IP:port endpoints (direct C2 endpoint assertions)
    for (const m of text.matchAll(IPV4_PORT_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end)) continue;
      const port = Number(m[2]);
      if (!Number.isFinite(port) || port < 1 || port > 65535) continue;
      const entry = add(m[1], 'ip', block, { form: OCCURRENCE_FORMS.IP_PORT, port });
      if (entry) {
        // Keep the faithful source spelling when the endpoint form is the first sighting
        if (entry.occurrences.length === 1 && !entry.original_value.includes(':')) {
          entry.original_value = `${m[1]}:${m[2]}`;
        }
        consumed.push([start, end]);
      }
    }

    for (const m of text.matchAll(IPV4_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end) || insideAnySpan(consumed, start, end)) continue;
      add(m[0], 'ip', block, { form: standaloneForm });
    }
    for (const m of text.matchAll(IPV6_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end)) continue;
      add(m[0], 'ipv6', block, { form: standaloneForm });
    }
    for (const m of text.matchAll(SHA256_RE)) add(m[0], 'sha256', block, { form: standaloneForm });
    for (const m of text.matchAll(SHA1_RE)) add(m[0], 'sha1', block, { form: standaloneForm });
    for (const m of text.matchAll(MD5_RE)) add(m[0], 'md5', block, { form: standaloneForm });
    for (const m of text.matchAll(CVE_RE)) add(m[0], 'cve', block, { form: standaloneForm });
    for (const m of text.matchAll(ATTACK_RE)) {
      if (/^T(1\d{3}|10\d{2}|11\d{2}|12\d{2}|15\d{2}|16\d{2})/.test(m[0])) {
        add(m[0], 'attack_technique', block, { form: standaloneForm });
      }
    }
    for (const m of text.matchAll(DOMAIN_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end)) continue;
      add(m[0].toLowerCase(), 'domain', block, { form: standaloneForm });
    }
  }

  // Finalize: evidence policy + parser-derived host cross references
  const out = [];
  for (const entry of byKey.values()) {
    if (entry.candidate_type === 'url' && entry.parsed.host) {
      const hostType = entry.parsed.host_kind === 'ip' ? 'ip' : 'domain';
      const hostKey = candidateKey(hostType, entry.parsed.host);
      entry.parsed.host_independently_asserted = byKey.has(hostKey);
    }
    if ((entry.candidate_type === 'ip' || entry.candidate_type === 'domain') && urlHostIndex.has(entry.normalized_value)) {
      entry.parsed.also_url_host_of = [...urlHostIndex.get(entry.normalized_value)].map((k) => k.split('\0')[1]).slice(0, 20);
    }
    entry.occurrence_count = entry.occurrences.length;
    applyEvidencePolicy(entry);
    out.push(entry);
  }
  return out;
}

/**
 * Review-set partition used by the pipeline, prompts and UI summaries.
 * @param {object[]} candidates
 */
export function summarizeCandidateSet(candidates) {
  const s = {
    total: 0,
    ioc_candidates: 0,
    explicit_assertions: 0,
    body_assertions: 0,
    context_only: 0,
    non_ioc: 0,
    ai_needed: 0,
    raw_occurrences: 0
  };
  for (const c of candidates || []) {
    s.total += 1;
    s.raw_occurrences += Array.isArray(c.occurrences) ? c.occurrences.length : 0;
    if (c.is_ioc === false) {
      s.non_ioc += 1;
      continue;
    }
    if (c.assessment === 'context_only') {
      s.context_only += 1;
      continue;
    }
    s.ioc_candidates += 1;
    if (c.source_assertion === 'explicit_ioc' || c.source_assertion === 'explicit_c2') s.explicit_assertions += 1;
    else s.body_assertions += 1;
    if (c.ai_needed) s.ai_needed += 1;
  }
  return s;
}

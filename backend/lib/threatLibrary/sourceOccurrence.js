/**
 * Source-span grounding for Threat Library candidates.
 *
 * A string that parses as IPv4 is not automatically a standalone IP IOC.
 * Validity depends on the source occurrence: the first four numeric labels of
 * a hostname such as `128.200.178.68.host.example.com` are not an independent
 * IP, even though they parse as one. The same IP is accepted when the source
 * also contains a token-bounded occurrence (`C2: 128.200.178.68`, `(1.2.3.4)`,
 * `https://1.2.3.4/path`).
 *
 * AI output is untrusted candidate data. Callers must ground IPv4/IPv6
 * proposals against the normalized/refanged source before accepting them.
 */

import { refangObservable, refangTextForExtraction } from './defang.js';
import { normalizeIpAddress } from '../publicIp.js';

/** Characters that continue a DNS label / token. */
const DNS_TOKEN_CHAR_RE = /[A-Za-z0-9_-]/;

const IP_TYPES = new Set(['ip', 'ipv4', 'ipv6']);

/**
 * Join canonical-block text for occurrence search (no diagnostic prefixes).
 * @param {{ blocks?: Array<{ text?: string|null }> }|null|undefined} doc
 */
export function sourceTextFromDocument(doc) {
  return (doc?.blocks || []).map((b) => String(b?.text || '')).join('\n');
}

/**
 * True when [start, end) is a complete DNS/IP token, not a subspan of a
 * larger dotted hostname (`10.20.30.40.foo.example.com`).
 *
 * Surrounding punctuation, whitespace, quotes, brackets, commas, and URL
 * scheme/path separators (`://`, `/`) are valid standalone boundaries.
 *
 * @param {string} text already-refanged (or raw) haystack
 * @param {number} start
 * @param {number} end
 */
export function isStandaloneObservableSpan(text, start, end) {
  const hay = String(text || '');
  if (start < 0 || end > hay.length || start >= end) return false;
  const left = start > 0 ? hay[start - 1] : '';
  const right = end < hay.length ? hay[end] : '';
  if (DNS_TOKEN_CHAR_RE.test(left) || DNS_TOKEN_CHAR_RE.test(right)) return false;
  if (left === '.' && start > 1 && DNS_TOKEN_CHAR_RE.test(hay[start - 2])) return false;
  if (right === '.' && DNS_TOKEN_CHAR_RE.test(hay[end + 1] || '')) return false;
  return true;
}

/**
 * Locate every occurrence of `value` in already-prepared text (case-insensitive).
 * @param {string} text
 * @param {string} value
 * @returns {Array<{ start: number, end: number }>}
 */
export function findValueSpans(text, value) {
  const hay = String(text || '');
  const needle = String(value || '');
  if (!hay || !needle) return [];
  const lowHay = hay.toLowerCase();
  const lowNeedle = needle.toLowerCase();
  const spans = [];
  let from = 0;
  while (from <= lowHay.length - lowNeedle.length) {
    const i = lowHay.indexOf(lowNeedle, from);
    if (i < 0) break;
    spans.push({ start: i, end: i + needle.length });
    from = i + needle.length;
  }
  return spans;
}

/**
 * Needles to search for a candidate: normalized value plus common source spellings.
 * @param {string} candidateType
 * @param {string} candidateValue
 */
export function sourceSearchNeedles(candidateType, candidateValue) {
  const raw = String(candidateValue || '').trim();
  if (!raw) return [];
  const type = String(candidateType || '').toLowerCase();
  const needles = new Set([raw, refangObservable(raw)]);
  if (IP_TYPES.has(type) || type === 'cidr') {
    const addr = raw.split('/')[0];
    const norm = normalizeIpAddress(addr);
    if (norm) needles.add(norm);
    if (addr) needles.add(addr);
  }
  return [...needles].filter(Boolean);
}

/**
 * Count standalone vs DNS-embedded occurrences of a candidate in source text.
 * @param {string} sourceText original or defanged report text
 * @param {string} candidateType
 * @param {string} candidateValue
 * @returns {{ standalone: number, embedded: number, total: number }}
 */
export function inspectSourceOccurrences(sourceText, candidateType, candidateValue) {
  const refanged = refangTextForExtraction(sourceText);
  const needles = sourceSearchNeedles(candidateType, candidateValue);
  let standalone = 0;
  let embedded = 0;
  const seen = new Set();
  for (const needle of needles) {
    for (const span of findValueSpans(refanged, needle)) {
      const key = `${span.start}:${span.end}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (isStandaloneObservableSpan(refanged, span.start, span.end)) standalone += 1;
      else embedded += 1;
    }
  }
  return { standalone, embedded, total: standalone + embedded };
}

/**
 * True when the source has at least one token-bounded occurrence of the value.
 * @param {string} sourceText
 * @param {string} candidateType
 * @param {string} candidateValue
 */
export function candidateHasStandaloneOccurrence(sourceText, candidateType, candidateValue) {
  return inspectSourceOccurrences(sourceText, candidateType, candidateValue).standalone > 0;
}

/**
 * True when the value occurs in the source only as a subspan of a larger DNS
 * token (numeric-prefix hostname). False when there is a standalone occurrence
 * or when the value is not found at all (unknown spelling is not evidence of
 * embedding — callers must not drop those existing candidates).
 * @param {string} sourceText
 * @param {string} candidateType
 * @param {string} candidateValue
 */
export function isOnlyEmbeddedInDnsHostname(sourceText, candidateType, candidateValue) {
  const r = inspectSourceOccurrences(sourceText, candidateType, candidateValue);
  return r.total > 0 && r.standalone === 0;
}

/**
 * Match-time gate for a regex hit in already-refanged extractor text.
 * @param {string} refangedText
 * @param {number} start
 * @param {number} end
 */
export function ipv4MatchIsStandalone(refangedText, start, end) {
  return isStandaloneObservableSpan(refangedText, start, end);
}

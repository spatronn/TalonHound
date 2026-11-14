/**
 * Observable dispositions: what happened to every observable-shaped token.
 *
 * Detection and judgement are separate records. A candidate row says what the
 * report's review set holds; a disposition says what became of a token found
 * in the source, including tokens that never became a candidate. Pure: takes
 * the extraction outcome and returns rows, writes nothing.
 *
 * The reconciliation pass reads the blocks with its own bounded, typed scanner
 * and does not reuse the extractor's decisions. A token no disposition accounts
 * for is reported as `undispositioned_token`: evidence would otherwise have
 * disappeared without trace.
 */

import { refangTextForExtraction } from './defang.js';
import { isReportIndicatorMember, isLinkedSourceIndicatorMember } from './indicatorMembership.js';
import { ipv4MatchIsStandalone } from './sourceOccurrence.js';
import { normalizeCandidateValue } from './candidateValue.js';

/**
 * v2: a digest-shaped token that is a whole label of an accounted hostname
 * ("<32 hex>.loophole.site") is part of that value, not a lost hash.
 */
export const OBSERVABLE_DISPOSITION_VERSION = 'tl-dispositions-v2';

export const DISPOSITIONS = Object.freeze({
  ACCEPTED: 'accepted',
  REJECTED: 'rejected',
  CONTEXT_ONLY: 'context_only',
  NEEDS_REVIEW: 'needs_review',
  INVALID: 'invalid',
  UNSUPPORTED: 'unsupported'
});

/** Rows persisted per run; counts always cover every row. */
export const MAX_DISPOSITION_ROWS = 5000;

const EXCERPT_CHARS = 240;
const MAX_RAW_CHARS = 500;

// Word-bounded like a real digest: "0x<40 hex>" is a wallet address, not a sha1.
const HEX_TOKEN_RE = /(?<![0-9a-z_])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-z_])/gi;
const IPV4_TOKEN_RE = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g;
const URL_TOKEN_RE = /\b(?:https?|wss?|ftp):\/\/[^\s<>"'`\]]+/gi;
/** A defang spelling the refanger did not resolve: the value was not readable. */
const DEFANG_RESIDUE_RE = /[a-z0-9-]+\s*(?:\[\s*(?:dot|\.)\s*\]|\(\s*(?:dot|\.)\s*\)|\{\s*(?:dot|\.)\s*\})\s*[a-z0-9-]+/gi;

function hexType(length) {
  return length === 64 ? 'sha256' : length === 40 ? 'sha1' : 'md5';
}

function bounded(text, max) {
  const s = String(text ?? '');
  return s.length > max ? s.slice(0, max) : s;
}

/**
 * Disposition of a candidate in its final state.
 * @param {object} c candidate (evidence record attached or in-memory)
 * @returns {{ disposition: string, reason_code: string, rule_id: string|null }}
 */
export function candidateDisposition(c) {
  const ev = c?.evidence && typeof c.evidence === 'object' ? c.evidence : {};
  const decision = c?.membership_decision || ev.membership_decision || null;
  const policy = c?.policy_decision || ev.policy_decision || null;
  const reason = decision?.reason_code || policy || 'unclassified';
  const rule = decision?.rule_id || (policy ? `policy:${policy}` : null);
  const out = (disposition) => ({ disposition, reason_code: reason, rule_id: rule });
  if (String(c?.assessment || '') === 'invalid' || String(c?.match_state || '') === 'invalid') return out(DISPOSITIONS.INVALID);
  if (c?.is_ioc === false) return out(DISPOSITIONS.UNSUPPORTED);
  if (isReportIndicatorMember(c) || isLinkedSourceIndicatorMember(c)) return out(DISPOSITIONS.ACCEPTED);
  const assessment = String(c?.assessment || '');
  const review = String(c?.review_status || '');
  if (assessment === 'context_only' || review === 'context_only' || String(c?.match_state || '') === 'context_only') {
    return out(DISPOSITIONS.CONTEXT_ONLY);
  }
  if (review === 'ignored' || review === 'rejected') return out(DISPOSITIONS.REJECTED);
  return out(DISPOSITIONS.NEEDS_REVIEW);
}

/**
 * Observable-shaped tokens of one block (hash, IPv4, URL, unresolved defang),
 * read independently of the extractor. URL tokens are consumed first: a hash or
 * address inside a URL belongs to that URL.
 * @param {string} rawText
 */
export function scanObservableTokens(rawText) {
  const text = refangTextForExtraction(String(rawText || ''));
  const tokens = [];
  const urlSpans = [];
  for (const m of text.matchAll(URL_TOKEN_RE)) {
    const value = m[0].replace(/[),.;:]+$/, '');
    urlSpans.push([m.index, m.index + value.length]);
    tokens.push({ type: 'url', value, start: m.index });
  }
  const inUrl = (at, len) => urlSpans.some(([a, b]) => at >= a && at + len <= b);
  for (const m of text.matchAll(HEX_TOKEN_RE)) {
    if (inUrl(m.index, m[0].length)) continue;
    tokens.push({ type: hexType(m[0].length), value: m[0].toLowerCase(), start: m.index });
  }
  for (const m of text.matchAll(IPV4_TOKEN_RE)) {
    if (inUrl(m.index, m[0].length)) continue;
    // "13.6.233.10-node.28" is one token, not an address: same boundary rule as extraction.
    if (!ipv4MatchIsStandalone(text, m.index, m.index + m[0].length)) continue;
    tokens.push({ type: 'ip', value: m[0], start: m.index });
  }
  for (const m of text.matchAll(DEFANG_RESIDUE_RE)) {
    tokens.push({ type: 'defang_residue', value: m[0], start: m.index });
  }
  return tokens;
}

/**
 * @param {{
 *   candidates: object[],
 *   tokenLog?: object[],
 *   blocks?: object[]
 * }} input candidates in their final state; tokenLog = tokens the extractor
 *   rejected before they became candidates; blocks = the document's blocks with
 *   zones (chrome is not scanned)
 * @returns {{ rows: object[], counts: Record<string, number>, truncated: boolean }}
 */
export function buildObservableDispositions({ candidates = [], tokenLog = [], blocks = [] }) {
  const rows = [];
  const counts = { total: 0, undispositioned: 0 };
  const accounted = new Set();
  const note = (v) => accounted.add(String(v || '').toLowerCase());
  const push = (row) => {
    counts.total += 1;
    counts[row.disposition] = (counts[row.disposition] || 0) + 1;
    rows.push(row);
  };

  for (const c of candidates) {
    const ev = c?.evidence && typeof c.evidence === 'object' ? c.evidence : {};
    const verdict = candidateDisposition(c);
    note(c.normalized_value);
    note(c.original_value);
    const occurrences = Array.isArray(c.occurrences) && c.occurrences.length
      ? c.occurrences
      : Array.isArray(ev.occurrences) ? ev.occurrences : [];
    const base = {
      observable_type: c.candidate_type,
      raw_value: bounded(c.original_value, MAX_RAW_CHARS),
      normalized_value: bounded(c.normalized_value, MAX_RAW_CHARS),
      ...verdict
    };
    if (!occurrences.length) {
      push({
        ...base,
        source_kind: c.has_original_document_occurrence === false ? 'linked_source' : 'document',
        block_id: c.block_id || null,
        section_path: [],
        table_index: null,
        row_index: null,
        column_index: null,
        char_start: null,
        char_end: null,
        excerpt: bounded(c.evidence_text, EXCERPT_CHARS) || null
      });
      continue;
    }
    for (const o of occurrences) {
      push({
        ...base,
        source_kind: 'document',
        block_id: o.block_id || null,
        section_path: Array.isArray(o.section_path) ? o.section_path.slice(0, 8) : [],
        table_index: Number.isInteger(o.table_index) ? o.table_index : null,
        row_index: Number.isInteger(o.table_row) ? o.table_row : null,
        column_index: Number.isInteger(o.table_column) ? o.table_column : null,
        char_start: Number.isInteger(o.char_start) ? o.char_start : null,
        char_end: Number.isInteger(o.char_end) ? o.char_end : null,
        excerpt: bounded(o.surrounding_text, EXCERPT_CHARS) || null
      });
    }
  }

  for (const t of tokenLog) {
    note(t.normalized_value);
    note(t.raw_value);
    push({
      source_kind: 'document',
      observable_type: t.observable_type || 'unknown',
      raw_value: bounded(t.raw_value, MAX_RAW_CHARS),
      normalized_value: t.normalized_value ? bounded(t.normalized_value, MAX_RAW_CHARS) : null,
      disposition: t.disposition || DISPOSITIONS.REJECTED,
      reason_code: t.reason_code || 'rejected',
      rule_id: t.rule_id || `extractor:${t.reason_code || 'rejected'}`,
      block_id: t.block_id || null,
      section_path: Array.isArray(t.section_path) ? t.section_path.slice(0, 8) : [],
      table_index: null,
      row_index: null,
      column_index: null,
      char_start: null,
      char_end: null,
      excerpt: bounded(t.excerpt, EXCERPT_CHARS) || null
    });
  }

  // Independent reconciliation: every typed token in a content block.
  const urlValues = [...accounted].filter((v) => /^(?:https?|wss?|ftp):\/\//.test(v));
  const hostLabels = new Set(
    [...accounted]
      .filter((v) => /^[a-z0-9_.-]+$/.test(v) && v.includes('.'))
      .flatMap((v) => v.split('.'))
      .filter((l) => /^[a-f0-9]{32,128}$/.test(l))
  );
  const seen = new Set();
  for (const b of blocks) {
    if (!b?.text || b.zone === 'header_footer' || b.layout === 'page_edge') continue;
    for (const t of scanObservableTokens(b.text)) {
      const value = String(t.value).toLowerCase();
      const key = `${b.id}\0${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (accounted.has(value) || (t.type === 'url' && accounted.has(value.replace(/\/$/, '')))) continue;
      // The candidate holds the normalized URL ("https://host:443/x" -> "https://host/x").
      if (t.type === 'url') {
        const n = normalizeCandidateValue(t.value, 'url');
        if (n?.ok && accounted.has(String(n.normalizedValue).toLowerCase())) continue;
      }
      // A URL token the extractor bounded differently (a trailing fragment it
      // trimmed) or a value that is part of an accounted URL is accounted for.
      if (urlValues.some((u) => u.includes(value) || value.startsWith(u))) continue;
      if (/^(?:md5|sha1|sha256|sha512)$/.test(t.type) && hostLabels.has(value)) continue;
      const residue = t.type === 'defang_residue';
      // "https://host/{campaign}" is a URL template, not a value.
      const template = t.type === 'url' && /[{}]|%7b|\$\{|<[^>]*>/i.test(value);
      if (!residue && !template) counts.undispositioned += 1;
      push({
        source_kind: 'document',
        observable_type: t.type,
        raw_value: bounded(t.value, MAX_RAW_CHARS),
        normalized_value: residue ? null : bounded(value, MAX_RAW_CHARS),
        disposition: residue ? DISPOSITIONS.NEEDS_REVIEW : template ? DISPOSITIONS.INVALID : DISPOSITIONS.REJECTED,
        reason_code: residue ? 'unresolved_defang_spelling' : template ? 'url_template_placeholder' : 'undispositioned_token',
        rule_id: `reconcile:${OBSERVABLE_DISPOSITION_VERSION}`,
        block_id: b.id || null,
        section_path: Array.isArray(b.section_path) ? b.section_path.slice(0, 8) : [],
        table_index: null,
        row_index: null,
        column_index: null,
        char_start: null,
        char_end: null,
        excerpt: bounded(String(b.text).slice(Math.max(0, t.start - 60), t.start + 120), EXCERPT_CHARS)
      });
    }
  }

  // The rows that need attention survive the cap ahead of accepted ones.
  const rank = (r) => (r.disposition === DISPOSITIONS.ACCEPTED ? 2 : r.disposition === DISPOSITIONS.UNSUPPORTED ? 1 : 0);
  const truncated = rows.length > MAX_DISPOSITION_ROWS;
  const kept = truncated ? [...rows].sort((a, b) => rank(a) - rank(b)).slice(0, MAX_DISPOSITION_ROWS) : rows;
  return { rows: kept, counts, truncated };
}

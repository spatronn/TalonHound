/**
 * Threat Library TLP policy: how a report's effective TLP is derived.
 *
 * TLP is a sharing restriction, never a sensitivity score. The effective
 * value (`threat_reports.tlp`) is resolved with this precedence:
 *
 *   1. manual   — set by an analyst / admin (import request or the report
 *                 page). Durable: reprocessing never overwrites it.
 *   2. explicit — a TLP marking written in the source document itself,
 *                 found deterministically (`detectExplicitTlp`). Several
 *                 distinct markings resolve to the most restrictive one.
 *   3. default  — no marking: the safe default for the source type. The
 *                 data model has no "unset" TLP, and the project's existing
 *                 import default for every source type is TLP:CLEAR.
 *
 * The AI stage may still report a `tlp` it saw, but that hint is never used
 * for the effective value: a model must not invent a restriction from the
 * subject matter (state actors, dissidents, malware, …).
 */

import { TLP_VALUES, normalizeTlp } from './constants.js';

export const TLP_SOURCES = Object.freeze(['explicit', 'default', 'manual']);

/** Restriction order for downgrade checks and multi-marking resolution. */
export const TLP_RANK = Object.freeze({
  clear: 0,
  green: 1,
  amber: 2,
  amber_strict: 3,
  red: 4
});

// `TLP`, a mandatory separator (colon, dash or whitespace) and an uppercase
// level. The separator keeps run-together tokens such as TLPAMBER out.
const MARKING_RE = /\bTLP(?:\s*[:\-]\s*|\s+)(RED|AMBER\s*[+\-]\s*STRICT|AMBER\s+STRICT|AMBER|GREEN|CLEAR|WHITE)\b/g;

function canonicalMarking(token) {
  const t = String(token || '').toUpperCase().replace(/\s+/g, '');
  if (t === 'AMBER+STRICT' || t === 'AMBER-STRICT' || t === 'AMBERSTRICT') return 'amber_strict';
  if (t === 'WHITE') return 'clear';
  return t.toLowerCase();
}

export function isValidTlp(value) {
  return TLP_VALUES.includes(String(value || '').toLowerCase());
}

export function isValidTlpSource(value) {
  return TLP_SOURCES.includes(String(value || '').toLowerCase());
}

/** True when moving from `from` to `to` loosens the sharing restriction. */
export function isTlpDowngrade(from, to) {
  const a = TLP_RANK[normalizeTlp(from)] ?? 0;
  const b = TLP_RANK[normalizeTlp(to)] ?? 0;
  return b < a;
}

/**
 * Deterministic explicit-marking scan over the canonical document (title and
 * block texts). Only uppercase `TLP:LEVEL`-style markings count, so prose
 * such as "the tlp protocol" or a file name like `tlp_clear_01.pdf` never
 * matches. Returns null when no marking exists.
 *
 * @param {{ title?: string|null, blocks?: { id?: string, text?: string }[] }|null|undefined} document
 * @returns {{ tlp: string, distinct: string[], matches: { block_id: string|null, marking: string }[] }|null}
 */
export function detectExplicitTlp(document) {
  if (!document || typeof document !== 'object') return null;
  const sources = [];
  if (document.title) sources.push({ block_id: null, text: String(document.title) });
  for (const b of Array.isArray(document.blocks) ? document.blocks : []) {
    if (b && typeof b.text === 'string' && b.text) sources.push({ block_id: b.id || null, text: b.text });
  }
  const matches = [];
  for (const src of sources) {
    MARKING_RE.lastIndex = 0;
    let m;
    while ((m = MARKING_RE.exec(src.text)) !== null) {
      const level = canonicalMarking(m[1]);
      if (!TLP_VALUES.includes(level)) continue;
      matches.push({ block_id: src.block_id, marking: m[0], level });
    }
  }
  if (!matches.length) return null;
  const distinct = [...new Set(matches.map((x) => x.level))];
  const tlp = distinct.reduce((best, cur) => (TLP_RANK[cur] > TLP_RANK[best] ? cur : best), distinct[0]);
  return {
    tlp,
    distinct,
    matches: matches.slice(0, 20).map(({ block_id, marking }) => ({ block_id, marking }))
  };
}

/**
 * Safe default when nothing explicit exists. Every current source type
 * (public URL fetch, uploaded PDF, THIB bundle) already imported as
 * TLP:CLEAR before the derivation fix; keeping that here preserves existing
 * behaviour for private uploads instead of inventing a restriction.
 */
export function defaultTlpForSource(sourceType) {
  void sourceType;
  return 'clear';
}

/**
 * Resolve the effective TLP for a report after (re)analysis.
 *
 * @param {{ report: { tlp?: string|null, tlp_source?: string|null, source_type?: string|null }, document?: object|null, aiHint?: string|null }} input
 * @returns {{ tlp: string, tlp_source: 'manual'|'explicit'|'default', detection: object|null, ai_hint: string|null, changed: boolean }}
 */
export function resolveEffectiveTlp({ report, document = null, aiHint = null }) {
  const current = normalizeTlp(report?.tlp || 'clear');
  const detection = detectExplicitTlp(document);
  const hint = aiHint ? normalizeTlp(aiHint) : null;
  if (String(report?.tlp_source || '').toLowerCase() === 'manual') {
    return { tlp: current, tlp_source: 'manual', detection, ai_hint: hint, changed: false };
  }
  if (detection) {
    return { tlp: detection.tlp, tlp_source: 'explicit', detection, ai_hint: hint, changed: detection.tlp !== current };
  }
  const fallback = defaultTlpForSource(report?.source_type);
  return { tlp: fallback, tlp_source: 'default', detection: null, ai_hint: hint, changed: fallback !== current };
}

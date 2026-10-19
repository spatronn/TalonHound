/**
 * Publisher-evidence integrity for model output.
 *
 * Deterministic extraction anchors every candidate to real canonical text
 * (`evidence_text` + `block_id`). The model may propose a better quote, a
 * block and a classification — but it is untrusted: a quote must occur
 * verbatim in the canonical document (in a block that names the value), and
 * a cited block must exist and contain the value, before either can replace
 * the publisher anchor or support a malicious escalation. Everything the
 * model said is kept separately (`ai_classification`) for review and audit.
 *
 * Pure and deterministic; no model / database access.
 */

import { refangTextForExtraction } from './defang.js';

export const EVIDENCE_INTEGRITY_VERSION = 'tl-evidence-integrity-v2';

/**
 * v2: a malicious / suspicious model label needs a publisher ASSERTION, not
 * a mention. The sentence that names the value must carry threat vocabulary
 * (C2, malicious, payload, phishing, attacker, …), unless the deterministic
 * extraction already asserts the value. A document-level publisher
 * disclaimer ("… should not be treated as standalone malicious indicators")
 * blocks model-only escalation entirely.
 */
const ASSERTIVE_CONTEXT_RE =
  /\b(?:c2|c&c|cnc|command[\s-]*(?:and|&)[\s-]*control|malicious|malware|attackers?|attacker-controlled|threat[\s-]actors?|adversar(?:y|ies)|operators?|payloads?|exfiltrat\w*|beacon\w*|phish\w*|stagers?|droppers?|loaders?|backdoors?|implants?|rats?|stealers?|ransomware|compromised|weaponi[sz]ed|lures?|staging|hosted|delivers?|delivered|drops|dropped|redirects?|redirected|iocs?|indicators? of compromise|exploit\w*|sinkhol\w*|botnets?)\b/i;
const PUBLISHER_INDICATOR_DISCLAIMER_RE =
  /\b(?:should|must)\s+not\s+be\s+(?:treated|considered|used|regarded|interpreted)\s+as\s+(?:standalone\s+|stand-alone\s+|definitive\s+|stand\s+alone\s+)?(?:malicious\s+)?(?:indicators|iocs)\b|\bare\s+not\s+(?:malicious\s+)?(?:indicators\s+of\s+compromise|iocs)\b/i;
const DETERMINISTIC_ASSERTIONS = new Set(['explicit_ioc', 'explicit_c2', 'explicit_operational_infrastructure', 'linked_source_ioc']);
/** A hash names a sample: a narrative sample hash stays a model decision (no assertion vocabulary required). */
const SAMPLE_HASH_TYPES = new Set(['md5', 'sha1', 'sha256']);

/**
 * Whether the publisher disclaims the report's observables as indicators.
 * @param {object} document canonical document
 */
export function documentDisclaimsIndicators(document) {
  for (const b of Array.isArray(document?.blocks) ? document.blocks : []) {
    if (PUBLISHER_INDICATOR_DISCLAIMER_RE.test(String(b?.text || ''))) return true;
  }
  return false;
}

/** Sentence(s) of a normalized text around each occurrence of the value. */
function sentencesNaming(norm, spellings) {
  const out = [];
  for (const v of spellings) {
    if (!v) continue;
    let from = 0;
    for (;;) {
      const at = norm.indexOf(v, from);
      if (at < 0) break;
      const startBound = Math.max(norm.lastIndexOf('. ', at), norm.lastIndexOf('; ', at));
      const endBound = norm.indexOf('. ', at + v.length);
      const start = Math.max(0, startBound < 0 ? at - 200 : startBound, at - 240);
      const end = Math.min(norm.length, endBound < 0 ? at + v.length + 200 : endBound + 1, at + v.length + 240);
      out.push(norm.slice(start, end));
      from = at + v.length;
    }
  }
  return out;
}

function assertiveAround(texts, spellings) {
  return texts.some((t) => sentencesNaming(t, spellings).some((s) => ASSERTIVE_CONTEXT_RE.test(s.split(spellings[0] || '\u0000').join(' '))));
}

/** Minimum characters of a quote fragment that must match verbatim. */
const MIN_FRAGMENT = 12;

/**
 * Canonical comparison form: refanged, defang brackets removed, typographic
 * quotes / dashes unified, table separators and whitespace collapsed,
 * lowercase.
 * @param {string} text
 */
export function normalizeEvidenceText(text) {
  return refangTextForExtraction(String(text || ''))
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/hxxp/gi, 'http')
    // Quote marks around a value are dropped by models when quoting; they carry
    // no evidence, so they are ignored on both sides.
    .replace(/['"`‘’“”«»]/g, '')
    .replace(/[–—]/g, '-')
    .replace(/[¶|]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

/**
 * Quote fragments separated by an ellipsis the model inserted when trimming.
 * @param {string} quote
 */
function quoteFragments(quote) {
  return normalizeEvidenceText(quote)
    .split(/\s*(?:\.\.\.|…)\s*/)
    .map((s) => s.trim())
    .filter((s) => s.length >= MIN_FRAGMENT);
}

/**
 * @param {object} document canonical document
 * @returns {Map<string, { id: string, norm: string }>}
 */
export function indexDocumentBlocks(document) {
  const out = new Map();
  for (const b of Array.isArray(document?.blocks) ? document.blocks : []) {
    if (!b?.id) continue;
    out.set(String(b.id), { id: String(b.id), norm: normalizeEvidenceText(b.text || '') });
  }
  return out;
}

function valueSpellings(candidate) {
  return [candidate?.normalized_value, candidate?.original_value]
    .filter(Boolean)
    .map((v) => normalizeEvidenceText(v).replace(/\/$/, ''))
    .filter(Boolean);
}

function blockNamesValue(entry, spellings) {
  return Boolean(entry) && spellings.some((v) => v && entry.norm.includes(v));
}

/**
 * Ground one model candidate update against the canonical document.
 * @param {object} candidate deterministic candidate (publisher anchor)
 * @param {{ evidence_text?: string|null, evidence_block_ids?: string[] }} update
 * @param {Map<string, { id: string, norm: string }>} blocks indexDocumentBlocks(document)
 * @returns {{
 *   quote: 'absent'|'grounded'|'ungrounded',
 *   quote_block_id: string|null,
 *   cited_block_id: string|null,
 *   cited_block: 'absent'|'grounded'|'missing'|'value_absent',
 *   supported: boolean
 * }}
 */
export function groundAiCandidateUpdate(candidate, update, blocks, opts = {}) {
  const spellings = valueSpellings(candidate);
  const cited = (Array.isArray(update?.evidence_block_ids) ? update.evidence_block_ids : []).map(String).filter(Boolean);
  let citedStatus = 'absent';
  let citedBlockId = null;
  for (const id of cited) {
    const entry = blocks.get(id);
    if (!entry) {
      if (citedStatus === 'absent') citedStatus = 'missing';
      continue;
    }
    if (blockNamesValue(entry, spellings)) {
      citedStatus = 'grounded';
      citedBlockId = id;
      break;
    }
    citedStatus = 'value_absent';
  }

  let quoteStatus = 'absent';
  let quoteBlockId = null;
  const raw = String(update?.evidence_text || '').trim();
  if (raw) {
    const fragments = quoteFragments(raw);
    quoteStatus = 'ungrounded';
    if (fragments.length) {
      // Prefer the cited blocks, then any block; the block must name the value
      // (or the quote itself must), so a real sentence about something else
      // cannot become this value's evidence.
      const order = [...cited.map((id) => blocks.get(id)).filter(Boolean), ...blocks.values()];
      const quoteNamesValue = spellings.some((v) => fragments.some((f) => f.includes(v)));
      for (const entry of order) {
        if (!fragments.every((f) => entry.norm.includes(f))) continue;
        if (!quoteNamesValue && !blockNamesValue(entry, spellings)) continue;
        quoteStatus = 'grounded';
        quoteBlockId = entry.id;
        break;
      }
    }
  }

  // Assertion check (v2): the publisher text the claim rests on — the quoted /
  // cited block, else the candidate's own occurrences — must state a threat
  // role for the value, not merely name it.
  const deterministic = DETERMINISTIC_ASSERTIONS.has(String(candidate?.source_assertion || ''));
  const supportTexts = [];
  if (quoteBlockId && blocks.get(quoteBlockId)) supportTexts.push(blocks.get(quoteBlockId).norm);
  if (citedBlockId && blocks.get(citedBlockId)) supportTexts.push(blocks.get(citedBlockId).norm);
  if (!supportTexts.length) {
    supportTexts.push(normalizeEvidenceText(candidate?.evidence_text || ''));
    for (const o of Array.isArray(candidate?.occurrences) ? candidate.occurrences : []) {
      if (o?.surrounding_text) supportTexts.push(normalizeEvidenceText(o.surrounding_text));
    }
  }
  // No candidate text at hand: the publisher blocks that name the value.
  if (!supportTexts.some(Boolean)) {
    for (const entry of blocks.values()) if (blockNamesValue(entry, spellings)) supportTexts.push(entry.norm);
  }
  const sampleHash = SAMPLE_HASH_TYPES.has(String(candidate?.candidate_type || ''));
  const assertive = deterministic || sampleHash || assertiveAround(supportTexts.filter(Boolean), spellings);
  const disclaimer = opts.disclaimer === true && !deterministic;
  const grounded = quoteStatus === 'grounded' || citedStatus === 'grounded' ||
    (quoteStatus === 'absent' && citedStatus === 'absent');
  return {
    quote: quoteStatus,
    quote_block_id: quoteBlockId,
    cited_block_id: citedBlockId,
    cited_block: citedStatus,
    assertive,
    publisher_disclaimer: disclaimer,
    // A model claim is supported when it points at real publisher text that
    // names the value (a verbatim quote or a cited block containing it), or
    // cites nothing at all — then it is a reading of the candidate's own
    // deterministic occurrences, which are publisher text by construction.
    // Fabricated support (a quote that is not in the document, a block that
    // does not exist or does not name the value) is unsupported.
    // v2: and the supporting text asserts a threat role (or extraction did),
    // and the publisher did not disclaim the report's observables.
    supported: grounded && assertive && !disclaimer
  };
}

/** Assessments that escalate a candidate (need publisher support). */
export const ESCALATING_ASSESSMENTS = Object.freeze(new Set(['malicious', 'suspicious']));

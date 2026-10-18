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

export const EVIDENCE_INTEGRITY_VERSION = 'tl-evidence-integrity-v1';

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
export function groundAiCandidateUpdate(candidate, update, blocks) {
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

  return {
    quote: quoteStatus,
    quote_block_id: quoteBlockId,
    cited_block_id: citedBlockId,
    cited_block: citedStatus,
    // A model claim is supported when it points at real publisher text that
    // names the value (a verbatim quote or a cited block containing it), or
    // cites nothing at all — then it is a reading of the candidate's own
    // deterministic occurrences, which are publisher text by construction.
    // Fabricated support (a quote that is not in the document, a block that
    // does not exist or does not name the value) is unsupported.
    supported: quoteStatus === 'grounded' || citedStatus === 'grounded' ||
      (quoteStatus === 'absent' && citedStatus === 'absent')
  };
}

/** Assessments that escalate a candidate (need publisher support). */
export const ESCALATING_ASSESSMENTS = Object.freeze(new Set(['malicious', 'suspicious']));

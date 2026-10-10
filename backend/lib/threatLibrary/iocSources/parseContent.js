/**
 * Deterministic parse of linked IOC source content into candidate identities.
 * Reuses Threat Library extractors; never runs AI; never executes content.
 */

import { extractCandidatesFromDocument } from '../candidateExtraction.js';
import { htmlToCanonicalDocument, plainTextToCanonicalDocument } from '../urlIngest.js';
import { LINKED_SOURCE_IOC_ASSERTION } from './constants.js';
import { guessTypeFromUrl } from './discover.js';

/**
 * @param {string} contentType
 * @param {string} url
 * @param {string} [path]
 */
export function detectSourceFormat({ contentType, url, path }) {
  const ct = String(contentType || '').split(';')[0].trim().toLowerCase();
  const name = String(path || url || '').toLowerCase();
  if (ct === 'application/pdf' || name.endsWith('.pdf')) return 'pdf';
  if (ct === 'application/json' || name.endsWith('.json')) return 'json';
  if (ct === 'text/csv' || name.endsWith('.csv')) return 'csv';
  if (ct.includes('html') || name.endsWith('.html') || name.endsWith('.htm')) return 'html';
  if (name.endsWith('.txt') || name.endsWith('.md') || name.endsWith('.ioc') || ct.startsWith('text/')) return 'txt';
  const fromUrl = guessTypeFromUrl(url);
  if (fromUrl !== 'unknown' && fromUrl !== 'github_dir' && fromUrl !== 'github_file') return fromUrl;
  return 'txt';
}

/**
 * Parse a loose JSON indicator list when a recognizable schema is present.
 * @param {string} text
 * @returns {string|null} plain text lines of observables, or null if unsupported
 */
export function jsonIndicatorsToText(text) {
  let data;
  try {
    data = JSON.parse(String(text || ''));
  } catch {
    return null;
  }

  const values = [];
  const push = (v) => {
    if (v == null) return;
    if (typeof v === 'string' || typeof v === 'number') {
      const s = String(v).trim();
      if (s) values.push(s);
    }
  };

  const walk = (node, depth = 0) => {
    if (depth > 6 || values.length > 50_000) return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
      return;
    }
    if (!node || typeof node !== 'object') {
      push(node);
      return;
    }
    for (const key of ['indicators', 'iocs', 'observables', 'data', 'items', 'values']) {
      if (key in node) walk(node[key], depth + 1);
    }
    for (const key of ['value', 'indicator', 'ioc', 'observable', 'hash', 'ip', 'domain', 'url', 'sha256', 'md5', 'sha1']) {
      if (key in node) push(node[key]);
    }
  };

  walk(data);
  if (!values.length) return null;
  return values.join('\n');
}

/**
 * Build linked-source candidate objects from a canonical document extract.
 * @param {object} document
 * @param {{ sourcePublicId?: string, filePath?: string }} [meta]
 */
export function candidatesFromDocument(document, meta = {}) {
  const list = extractCandidatesFromDocument(document) || [];
  const out = [];
  for (const c of Array.isArray(list) ? list : []) {
    if (!c || c.is_ioc === false) continue;
    const type = String(c.candidate_type || '').toLowerCase();
    if (!type || type === 'cve' || type === 'attack_technique') continue;
    // Linked packs are treated as source-scoped authoritative lists (not original MODE A).
    out.push({
      candidate_type: c.candidate_type,
      original_value: c.original_value,
      normalized_value: c.normalized_value,
      assessment: c.assessment === 'context_only' || c.assessment === 'invalid' ? c.assessment : 'malicious',
      role: c.role || 'malicious_infrastructure',
      confidence: c.confidence ?? 0.9,
      evidence_text: c.evidence_text || null,
      section: c.section || meta.filePath || 'linked_ioc_source',
      block_id: c.block_id || null,
      page_number: c.page_number ?? null,
      review_status: 'pending',
      match_state: c.match_state || 'new',
      is_ioc: true,
      source_assertion: LINKED_SOURCE_IOC_ASSERTION,
      has_original_document_occurrence: false,
      evidence: {
        ...(c.evidence && typeof c.evidence === 'object' ? c.evidence : {}),
        source_assertion: LINKED_SOURCE_IOC_ASSERTION,
        document_has_authoritative_scope: false,
        linked_source: true,
        linked_source_id: meta.sourcePublicId || null,
        linked_source_path: meta.filePath || null,
        is_direct_source_observable: true,
        occurrences: Array.isArray(c.evidence?.occurrences)
          ? c.evidence.occurrences.map((o) => ({
              ...o,
              zone: o.zone || 'linked_ioc_source',
              asserted: true,
              occurrence_kind: o.occurrence_kind || 'standalone_indicator_row'
            }))
          : [
              {
                zone: 'linked_ioc_source',
                asserted: true,
                occurrence_kind: 'standalone_indicator_row',
                surrounding_text: c.evidence_text || c.original_value
              }
            ]
      }
    });
  }
  return out;
}

/**
 * @param {{ body: string, buffer?: Buffer, contentType?: string, url?: string, path?: string, sourcePublicId?: string, pdfToDocument?: Function }} input
 */
export async function parseIocSourceContent(input) {
  const format = detectSourceFormat({
    contentType: input.contentType,
    url: input.url,
    path: input.path
  });
  const warnings = [];
  let document = null;

  if (format === 'pdf') {
    if (typeof input.pdfToDocument !== 'function') {
      return { ok: false, code: 'unsupported_format', format, message: 'PDF parsing unavailable', candidates: [], warnings };
    }
    try {
      document = await input.pdfToDocument(input.buffer || Buffer.from(input.body || '', 'utf8'), {
        sourceUrl: input.url || null
      });
    } catch (err) {
      return {
        ok: false,
        code: 'parse_failed',
        format,
        message: String(err?.message || 'PDF parse failed').slice(0, 240),
        candidates: [],
        warnings
      };
    }
  } else if (format === 'html') {
    document = htmlToCanonicalDocument(input.body || '', { url: input.url, finalUrl: input.url });
  } else if (format === 'json') {
    const asText = jsonIndicatorsToText(input.body || '');
    if (!asText) {
      return {
        ok: false,
        code: 'unsupported_json_schema',
        format,
        message: 'JSON did not match a supported indicator schema',
        candidates: [],
        warnings
      };
    }
    document = plainTextToCanonicalDocument(asText, { title: input.path || 'JSON IOC source', sourceUrl: input.url });
  } else {
    // txt / csv / md / yaml-as-text
    document = plainTextToCanonicalDocument(input.body || '', {
      title: input.path || 'IOC source',
      sourceUrl: input.url
    });
  }

  if (!document) {
    return { ok: false, code: 'parse_failed', format, message: 'No document produced', candidates: [], warnings };
  }

  const candidates = candidatesFromDocument(document, {
    sourcePublicId: input.sourcePublicId,
    filePath: input.path
  });

  const typeBreakdown = {};
  for (const c of candidates) {
    const t = c.candidate_type;
    typeBreakdown[t] = (typeBreakdown[t] || 0) + 1;
  }

  return {
    ok: true,
    format,
    candidates,
    raw_count: candidates.length,
    unique_count: candidates.length,
    type_breakdown: typeBreakdown,
    warnings
  };
}

/**
 * Aggregate parse results and compute preview overlap stats.
 * @param {object[]} parseResults
 * @param {{ originalKeys?: Set<string>, otherLinkedKeys?: Set<string> }} [ctx]
 */
export function buildPreviewFromParses(parseResults, ctx = {}) {
  const byKey = new Map();
  let raw = 0;
  const warnings = [];
  const errors = [];
  const typeBreakdown = {};

  for (const r of parseResults || []) {
    if (!r.ok) {
      errors.push({ code: r.code, message: r.message, path: r.path || null });
      continue;
    }
    for (const w of r.warnings || []) warnings.push(w);
    for (const c of r.candidates || []) {
      raw += 1;
      const key = `${c.candidate_type}\0${c.normalized_value}`;
      if (!byKey.has(key)) byKey.set(key, c);
      typeBreakdown[c.candidate_type] = (typeBreakdown[c.candidate_type] || 0) + 1;
    }
  }

  const uniqueKeys = [...byKey.keys()];
  const originalKeys = ctx.originalKeys || new Set();
  const otherLinkedKeys = ctx.otherLinkedKeys || new Set();
  let overlapOriginal = 0;
  let overlapOther = 0;
  let newIdentities = 0;
  for (const key of uniqueKeys) {
    const inOrig = originalKeys.has(key);
    const inOther = otherLinkedKeys.has(key);
    if (inOrig) overlapOriginal += 1;
    if (inOther) overlapOther += 1;
    if (!inOrig && !inOther) newIdentities += 1;
  }

  return {
    estimated: false,
    raw_count: raw,
    unique_count: uniqueKeys.length,
    type_breakdown: typeBreakdown,
    overlap_with_original: overlapOriginal,
    overlap_with_other_linked_sources: overlapOther,
    new_identities: newIdentities,
    unsupported_or_contextual: errors.length,
    warnings: warnings.slice(0, 40),
    errors: errors.slice(0, 40),
    inspected_at: new Date().toISOString()
  };
}

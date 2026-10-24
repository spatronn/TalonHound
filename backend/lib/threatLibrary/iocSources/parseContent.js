/**
 * Deterministic parse of linked IOC source content into candidate identities.
 * Reuses Threat Library extractors; never runs AI; never executes content.
 * STIX JSON / STIX XML use structured semantic parsers (not free-text scans).
 */

import { extractCandidatesFromDocument } from '../candidateExtraction.js';
import { htmlToCanonicalDocument, plainTextToCanonicalDocument } from '../urlIngest.js';
import { LINKED_SOURCE_IOC_ASSERTION } from './constants.js';
import { guessTypeFromUrl } from './sourceType.js';
import {
  asciidocToCanonicalDocument,
  isPublisherReferenceCandidate,
  isReadmePath,
  markdownToCanonicalDocument,
  selectCampaignScope
} from './campaignScope.js';
import { candidatesFromStixEvidence } from './stix/candidates.js';
import { looksLikeStixJson, parseStixJsonSource } from './stix/json.js';
import { looksLikeStixXml, parseStixXmlSource } from './stix/xml.js';

/**
 * @param {string} contentType
 * @param {string} url
 * @param {string} [path]
 */
export function detectSourceFormat({ contentType, url, path }) {
  const ct = String(contentType || '').split(';')[0].trim().toLowerCase();
  const name = String(path || url || '').toLowerCase();
  if (ct === 'application/pdf' || name.endsWith('.pdf')) return 'pdf';
  if (
    ct === 'application/stix+json'
    || ct === 'application/vnd.oasis.stix+json'
    || (name.endsWith('.json') && /stix/i.test(name))
  ) return 'stix_json';
  if (ct === 'application/json' || name.endsWith('.json')) return 'json';
  if (
    ct.includes('stix+xml')
    || ct === 'application/xml'
    || ct === 'text/xml'
    || name.endsWith('.xml')
    || name.endsWith('.stix')
  ) {
    // Narrow to STIX XML when name/cues say so; plain XML still probed at parse time.
    if (/stix/i.test(name) || ct.includes('stix')) return 'stix_xml';
    return 'xml';
  }
  if (name.endsWith('.adoc') || name.endsWith('.asciidoc')) return 'asciidoc';
  if (ct === 'text/csv' || name.endsWith('.csv')) return 'csv';
  if (ct.includes('html') || name.endsWith('.html') || name.endsWith('.htm')) return 'html';
  if (name.endsWith('.md') || name.endsWith('.markdown')) return 'markdown';
  if (
    name.endsWith('.txt')
    || name.endsWith('.ioc')
    || name.endsWith('.sha256')
    || name.endsWith('.sha1')
    || name.endsWith('.md5')
    || ct.startsWith('text/')
  ) return 'txt';
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

  // STIX bundles are never flattened through the loose walker.
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    if (data.type === 'bundle' || Array.isArray(data.objects) || looksLikeStixJson(text)) {
      return null;
    }
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

function typeBreakdownFromCandidates(candidates) {
  const typeBreakdown = {};
  for (const c of candidates) {
    const t = c.candidate_type;
    typeBreakdown[t] = (typeBreakdown[t] || 0) + 1;
  }
  return typeBreakdown;
}

function finishStixParse(parsed, meta, warnings = []) {
  if (!parsed.ok) {
    return {
      ok: false,
      code: parsed.code || 'parse_failed',
      format: parsed.format || 'stix_json',
      message: parsed.message || 'STIX parse failed',
      candidates: [],
      warnings,
      classification: parsed.summary?.classification || null,
      stix_diagnostics: parsed.summary?.diagnostics || []
    };
  }
  const candidates = candidatesFromStixEvidence(parsed.evidence, meta).filter(
    (c) => !isPublisherReferenceCandidate(c, meta.reportScope || {})
  );
  // Indicator candidates only count toward unique_count for inspect preview.
  const indicatorCandidates = candidates.filter((c) => c.assessment === 'malicious' && c.is_ioc !== false);
  return {
    ok: true,
    format: parsed.format,
    candidates: indicatorCandidates,
    raw_count: indicatorCandidates.length,
    unique_count: indicatorCandidates.length,
    type_breakdown: typeBreakdownFromCandidates(indicatorCandidates),
    warnings,
    classification: parsed.summary?.classification || null,
    stix_diagnostics: (parsed.summary?.diagnostics || []).slice(0, 40),
    stix_meta: {
      spec_version: parsed.spec_version || null,
      bundle_id: parsed.bundle_id || null,
      indicator_count: parsed.indicator_count ?? null,
      object_counts: parsed.object_counts || null
    },
    // Context-only / unsupported retained for diagnostics (not as Indicator candidates).
    context_candidates: candidates.filter((c) => c.assessment === 'context_only')
  };
}

/**
 * @param {{ body: string, buffer?: Buffer, contentType?: string, url?: string, path?: string, sourcePublicId?: string, pdfToDocument?: Function, reportScope?: object }} input
 */
export async function parseIocSourceContent(input) {
  let format = detectSourceFormat({
    contentType: input.contentType,
    url: input.url,
    path: input.path
  });
  const warnings = [];
  let document = null;
  const meta = {
    sourcePublicId: input.sourcePublicId,
    filePath: input.path,
    reportScope: input.reportScope || {}
  };

  // Content-sniff STIX even when the URL/extension said plain json/xml/txt.
  const bodyText = input.body || '';
  if ((format === 'json' || format === 'stix_json') && looksLikeStixJson(bodyText)) {
    format = 'stix_json';
  }
  if ((format === 'xml' || format === 'stix_xml' || format === 'txt') && looksLikeStixXml(bodyText)) {
    format = 'stix_xml';
  }

  if (format === 'stix_json') {
    return finishStixParse(parseStixJsonSource(bodyText), meta, warnings);
  }
  if (format === 'stix_xml') {
    return finishStixParse(parseStixXmlSource(bodyText), meta, warnings);
  }

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
  } else if (format === 'asciidoc') {
    document = asciidocToCanonicalDocument(input.body || '', { title: input.path || 'IOC source', sourceUrl: input.url });
  } else if (format === 'markdown') {
    document = markdownToCanonicalDocument(input.body || '', { title: input.path || 'IOC source', sourceUrl: input.url });
  } else if (format === 'json') {
    if (looksLikeStixJson(bodyText)) {
      return finishStixParse(parseStixJsonSource(bodyText), meta, warnings);
    }
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
  } else if (format === 'xml') {
    // Non-STIX XML is not text-scanned for IOC shapes (avoids contextual FPs).
    return {
      ok: false,
      code: 'unsupported_format',
      format,
      message: 'XML is not a recognized STIX 1.x package',
      candidates: [],
      warnings
    };
  } else {
    // txt / csv / md-as-text fallback
    if (isReadmePath(input.path || input.url || '') && /\.md(?:$|\?)/i.test(String(input.path || input.url || ''))) {
      document = markdownToCanonicalDocument(input.body || '', { title: input.path || 'IOC source', sourceUrl: input.url });
      format = 'markdown';
    } else {
      document = plainTextToCanonicalDocument(input.body || '', {
        title: input.path || 'IOC source',
        sourceUrl: input.url
      });
    }
  }

  if (!document) {
    return { ok: false, code: 'parse_failed', format, message: 'No document produced', candidates: [], warnings };
  }

  // Campaign scope (tl-ioc-source-scope-v1): a folder README holds IOCs only
  // for the campaign that links / names this report. A README that cannot be
  // tied to the report contributes nothing.
  let scope = null;
  if (isReadmePath(input.path || input.url || '')) {
    const selected = selectCampaignScope(document, input.reportScope || {});
    scope = {
      status: selected.status,
      multi_campaign: selected.multi_campaign,
      section_heading: selected.section_heading,
      excluded_sections: selected.excluded_sections.slice(0, 20)
    };
    if (selected.status === 'unresolved' || !selected.document) {
      return {
        ok: false,
        code: 'campaign_scope_unresolved',
        format,
        message: 'The README is not tied to this report (no section links or names it)',
        candidates: [],
        warnings,
        scope
      };
    }
    document = selected.document;
  }

  // Campaign READMEs: only table rows are IOC inventory (ESET AsciiDoc /
  // markdown tables). Prose/Reference paragraphs are for scope tying only —
  // never free-text promote domains from an Elastic-style instructions README.
  let extractDoc = document;
  if (isReadmePath(input.path || input.url || '')) {
    const tableBlocks = (document.blocks || []).filter((b) => b?.type === 'table');
    if (!tableBlocks.length) {
      return {
        ok: true,
        format,
        candidates: [],
        raw_count: 0,
        unique_count: 0,
        type_breakdown: {},
        warnings: [...warnings, 'readme_scope_only_no_ioc_tables'],
        ...(scope ? { scope } : {})
      };
    }
    extractDoc = { ...document, blocks: tableBlocks };
  }

  const candidates = candidatesFromDocument(extractDoc, {
    sourcePublicId: input.sourcePublicId,
    filePath: input.path
  }).filter((c) => !isPublisherReferenceCandidate(c, input.reportScope || {}));

  return {
    ok: true,
    format,
    candidates,
    raw_count: candidates.length,
    unique_count: candidates.length,
    type_breakdown: typeBreakdownFromCandidates(candidates),
    warnings,
    ...(scope ? { scope } : {})
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
  const classification = {
    indicator: 0,
    context_only: 0,
    excluded: 0,
    uncertain: 0,
    unsupported: 0
  };
  const stixDiagnostics = [];

  for (const r of parseResults || []) {
    if (!r.ok) {
      errors.push({ code: r.code, message: r.message, path: r.path || null });
      continue;
    }
    for (const w of r.warnings || []) warnings.push(w);
    if (r.classification && typeof r.classification === 'object') {
      for (const k of Object.keys(classification)) {
        classification[k] += Number(r.classification[k] || 0);
      }
    }
    for (const d of r.stix_diagnostics || []) {
      if (stixDiagnostics.length < 40) stixDiagnostics.push({ ...d, path: r.path || null });
    }
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
    classification,
    stix_diagnostics: stixDiagnostics,
    warnings: warnings.slice(0, 40),
    errors: errors.slice(0, 40),
    inspected_at: new Date().toISOString()
  };
}

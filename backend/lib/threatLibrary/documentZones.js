/**
 * Document structural zone classification for Threat Library.
 * Language-agnostic intent with optional multilingual heading hints (not the sole authority).
 */

import { collapseLetterSpacing, isObservableOnlyLine, hasCitationMarker } from './pdfLayout.js';
import { interpretIocTable, looksLikeIocTableHeader } from './tableSemantics.js';

/** @typedef {'report_body'|'explicit_ioc_section'|'c2_section'|'sample_table'|'reference_section'|'source_metadata'|'header_footer'|'navigation'|'vendor_about'|'code'|'unknown'} DocumentZone */

/** Minimum consecutive indicator-only rows that form a structural IOC list without a heading. */
export const OBSERVABLE_LIST_MIN_ROWS = 3;

export const DOCUMENT_ZONES = Object.freeze([
  'report_body',
  'explicit_ioc_section',
  'c2_section',
  'sample_table',
  'reference_section',
  'source_metadata',
  'header_footer',
  'navigation',
  'vendor_about',
  'code',
  'unknown'
]);

/** Negative / context-only zones for IOC promotion */
export const NEGATIVE_ZONES = new Set([
  'reference_section',
  'source_metadata',
  'header_footer',
  'navigation',
  'vendor_about'
]);

/** Strong positive assertion zones */
export const STRONG_IOC_ZONES = new Set(['explicit_ioc_section', 'c2_section', 'sample_table']);

/**
 * Multilingual heading hints (optimization only — semantic AI still required).
 * Intent-based groups, not vendor allowlists.
 */
const HEADING_HINTS = Object.freeze({
  explicit_ioc_section: [
    /\biocs?\b/i,
    /indicators?\s+of\s+compromise/i,
    /compromise\s+indicators?/i,
    /^(?:host|network|file|atomic|additional|other|related)?\s*indicators?\s*[:：]?$/i,
    /附录\s*ioc/i,
    /威胁指标/i,
    /compromisso|indicadores/i,
    /göstergeler/i,
    /compromise\s+göstergeleri/i
  ],
  c2_section: [
    /\bc\s*&\s*c\b/i,
    /\bc2\b/i,
    /command\s*(and|&)\s*control/i,
    /c&c/i,
    // Label-like CJK C2 headings only — "远控" alone also names RAT malware in titles.
    /控制端|回连地址|通信地址|远控地址|c2地址|c2服务器/i,
    /komuta\s*kontrol/i
  ],
  sample_table: [
    /malicious\s+samples?/i,
    /sample\s+hash/i,
    /md5|sha.?256|file\s+hash/i,
    /恶意样本|样本哈希|文件哈希/i,
    /örnek\s+hash/i
  ],
  reference_section: [
    /^references?\b/i,
    /bibliography/i,
    /related\s+(reports?|articles?|links?)/i,
    /further\s+reading/i,
    /参考链接|参考文献|相关链接|引用/i,
    /kaynaklar|referanslar/i
  ],
  source_metadata: [
    /source\s*url/i,
    /permalink/i,
    /原文链接|来源|作者/i,
    /published\s+by/i
  ],
  vendor_about: [
    /about\s+us/i,
    /disclaimer/i,
    /privacy\s+policy/i,
    /关于我们|免责声明/i
  ],
  code: [
    /\bclass\s+\w+/i,
    /\bnamespace\b/i,
    /\.NET|C#|Java\b|method\s+Main\b/i,
    /反编译|代码片段/i
  ]
});

/**
 * @param {string} text
 * @returns {DocumentZone|null}
 */
/** Strong / code hints must be label-like headings, not long titles or prose. */
const LABEL_MAX_CHARS = Object.freeze({
  explicit_ioc_section: 48,
  c2_section: 40,
  sample_table: 40,
  code: 40
});

export function classifyHeadingText(text, opts = {}) {
  const t = collapseLetterSpacing(String(text || '').trim());
  if (!t || t.length > 160) return null;
  // A table header row that survived only as a heading ("Type Indicator
  // Description", "Tür Gösterge Açıklama") opens an explicit IOC table.
  if (looksLikeIocTableHeader(t)) return 'explicit_ioc_section';
  for (const [zone, patterns] of Object.entries(HEADING_HINTS)) {
    const max = LABEL_MAX_CHARS[zone];
    if (max && t.length > max) continue;
    // Code hints only apply to real headings (prose mentioning C#/.NET is body text).
    if (zone === 'code' && opts.isHeading === false) continue;
    for (const re of patterns) {
      if (re.test(t)) return /** @type {DocumentZone} */ (zone);
    }
  }
  return null;
}

/**
 * Normalize text for repetition detection.
 * @param {string} text
 */
export function normalizeForRepetition(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/https?:\/\/\S+/gi, 'URL')
    .replace(/\d{1,2}[\/.\-]\d{1,2}[\/.\-]\d{2,4}/g, 'DATE')
    .replace(/\d{1,2}:\d{2}(:\d{2})?/g, 'TIME')
    .replace(/\bpage\s*\d+\b/gi, 'PAGE')
    .replace(/\d+\s*\/\s*\d+/g, 'PAGE')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 240);
}

/**
 * Detect repeated short blocks across pages (PDF headers/footers).
 * @param {import('./canonicalDocument.js').CanonicalBlock[]} blocks
 * @returns {Set<string>} block ids
 */
export function detectRepeatedHeaderFooterBlockIds(blocks) {
  const byNorm = new Map();
  for (const b of blocks || []) {
    const text = String(b.text || '').trim();
    if (!text || text.length > 220) continue;
    const norm = normalizeForRepetition(text);
    if (norm.length < 8) continue;
    if (!byNorm.has(norm)) byNorm.set(norm, []);
    byNorm.get(norm).push(b);
  }

  const pages = new Set((blocks || []).map((b) => b.page).filter((p) => p != null));
  const pageCount = Math.max(pages.size, 1);
  const flagged = new Set();

  for (const [, group] of byNorm) {
    // A block is only "repeated" when the same normalized text occurs more than once.
    if (group.length < 2) continue;
    const distinctPages = new Set(group.map((b) => b.page).filter((p) => p != null));
    const repeatPages = distinctPages.size || group.length;
    // Appear on many pages OR on both pages of a two-page document (short text only)
    if (
      (pageCount >= 3 && repeatPages >= Math.min(3, Math.ceil(pageCount * 0.4))) ||
      (pageCount === 2 && repeatPages === 2 && group.every((b) => String(b.text || '').length < 180))
    ) {
      for (const b of group) {
        if (b.id) flagged.add(b.id);
      }
    }
  }
  return flagged;
}

/**
 * Annotate canonical blocks with zone metadata (mutates copies).
 * @param {import('./canonicalDocument.js').CanonicalDocument} doc
 * @param {{ sourceUrl?: string|null, sourceHost?: string|null }} [opts]
 */
export function annotateDocumentZones(doc, opts = {}) {
  const blocks = (doc.blocks || []).map((b) => ({ ...b }));
  const footerIds = detectRepeatedHeaderFooterBlockIds(blocks);
  /** @type {DocumentZone} */
  let currentZone = 'report_body';
  let currentHeading = null;

  for (const b of blocks) {
    const text = String(b.text || '').trim();
    const pageEdge = b.layout === 'page_edge';
    if (b.type === 'heading' && !pageEdge) currentHeading = collapseLetterSpacing(text).slice(0, 120);
    else if (!pageEdge) b.section_heading = currentHeading;
    const isHeadingLike =
      !pageEdge &&
      b.type !== 'table' &&
      (b.type === 'heading' ||
        (text.length > 0 &&
          text.length <= 72 &&
          !/https?:\/\//i.test(text) &&
          !/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(text) &&
          !/\b[a-f0-9]{32}\b/i.test(text)));
    const headingZone = isHeadingLike ? classifyHeadingText(text, { isHeading: b.type === 'heading' }) : null;

    if (
      headingZone &&
      ['explicit_ioc_section', 'c2_section', 'sample_table', 'reference_section', 'vendor_about', 'code'].includes(
        headingZone
      )
    ) {
      currentZone = headingZone;
      b.zone_reason = 'heading_hint';
    } else if (b.type === 'heading' && !pageEdge) {
      // A structural heading the hints do not recognise closes the current
      // section: strong / negative zones must be explicitly delimited.
      currentZone = 'report_body';
      b.zone_reason = 'heading_reset';
    }

    /** @type {DocumentZone} */
    let zone = currentZone;
    if (pageEdge || footerIds.has(b.id)) {
      zone = 'header_footer';
      b.zone_reason = pageEdge ? 'page_edge' : 'repeated_block';
    } else if (opts.sourceUrl && text.includes(String(opts.sourceUrl).slice(0, 40))) {
      zone = zone === 'report_body' ? 'source_metadata' : zone;
      if (zone === 'source_metadata') b.zone_reason = 'source_url';
    } else if (opts.sourceHost && /\bhttps?:\/\//i.test(text) && text.toLowerCase().includes(String(opts.sourceHost).toLowerCase()) && text.length < 200) {
      // Short blocks mentioning source host tend to be printed provenance
      if (footerIds.has(b.id) || text.length < 160) {
        zone = 'source_metadata';
        b.zone_reason = 'source_host';
      }
    }

    b.zone = zone;
    b.section = b.section || zone;

    // A typed indicator table proves IOC semantics by its own structure —
    // headings in an unknown language are not required. Negative zones
    // (references, vendor chrome) still win.
    if (b.type === 'table' && b.table) {
      const negative = NEGATIVE_ZONES.has(zone);
      const interpretation = interpretIocTable(b, { negativeZone: negative });
      b.ioc_table = interpretation;
      if (interpretation.kind === 'ioc_table' && interpretation.explicit && !negative) {
        b.zone = 'explicit_ioc_section';
        b.section = b.section === zone ? 'explicit_ioc_section' : b.section;
        b.zone_reason = 'ioc_table';
      }
    }
  }

  applyObservableListZones(blocks);

  return {
    ...doc,
    blocks,
    meta: {
      ...(doc.meta || {}),
      zones_annotated: true,
      source_url: opts.sourceUrl || doc.meta?.source_url || null,
      source_host: opts.sourceHost || doc.meta?.source_host || null
    }
  };
}

/**
 * Structural IOC-list detection (no headings needed): >= OBSERVABLE_LIST_MIN_ROWS
 * consecutive indicator-only rows in body text form an explicit IOC list;
 * a run made of citation-marked rows ("[1] https://…") is a reference list.
 * Header/footer rows in between (page breaks) do not interrupt a run.
 * @param {object[]} blocks — zone-annotated, mutated in place
 */
export function applyObservableListZones(blocks) {
  let run = [];
  const flush = () => {
    if (run.length >= OBSERVABLE_LIST_MIN_ROWS) {
      const cited = run.filter((b) => hasCitationMarker(b.text)).length;
      const zone = cited * 2 >= run.length ? 'reference_section' : 'explicit_ioc_section';
      for (const b of run) {
        if (b.zone === 'report_body' || b.zone === 'unknown') {
          b.zone = zone;
          b.section = zone;
          b.zone_reason = zone === 'reference_section' ? 'citation_list' : 'observable_list';
        }
      }
    }
    run = [];
  };
  for (const b of blocks || []) {
    if (b.zone === 'header_footer') continue;
    const row = b.type === 'list_item' || b.layout === 'observable_row' || isObservableOnlyLine(b.text);
    if (row && String(b.text || '').length <= 400) {
      run.push(b);
    } else {
      flush();
    }
  }
  flush();
}

/**
 * Evidence tier from zone + AI-independent signals.
 * @param {DocumentZone|string|null|undefined} zone
 * @returns {'A'|'B'|'C'|'D'}
 */
export function evidenceTierForZone(zone) {
  if (STRONG_IOC_ZONES.has(String(zone || ''))) return 'A';
  if (NEGATIVE_ZONES.has(String(zone || ''))) return 'D';
  if (zone === 'code') return 'C';
  return 'C';
}

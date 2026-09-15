/**
 * Document structural zone classification for Threat Library.
 * Language-agnostic intent with optional multilingual heading hints (not the sole authority).
 */

import { collapseLetterSpacing, isObservableOnlyLine, hasCitationMarker } from './pdfLayout.js';
import { refangTextForExtraction } from './defang.js';
import { isPrivateOrReservedAddress } from './candidateValue.js';
import { classifyTypeLabel } from './observableTypeResolver.js';
import { interpretIocTable, looksLikeIocTableHeader, parseDeclaredType } from './tableSemantics.js';
import {
  INDICATOR_HEADING_FORMS,
  classifyIndicatorHeading,
  classifySectionRole,
  isObservableListLine,
  zoneForSectionRole
} from './indicatorScope.js';

/**
 * Bump when zone / scope semantics change (candidates are re-derived; the
 * canonical document itself is unchanged).
 * v2: descriptive indicator headings ("Indicators: …") open an authoritative
 * section once structurally confirmed; sub-labels inside an open section
 * inherit its scope (no per-subgroup run-length gate); ≥3-row discovery is a
 * fallback for unlabelled lists only.
 */
export const THREAT_LIBRARY_DOCUMENT_ZONES_VERSION = 'tl-zones-v2';

/**
 * A short heading that is itself an observable-type label ("Domain", "IP
 * Addresses", "Hash Values (SHA-256)", "Mutex") types the blocks beneath it.
 * Inside an open indicator section such a sub-heading continues the section
 * instead of closing it (publisher lists per type under one IOC heading).
 * @param {string} text
 * @returns {{ label: string, declared_type: string|null, semantics: 'network'|'artifact'|'neutral' }|null}
 */
export function typeLabelHeading(text) {
  const t = String(text || '').trim();
  if (!t || t.length > 40 || /[.!?。]$/.test(t)) return null;
  const declared = parseDeclaredType(t);
  const label = classifyTypeLabel(t);
  if (!declared && label.semantics === 'neutral') return null;
  return { label: t, declared_type: declared ? declared.type : null, semantics: declared ? 'network' : label.semantics };
}

/** @typedef {'report_body'|'explicit_ioc_section'|'c2_section'|'sample_table'|'operational_infrastructure'|'reference_section'|'source_metadata'|'header_footer'|'navigation'|'vendor_about'|'code'|'unknown'} DocumentZone */

/** Minimum consecutive indicator-only rows that form a structural IOC list without a heading. */
export const OBSERVABLE_LIST_MIN_ROWS = 3;

export const DOCUMENT_ZONES = Object.freeze([
  'report_body',
  'explicit_ioc_section',
  'c2_section',
  'sample_table',
  'operational_infrastructure',
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

/** Strong positive assertion zones (publisher-curated operational indicator sets). */
export const STRONG_IOC_ZONES = new Set([
  'explicit_ioc_section',
  'c2_section',
  'sample_table',
  'operational_infrastructure'
]);

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
  if (!t || t.length > 200) return null;
  // A table header row that survived only as a heading ("Type Indicator
  // Description", "Tür Gösterge Açıklama") opens an explicit IOC table.
  if (looksLikeIocTableHeader(t)) return 'explicit_ioc_section';
  const roleZone = zoneForSectionRole(classifySectionRole(t, { allowDescriptiveSuffix: opts.allowDescriptiveSuffix }));
  if (roleZone) return /** @type {DocumentZone} */ (roleZone);
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
    .replace(/\bwww\.[a-z0-9.-]+\b/gi, 'HOST')
    .replace(/^\d{1,3}\s+/, '')
    .replace(/\b[a-z]{2,6}[-–—]\w+[-–—]\d{4}[-–—]\d+\b/gi, 'DOCID')
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

const ZONE_OPENING_HEADINGS = new Set([
  'explicit_ioc_section',
  'c2_section',
  'sample_table',
  'operational_infrastructure',
  'reference_section',
  'vendor_about',
  'code'
]);

const CIDR_IN_TEXT_RE =
  /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\/(?:3[0-2]|[12]?\d)\b/g;

/**
 * Join a wrapped heading with the next same-page heading when a title split
 * across visual lines (e.g. "...Administering PurpleBravo" + "Infrastructure").
 * @param {object[]} blocks
 * @param {number} index
 */
export function combinedHeadingText(blocks, index) {
  const b = blocks[index];
  if (!b || b.type !== 'heading') return String(b?.text || '').trim();
  const a = collapseLetterSpacing(String(b.text || '').trim());
  const next = blocks[index + 1];
  if (
    next &&
    next.type === 'heading' &&
    next.page === b.page &&
    next.layout !== 'page_edge' &&
    String(next.text || '').trim().length <= 40 &&
    !/[.!?。]$/.test(a)
  ) {
    return `${a} ${collapseLetterSpacing(String(next.text || '').trim())}`.trim();
  }
  return a;
}

/**
 * A block whose placement (not its prose) says "indicator row": list items,
 * observable-only lines, single-column table rows, typed tables.
 * @param {object} b
 */
export function isIndicatorStructureBlock(b) {
  if (!b || b.layout === 'page_edge') return false;
  if (b.type === 'list_item' || b.layout === 'observable_row') return true;
  if (b.type === 'table' || b.type === 'list') return true;
  return isObservableListLine(String(b.text || ''));
}

/**
 * A row block that carries an observable itself (not a typed table, which
 * proves itself, and not a prose list item).
 * @param {object} b
 */
function isIndicatorRowBlock(b) {
  if (!b || b.layout === 'page_edge' || b.type === 'heading') return false;
  const text = String(b.text || '');
  if (b.layout === 'observable_row' || isObservableListLine(text)) return true;
  if (b.type === 'list_item' || b.type === 'list' || (b.type === 'table' && !b.table)) {
    return text.length <= 160 && OBSERVABLE_IN_TEXT_RE.test(refangTextForExtraction(text));
  }
  return false;
}

const OBSERVABLE_IN_TEXT_RE =
  /https?:\/\/|(?:\d{1,3}\.){3}\d{1,3}|\b[a-f0-9]{32,64}\b|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/i;

/**
 * Words that make a short heading read as a group label for indicators rather
 * than a new topic (multilingual, intent-based — not vendor names).
 */
const GROUP_LABEL_CONCEPT_RE =
  /\b(?:domains?|ips?|ip\s+addresses?|addresses?|urls?|hash(?:es)?|hosts?|hostnames?|servers?|c2|c&c|indicators?|iocs?|samples?|files?|infrastructure|decoys?|types?|campaigns?|clusters?|groups?|waves?|stages?|additional|supporting|related|other|network|emails?|sha-?\d*|md5|mutex(?:es)?|endpoints?|ranges?|cidrs?|payloads?|droppers?|loaders?|implants?|beacons?|alan\s+ad(?:ı|ları)|adres(?:ler)?|sunucu(?:lar)?|ek|ilgili|diğer)\b|域名|地址|服务器|样本|哈希|相关|其他|附加|基础设施|诱饵/i;

/**
 * Sub-label inside an open indicator section ("Scambling Domains (Type 2)",
 * "Supporting IP Addresses…", "Decoy domains"): a short heading that opens no
 * other section, names an indicator group concept, and is either nested
 * deeper than the opening heading (DOM hierarchy) or directly followed by
 * indicator rows. It inherits the section scope. "Frequently Asked Questions"
 * or "Conclusion" name a new topic and close the section.
 * @param {object} b heading block
 * @param {object[]} blocks
 * @param {number} i
 * @param {{ level: number|null }} opening
 * @param {Set<string>} chromeIds
 */
function isSubgroupLabelHeading(b, blocks, i, opening, chromeIds) {
  const text = collapseLetterSpacing(String(b.text || '').trim());
  if (!text || text.length > 72 || /[.!?。]$/.test(text)) return false;
  if (!GROUP_LABEL_CONCEPT_RE.test(text)) return false;
  const level = Number.isInteger(b.level) ? b.level : null;
  if (level != null && opening.level != null && level > opening.level) return true;
  const next = nextContentBlock(blocks, i, chromeIds);
  return Boolean(next) && isIndicatorRowBlock(next);
}

/**
 * Previous content block before index i (skipping running headers / footers / page edges).
 * @param {object[]} blocks
 * @param {number} i
 * @param {Set<string>} chromeIds
 */
function previousContentBlock(blocks, i, chromeIds) {
  for (let j = i - 1; j >= 0; j -= 1) {
    const p = blocks[j];
    if (p.layout === 'page_edge' || chromeIds.has(p.id)) continue;
    return p;
  }
  return null;
}

/**
 * Next content block after index i (skipping running headers / footers / page edges).
 * @param {object[]} blocks
 * @param {number} i
 * @param {Set<string>} chromeIds
 */
function nextContentBlock(blocks, i, chromeIds) {
  for (let j = i + 1; j < blocks.length; j += 1) {
    const n = blocks[j];
    if (n.layout === 'page_edge' || chromeIds.has(n.id)) continue;
    return n;
  }
  return null;
}

/**
 * Structural confirmation for a descriptive indicator heading: the section it
 * opens (up to the next real heading) must contain at least one indicator
 * structure block. A heading that only introduces prose is not an appendix.
 * @param {object[]} blocks
 * @param {number} i heading index
 * @param {Set<string>} chromeIds
 */
export function sectionHasIndicatorStructure(blocks, i, chromeIds, limit = 80) {
  let seen = 0;
  for (let j = i + 1; j < blocks.length && seen < limit; j += 1) {
    const n = blocks[j];
    if (n.layout === 'page_edge' || chromeIds.has(n.id)) continue;
    if (n.type === 'heading') return false;
    seen += 1;
    if (isIndicatorStructureBlock(n)) return true;
  }
  return false;
}

/**
 * Annotate canonical blocks with zone metadata (mutates copies).
 * Repeated running headers/footers never close an open indicator section.
 *
 * Scope model: a heading declares a section role → the section is
 * authoritative (indicator / C2 / sample / operational) or not → every block
 * until a real section boundary inherits that scope, including short
 * sub-labelled groups → occurrence-level relation decides assertion vs mention
 * (see indicatorScope). Run-length list discovery is a fallback for unlabelled
 * lists only.
 * @param {import('./canonicalDocument.js').CanonicalDocument} doc
 * @param {{ sourceUrl?: string|null, sourceHost?: string|null }} [opts]
 */
export function annotateDocumentZones(doc, opts = {}) {
  const blocks = (doc.blocks || []).map((b) => ({ ...b }));
  const footerIds = detectRepeatedHeaderFooterBlockIds(blocks);
  /** @type {DocumentZone} */
  let currentZone = 'report_body';
  let currentHeading = null;
  let currentRole = null;
  /** @type {{ label: string, declared_type: string|null, semantics: string }|null} */
  let currentTypeLabel = null;
  /** Heading that opened the current strong zone (scope ancestry for diagnostics + hierarchy). */
  let opening = { id: null, text: null, level: null, form: null };
  /** Developer trace of scope decisions (bounded, not analyst UI). */
  const scopeTrace = [];
  const trace = (entry) => {
    if (scopeTrace.length < 120) scopeTrace.push(entry);
  };

  for (let i = 0; i < blocks.length; i += 1) {
    const b = blocks[i];
    const text = String(b.text || '').trim();
    const pageEdge = b.layout === 'page_edge';
    const isRepeatedChrome = footerIds.has(b.id);
    if (b.type === 'heading' && !pageEdge && !isRepeatedChrome) {
      currentHeading = collapseLetterSpacing(text).slice(0, 160);
    } else if (!pageEdge && !isRepeatedChrome) {
      b.section_heading = currentHeading;
    }
    const isHeadingLike =
      !pageEdge &&
      !isRepeatedChrome &&
      b.type !== 'table' &&
      (b.type === 'heading' ||
        (text.length > 0 &&
          text.length <= 72 &&
          !/[.!?。]$/.test(text) &&
          !/\b(?:hxxps?|https?):\/\//i.test(text) &&
          !/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(text) &&
          !/\b[a-f0-9]{32}\b/i.test(text) &&
          // A single observable value ("c2.evil.example") is a row, never a heading.
          !isObservableOnlyLine(text)));
    const headingText = isHeadingLike && b.type === 'heading' ? combinedHeadingText(blocks, i) : text;
    const indicatorHeading = isHeadingLike ? classifyIndicatorHeading(headingText) : null;
    const descriptiveForm = indicatorHeading?.form === INDICATOR_HEADING_FORMS.DESCRIPTIVE_SUFFIX;
    let headingZone = isHeadingLike ? classifyHeadingText(headingText, { isHeading: b.type === 'heading' }) : null;
    let headingRole = isHeadingLike ? classifySectionRole(headingText) : null;
    const isRealHeading = b.type === 'heading' && !pageEdge && !isRepeatedChrome;
    const labelHeading = isRealHeading ? typeLabelHeading(text) : null;

    // "Indicators: <descriptive text>" is only an appendix when the section it
    // opens actually holds indicator structure; otherwise it is a narrative title.
    if (headingZone && descriptiveForm && STRONG_IOC_ZONES.has(headingZone) && !sectionHasIndicatorStructure(blocks, i, footerIds)) {
      trace({ block_id: b.id, decision: 'indicator_heading_unconfirmed', heading: headingText.slice(0, 120), zone: headingZone });
      b.zone_reason = 'indicator_heading_unconfirmed';
      headingZone = null;
      headingRole = null;
    }

    if (headingZone && ZONE_OPENING_HEADINGS.has(headingZone)) {
      currentZone = headingZone;
      currentRole = headingRole;
      currentTypeLabel = null;
      b.zone_reason = descriptiveForm ? 'heading_hint_descriptive' : 'heading_hint';
      b.section_role = headingRole;
      opening = {
        id: b.id,
        text: headingText.slice(0, 160),
        level: Number.isInteger(b.level) ? b.level : null,
        form: indicatorHeading?.form || null
      };
      b.scope_opening_id = b.id;
      trace({ block_id: b.id, decision: 'open', zone: headingZone, role: headingRole, heading: opening.text, level: opening.level, form: opening.form });
    } else if (isRealHeading) {
      const inStrong = STRONG_IOC_ZONES.has(currentZone);
      // A title wrapped over two visual lines: the previous CONTENT block (a
      // running header / page edge does not count) is a heading on the same page.
      const prev = previousContentBlock(blocks, i, footerIds);
      const wrappedContinuation =
        inStrong &&
        text.length <= 40 &&
        !/[.!?。]$/.test(text) &&
        Boolean(prev) &&
        prev.type === 'heading' &&
        prev.page === b.page;
      // "Domain" / "IP Addresses" / "Hash Values" under an open IOC heading are
      // per-type sub-lists of the same publisher-curated section.
      const typedContinuation = Boolean(labelHeading) && inStrong;
      // Any other short sub-label that groups rows inside the section (decoy /
      // supporting / per-campaign groups) inherits the section scope.
      const subgroupContinuation =
        inStrong &&
        !typedContinuation &&
        !wrappedContinuation &&
        !headingRole &&
        !headingZone &&
        isSubgroupLabelHeading(b, blocks, i, opening, footerIds);
      if (!wrappedContinuation && !typedContinuation && !subgroupContinuation) {
        if (inStrong) {
          trace({ block_id: b.id, decision: 'reset', from_zone: currentZone, heading: headingText.slice(0, 120), level: Number.isInteger(b.level) ? b.level : null, opened_by: opening.id });
        }
        currentZone = 'report_body';
        currentRole = null;
        opening = { id: null, text: null, level: null, form: null };
        if (b.zone_reason !== 'indicator_heading_unconfirmed') b.zone_reason = 'heading_reset';
      } else {
        b.zone_reason = typedContinuation ? 'typed_subheading' : subgroupContinuation ? 'subgroup_label' : 'heading_continuation';
        b.section_role = currentRole;
        b.scope_opening_id = opening.id;
        trace({ block_id: b.id, decision: b.zone_reason, zone: currentZone, heading: headingText.slice(0, 120), opened_by: opening.id });
      }
      currentTypeLabel = labelHeading;
      if (labelHeading) b.type_label_heading = labelHeading;
    }
    if (!isRealHeading && !pageEdge && !isRepeatedChrome && opening.id && STRONG_IOC_ZONES.has(currentZone)) {
      b.scope_opening_id = opening.id;
    }

    /** @type {DocumentZone} */
    let zone = currentZone;
    if (pageEdge || isRepeatedChrome) {
      zone = 'header_footer';
      b.zone_reason = pageEdge ? 'page_edge' : 'repeated_block';
    } else if (opts.sourceUrl && text.includes(String(opts.sourceUrl).slice(0, 40))) {
      zone = zone === 'report_body' ? 'source_metadata' : zone;
      if (zone === 'source_metadata') b.zone_reason = 'source_url';
    } else if (opts.sourceHost && /\bhttps?:\/\//i.test(text) && text.toLowerCase().includes(String(opts.sourceHost).toLowerCase()) && text.length < 200) {
      if (footerIds.has(b.id) || text.length < 160) {
        zone = 'source_metadata';
        b.zone_reason = 'source_host';
      }
    }

    b.zone = zone;
    b.section = b.section || zone;
    if (currentRole && !b.section_role && zone === currentZone) b.section_role = currentRole;
    // A type-label heading types the value rows beneath it (list items,
    // observable-only lines, single-token code blocks) — never prose paragraphs.
    if (
      currentTypeLabel &&
      b.type !== 'heading' &&
      b.type !== 'table' &&
      !pageEdge &&
      !isRepeatedChrome &&
      (b.type === 'list_item' || isObservableOnlyLine(text) || (b.type === 'code' && !/\s/.test(text)))
    ) {
      b.type_label = currentTypeLabel.label;
      if (currentTypeLabel.declared_type) b.declared_type_label = currentTypeLabel.declared_type;
    }

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

  // Discovery fallback: unlabelled lists in body text. Rows already inside an
  // authoritative section are untouched (inheritance never depends on run length).
  applyObservableListZones(blocks);
  applyCidrParagraphZones(blocks);

  return {
    ...doc,
    blocks,
    meta: {
      ...(doc.meta || {}),
      zones_annotated: true,
      zones_version: THREAT_LIBRARY_DOCUMENT_ZONES_VERSION,
      scope_trace: scopeTrace,
      source_url: opts.sourceUrl || doc.meta?.source_url || null,
      source_host: opts.sourceHost || doc.meta?.source_host || null
    }
  };
}

/**
 * Structural IOC-list DISCOVERY (no headings needed): >= OBSERVABLE_LIST_MIN_ROWS
 * consecutive indicator-only rows in body text form an explicit IOC list;
 * a run made of citation-marked rows ("[1] https://…") is a reference list.
 * Header/footer rows in between (page breaks) do not interrupt a run.
 * This is a fallback for unlabelled lists; it never gates rows that already
 * inherit an authoritative section (those keep their zone regardless of run length).
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
 * A paragraph packed with CIDR ranges is a structural indicator list even
 * when PDF layout did not split it into one-row-per-CIDR.
 * @param {object[]} blocks
 */
export function applyCidrParagraphZones(blocks) {
  for (const b of blocks || []) {
    if (NEGATIVE_ZONES.has(b.zone) || b.zone === 'header_footer' || STRONG_IOC_ZONES.has(b.zone)) continue;
    const text = String(b.text || '');
    const matches = text.match(CIDR_IN_TEXT_RE);
    if (!matches || matches.length < 2) continue;
    const publicCidrs = matches.filter((m) => !isPrivateOrReservedAddress(m.split('/')[0]));
    if (publicCidrs.length < 2) continue;
    if (matches.length < 3 && String(b.text || '').length > 220) continue;
    b.zone = 'operational_infrastructure';
    b.section = b.section && b.section !== 'report_body' ? b.section : 'operational_infrastructure';
    b.zone_reason = 'cidr_list';
    if (!b.section_role) b.section_role = 'operational_infrastructure';
  }
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

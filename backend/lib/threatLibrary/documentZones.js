/**
 * Document structural zone classification for Threat Library.
 * Language-agnostic intent with optional multilingual heading hints (not the sole authority).
 */

import { annotateSectionTree } from './sectionTree/annotate.js';
import { collapseLetterSpacing, isObservableOnlyLine, hasCitationMarker, inventoryPairLines } from './pdfLayout.js';
import { refangTextForExtraction } from './defang.js';
import { isPrivateOrReservedAddress } from './candidateValue.js';
import { classifyTypeLabel } from './observableTypeResolver.js';
import { interpretIocTable, looksLikeIocTableHeader, parseDeclaredType, tableVersionColumns } from './tableSemantics.js';
import {
  INDICATOR_HEADING_FORMS,
  classifyIndicatorHeading,
  classifySectionRole,
  isAnnotatedIndicatorRowLine,
  isFilenameShapedToken,
  isIndicatorRowShape,
  isIndicatorValueLine,
  isObservableListLine,
  isQualifiedIocInventoryHeading,
  RECORD_FIELD_LINE_RE,
  SECTION_ROLES,
  zoneForSectionRole
} from './indicatorScope.js';

/**
 * Bump when zone / scope semantics change (candidates are re-derived; the
 * canonical document itself is unchanged).
 * v2: descriptive indicator headings ("Indicators: …") open an authoritative
 * section once structurally confirmed; sub-labels inside an open section
 * inherit its scope (no per-subgroup run-length gate); ≥3-row discovery is a
 * fallback for unlabelled lists only.
 * v3: document hierarchy — a heading nested under an open indicator section
 * whose content starts with indicator rows continues it whatever its label;
 * a prose sub-heading suspends the section and a later sibling sub-list
 * resumes it; scheme-less host/path URL rows count as indicator rows.
 * v4: a C2 / operational-infrastructure heading with a known level opens an
 * authoritative section only when its subtree holds indicator structure
 * (prose-only topics are narrative); a suspended section resumes only at a
 * sibling of the heading that closed it, never inside that sub-topic.
 * v5: that subtree confirmation counts publisher indicator content only (an
 * indicator row, or a structured table that reads as an IOC table): a code
 * listing, an HTTP request example or a descriptive table without an
 * indicator column no longer turns a technical-analysis topic into a C2 /
 * operational-infrastructure section.
 * v6: topic-label confirmation applies to synthetic/bold headings the same way
 * as real HTML headings (level-less headings use a section-scoped content
 * check); artifact type-label siblings such as "Receiving a command" close an
 * authoritative section instead of continuing it as a typed sub-heading.
 * v7: after an authoritative section has shown indicator rows, a following
 * non-indicator list (article tags / categories / related-topic chips) closes
 * the section — page metadata must not inherit IOC scope or a Domains type
 * label from the preceding appendix.
 * v8: synthetic/bold subgroup labels inside an open IOC section (malware /
 * tool family names such as "GoSerpent" above hash rows) continue the section
 * when the next content block is an indicator row — same "whatever its label"
 * rule nested real headings already had in v3. GROUP_LABEL_CONCEPT_RE remains
 * for real heading subgroup labels without a deeper hierarchy level.
 * v9: publisher IOC appendix is a parent scope independent of child C2 /
 * sample / operational subsections. Opening "OctLurk C2" may replace the
 * active child zone, but leaving that child for a sibling "Loaders" /
 * "Plugins" heading nested under the appendix restores explicit_ioc_section
 * instead of dropping to report_body. Appendix ends only at a heading at or
 * above the appendix level, or a deeper heading whose subtree has no
 * publisher indicator content (related-article chrome).
 * v10: filename-first annotated IOC rows ("loader.exe &lt;hash&gt;") count as
 * indicator content for scope continuation (aligned with isIndicatorRowShape);
 * unlabelled observable-list discovery does not promote runs whose lead-in
 * describes legitimate / shared services; body IOC-looking tables no longer
 * self-prove solely from column headers when outside headed appendix scope
 * (tl-table-v7).
 * v11: a sub-label that names an indicator group ("Samples", "Loaders") keeps
 * an open IOC section when a publisher IOC table sits directly beneath it, the
 * same as when indicator rows do — the inventory's representation (rows vs a
 * Filename|MD5 table) no longer decides scope when the hierarchy is unknown
 * (level-less headings, or equal PDF-inferred levels; real same-level HTML
 * siblings still close the section). A paragraph or row whose text is a pure filename/hash inventory
 * (row boundaries lost upstream) is read as an observable row with one pair
 * per line; block ids are unchanged.
 * v12: mid-appendix sample inventory rows ("File size:", "File type:",
 * "File location:") are not treated as article-tag chrome. Closing the
 * publisher IOC section on those key-value list items dropped every later
 * hash/URL under the same "Indicators of Compromise" heading to report_body
 * (MODE A false negatives). Article tag chips remain bare phrases without a
 * field label and still end the section after indicator content. Real
 * same-level HTML siblings whose label matches GROUP_LABEL_CONCEPT_RE
 * ("Additional Resources", "Related articles") no longer continue the
 * appendix merely because a following link line looks like an indicator row.
 * v13: the same key-value records as paragraphs ("File name: eld0.exe",
 * "Description: Python agent host") are record fields, not synthetic headings:
 * one used to reset the appendix (and its anchor), so every later H3
 * "Operation A/B/C" block fell to report_body, while another reopened it at
 * random. A colon record label ("Docro extension path:") whose short run still
 * lists indicator rows keeps scope, and "SHA256 hash: <hash> File size: …"
 * merged on one line is one indicator row (Unit 42 PPI report, 25 misses).
 * v14 (ten-report audit): a qualified inventory heading ("Observations") opens
 * an IOC section only when its first table is a declared-type IOC table
 * (indicator column + observable-type column); otherwise it stays narrative.
 * v15 (twelve-report audit): "Contact" is a reference heading only as a
 * whole contact block ("Contact", "Contact us", "Contact information"); a
 * topic that starts with the word ("Contact Form Engagement") is narrative.
 */
export const THREAT_LIBRARY_DOCUMENT_ZONES_VERSION = 'tl-zones-v17';

/**
 * Pure filename/hash inventory whose row boundaries were lost before zoning
 * (several pairs on one PDF line, or rows merged into one paragraph). The
 * block keeps its id and page; only its row structure is restored, so each
 * hash reads with its own filename. Anything that is not exclusively
 * filename/hash pairs is left untouched (ambiguous text stays narrative).
 * @param {object} b block copy
 */
export function recoverInventoryRowBlock(b) {
  if (!b || b.layout === 'page_edge') return b;
  const rowLike = b.type === 'paragraph' || (b.type === 'list_item' && b.layout === 'observable_row');
  if (!rowLike) return b;
  const text = String(b.text || '');
  if (/[\r\n]/.test(text)) return b;
  const pairs = inventoryPairLines(text);
  if (!pairs) return b;
  return {
    ...b,
    type: 'list_item',
    layout: 'observable_row',
    text: pairs.join('\n'),
    ...(b.type === 'paragraph' ? { layout_recovered: 'inventory_paragraph' } : {})
  };
}

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
  'delegated_ioc_scope',
  'reference_section',
  'source_metadata',
  'header_footer',
  'navigation',
  'vendor_about',
  'code',
  'unknown'
]);

/**
 * Body scope of a document whose every formal IOC section is empty (the
 * publisher released its indicators elsewhere — "available for download
 * here"). Authority is delegated to the publisher's own assertions in the
 * body: operational clauses, endpoints and rows of network / indicator-typed
 * table columns. Narrative mentions in it assert nothing. Section-tree only.
 */
export const DELEGATED_IOC_ZONE = 'delegated_ioc_scope';

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
  'operational_infrastructure',
  DELEGATED_IOC_ZONE
]);

/**
 * Multilingual heading hints (optimization only — semantic AI still required).
 * Intent-based groups, not vendor allowlists.
 */
const HEADING_HINTS = Object.freeze({
  explicit_ioc_section: [
    // Label-like IOC titles only (lead + optional separator / end). Do not
    // match mid-phrase or hyphenated compounds ("IOC-shaped", "IOC inventory
    // methodology discussion", "near IOC inventory") — those are narrative.
    /^(?:(?:host|network|file|atomic|additional|other|related)\s+)?iocs?\b(?!-)\s*(?:[:：\-–—|(\[（]|$)/i,
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
    /\bc2s?\b/i,
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
    // "Reference IoCs" (Securelist) heads an indicator list, not a bibliography.
    /^references?\b(?!\s+(?:iocs?|indicators?)\b)/i,
    // Credits / "Existing blogs with similar behavior tracked:" after an IOC
    // table (Microsoft): citations, never indicators (tl-section-tree-v12).
    /^acknowledge?ments?\b/i,
    /bibliography/i,
    // A contact / "Contact us" block, not a topic that starts with the word
    // ("Contact Form Engagement" is the lure narrative, not chrome).
    /^contact(?:s|ing)?(?:\s+(?:us|information|info|details|the\s+(?:authors?|team|researchers?)|our\s+team))?\s*[:.!]?\s*$/i,
    /^reporting\b/i,
    /how\s+to\s+report/i,
    /related\s+(reports?|articles?|links?|resources?)/i,
    /^additional\s+resources?\b/i,
    /^see\s+also\b/i,
    /further\s+(?:reading|information)/i,
    /参考链接|参考文献|相关链接|引用|联系方式/i,
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
 *
 * Never merge a parent section label with a child subsection title: combining
 * "Indicators of compromise" + "C2" would open c2_section and lose the
 * publisher IOC appendix parent. Distinct heading levels, or a next heading
 * that opens its own zone while this one already opens a different zone, stay
 * separate.
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
    const thisLevel = Number.isInteger(b.level) ? b.level : null;
    const nextLevel = Number.isInteger(next.level) ? next.level : null;
    if (thisLevel != null && nextLevel != null && nextLevel !== thisLevel) return a;
    const nextText = collapseLetterSpacing(String(next.text || '').trim());
    const aloneZone = classifyHeadingText(a, { isHeading: true });
    const nextZone = classifyHeadingText(nextText, { isHeading: true });
    if (aloneZone === 'explicit_ioc_section') return a;
    if (
      aloneZone &&
      nextZone &&
      aloneZone !== nextZone &&
      ZONE_OPENING_HEADINGS.has(aloneZone) &&
      ZONE_OPENING_HEADINGS.has(nextZone)
    ) {
      return a;
    }
    return `${a} ${nextText}`.trim();
  }
  return a;
}

/**
 * Short list items that are article tags / categories / topic chips rather than
 * publisher IOC rows. Bare filename-shaped tokens (`Node.js`) count as chrome;
 * annotated indicator rows (`host – Decoy domain`) do not.
 *
 * Sample / file inventory rows under an IOC appendix use "Label: value"
 * (`File size: 1,991 bytes`). Those stay inside the appendix — only bare
 * chips without a field label end the section after indicator content.
 * @param {object} b
 */
export function isArticleMetadataListItem(b) {
  if (!b || (b.type !== 'list' && b.type !== 'list_item')) return false;
  const text = String(b.text || '').trim();
  if (!text || text.length > 64) return false;
  if (isIndicatorValueLine(text) || isObservableListLine(text)) return false;
  // Publisher sample cards: "File size:", "File type:", "SHA-256 hash:", …
  // Article tags are bare phrases ("MacOS", "Threat intelligence").
  if (/^[\p{L}\p{N}][\p{L}\p{N} ./+_-]{0,48}:\s+\S/u.test(text)) return false;
  const refanged = refangTextForExtraction(text);
  if (/https?:\/\//i.test(refanged) || /\b[a-f0-9]{32,64}\b/i.test(refanged)) return false;
  // A real host/IP (including defanged / annotated rows) keeps the IOC section
  // open. Bare filename-shaped tokens (`Node.js`) and non-observable labels
  // (article tags) close it.
  const hostOrIp =
    /\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3})\b/i.exec(
      refanged
    );
  if (hostOrIp) return isFilenameShapedToken(hostOrIp[0]);
  return true;
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
  const text = String(b.text || '').trim();
  if (b.layout === 'observable_row' || isObservableListLine(text) || isIndicatorValueLine(text)) return true;
  // Annotated publisher rows on either side of the value ("<md5> oleasapi.dll"
  // or "loader.exe <md5>") are indicator lines. Match isIndicatorRowShape so
  // filename-first rows keep appendix scope when a sibling sub-heading follows.
  if (
    (b.type === 'paragraph' || b.type === 'list_item' || b.type === 'list' || b.type === 'code') &&
    isAnnotatedIndicatorRowLine(text)
  ) {
    return true;
  }
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
 * @param {{ inferredLevels?: boolean }} [opts] heading levels are estimates
 *   (PDF numbering / font height), not document structure
 */
function isSubgroupLabelHeading(b, blocks, i, opening, chromeIds, opts = {}) {
  const text = collapseLetterSpacing(String(b.text || '').trim());
  if (!text || text.length > 72 || /[.!?。]$/.test(text)) return false;
  if (!GROUP_LABEL_CONCEPT_RE.test(text)) return false;
  const level = Number.isInteger(b.level) ? b.level : null;
  // Real same-or-shallower HTML siblings are new topics ("Additional Resources"),
  // not appendix subgroups — even when "additional"/"related" matches the
  // group-label vocabulary and a following link row looks indicator-shaped.
  if (
    level != null &&
    opening.level != null &&
    level <= opening.level &&
    opts.inferredLevels !== true
  ) {
    return false;
  }
  if (level != null && opening.level != null && level > opening.level) return true;
  const next = nextContentBlock(blocks, i, chromeIds);
  if (!next) return false;
  if (isIndicatorRowBlock(next)) return true;
  // An IOC table beneath the label (Filename | MD5 inventory) is the same
  // publisher content as rows when the hierarchy is unknown — level-less, or
  // PDF levels that only estimate rank. A real same-level HTML sibling
  // ("Related infrastructure") is a new section, so a table there must
  // self-prove on its own (tl-table-v7). Called only inside an open
  // authoritative section.
  const hierarchyUnknown = level == null || opening.level == null || (opts.inferredLevels === true && level === opening.level);
  return hierarchyUnknown && isIndicatorContentBlock(next, { underAuthoritativeTopic: true });
}

/**
 * Heading levels of a PDF canonical document are inferred from numbering and
 * relative font height (pdfLayout.inferPdfHeadingLevel): equal levels are an
 * absence of evidence, not proof that two headings are siblings.
 * @param {{ meta?: object }} doc
 */
function hasInferredHeadingLevels(doc) {
  return doc?.meta?.adapter === 'pdf' || /^threat_library_pdf_/.test(String(doc?.meta?.extractor || ''));
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
 * Structural confirmation for a qualified inventory heading ("Observations"):
 * the first table of the section it opens (up to the next heading, past at
 * most a few lead-in paragraphs) is a self-proving IOC table — an indicator
 * column plus a declared observable-type column. Prose, a descriptive table or
 * a table without a declared type column never confirms it.
 * @param {object[]} blocks
 * @param {number} i heading index
 * @param {Set<string>} chromeIds
 */
export function sectionLeadsWithDeclaredIocTable(blocks, i, chromeIds, limit = 4) {
  let seen = 0;
  for (let j = i + 1; j < blocks.length && seen < limit; j += 1) {
    const n = blocks[j];
    if (!n || n.layout === 'page_edge' || chromeIds?.has?.(n.id)) continue;
    if (n.type === 'heading') return false;
    seen += 1;
    if (n.type !== 'table' || !n.table) continue;
    const interp = interpretIocTable(n, { inAuthoritativeScope: false });
    return interp.kind === 'ioc_table' && interp.explicit === true && interp.declared_type_column != null;
  }
  return false;
}

/**
 * Zone for a qualified inventory heading confirmed by its section content, or
 * null. Shared by the linear zone pass and the section-tree annotator.
 * @param {string} text heading text
 * @param {object[]} blocks
 * @param {number} i heading index
 * @param {Set<string>} chromeIds
 * @returns {{ zone: string, role: string }|null}
 */
export function confirmedQualifiedIocHeading(text, blocks, i, chromeIds) {
  if (!isQualifiedIocInventoryHeading(text)) return null;
  if (!sectionLeadsWithDeclaredIocTable(blocks, i, chromeIds)) return null;
  return { zone: 'explicit_ioc_section', role: SECTION_ROLES.IOC_APPENDIX };
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

/** Section zones whose label headings also title narrative topics. */
const TOPIC_LABEL_ZONES = new Set(['c2_section', 'operational_infrastructure']);

/**
 * A block that carries publisher indicator content itself: an indicator row
 * (value line, list of values, short list item / unstructured table row with
 * an observable) or a structured table that reads as an IOC table. A code
 * listing, an HTTP request example or a descriptive table without an
 * indicator column is technical content, not an indicator list — whatever
 * observables its text happens to contain.
 * @param {object} b
 */
/**
 * @param {object} b
 * @param {{ underAuthoritativeTopic?: boolean }} [opts]
 *   underAuthoritativeTopic: the caller is confirming a C2 / operational /
 *   IOC topic label. IOC-shaped tables (including Domain|IP|First seen) may
 *   confirm that label. Without this flag, only self-proving tables confirm —
 *   otherwise a body analysis grid would open a C2 section that then marks
 *   the same grid authoritative (circular promotion).
 */
function isIndicatorContentBlock(b, opts = {}) {
  if (!b || b.type === 'heading' || b.layout === 'page_edge') return false;
  if (b.type === 'table' && b.table) {
    const underTopic = opts.underAuthoritativeTopic === true;
    const interp = interpretIocTable(b, { inAuthoritativeScope: underTopic });
    if (interp.kind !== 'ioc_table') return false;
    if (underTopic) return true;
    return interp.explicit === true;
  }
  return isIndicatorRowBlock(b);
}

/**
 * Publisher indicator content in the immediate section after block i (until
 * the next real heading). Used for level-less / synthetic topic headings that
 * cannot use DOM subtree bounds.
 * @param {object[]} blocks
 * @param {number} i
 * @param {Set<string>} chromeIds
 * @param {number} [limit]
 * @param {{ underAuthoritativeTopic?: boolean }} [opts]
 */
export function sectionHasIndicatorContent(blocks, i, chromeIds, limit = 80, opts = {}) {
  let seen = 0;
  for (let j = i + 1; j < blocks.length && seen < limit; j += 1) {
    const n = blocks[j];
    if (n.layout === 'page_edge' || chromeIds.has(n.id)) continue;
    if (n.type === 'heading') return false;
    seen += 1;
    if (isIndicatorContentBlock(n, opts)) return true;
  }
  return false;
}

/**
 * Whether a C2 / operational topic heading is structurally confirmed as an
 * authoritative section. Real headings with a known level use the subtree;
 * synthetic/bold paragraphs and level-less PDF headings use the section walk
 * with the same indicator-content predicate (Invariant A).
 * @param {object} b
 * @param {object[]} blocks
 * @param {number} i
 * @param {Set<string>} chromeIds
 */
function topicHeadingHasIndicatorContent(b, blocks, i, chromeIds) {
  const opts = { underAuthoritativeTopic: true };
  if (b.type === 'heading' && Number.isInteger(b.level)) {
    return subtreeHasIndicatorStructure(blocks, i, chromeIds, 200, opts);
  }
  return sectionHasIndicatorContent(blocks, i, chromeIds, 80, opts);
}

/**
 * A type-label heading continues an open authoritative section only when it is
 * nested under that section (or levels are unknown) and it is a genuine
 * per-type list label: network / declared types, or an artifact label whose
 * own content starts with indicator rows. A sibling topic that merely matches
 * an artifact vocabulary word ("Receiving a command") closes the section.
 * @param {{ semantics: string, declared_type: string|null }|null} labelHeading
 * @param {object} b
 * @param {object[]} blocks
 * @param {number} i
 * @param {{ level: number|null }} opening
 * @param {Set<string>} chromeIds
 */
/** Same-level sibling headings that are pure per-type IOC list labels. */
const PURE_TYPE_LIST_HEADING_RE =
  /^(?:(?:list\s+of\s+|observed\s+|extracted\s+)?)?(?:domains?|ip(?:v[46])?(?:\s+addresses?)?|urls?|hosts?(?:names?)?|emails?|hashes?|hash\s+values?|md5|sha-?1|sha-?256|sha-?512|file\s+hashes?|samples?|filenames?|mutex(?:es)?|c2s?(?:\s+servers?)?)(?:\s*\([^)]*\))?$/i;

function isTypedSubheadingContinuation(labelHeading, b, blocks, i, opening, chromeIds) {
  if (!labelHeading) return false;
  const level = Number.isInteger(b.level) ? b.level : null;
  const networkOrDeclared = labelHeading.semantics === 'network' || Boolean(labelHeading.declared_type);
  // Same-or-shallower than the current opening: only pure per-type list labels
  // continue ("Hash Values" / "IP Addresses" / "Domain"). Compound sibling
  // topics ("Related infrastructure", "Additional findings") close the appendix
  // even when they mention network vocabulary.
  if (level != null && opening.level != null && level <= opening.level) {
    const text = String(b.text || labelHeading.label || '').trim();
    return networkOrDeclared && PURE_TYPE_LIST_HEADING_RE.test(text);
  }
  if (networkOrDeclared) return true;
  return sectionOpensWithIndicatorContent(blocks, i, chromeIds);
}

/**
 * Whether a non-heading block is label/title shaped (bold paragraph headings)
 * rather than a short prose sentence. Used so synthetic heading open/close
 * logic does not treat "The following servers were used:" as a section boundary.
 * @param {string} text
 */
export function looksLikeLabelHeading(text) {
  const t = String(text || '').trim();
  if (!t || t.length > 72) return false;
  if (/[.!?。]$/.test(t)) return false;
  // Figure / table captions are body chrome, never C2 / IOC section openers —
  // even when the caption text mentions "C2" or "Indicators".
  if (/^\[?\s*(?:figure|table|fig\.?|tab\.?|image|diagram)\s*[\d\-]/i.test(t)) return false;
  // Observable value rows — including defanged hosts with a parenthetical
  // gloss ("osc-cdn[.]com (actor-used …)") — are never section titles.
  if (/(?:\[\.\])|hxxps?:\/\//i.test(t)) return false;
  if (/^(?:https?:\/\/|\d{1,3}(?:\.\d{1,3}){3})\S*/i.test(t)) return false;
  if (/^[a-f0-9]{32,64}\b/i.test(t)) return false;
  const lead = t.split(/\s+/)[0].replace(/[.,;:)\]].*$/, '');
  if (lead && (isObservableOnlyLine(lead) || isIndicatorValueLine(lead))) return false;
  // "File name: eld0.exe" / "Description: Python agent host" are attribute
  // fields of one indicator record, never section titles (tl-zones-v13).
  if (RECORD_FIELD_LINE_RE.test(t)) return false;
  const words = t.split(/\s+/).filter(Boolean);
  // Trailing colon is a section label only when short ("C2:", "Network IOCs:").
  if (/[:：]$/.test(t) && (t.length > 48 || words.length > 5)) return false;
  // Determiner-led multi-word lines are sentences, not headings.
  if (/^(?:the|a|an|this|these|those|we|they|it|our|their)\b/i.test(t) && words.length >= 4) return false;
  return true;
}

/**
 * Structural confirmation over a heading's whole subtree (every block until a
 * heading at the same or a shallower level), so typed sub-headings ("C2 › IPs")
 * stay inside. Requires an integer level on heading i. Only publisher
 * indicator content confirms (isIndicatorContentBlock): a topic heading that
 * merely names C2 ("Outlook calendar events as a C2 channel") over prose, code
 * listings and protocol tables stays narrative.
 * @param {object[]} blocks
 * @param {number} i heading index
 * @param {Set<string>} chromeIds
 */
export function subtreeHasIndicatorStructure(blocks, i, chromeIds, limit = 200, opts = {}) {
  const level = blocks[i].level;
  let seen = 0;
  for (let j = i + 1; j < blocks.length && seen < limit; j += 1) {
    const n = blocks[j];
    if (n.layout === 'page_edge' || chromeIds.has(n.id)) continue;
    if (n.type === 'heading') {
      if (!Number.isInteger(n.level) || n.level <= level) return false;
      continue;
    }
    seen += 1;
    if (isIndicatorContentBlock(n, opts)) return true;
  }
  return false;
}

/**
 * True when the content directly under heading i starts with indicator
 * structure: an indicator row (value line, list of values, scheme-less URL
 * row) or a table that reads as an IOC table. Prose first → false. Used to
 * keep arbitrarily-labelled nested sub-headings inside an IOC section.
 * @param {object[]} blocks
 * @param {number} i heading index
 * @param {Set<string>} chromeIds
 */
export function sectionOpensWithIndicatorContent(blocks, i, chromeIds) {
  return isIndicatorContentBlock(nextContentBlock(blocks, i, chromeIds));
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
  // One structural authority: every section decision below comes from the graph.
  const tree = annotateSectionTree(doc);
  const treeById = new Map(tree.blocks.map((b) => [b.id, b]));
  const blocks = (doc.blocks || []).map((b) => recoverInventoryRowBlock({ ...b }));
  const footerIds = detectRepeatedHeaderFooterBlockIds(blocks);
  let currentHeading = null;
  /** @type {{ label: string, declared_type: string|null, semantics: string }|null} */
  let currentTypeLabel = null;
  /** Software-version columns of the last table, carried across page-break chrome only. */
  let versionCarry = null;

  for (let i = 0; i < blocks.length; i += 1) {
    const b = blocks[i];
    const text = String(b.text || '').trim();
    const pageEdge = b.layout === 'page_edge';
    const isRepeatedChrome = footerIds.has(b.id);
    const graph = treeById.get(b.id) || {};
    b.section_path = graph.section_path || [];
    b.section_path_ids = graph.section_path_ids || [];
    b.authoritative_ancestor_id = graph.authoritative_ancestor_id || null;
    b.authoritative_zone = graph.authoritative_zone || null;
    b.tree_zone = graph.tree_zone || 'report_body';
    b.negative_scope = graph.negative_scope === true;
    if (graph.declared_indicator_section === true) b.declared_indicator_section = true;
    if (graph.delegated_scope === true) b.delegated_scope = true;

    if (b.type === 'heading' && !pageEdge && !isRepeatedChrome) {
      currentHeading = collapseLetterSpacing(text).slice(0, 160);
    } else if (!pageEdge && !isRepeatedChrome) {
      b.section_heading = currentHeading;
    }

    /** @type {DocumentZone} */
    let zone = b.tree_zone;
    if (b.authoritative_ancestor_id) {
      b.scope_opening_id = b.authoritative_ancestor_id;
      b.zone_reason = 'section_graph_ancestry';
      const role = classifySectionRole(treeById.get(b.authoritative_ancestor_id)?.text || '');
      if (role) b.section_role = role;
    }

    // A type-label heading types the value rows beneath it (list items,
    // observable-only lines, single-token code blocks), never prose paragraphs.
    if (b.type === 'heading' && !pageEdge && !isRepeatedChrome) {
      currentTypeLabel = STRONG_IOC_ZONES.has(graph.tree_heading_zone) && classifyHeadingText(text, { isHeading: true }) ? null : typeLabelHeading(text);
      if (currentTypeLabel) b.type_label_heading = currentTypeLabel;
    } else if (b.type === 'paragraph' && text.length <= 72 && STRONG_IOC_ZONES.has(zone) && looksLikeLabelHeading(text) && !isObservableOnlyLine(text)) {
      const label = typeLabelHeading(text);
      const next = nextContentBlock(blocks, i, footerIds);
      if (label) {
        currentTypeLabel = label;
        b.type_label_heading = label;
      } else if (next && isIndicatorRowBlock(next)) {
        // A new inventory lead-in that is not type vocabulary starts a fresh subgroup.
        currentTypeLabel = null;
      }
    }

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
    if (
      currentTypeLabel &&
      b.type !== 'heading' &&
      b.type !== 'table' &&
      !pageEdge &&
      !isRepeatedChrome &&
      (b.type === 'list_item' || isIndicatorValueLine(text) || (b.type === 'code' && !/\s/.test(text)))
    ) {
      b.type_label = currentTypeLabel.label;
      if (currentTypeLabel.declared_type) b.declared_type_label = currentTypeLabel.declared_type;
    }

    if (b.type === 'table' && b.table) {
      const versions = tableVersionColumns(b.table, versionCarry);
      versionCarry = { width: versions.width, columns: versions.columns };
      if (versions.columns.length) {
        b.version_columns = versions.columns;
        if (versions.header_row) b.version_header_row = true;
      }
      const negative = NEGATIVE_ZONES.has(zone);
      const interpretation = interpretIocTable(b, {
        negativeZone: negative,
        versionColumns: versions.columns,
        inAuthoritativeScope: STRONG_IOC_ZONES.has(zone)
      });
      b.ioc_table = interpretation;
      if (interpretation.kind === 'ioc_table' && interpretation.explicit && !negative && !STRONG_IOC_ZONES.has(zone)) {
        // A table that proves itself outside any asserting section: a structural
        // signal for the row reading; the section itself stays uncertain.
        b.zone_reason = 'ioc_table';
      } else if (interpretation.kind === 'ioc_table' && interpretation.file_hash_inventory && zone === 'sample_table') {
        b.zone_reason = 'file_hash_inventory';
      }
    } else if (zone !== 'header_footer') {
      versionCarry = null;
    }
  }

  // Discovery fallback: unlabelled lists in body text. Rows already inside an
  // authoritative section are untouched (inheritance never depends on run length).
  applyObservableListZones(blocks);
  demoteLegitimateServiceListDiscovery(blocks);
  applyCidrParagraphZones(blocks);

  return {
    ...doc,
    blocks,
    section_graph: tree,
    meta: {
      ...(doc.meta || {}),
      zones_annotated: true,
      zones_version: THREAT_LIBRARY_DOCUMENT_ZONES_VERSION,
      scope_trace: tree.meta.trace || [],
      source_url: opts.sourceUrl || doc.meta?.source_url || null,
      source_host: opts.sourceHost || doc.meta?.source_host || null
    }
  };
}

/**
 * Lead-in prose that names shared / legitimate services. An unlabelled domain
 * list after such a sentence must not become an authoritative IOC section.
 */
const LEGITIMATE_SERVICE_LEADIN_RE =
  /\b(?:legitimate|benign|trusted|reputable|popular|known[- ]good|shared\s+(?:cloud\s+)?(?:service|services|infrastructure|platform|platforms)|third[- ]party\s+service|review\s+traffic|monitor(?:ing)?\s+traffic|allow\s*list|allowlist|white\s*list|whitelist)\b/i;

/**
 * When structural list discovery promoted a run whose immediately preceding
 * content describes legitimate / shared services, demote those blocks back to
 * report_body. Does not invent benign labels — values stay extractable as
 * candidates without MODE A authority.
 * @param {object[]} blocks
 */
export function demoteLegitimateServiceListDiscovery(blocks) {
  let runStart = -1;
  const demoteRun = (from, to, leadIn) => {
    if (from < 0 || to < from) return;
    if (!LEGITIMATE_SERVICE_LEADIN_RE.test(String(leadIn || ''))) return;
    for (let i = from; i <= to; i += 1) {
      const b = blocks[i];
      if (b?.zone_reason === 'observable_list' && b.zone === 'report_body') b.zone_reason = 'legitimate_service_list';
    }
  };
  for (let i = 0; i < (blocks || []).length; i += 1) {
    const b = blocks[i];
    if (b?.zone_reason === 'observable_list') {
      if (runStart < 0) runStart = i;
      continue;
    }
    if (runStart >= 0) {
      const prev = previousContentBlock(blocks, runStart, new Set());
      demoteRun(runStart, i - 1, prev?.text);
      runStart = -1;
    }
  }
  if (runStart >= 0) {
    const prev = previousContentBlock(blocks, runStart, new Set());
    demoteRun(runStart, blocks.length - 1, prev?.text);
  }
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
      const citations = cited * 2 >= run.length;
      for (const b of run) {
        if (b.zone === 'report_body' || b.zone === 'unknown') {
          if (citations) {
            b.zone = 'reference_section';
            b.section = 'reference_section';
          }
          b.zone_reason = citations ? 'citation_list' : 'observable_list';
        }
      }
    }
    run = [];
  };
  for (const b of blocks || []) {
    if (b.zone === 'header_footer') continue;
    const row = b.type === 'list_item' || b.layout === 'observable_row' || isIndicatorValueLine(b.text);
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
    b.zone_reason = 'cidr_list';
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

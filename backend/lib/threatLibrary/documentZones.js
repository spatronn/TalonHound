/**
 * Document structural zone classification for Threat Library.
 * Language-agnostic intent with optional multilingual heading hints (not the sole authority).
 */

import { collapseLetterSpacing, isObservableOnlyLine, hasCitationMarker } from './pdfLayout.js';
import { refangTextForExtraction } from './defang.js';
import { isPrivateOrReservedAddress } from './candidateValue.js';
import { classifyTypeLabel } from './observableTypeResolver.js';
import { interpretIocTable, looksLikeIocTableHeader, parseDeclaredType, tableVersionColumns } from './tableSemantics.js';
import {
  INDICATOR_HEADING_FORMS,
  classifyIndicatorHeading,
  classifySectionRole,
  isFilenameShapedToken,
  isIndicatorRowShape,
  isIndicatorValueLine,
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
 */
export const THREAT_LIBRARY_DOCUMENT_ZONES_VERSION = 'tl-zones-v9';

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
 * @param {object} b
 */
export function isArticleMetadataListItem(b) {
  if (!b || (b.type !== 'list' && b.type !== 'list_item')) return false;
  const text = String(b.text || '').trim();
  if (!text || text.length > 64) return false;
  if (isIndicatorValueLine(text) || isObservableListLine(text)) return false;
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
  // Annotated publisher rows ("<md5> oleasapi.dll") are indicator lines even
  // when isIndicatorValueLine rejects the trailing filename token. Require the
  // lead token itself to be an observable — never "GET https://…" API lines.
  if (
    (b.type === 'paragraph' || b.type === 'list_item' || b.type === 'list' || b.type === 'code') &&
    text.length > 0 &&
    text.length <= 160
  ) {
    const focus = text.split(/\s+/)[0]?.replace(/[.,;:)\]]+$/, '') || '';
    const focusLooksObservable =
      Boolean(focus) &&
      (/^[a-f0-9]{32,64}$/i.test(focus) ||
        /^(?:\d{1,3}\.){3}\d{1,3}$/.test(focus) ||
        /\[\.]/.test(focus) ||
        isIndicatorValueLine(focus) ||
        isObservableOnlyLine(focus));
    if (focusLooksObservable && isIndicatorRowShape(text, focus)) return true;
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
function isIndicatorContentBlock(b) {
  if (!b || b.type === 'heading' || b.layout === 'page_edge') return false;
  if (b.type === 'table' && b.table) return interpretIocTable(b, {}).kind === 'ioc_table';
  return isIndicatorRowBlock(b);
}

/**
 * Publisher indicator content in the immediate section after block i (until
 * the next real heading). Used for level-less / synthetic topic headings that
 * cannot use DOM subtree bounds.
 * @param {object[]} blocks
 * @param {number} i
 * @param {Set<string>} chromeIds
 */
export function sectionHasIndicatorContent(blocks, i, chromeIds, limit = 80) {
  let seen = 0;
  for (let j = i + 1; j < blocks.length && seen < limit; j += 1) {
    const n = blocks[j];
    if (n.layout === 'page_edge' || chromeIds.has(n.id)) continue;
    if (n.type === 'heading') return false;
    seen += 1;
    if (isIndicatorContentBlock(n)) return true;
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
  if (b.type === 'heading' && Number.isInteger(b.level)) {
    return subtreeHasIndicatorStructure(blocks, i, chromeIds);
  }
  return sectionHasIndicatorContent(blocks, i, chromeIds);
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
function isTypedSubheadingContinuation(labelHeading, b, blocks, i, opening, chromeIds) {
  if (!labelHeading) return false;
  const level = Number.isInteger(b.level) ? b.level : null;
  const networkOrDeclared = labelHeading.semantics === 'network' || Boolean(labelHeading.declared_type);
  // Same-or-shallower than the current opening: network / declared type labels
  // may still be sibling per-type lists ("Hash Values" / "IP Addresses" /
  // "Domain" under one IOC heading, even when a prior type label opened a
  // sample_table). Artifact vocabulary alone ("Receiving a command") is a
  // topic boundary at that level, not a typed sub-list.
  if (level != null && opening.level != null && level <= opening.level) {
    return networkOrDeclared;
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
  // Observable value rows — including defanged hosts with a parenthetical
  // gloss ("osc-cdn[.]com (actor-used …)") — are never section titles.
  if (/(?:\[\.\])|hxxps?:\/\//i.test(t)) return false;
  if (/^(?:https?:\/\/|\d{1,3}(?:\.\d{1,3}){3})\S*/i.test(t)) return false;
  if (/^[a-f0-9]{32,64}\b/i.test(t)) return false;
  const lead = t.split(/\s+/)[0].replace(/[.,;:)\]].*$/, '');
  if (lead && (isObservableOnlyLine(lead) || isIndicatorValueLine(lead))) return false;
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
export function subtreeHasIndicatorStructure(blocks, i, chromeIds, limit = 200) {
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
    if (isIndicatorContentBlock(n)) return true;
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
  /**
   * Parent publisher-IOC appendix (explicit_ioc_section), retained while child
   * C2 / sample / operational subsections open and close beneath it. Null when
   * the active strong zone was opened without an appendix parent (standalone
   * C2 heading, top-level sample table, …).
   * @type {{ id: string|null, text: string|null, level: number|null, form: string|null, zone: DocumentZone, role: string|null }|null}
   */
  let appendixAnchor = null;
  /** Authoritative section closed by a deeper prose sub-heading (may resume). */
  let suspended = null;
  /** Software-version columns of the last table, carried across page-break chrome only. */
  let versionCarry = null;
  /** Developer trace of scope decisions (bounded, not analyst UI). */
  const scopeTrace = [];
  const trace = (entry) => {
    if (scopeTrace.length < 120) scopeTrace.push(entry);
  };
  /** True once the open strong section has shown at least one indicator row. */
  let sectionSawIndicatorContent = false;

  const clearAppendixAnchor = () => {
    appendixAnchor = null;
  };

  const clearStrongScope = () => {
    suspended = null;
    currentZone = 'report_body';
    currentRole = null;
    currentTypeLabel = null;
    sectionSawIndicatorContent = false;
    opening = { id: null, text: null, level: null, form: null };
    clearAppendixAnchor();
  };

  /**
   * Leaving a child strong zone (C2 / sample / …) while still nested under the
   * publisher IOC appendix: restore the appendix when this heading's subtree
   * still holds publisher indicator content. A deeper related-article / prose
   * topic with no indicator rows ends the appendix.
   */
  const retainAppendixUnderHeading = (level, headingIndex) => {
    if (!appendixAnchor) return false;
    if (level == null || appendixAnchor.level == null || level <= appendixAnchor.level) return false;
    return (
      sectionOpensWithIndicatorContent(blocks, headingIndex, footerIds) ||
      subtreeHasIndicatorStructure(blocks, headingIndex, footerIds)
    );
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
        // Only prose/caption blocks may act as synthetic headings. List rows,
        // code lines and other short content stay content even when brief.
        ((b.type === 'paragraph' || b.type === 'caption') &&
          text.length > 0 &&
          text.length <= 72 &&
          !/\b(?:hxxps?|https?):\/\//i.test(text) &&
          !/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(text) &&
          !/\b[a-f0-9]{32}\b/i.test(text) &&
          // A single observable value ("c2.evil.example") is a row, never a heading.
          !isObservableOnlyLine(text) &&
          looksLikeLabelHeading(text)));
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

    // "C2 infrastructure" / "Dead-drop C2 communication" name a topic as often
    // as a list. Real headings, synthetic/bold paragraphs, and level-less PDF
    // headings open an authoritative section only when their content holds
    // publisher indicator structure; a prose-only topic is narrative.
    if (
      headingZone &&
      !descriptiveForm &&
      TOPIC_LABEL_ZONES.has(headingZone) &&
      !topicHeadingHasIndicatorContent(b, blocks, i, footerIds)
    ) {
      trace({ block_id: b.id, decision: 'topic_heading_unconfirmed', heading: headingText.slice(0, 120), zone: headingZone });
      b.zone_reason = 'indicator_heading_unconfirmed';
      headingZone = null;
      headingRole = null;
    }

    if (headingZone && ZONE_OPENING_HEADINGS.has(headingZone)) {
      const level = Number.isInteger(b.level) ? b.level : null;
      const openingStrong = STRONG_IOC_ZONES.has(headingZone);
      const childUnderAppendix =
        openingStrong &&
        appendixAnchor != null &&
        appendixAnchor.level != null &&
        level != null &&
        level > appendixAnchor.level &&
        headingZone !== 'explicit_ioc_section';

      suspended = null;
      currentZone = headingZone;
      currentRole = headingRole;
      currentTypeLabel = null;
      sectionSawIndicatorContent = false;
      b.zone_reason = descriptiveForm ? 'heading_hint_descriptive' : 'heading_hint';
      b.section_role = headingRole;
      opening = {
        id: b.id,
        text: headingText.slice(0, 160),
        level,
        form: indicatorHeading?.form || null
      };
      b.scope_opening_id = b.id;

      if (headingZone === 'explicit_ioc_section') {
        // New / replacement appendix root.
        appendixAnchor = {
          id: opening.id,
          text: opening.text,
          level: opening.level,
          form: opening.form,
          zone: 'explicit_ioc_section',
          role: headingRole
        };
      } else if (!childUnderAppendix && openingStrong) {
        // Standalone strong section (C2 / sample / operational without an
        // appendix parent) — no appendix to fall back to when it closes.
        clearAppendixAnchor();
      }
      // childUnderAppendix: keep appendixAnchor; only the active child opening changes.

      if (!openingStrong && (headingZone === 'reference_section' || headingZone === 'vendor_about' || headingZone === 'code')) {
        clearAppendixAnchor();
      }

      trace({
        block_id: b.id,
        decision: 'open',
        zone: headingZone,
        role: headingRole,
        heading: opening.text,
        level: opening.level,
        form: opening.form,
        appendix_anchor: appendixAnchor?.id || null
      });
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
      // per-type sub-lists of the same publisher-curated section. Sibling
      // artifact topics ("Receiving a command") are not.
      const typedContinuation =
        inStrong && isTypedSubheadingContinuation(labelHeading, b, blocks, i, opening, footerIds);
      // Any other short sub-label that groups rows inside the section (decoy /
      // supporting / per-campaign groups) inherits the section scope.
      const subgroupContinuation =
        inStrong &&
        !typedContinuation &&
        !wrappedContinuation &&
        !headingRole &&
        !headingZone &&
        isSubgroupLabelHeading(b, blocks, i, opening, footerIds);
      // Document hierarchy: a heading nested deeper than the one that opened
      // the section, whose own content starts with indicator rows, is a
      // sub-list of that section whatever its label says ("VBS", "Stage 2
      // payloads"). A deeper heading followed by prose ("About the author")
      // still closes it.
      const level = Number.isInteger(b.level) ? b.level : null;
      const hierarchyContinuation =
        inStrong &&
        !typedContinuation &&
        !wrappedContinuation &&
        !subgroupContinuation &&
        !headingRole &&
        !headingZone &&
        level != null &&
        opening.level != null &&
        level > opening.level &&
        sectionOpensWithIndicatorContent(blocks, i, footerIds);
      // A deeper heading that closed the section (a prose sub-topic) leaves it
      // suspended: a later sibling sub-list under the same parent heading
      // (typed label, or indicator rows beneath it) resumes it. A heading
      // nested under that prose sub-topic belongs to the sub-topic ("Integrated
      // Coverage" › "Email Security"), never to the suspended section.
      const resumed =
        !inStrong &&
        suspended != null &&
        !headingRole &&
        !headingZone &&
        level != null &&
        level > suspended.opening.level &&
        (suspended.closerLevel == null || level <= suspended.closerLevel) &&
        (Boolean(labelHeading) || sectionOpensWithIndicatorContent(blocks, i, footerIds));
      if (resumed) {
        currentZone = suspended.zone;
        currentRole = suspended.role;
        opening = suspended.opening;
        suspended = null;
        b.zone_reason = 'subsection_resumed';
        b.section_role = currentRole;
        b.scope_opening_id = opening.id;
        trace({ block_id: b.id, decision: 'resumed', zone: currentZone, heading: headingText.slice(0, 120), level, opened_by: opening.id });
      } else if (
        // Child C2 (or sample/operational) scope must not paint Loaders /
        // Plugins / Samples rows as explicit_c2. When a non-C2 sub-list
        // continues under the appendix, restore the parent appendix zone
        // first — typed network sub-lists ("Domains", "IPs") stay in C2.
        appendixAnchor &&
        currentZone !== appendixAnchor.zone &&
        STRONG_IOC_ZONES.has(currentZone) &&
        ((subgroupContinuation || hierarchyContinuation || wrappedContinuation) ||
          (typedContinuation && labelHeading && labelHeading.semantics !== 'network'))
      ) {
        const fromZone = currentZone;
        currentZone = appendixAnchor.zone;
        currentRole = appendixAnchor.role;
        opening = {
          id: appendixAnchor.id,
          text: appendixAnchor.text,
          level: appendixAnchor.level,
          form: appendixAnchor.form
        };
        suspended = null;
        sectionSawIndicatorContent = true;
        b.zone_reason = typedContinuation
          ? 'typed_subheading'
          : subgroupContinuation
            ? 'subgroup_label'
            : hierarchyContinuation
              ? 'nested_indicator_subheading'
              : wrappedContinuation
                ? 'heading_continuation'
                : 'appendix_scope_retained';
        b.section_role = currentRole;
        b.scope_opening_id = opening.id;
        if (labelHeading) {
          currentTypeLabel = labelHeading;
          b.type_label_heading = labelHeading;
        } else {
          currentTypeLabel = null;
        }
        trace({
          block_id: b.id,
          decision: 'appendix_retained',
          from_zone: fromZone,
          zone: currentZone,
          heading: headingText.slice(0, 120),
          level,
          opened_by: opening.id,
          via: b.zone_reason
        });
      } else if (!wrappedContinuation && !typedContinuation && !subgroupContinuation && !hierarchyContinuation) {
        const fallBackToAppendix = inStrong && retainAppendixUnderHeading(level, i);
        if (fallBackToAppendix) {
          // Child C2/sample scope ends; parent IOC appendix continues for
          // Loaders / Plugins / Samples siblings that still list indicators.
          const fromZone = currentZone;
          currentZone = appendixAnchor.zone;
          currentRole = appendixAnchor.role;
          opening = {
            id: appendixAnchor.id,
            text: appendixAnchor.text,
            level: appendixAnchor.level,
            form: appendixAnchor.form
          };
          suspended = null;
          currentTypeLabel = null;
          sectionSawIndicatorContent = true;
          b.zone_reason = 'appendix_scope_retained';
          b.section_role = currentRole;
          b.scope_opening_id = opening.id;
          trace({
            block_id: b.id,
            decision: 'appendix_retained',
            from_zone: fromZone,
            zone: currentZone,
            heading: headingText.slice(0, 120),
            level,
            opened_by: opening.id,
            appendix_anchor: appendixAnchor.id
          });
        } else {
          if (inStrong) {
            trace({
              block_id: b.id,
              decision: 'reset',
              from_zone: currentZone,
              heading: headingText.slice(0, 120),
              level,
              opened_by: opening.id,
              appendix_anchor: appendixAnchor?.id || null
            });
            suspended =
              level != null && opening.level != null && level > opening.level
                ? { zone: currentZone, role: currentRole, opening, closerLevel: level }
                : null;
          } else if (suspended && (level == null || level <= suspended.opening.level)) {
            suspended = null;
          }
          // Full exit from the strong section (and any appendix parent).
          if (!suspended) {
            currentZone = 'report_body';
            currentRole = null;
            sectionSawIndicatorContent = false;
            opening = { id: null, text: null, level: null, form: null };
            clearAppendixAnchor();
          } else {
            // Deeper prose sub-topic suspends the child; appendix parent stays
            // so a later sibling under the appendix can resume via existing
            // resume logic or a later appendix_retained path after resume.
            currentZone = 'report_body';
            currentRole = null;
            sectionSawIndicatorContent = false;
            opening = { id: null, text: null, level: null, form: null };
          }
          if (b.zone_reason !== 'indicator_heading_unconfirmed') b.zone_reason = 'heading_reset';
        }
      } else {
        b.zone_reason = typedContinuation
          ? 'typed_subheading'
          : subgroupContinuation
            ? 'subgroup_label'
            : hierarchyContinuation
              ? 'nested_indicator_subheading'
              : 'heading_continuation';
        b.section_role = currentRole;
        b.scope_opening_id = opening.id;
        trace({ block_id: b.id, decision: b.zone_reason, zone: currentZone, heading: headingText.slice(0, 120), opened_by: opening.id });
      }
      currentTypeLabel = labelHeading;
      if (labelHeading) b.type_label_heading = labelHeading;
    } else if (
      isHeadingLike &&
      !headingZone &&
      STRONG_IOC_ZONES.has(currentZone) &&
      // Only prose/caption synthetic headings close scope. List rows, code
      // lines and table cells can be short and heading-shaped but are content.
      (b.type === 'paragraph' || b.type === 'caption')
    ) {
      // A bold/short paragraph that looks like a heading but does not open a
      // zone is a section boundary unless it is a genuine per-type / subgroup
      // list label with indicator content beneath (Invariant A/B). Malware /
      // tool family labels ("GoSerpent", "Stowaway") are not type vocabulary
      // but still group indicator rows under the open appendix — same rule as
      // hierarchyContinuation for nested real headings (v3).
      const synthLabel = typeLabelHeading(text);
      const synthTyped = isTypedSubheadingContinuation(synthLabel, b, blocks, i, opening, footerIds);
      const next = nextContentBlock(blocks, i, footerIds);
      const synthSubgroup =
        !synthTyped &&
        Boolean(next) &&
        isIndicatorRowBlock(next);
      // A short line immediately above a table is a caption / recovered header
      // ("IP Address First Seen Last Seen"), not a new topic boundary.
      const tableCaptionContinuation = Boolean(next) && next.type === 'table';
      if (!synthTyped && !synthSubgroup && !tableCaptionContinuation) {
        // Synthetic labels have no DOM level; if a following real heading still
        // opens publisher indicator content under the appendix, keep the
        // appendix rather than discarding parent membership with the child C2.
        let synthAppendixKeep = false;
        if (appendixAnchor && next && next.type === 'heading') {
          const nextIndex = blocks.findIndex((x, idx) => idx > i && x.id === next.id);
          synthAppendixKeep =
            nextIndex >= 0 && subtreeHasIndicatorStructure(blocks, nextIndex, footerIds);
        }
        if (synthAppendixKeep) {
          const fromZone = currentZone;
          currentZone = appendixAnchor.zone;
          currentRole = appendixAnchor.role;
          opening = {
            id: appendixAnchor.id,
            text: appendixAnchor.text,
            level: appendixAnchor.level,
            form: appendixAnchor.form
          };
          suspended = null;
          currentTypeLabel = null;
          sectionSawIndicatorContent = true;
          b.zone_reason = 'appendix_scope_retained';
          b.section_role = currentRole;
          b.scope_opening_id = opening.id;
          trace({
            block_id: b.id,
            decision: 'appendix_retained',
            from_zone: fromZone,
            zone: currentZone,
            heading: headingText.slice(0, 120),
            reason: 'synthetic_heading_appendix_retained',
            opened_by: opening.id
          });
        } else {
          trace({
            block_id: b.id,
            decision: 'reset',
            from_zone: currentZone,
            heading: headingText.slice(0, 120),
            level: null,
            opened_by: opening.id,
            reason: 'synthetic_heading_boundary'
          });
          clearStrongScope();
          b.zone_reason = 'heading_reset';
        }
      } else if (synthLabel || tableCaptionContinuation || synthSubgroup) {
        if (synthLabel) {
          currentTypeLabel = synthLabel;
          b.type_label_heading = synthLabel;
        }
        b.zone_reason = synthTyped ? 'typed_subheading' : tableCaptionContinuation ? 'table_caption' : 'subgroup_label';
        b.section_role = currentRole;
        b.scope_opening_id = opening.id;
        trace({ block_id: b.id, decision: b.zone_reason, zone: currentZone, heading: headingText.slice(0, 120), opened_by: opening.id });
      }
    }

    // Post-appendix chrome: once a strong section has shown indicator rows, a
    // following article-tag / category list closes scope so metadata never
    // inherits the Domains type label or explicit IOC assertion. Annotated IOC
    // rows ("host – Decoy domain") stay inside the section.
    if (
      !isRealHeading &&
      !pageEdge &&
      !isRepeatedChrome &&
      STRONG_IOC_ZONES.has(currentZone) &&
      sectionSawIndicatorContent &&
      isArticleMetadataListItem(b)
    ) {
      trace({
        block_id: b.id,
        decision: 'reset',
        from_zone: currentZone,
        reason: 'post_indicator_metadata_list',
        opened_by: opening.id
      });
      clearStrongScope();
      b.zone_reason = 'post_indicator_metadata_list';
    }

    if (
      !isRealHeading &&
      !pageEdge &&
      !isRepeatedChrome &&
      STRONG_IOC_ZONES.has(currentZone) &&
      (isIndicatorRowBlock(b) || isIndicatorValueLine(text) || isObservableListLine(text))
    ) {
      sectionSawIndicatorContent = true;
    }

    if (!isRealHeading && !pageEdge && !isRepeatedChrome && opening.id && STRONG_IOC_ZONES.has(currentZone)) {
      b.scope_opening_id = opening.id;
    }

    /** @type {DocumentZone} */
    let zone = currentZone;
    if (b.zone_reason === 'post_indicator_metadata_list') {
      zone = 'source_metadata';
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
    if (currentRole && !b.section_role && zone === currentZone) b.section_role = currentRole;
    // A type-label heading types the value rows beneath it (list items,
    // observable-only lines, single-token code blocks) — never prose paragraphs.
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
      const inAuthoritativeScope = STRONG_IOC_ZONES.has(zone);
      const interpretation = interpretIocTable(b, {
        negativeZone: negative,
        versionColumns: versions.columns,
        inAuthoritativeScope
      });
      b.ioc_table = interpretation;
      if (interpretation.kind === 'ioc_table' && interpretation.explicit && !negative) {
        // File-hash inventories that are already under a sample heading keep
        // sample_table; only self-proving network/typed IOC tables open a new
        // explicit_ioc_section from body text.
        if (interpretation.file_hash_inventory && zone === 'sample_table') {
          b.zone = 'sample_table';
          b.zone_reason = 'file_hash_inventory';
        } else {
          b.zone = 'explicit_ioc_section';
          b.section = b.section === zone ? 'explicit_ioc_section' : b.section;
          b.zone_reason = 'ioc_table';
        }
      }
    } else if (zone !== 'header_footer') {
      versionCarry = null;
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

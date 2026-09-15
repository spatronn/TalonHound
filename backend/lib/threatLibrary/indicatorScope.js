/**
 * Source indicator-scope and occurrence-relation model.
 *
 * Threat Library must not treat every syntactic observable in a report as a
 * review IOC. When the publisher curates operational indicator sections
 * (IOC appendix, C2 list, VPN/admin infrastructure, sample table), those
 * sections are authoritative. Narrative mentions — including that an actor
 * bought or used a legitimate service — stay context unless the source
 * independently asserts the exact observable as malicious / operational
 * infrastructure.
 *
 * No vendor or domain allowlists. Heading hints are multilingual optimizations;
 * unknown-language sections still work via list/table structure.
 */

import { collapseLetterSpacing, isObservableOnlyLine } from './pdfLayout.js';
import { refangTextForExtraction } from './defang.js';

export const INDICATOR_SCOPES = Object.freeze({
  AUTHORITATIVE: 'authoritative',
  CONTEXTUAL: 'contextual',
  EXCLUDED: 'excluded'
});

export const SOURCE_RELATIONS = Object.freeze({
  OPERATIONAL_MALICIOUS: 'operational_malicious',
  PROVIDER_SERVICE: 'provider_service',
  CONTEXTUAL: 'contextual',
  REFERENCE: 'reference'
});

/**
 * Structural kind of one occurrence. Row kinds are source assertions when they
 * sit inside an authoritative section; narrative kinds need relation semantics
 * whatever the zone says. Zone membership alone never asserts maliciousness.
 */
export const OCCURRENCE_KINDS = Object.freeze({
  TYPED_TABLE_ROW: 'typed_table_row',
  STANDALONE_INDICATOR_ROW: 'standalone_indicator_row',
  LIST_ITEM: 'list_item',
  ENDPOINT: 'endpoint',
  NARRATIVE_ASSERTION: 'narrative_assertion',
  NARRATIVE_CONTEXT: 'narrative_context',
  NARRATIVE_MENTION: 'narrative_mention',
  REFERENCE: 'reference'
});

const ROW_KINDS = new Set([
  OCCURRENCE_KINDS.TYPED_TABLE_ROW,
  OCCURRENCE_KINDS.STANDALONE_INDICATOR_ROW,
  OCCURRENCE_KINDS.LIST_ITEM,
  OCCURRENCE_KINDS.ENDPOINT
]);

/**
 * @param {string|null|undefined} kind
 */
export function isRowOccurrenceKind(kind) {
  return ROW_KINDS.has(String(kind || ''));
}

/** How a heading declared an indicator section. */
export const INDICATOR_HEADING_FORMS = Object.freeze({
  /** A recognised label ("IOCs", "Appendix B: C2 Servers", "Göstergeler"). */
  LABEL: 'label',
  /** Indicator concept first, then descriptive text ("Indicators: Campaign A"). */
  DESCRIPTIVE_SUFFIX: 'descriptive_suffix'
});

export const SECTION_ROLES = Object.freeze({
  IOC_APPENDIX: 'ioc_appendix',
  C2_INFRASTRUCTURE: 'c2_infrastructure',
  OPERATIONAL_INFRASTRUCTURE: 'operational_infrastructure',
  SAMPLE_TABLE: 'sample_table',
  NARRATIVE: 'narrative',
  REFERENCES: 'references',
  SOURCE_METADATA: 'source_metadata',
  LAYOUT: 'layout'
});

/** Appendix / annex / 附录 / ek / anhang — not a specific letter or number. */
const APPENDIX_RE =
  /\b(?:appendix|appendices|annex|annexe|anexo|anhang|anlage|ekler|ek\b|附录|附件|annexes?)\b/i;

const C2_INTENT_RE =
  /\b(?:c\s*&\s*c|c2|c&c|command\s*(?:and|&)\s*control|komuta\s*kontrol)\b|控制端|回连地址|通信地址|远控地址|c2地址|c2服务器/i;

const IOC_INTENT_RE =
  /\b(?:iocs?|indicators?\s+of\s+compromise|compromise\s+indicators?|network\s+indicators?|host\s+indicators?|file\s+indicators?|technical\s+indicators?|atomic\s+indicators?|detection\s+data|observables?)\b|威胁指标|妥协指标|göstergeler|indicadores/i;

const OPERATIONAL_INFRA_RE =
  /\b(?:vpn\s+nodes?|admin(?:istrative)?\s+(?:nodes?|infrastructure)|(?:ip|ipv4|ipv6)\s+(?:address\s+)?ranges?|address\s+ranges?|malicious\s+infrastructure|threat\s+infrastructure|operator\s+infrastructure|admin(?:istering|istration)\b.{0,48}(?:infrastructure|nodes?|ranges?)|(?:infrastructure|nodes?|ranges?).{0,48}admin(?:istering|istration)?)\b|基础设施|运营节点/i;

const SAMPLE_INTENT_RE = /\b(?:malicious\s+samples?|sample\s+hash|file\s+hash)\b|恶意样本|样本哈希|örnek\s+hash/i;

const REFERENCE_INTENT_RE =
  /^(?:references?|bibliography|quellen|kaynaklar|referanslar|références|referencias)\b|参考链接|参考文献|相关链接/i;

/**
 * Indicator concept at the head of a heading, then a separator or the end:
 * "Indicators: Three Casinos…", "Indicators – Network Infrastructure",
 * "IOCs (Type 3)", "Göstergeler: Ek Altyapı", "威胁指标：活动A". A heading that
 * merely contains the word later in a sentence ("Why these indicators matter",
 * "Indicators suggest a Chinese origin") does not match: the concept must lead
 * and be closed by punctuation, "of", or the end of the heading.
 */
const INDICATOR_HEAD_RE =
  /^(?:(?:host|network|file|atomic|additional|other|related|technical|known|key|observed|associated|new|ağ|dosya|ek)\s+)?(?:indicators?|iocs?|göstergeler|indicadores|威胁指标|妥协指标)\s*(?:[:：\-–—|(\[（]|of\b|$)/i;

/**
 * Classify a heading as an indicator-section declaration, with its form.
 * @param {string} text
 * @returns {{ role: string, form: string }|null}
 */
export function classifyIndicatorHeading(text) {
  const t = collapseLetterSpacing(String(text || '').trim());
  if (!t || t.length > 200) return null;
  const role = classifySectionRole(t, { allowDescriptiveSuffix: false });
  if (role) return { role, form: INDICATOR_HEADING_FORMS.LABEL };
  const m = t.match(INDICATOR_HEAD_RE);
  if (!m) return null;
  const rest = t.slice(m[0].length).trim();
  return {
    role: SECTION_ROLES.IOC_APPENDIX,
    form: rest ? INDICATOR_HEADING_FORMS.DESCRIPTIVE_SUFFIX : INDICATOR_HEADING_FORMS.LABEL
  };
}

/**
 * Classify a heading's section role. Returns null when the heading does not
 * declare an indicator, reference or sample section (narrative / unknown).
 * A bare indicator concept followed by descriptive text ("Indicators: …")
 * counts as an IOC appendix; callers that need to know it was the descriptive
 * form (and confirm it structurally) use classifyIndicatorHeading.
 * @param {string} text
 * @param {{ allowDescriptiveSuffix?: boolean }} [opts]
 * @returns {string|null}
 */
export function classifySectionRole(text, opts = {}) {
  const t = collapseLetterSpacing(String(text || '').trim());
  if (!t || t.length > 200) return null;
  if (REFERENCE_INTENT_RE.test(t) && t.length <= 80) return SECTION_ROLES.REFERENCES;
  if (SAMPLE_INTENT_RE.test(t) && t.length <= 80) return SECTION_ROLES.SAMPLE_TABLE;
  if (C2_INTENT_RE.test(t)) return SECTION_ROLES.C2_INFRASTRUCTURE;
  if (OPERATIONAL_INFRA_RE.test(t)) return SECTION_ROLES.OPERATIONAL_INFRASTRUCTURE;
  if (IOC_INTENT_RE.test(t)) return SECTION_ROLES.IOC_APPENDIX;
  if (APPENDIX_RE.test(t) && /(?:server|node|range|indicator|ioc|infrastructure|vpn|c2|hash|sample)/i.test(t)) {
    if (C2_INTENT_RE.test(t)) return SECTION_ROLES.C2_INFRASTRUCTURE;
    if (OPERATIONAL_INFRA_RE.test(t) || /\b(?:vpn|range|node|infrastructure)\b/i.test(t)) {
      return SECTION_ROLES.OPERATIONAL_INFRASTRUCTURE;
    }
    return SECTION_ROLES.IOC_APPENDIX;
  }
  if (opts.allowDescriptiveSuffix !== false && INDICATOR_HEAD_RE.test(t)) return SECTION_ROLES.IOC_APPENDIX;
  return null;
}

/**
 * Map a section role onto a document zone.
 * @param {string|null} role
 */
export function zoneForSectionRole(role) {
  switch (role) {
    case SECTION_ROLES.C2_INFRASTRUCTURE:
      return 'c2_section';
    case SECTION_ROLES.SAMPLE_TABLE:
      return 'sample_table';
    case SECTION_ROLES.IOC_APPENDIX:
      return 'explicit_ioc_section';
    case SECTION_ROLES.OPERATIONAL_INFRASTRUCTURE:
      return 'operational_infrastructure';
    case SECTION_ROLES.REFERENCES:
      return 'reference_section';
    default:
      return null;
  }
}

const AUTHORITATIVE_ZONES = new Set([
  'explicit_ioc_section',
  'c2_section',
  'sample_table',
  'operational_infrastructure'
]);

const EXCLUDED_ZONES = new Set([
  'reference_section',
  'source_metadata',
  'header_footer',
  'navigation',
  'vendor_about'
]);

/**
 * @param {string|null|undefined} zone
 */
export function indicatorScopeForZone(zone) {
  const z = String(zone || '');
  if (AUTHORITATIVE_ZONES.has(z)) return INDICATOR_SCOPES.AUTHORITATIVE;
  if (EXCLUDED_ZONES.has(z)) return INDICATOR_SCOPES.EXCLUDED;
  return INDICATOR_SCOPES.CONTEXTUAL;
}

/**
 * Document-level: does the publisher curate at least one operational indicator set?
 * @param {object[]} blocks
 */
export function discoverDocumentIndicatorScope(blocks) {
  const zones = new Set();
  const roles = new Set();
  let authoritativeBlocks = 0;
  for (const b of blocks || []) {
    const zone = b.zone || 'report_body';
    zones.add(zone);
    if (b.section_role) roles.add(b.section_role);
    if (AUTHORITATIVE_ZONES.has(zone)) authoritativeBlocks += 1;
    const headingRole = b.type === 'heading' ? classifySectionRole(b.text) : null;
    if (headingRole) roles.add(headingRole);
  }
  return {
    has_authoritative_indicator_scope: authoritativeBlocks > 0,
    authoritative_block_count: authoritativeBlocks,
    zones: [...zones],
    section_roles: [...roles]
  };
}

/**
 * Strong operational-malicious relation: the source asserts this exact
 * observable is C2 / payload / attacker infrastructure, not merely mentioned.
 * Hints are multilingual optimizations — unknown languages still use
 * structural forms (ip:port, indicator-list row).
 */
const OPERATIONAL_RELATION_RE =
  /\b(?:c2|c&c|c\s*&\s*c|command\s*(?:and|&)\s*control|beacon(?:s|ing)?|connects?\s+to|communicat(?:es|ed|ing)\s+with|callback|payload|downloads?\s+(?:hxxps?:\/\/|https?:\/\/|from|OBSERVABLE)|downloaded?\s+from|fetch(?:es|ed)?\s+from|drops?\s+from|phish(?:ing)?|malware\s+(?:connects?|beacons?|talks?)|attacker[- ]controlled|malicious\s+(?:server|host|domain|url|ip|infrastructure)|hard-?coded|(?:fetch|download|retriev|pull|load|deliver|drop|serv|stag|exfiltrat|upload)\w*\b[^.;]{0,60}?\b(?:from|to)\s+OBSERVABLE|(?:hosted|served|staged|stored)\s+(?:at|on)\s+OBSERVABLE)\b|回连|远控|木马连接|命令控制|komuta|bağlan(?:ır|ıyor|dı|maktadır)/i;

const PROVIDER_RELATION_RE =
  /\b(?:purchased?|bought|rented?|leased?|registered?\s+(?:via|through|with|at)|subscri(?:bed|be)|procur(?:ed|e)|to\s+purchase|to\s+host|services?\s+such\s+as|infrastructure\s+provider|cloud\s+provider|hosting\s+provider|vps\s+provider|vpn\s+provider|used\s+(?:the\s+)?(?:commercial\s+)?(?:services?|providers?|vendors?|platforms?|vpn|vps|proxy|cloud(?:\s+provider)?)|from\s+(?:a\s+)?(?:vps|vpn|proxy|hosting|cloud)\s+(?:provider|vendor|service)|commercial\s+vpn)\b|satın\s+al|satın\s+ald|购买|租用|注册于/i;

const PROVIDER_CATALOGUE_RE =
  /\b(?:likely\s+to\s+purchase|to\s+obtain\s+(?:infrastructure|services?|prox(?:y|ies)|vps|vpn)|used\s+\w[\w.-]*\s+(?:to\s+purchase|for\s+(?:infrastructure|hosting|prox(?:y|ies)|vps)))\b/i;

/**
 * Contextual relation: the observable names who researched / reported /
 * documented something, or an organisation, vendor or tool — not attacker
 * infrastructure. "Org Name (OBSERVABLE)" is the parenthetical-organisation
 * shape ("Interisle Consulting (interisle[.]net) flagged …").
 */
const CONTEXT_RELATION_RE =
  /\b(?:research(?:er|ers|ed)?|consult(?:ing|ancy|ants?)|according\s+to|reported\s+by|report(?:ed)?\s+(?:by|from)|documented\s+(?:by|in)|analys(?:ts?|is)\s+(?:at|from|by)|team\s+at|colleagues?\s+at|published\s+(?:by|on)|blog\s+post|advisory\s+(?:by|from)|whitepaper|write-?up|security\s+(?:firm|vendor|company|researchers?)|flagged\s+by|credit(?:s|ed)?\s+to|thanks\s+to|courtesy\s+of|our\s+(?:website|blog|site|portal))\b|araştırma|firması|şirketi|göre|研究(?:人员|团队)?|安全公司|据|\b[A-Z][\w&.'-]*(?:\s+[A-Z][\w&.'-]*){0,4}\s*[(（]\s*OBSERVABLE\s*[)）]/;

/** Value-only lines and "value – note" / "label: value" rows are structural indicator rows. */
/** "1. ", "[2] ", "• " — a list marker must be followed by whitespace so "36.35.56.0/24" keeps its first octet. */
const BULLET_PREFIX_RE = /^(?:[\[(]?\d{1,3}[\])]?[.、)]?\s+|[-•*·]\s*)/;
const OTHER_OBSERVABLE_RE =
  /https?:\/\/|(?:\d{1,3}\.){3}\d{1,3}|\b[a-f0-9]{32,64}\b|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/i;

const OBSERVABLE_TOKEN_RE =
  /^(?:https?:\/\/\S+|(?:\d{1,3}\.){3}\d{1,3}(?:\/(?:3[0-2]|[12]?\d)|:\d{1,5})?|[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?)$/i;

/**
 * A line made only of observables ("36.35.56.0/24 36.49.207.0/24", a <pre>
 * block of hashes, "a.example, b.example"): a publisher list whose layout
 * did not split one value per row. Structural, like a list.
 * @param {string} text
 */
export function isObservableListLine(text) {
  const t = refangTextForExtraction(String(text || '').trim()).replace(BULLET_PREFIX_RE, '').trim();
  if (!t || t.length > 2000) return false;
  const tokens = t.split(/[\s,;|，；]+/).filter(Boolean);
  if (!tokens.length) return false;
  return tokens.every((tok) => OBSERVABLE_TOKEN_RE.test(tok.replace(/[.,;)\]。，；]+$/, '')));
}

/**
 * True when a short line is one indicator value plus at most a short label or
 * annotation on one side ("vip311[.]cc – Decoy domain", "C2 203.0.113.44",
 * "Domain: evil.example"). A value embedded in prose on both sides is not a row.
 * @param {string} text
 * @param {string} value normalized or original observable spelling
 */
export function isIndicatorRowShape(text, value) {
  const t = refangTextForExtraction(String(text || '').trim()).replace(BULLET_PREFIX_RE, '').trim();
  if (!t) return false;
  if (isObservableListLine(t)) return true;
  if (t.length > 160) return false;
  if (isObservableOnlyLine(t)) return true;
  const v = refangTextForExtraction(String(value || '').trim());
  if (!v) return false;
  const idx = t.toLowerCase().indexOf(v.toLowerCase());
  if (idx < 0) return false;
  const before = t.slice(0, idx).trim();
  const after = t.slice(idx + v.length).trim();
  if (before && after) return false;
  const annotation = before || after;
  if (!annotation) return true;
  if (annotation.length > 80) return false;
  if (/[.!?。]$/.test(annotation) && annotation.split(/\s+/).length > 6) return false;
  if (OTHER_OBSERVABLE_RE.test(annotation)) return false;
  return true;
}

/**
 * The clause that actually mentions the observable, so a mixed sentence does
 * not transfer "beacons to Y" onto an unrelated "traffic to X".
 * @param {string} text
 * @param {string|null} value
 */
export function clauseContaining(text, value) {
  const hay = String(text || '');
  const needle = String(value || '').trim();
  if (!needle) return hay;
  const parts = hay.split(/(?<=[.;，；])\s+|,\s+|\s+(?:and|und|et|ve|和)\s+/);
  const variants = [needle, needle.replace(/\[\.\]/g, '.'), needle.replace(/\./g, '[.]')];
  const hit = parts.find((p) => {
    const low = p.toLowerCase();
    return variants.some((v) => v && low.includes(String(v).toLowerCase()));
  });
  return hit || hay;
}

function escapeRegExp(s) {
  return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function maskObservable(text, value) {
  const hay = String(text || '');
  const needle = String(value || '').trim();
  if (!needle) return hay;
  const variants = [...new Set([needle, needle.replace(/\[\.\]/g, '.'), needle.replace(/\./g, '[.]')])];
  let out = hay;
  for (const v of variants) {
    if (!v) continue;
    out = out.replace(new RegExp(escapeRegExp(v), 'ig'), ' OBSERVABLE ');
  }
  return out;
}

/** Other URLs/IPs in the same sentence must not transfer "downloads https://X" onto Y. */
function maskForeignNetworkTokens(text, keepValue) {
  const keep = String(keepValue || '').toLowerCase();
  return String(text || '')
    .replace(/\b(?:hxxps?|https?):\/\/[^\s<>"'）)\]]+/gi, (m) => {
      const low = m.toLowerCase().replace(/hxxp/g, 'http');
      if (keep && (low.includes(keep) || keep.includes(low))) return m;
      return ' URL ';
    })
    .replace(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(?:3[0-2]|[12]?\d))?\b/g, (m) => {
      if (keep && keep.includes(m)) return m;
      return ' IP ';
    });
}
/**
 * Structural reading of one occurrence: is it an indicator row (assertion by
 * placement) or a mention inside prose?
 * @param {{ form?: string, block_type?: string|null, layout?: string|null, zone_reason?: string|null, structural_row?: boolean, row_shape?: boolean }} occ
 */
function structuralRowOf(occ) {
  if (occ.structural_row === true || occ.row_shape === true) return true;
  const form = String(occ.form || '');
  if (form === 'table_row' || form === 'list_row' || form === 'ip_port') return true;
  const bt = String(occ.block_type || '');
  if (bt === 'list_item' || occ.layout === 'observable_row') return true;
  const zr = String(occ.zone_reason || '');
  return zr === 'observable_list' || zr === 'cidr_list' || zr === 'ioc_table';
}

/**
 * Semantic relation of one occurrence to the observable it contains, with the
 * marker that produced it.
 *
 * Rows (table / list / value-only / annotated indicator lines / ip:port) inside
 * an authoritative section are source assertions. Prose is read for its
 * relation in every zone: an authoritative zone is evidence, never proof — a
 * research firm named in a C2 section stays contextual, a "connects to" clause
 * in the same section is operational.
 *
 * @param {string} surroundingText
 * @param {{ form?: string, zone?: string, value?: string, original?: string, structuralRow?: boolean, blockType?: string|null, layout?: string|null, zoneReason?: string|null }} [opts]
 * @returns {{ relation: string, marker: 'excluded_zone'|'structural_row'|'operational'|'provider'|'contextual'|'none'|'empty', authoritative: boolean, structural_row: boolean }}
 */
export function classifySourceRelationDetail(surroundingText, opts = {}) {
  const zone = String(opts.zone || '');
  const authoritative = AUTHORITATIVE_ZONES.has(zone);
  const structuralRow = structuralRowOf({
    form: opts.form,
    block_type: opts.blockType,
    layout: opts.layout,
    zone_reason: opts.zoneReason,
    structural_row: opts.structuralRow
  });
  if (EXCLUDED_ZONES.has(zone)) {
    return { relation: SOURCE_RELATIONS.REFERENCE, marker: 'excluded_zone', authoritative: false, structural_row: structuralRow };
  }

  const form = String(opts.form || '');
  // Endpoint / typed-table forms assert an observable in any zone; other row
  // forms assert only where the publisher curates the list.
  if (form === 'ip_port' || form === 'table_row' || (authoritative && structuralRow)) {
    return { relation: SOURCE_RELATIONS.OPERATIONAL_MALICIOUS, marker: 'structural_row', authoritative, structural_row: true };
  }

  const focusValue = opts.value || opts.original || '';
  const surrounding = refangTextForExtraction(String(surroundingText || ''));
  const full = maskForeignNetworkTokens(maskObservable(surrounding, focusValue), focusValue);
  const text = maskForeignNetworkTokens(
    maskObservable(clauseContaining(surrounding, focusValue), focusValue),
    focusValue
  );
  if (!text.trim()) return { relation: SOURCE_RELATIONS.CONTEXTUAL, marker: 'empty', authoritative, structural_row: false };

  const operational = OPERATIONAL_RELATION_RE.test(text);
  const providerLocal = PROVIDER_RELATION_RE.test(text) || PROVIDER_CATALOGUE_RE.test(text);
  const providerCatalogue = PROVIDER_RELATION_RE.test(full) || PROVIDER_CATALOGUE_RE.test(full);
  const provider = providerLocal || (providerCatalogue && !operational);

  if (operational && !provider) {
    return { relation: SOURCE_RELATIONS.OPERATIONAL_MALICIOUS, marker: 'operational', authoritative, structural_row: false };
  }
  if (provider && !operational) {
    return { relation: SOURCE_RELATIONS.PROVIDER_SERVICE, marker: 'provider', authoritative, structural_row: false };
  }
  if (operational && provider) {
    if (/\b(?:as|is|were|was)\s+(?:a\s+)?(?:c2|c&c|command)/i.test(text)) {
      return { relation: SOURCE_RELATIONS.OPERATIONAL_MALICIOUS, marker: 'operational', authoritative, structural_row: false };
    }
    return { relation: SOURCE_RELATIONS.PROVIDER_SERVICE, marker: 'provider', authoritative, structural_row: false };
  }
  if (CONTEXT_RELATION_RE.test(text)) {
    return { relation: SOURCE_RELATIONS.CONTEXTUAL, marker: 'contextual', authoritative, structural_row: false };
  }
  return { relation: SOURCE_RELATIONS.CONTEXTUAL, marker: 'none', authoritative, structural_row: false };
}

/**
 * Semantic relation of one occurrence to the observable it contains.
 * @param {string} surroundingText
 * @param {{ form?: string, zone?: string, value?: string, original?: string }} [opts]
 */
export function classifySourceRelation(surroundingText, opts = {}) {
  return classifySourceRelationDetail(surroundingText, opts).relation;
}

/**
 * Occurrence kind from its structural reading and relation.
 * @param {{ form?: string, block_type?: string|null }} occ
 * @param {{ relation: string, marker: string, structural_row: boolean }} detail
 */
export function occurrenceKindFor(occ, detail) {
  if (detail.marker === 'excluded_zone') return OCCURRENCE_KINDS.REFERENCE;
  const form = String(occ.form || '');
  if (form === 'table_row') return OCCURRENCE_KINDS.TYPED_TABLE_ROW;
  if (form === 'ip_port') return OCCURRENCE_KINDS.ENDPOINT;
  if (detail.structural_row) {
    return String(occ.block_type || '') === 'list_item' || form === 'list_row'
      ? OCCURRENCE_KINDS.LIST_ITEM
      : OCCURRENCE_KINDS.STANDALONE_INDICATOR_ROW;
  }
  if (detail.relation === SOURCE_RELATIONS.OPERATIONAL_MALICIOUS) return OCCURRENCE_KINDS.NARRATIVE_ASSERTION;
  if (detail.marker === 'provider' || detail.marker === 'contextual') return OCCURRENCE_KINDS.NARRATIVE_CONTEXT;
  return OCCURRENCE_KINDS.NARRATIVE_MENTION;
}

/**
 * Strongest relation across occurrences of one candidate.
 * @param {object} candidate
 */
export function strongestSourceRelation(candidate) {
  const rank = {
    [SOURCE_RELATIONS.OPERATIONAL_MALICIOUS]: 4,
    [SOURCE_RELATIONS.PROVIDER_SERVICE]: 2,
    [SOURCE_RELATIONS.CONTEXTUAL]: 1,
    [SOURCE_RELATIONS.REFERENCE]: 0
  };
  let best = SOURCE_RELATIONS.CONTEXTUAL;
  const occ = Array.isArray(candidate.occurrences) ? candidate.occurrences : [];
  if (!occ.length) {
    return classifySourceRelation(candidate.evidence_text || '', {
      form: candidate.form,
      zone: candidate.zone,
      value: candidate.normalized_value,
      original: candidate.original_value
    });
  }
  for (const o of occ) {
    const rel = o.source_relation || relationDetailForOccurrence(candidate, o).relation;
    if ((rank[rel] || 0) > (rank[best] || 0)) best = rel;
  }
  return best;
}

/**
 * @param {object} candidate
 * @param {object} o occurrence
 */
function relationDetailForOccurrence(candidate, o) {
  return classifySourceRelationDetail(o.surrounding_text || '', {
    form: o.form,
    zone: o.zone || o.section_kind,
    value: candidate.normalized_value,
    original: o.original_value || candidate.original_value,
    structuralRow: o.structural_row === true || o.row_shape === true,
    blockType: o.block_type || null,
    layout: o.layout || null,
    zoneReason: o.zone_reason || null
  });
}

/**
 * Annotate each occurrence with source_relation, relation_marker and
 * occurrence_kind (mutates candidate).
 * @param {object} candidate
 */
export function attachOccurrenceRelations(candidate) {
  const occ = Array.isArray(candidate.occurrences) ? candidate.occurrences : [];
  for (const o of occ) {
    const detail = relationDetailForOccurrence(candidate, o);
    o.source_relation = detail.relation;
    o.relation_marker = detail.marker;
    o.occurrence_kind = occurrenceKindFor(o, detail);
    // Source assertion = publisher-curated section AND (row placement OR an
    // operational clause). Zone alone is never an assertion.
    o.asserted = detail.authoritative && (detail.structural_row || detail.relation === SOURCE_RELATIONS.OPERATIONAL_MALICIOUS);
  }
  candidate.source_relation = strongestSourceRelation(candidate);
  return candidate;
}

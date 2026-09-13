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

import { collapseLetterSpacing } from './pdfLayout.js';
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
 * Classify a heading's section role. Returns null when the heading does not
 * declare an indicator, reference or sample section (narrative / unknown).
 * @param {string} text
 * @returns {string|null}
 */
export function classifySectionRole(text) {
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
  /\b(?:c2|c&c|c\s*&\s*c|command\s*(?:and|&)\s*control|beacon(?:s|ing)?|connects?\s+to|communicat(?:es|ed|ing)\s+with|callback|payload|downloads?\s+(?:hxxps?:\/\/|https?:\/\/|from|OBSERVABLE)|downloaded?\s+from|fetch(?:es|ed)?\s+from|drops?\s+from|phish(?:ing)?|malware\s+(?:connects?|beacons?|talks?)|attacker[- ]controlled|malicious\s+(?:server|host|domain|url|ip|infrastructure)|hard-?coded)\b|回连|远控|木马连接|命令控制|komuta/i;

const PROVIDER_RELATION_RE =
  /\b(?:purchased?|bought|rented?|leased?|registered?\s+(?:via|through|with|at)|subscri(?:bed|be)|procur(?:ed|e)|to\s+purchase|to\s+host|services?\s+such\s+as|infrastructure\s+provider|cloud\s+provider|hosting\s+provider|vps\s+provider|vpn\s+provider|used\s+(?:the\s+)?(?:commercial\s+)?(?:services?|providers?|vendors?|platforms?|vpn|vps|proxy|cloud(?:\s+provider)?)|from\s+(?:a\s+)?(?:vps|vpn|proxy|hosting|cloud)\s+(?:provider|vendor|service)|commercial\s+vpn)\b|satın\s+al|satın\s+ald|购买|租用|注册于/i;

const PROVIDER_CATALOGUE_RE =
  /\b(?:likely\s+to\s+purchase|to\s+obtain\s+(?:infrastructure|services?|prox(?:y|ies)|vps|vpn)|used\s+\w[\w.-]*\s+(?:to\s+purchase|for\s+(?:infrastructure|hosting|prox(?:y|ies)|vps)))\b/i;

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
 * Semantic relation of one occurrence to the observable it contains.
 * @param {string} surroundingText
 * @param {{ form?: string, zone?: string, value?: string, original?: string }} [opts]
 */
export function classifySourceRelation(surroundingText, opts = {}) {
  const zone = String(opts.zone || '');
  if (EXCLUDED_ZONES.has(zone)) return SOURCE_RELATIONS.REFERENCE;
  if (AUTHORITATIVE_ZONES.has(zone)) return SOURCE_RELATIONS.OPERATIONAL_MALICIOUS;

  const form = String(opts.form || '');
  if (form === 'ip_port' || form === 'table_row') return SOURCE_RELATIONS.OPERATIONAL_MALICIOUS;

  const focusValue = opts.value || opts.original || '';
  const surrounding = refangTextForExtraction(String(surroundingText || ''));
  const full = maskForeignNetworkTokens(maskObservable(surrounding, focusValue), focusValue);
  const text = maskForeignNetworkTokens(
    maskObservable(clauseContaining(surrounding, focusValue), focusValue),
    focusValue
  );
  if (!text.trim()) return SOURCE_RELATIONS.CONTEXTUAL;

  const operational = OPERATIONAL_RELATION_RE.test(text);
  const providerLocal = PROVIDER_RELATION_RE.test(text) || PROVIDER_CATALOGUE_RE.test(text);
  const providerCatalogue = PROVIDER_RELATION_RE.test(full) || PROVIDER_CATALOGUE_RE.test(full);
  const provider = providerLocal || (providerCatalogue && !operational);

  if (operational && !provider) return SOURCE_RELATIONS.OPERATIONAL_MALICIOUS;
  if (provider && !operational) return SOURCE_RELATIONS.PROVIDER_SERVICE;
  if (operational && provider) {
    if (/\b(?:as|is|were|was)\s+(?:a\s+)?(?:c2|c&c|command)/i.test(text)) {
      return SOURCE_RELATIONS.OPERATIONAL_MALICIOUS;
    }
    return SOURCE_RELATIONS.PROVIDER_SERVICE;
  }
  return SOURCE_RELATIONS.CONTEXTUAL;
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
    const rel = o.source_relation || classifySourceRelation(o.surrounding_text || '', {
      form: o.form,
      zone: o.zone || o.section_kind,
      value: candidate.normalized_value,
      original: o.original_value || candidate.original_value
    });
    if ((rank[rel] || 0) > (rank[best] || 0)) best = rel;
  }
  return best;
}

/**
 * Annotate each occurrence with source_relation (mutates candidate).
 * @param {object} candidate
 */
export function attachOccurrenceRelations(candidate) {
  const occ = Array.isArray(candidate.occurrences) ? candidate.occurrences : [];
  for (const o of occ) {
    o.source_relation = classifySourceRelation(o.surrounding_text || '', {
      form: o.form,
      zone: o.zone || o.section_kind,
      value: candidate.normalized_value,
      original: candidate.original_value
    });
  }
  candidate.source_relation = strongestSourceRelation(candidate);
  return candidate;
}

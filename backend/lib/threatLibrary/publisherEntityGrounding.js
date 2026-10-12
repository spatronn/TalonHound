/**
 * Publisher-entity grounding for model-written report intelligence.
 *
 * A model reading a vendor blog may promote the publisher's own name to a
 * threat role: report 18651 (hatching.io) got a "Hatching" campaign entity,
 * described as an "Automated malware analysis solutions campaign" (the site's
 * og:title) and repeated in the summary, although the article never names a
 * campaign. A publisher / vendor name is not a campaign or a threat actor.
 *
 * This deterministic gate, applied to every model result before persistence
 * and re-applied by Refresh extraction to stored results:
 *   1. A campaign / threat_actor entity whose name is the publisher identity
 *      (registrable host label of the source URL or source name, or a site
 *      name the page declares) is dropped, with the relationships that use it,
 *      unless the source body itself states that threat role: "the X campaign",
 *      "Operation X", "a group tracked as X", and so on.
 *   2. Summary clauses that attach the dropped name to a threat role
 *      ("associated with the 'X' campaign", "part of the X operation",
 *      "by the X group") are removed. Other mentions of the publisher stay.
 * Every other entity, including legitimate campaigns and actors named in the
 * source, is untouched. Subtractive only; the shared threat_entities row is
 * never deleted (callers unlink it from one report). No model call and no
 * `./ai/*` import (Refresh extraction reuses it).
 */

import { hostBrandLabel } from './extract/titleSelection.js';

export const PUBLISHER_ENTITY_GROUNDING_VERSION = 'tl-publisher-entity-v1';

const THREAT_ROLE_TYPES = new Set(['campaign', 'threat_actor']);
const ROLE_NOUNS = 'campaign|campaigns|operation|threat\\s+actor|actor|group|apt|gang|cluster|intrusion\\s+set|crew|activity\\s+cluster';
const NAMING_VERBS = 'dubbed|named|called|known\\s+as|tracked\\s+as|designated';
const QUOTE = `["'\\u2018\\u2019\\u201c\\u201d]?`;
/** Corporate / generic suffixes a publisher name may carry ("Hatching International B.V."). */
const ORG_SUFFIX_RE = /\s+(?:international|labs?|research|security|team|inc\.?|ltd\.?|llc|gmbh|b\.?v\.?|corp(?:oration)?\.?|co\.?)$/i;

function norm(text) {
  return String(text || '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, '');
}

function escapeRe(text) {
  return String(text || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stripOrgSuffixes(name) {
  let out = String(name || '').trim();
  for (let i = 0; i < 3; i += 1) {
    const next = out.replace(ORG_SUFFIX_RE, '').trim();
    if (next === out) break;
    out = next;
  }
  return out;
}

/**
 * Normalized names that identify the report's publisher.
 * @param {{ source_url?: string|null, source_name?: string|null }} report
 * @param {{ meta?: { site_names?: string[] } }|null} document
 */
export function publisherIdentity(report, document) {
  const keys = new Set();
  const add = (value) => {
    const k = norm(stripOrgSuffixes(value));
    if (k.length >= 3) keys.add(k);
  };
  if (report?.source_url) add(hostBrandLabel(report.source_url));
  if (report?.source_name) {
    const name = String(report.source_name);
    add(/\.[a-z]{2,}$/i.test(name) && !/\s/.test(name) ? hostBrandLabel(`https://${name}`) : name);
  }
  for (const site of Array.isArray(document?.meta?.site_names) ? document.meta.site_names : []) add(site);
  return keys;
}

function bodyText(document) {
  return (Array.isArray(document?.blocks) ? document.blocks : [])
    .map((b) => {
      const cells = Array.isArray(b?.rows) ? b.rows.flat().join(' ') : '';
      return `${b?.text || ''} ${cells}`;
    })
    .join('\n');
}

/**
 * Does the source body state a threat role for this name?
 * @param {string} name
 * @param {string} text
 */
export function sourceStatesThreatRole(name, text) {
  const n = escapeRe(String(name || '').trim());
  if (!n) return false;
  const patterns = [
    new RegExp(`${QUOTE}\\b${n}\\b${QUOTE}\\s+(?:${ROLE_NOUNS})\\b`, 'i'),
    new RegExp(`\\b(?:${ROLE_NOUNS})\\s+(?:(?:is|was|are|were)\\s+)?(?:${NAMING_VERBS})\\s+${QUOTE}\\b${n}\\b`, 'i'),
    new RegExp(`\\boperation\\s+${QUOTE}\\b${n}\\b`, 'i')
  ];
  return patterns.some((re) => re.test(String(text || '')));
}

/**
 * Entities whose name is the publisher identity in a threat role the source
 * never states.
 * @param {Array<{ name?: string, entity_type?: string }>} entities
 * @param {{ report: object, document: object }} ctx
 */
export function unsupportedPublisherEntities(entities, { report, document }) {
  const identity = publisherIdentity(report, document);
  if (!identity.size) return [];
  const text = bodyText(document);
  return (entities || []).filter((e) => {
    if (!THREAT_ROLE_TYPES.has(String(e?.entity_type || '').toLowerCase())) return false;
    const key = norm(stripOrgSuffixes(e?.name));
    if (!key || !identity.has(key)) return false;
    return !sourceStatesThreatRole(e.name, text);
  });
}

/**
 * Remove summary clauses that attach a dropped name to a threat role.
 * @param {string|null|undefined} summary
 * @param {string[]} names
 * @returns {{ summary: string|null, changed: boolean, unresolved: string[] }}
 */
export function groundSummaryPublisherEntities(summary, names) {
  if (summary == null || !names.length) return { summary: summary ?? null, changed: false, unresolved: [] };
  let out = String(summary);
  const unresolved = [];
  for (const name of names) {
    const n = escapeRe(String(name).trim());
    const ref = `(?:the\\s+)?${QUOTE}${n}${QUOTE}`;
    const role = `(?:\\s+(?:${ROLE_NOUNS}))`;
    const clauses = [
      new RegExp(`,?\\s*(?:which\\s+(?:is|was)\\s+|that\\s+(?:is|was)\\s+|and\\s+(?:is\\s+|was\\s+)?)?(?:associated|linked|attributed|tied|connected|related)\\s+(?:with|to)\\s+${ref}${role}?(?=[\\s,.;:)]|$)`, 'gi'),
      new RegExp(`,?\\s*(?:as\\s+)?(?:a\\s+)?part\\s+of\\s+${ref}${role}(?=[\\s,.;:)]|$)`, 'gi'),
      new RegExp(`,?\\s*(?:by|from)\\s+${ref}\\s+(?:threat\\s+actor|actor|group|apt|gang|crew)(?=[\\s,.;:)]|$)`, 'gi')
    ];
    for (const re of clauses) out = out.replace(re, '');
    if (new RegExp(`${QUOTE}\\b${n}\\b${QUOTE}${role}`, 'i').test(out)) unresolved.push(name);
  }
  out = out.replace(/\s{2,}/g, ' ').replace(/\s+([.,;:])/g, '$1').replace(/,\./g, '.').trim();
  return { summary: out, changed: out !== String(summary), unresolved };
}

/**
 * Ground a model result (pipeline: before persistence). Returns a new value.
 * @param {{ summary?: string, entities?: object[], relationships?: object[] }|null|undefined} aiValue
 * @param {{ report: object, document: object }} ctx
 */
export function groundAiPublisherEntities(aiValue, ctx) {
  const diagnostics = {
    version: PUBLISHER_ENTITY_GROUNDING_VERSION,
    entities_removed: [],
    relationships_removed: 0,
    summary_changed: false,
    summary_unresolved: []
  };
  if (!aiValue || typeof aiValue !== 'object') return { value: aiValue, diagnostics };
  const entities = Array.isArray(aiValue.entities) ? aiValue.entities : [];
  const dropped = unsupportedPublisherEntities(entities, ctx);
  if (!dropped.length) return { value: aiValue, diagnostics };

  const droppedNames = new Set(dropped.map((e) => String(e.name)));
  diagnostics.entities_removed = dropped.map((e) => ({ name: e.name, entity_type: e.entity_type }));
  const relationships = (Array.isArray(aiValue.relationships) ? aiValue.relationships : []).filter((r) => {
    const uses = droppedNames.has(String(r?.subject_ref)) || droppedNames.has(String(r?.object_ref));
    if (uses) diagnostics.relationships_removed += 1;
    return !uses;
  });
  const summary = groundSummaryPublisherEntities(aiValue.summary, [...droppedNames]);
  diagnostics.summary_changed = summary.changed;
  diagnostics.summary_unresolved = summary.unresolved;
  return {
    value: {
      ...aiValue,
      entities: entities.filter((e) => !droppedNames.has(String(e.name))),
      ...(Array.isArray(aiValue.relationships) ? { relationships } : {}),
      ...(aiValue.summary != null ? { summary: summary.summary } : {})
    },
    diagnostics
  };
}

/**
 * Stored-result variant for Refresh extraction. Pure; the caller writes.
 * @param {{ summary?: string|null, entities?: Array<{ entity_id: number|string, name: string, entity_type: string }> }} stored
 * @param {{ report: object, document: object }} ctx
 */
export function groundStoredPublisherEntities(stored, ctx) {
  const dropped = unsupportedPublisherEntities(stored?.entities || [], ctx);
  const summary = groundSummaryPublisherEntities(stored?.summary ?? null, dropped.map((e) => String(e.name)));
  return {
    summary: summary.summary,
    summary_changed: summary.changed,
    summary_unresolved: summary.unresolved,
    entity_ids_removed: dropped.map((e) => e.entity_id),
    entities_removed: dropped.map((e) => ({ entity_id: e.entity_id, name: e.name, entity_type: e.entity_type }))
  };
}

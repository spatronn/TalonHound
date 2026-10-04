/**
 * Report-level AI intelligence: report tags.
 *
 * A report tag is a short, reusable label for what the report is primarily
 * about (kind of operation, targeted sector/region, exploited technology,
 * defining technique). Named actors / malware / campaigns / tools are
 * entities, threat categories retired from the catalog live in Threat
 * Classifications, and a concept the report text never discusses is dropped.
 *
 * Tags reuse the global `tags` catalog and `threat_report_tags` links.
 * Persistence is additive and idempotent: re-analysis never removes analyst
 * (or prior AI) tags.
 *
 * Automatic MITRE ATT&CK mapping was removed after quality evaluation
 * (semantic-v8). Historical threat_report_mitre_mappings rows are retained
 * but nothing here reads or writes them.
 */

import {
  normalizeTagName,
  normalizeTagSlug,
  parseNormalizedTagName
} from '../tagHelpers.js';
import { ensureCatalogTag } from '../tagCatalogService.js';
import { addReportTag } from './reportTags.js';

/** Report tags linked by one analysis (accepted = enabled catalog tags). */
export const REPORT_TAG_MAX = 5;
/**
 * Ranked suggestions carried from the chunk merge to persistence. A suggestion
 * that resolves to a disabled catalog tag (e.g. a category retired into Threat
 * Classifications) must not cost one of the REPORT_TAG_MAX slots.
 */
export const REPORT_TAG_CANDIDATE_MAX = 10;
export const REPORT_TAG_NAME_MAX = 40;

/** Generic words that add no report-level discrimination. */
export const FILLER_REPORT_TAGS = Object.freeze(new Set([
  'security',
  'cyber',
  'cybersecurity',
  'malicious',
  'threat',
  'attack',
  'report',
  'research',
  'article',
  'blog',
  'analysis',
  'malware',
  'ioc',
  'indicator',
  'indicators',
  'compromise',
  'general',
  'unknown',
  'information',
  'data'
]));

const HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const URL_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
const CVE_RE = /^cve[- ]\d{4}[- ]\d{4,}$/i;
const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/**
 * Collapse hyphen/underscore variants to the catalog name form so
 * "credential-theft" and "Credential Theft" resolve to one lookup key.
 * Does not change global tag uniqueness — only AI suggestion resolution.
 */
export function canonicalizeAiTagName(raw) {
  const collapsed = String(raw || '').trim().replace(/[-_]+/g, ' ');
  return parseNormalizedTagName(collapsed);
}

export function isFillerReportTag(name) {
  return FILLER_REPORT_TAGS.has(normalizeTagName(name));
}

export function isIocLikeTag(name) {
  const s = String(name || '').trim();
  if (!s) return true;
  if (HASH_RE.test(s)) return true;
  if (URL_RE.test(s)) return true;
  if (CVE_RE.test(s)) return true;
  if (IP_RE.test(s)) return true;
  if (s.includes('/') || s.includes('\\')) return true;
  return false;
}

/**
 * Filter/normalize one AI tag string. Returns { ok, name, reason }.
 */
export function sanitizeAiTag(raw) {
  if (raw == null) return { ok: false, reason: 'empty' };
  if (typeof raw !== 'string') return { ok: false, reason: 'malformed' };
  const trimmed = raw.trim();
  if (!trimmed) return { ok: false, reason: 'empty' };
  // Check the original token first — hyphen collapse would hide CVE/hash forms.
  if (isIocLikeTag(trimmed)) return { ok: false, reason: 'ioc_like' };
  const parsed = canonicalizeAiTagName(trimmed);
  if (!parsed.ok) return { ok: false, reason: parsed.error };
  if (parsed.name.length > REPORT_TAG_NAME_MAX) return { ok: false, reason: 'too_long' };
  if (isFillerReportTag(parsed.name)) return { ok: false, reason: 'filler' };
  if (isIocLikeTag(parsed.name)) return { ok: false, reason: 'ioc_like' };
  return { ok: true, name: parsed.name };
}

/** Function words ignored when checking that a tag is grounded in the report. */
const TAG_GROUNDING_STOPWORDS = new Set(['a', 'an', 'and', 'as', 'at', 'by', 'for', 'from', 'in', 'of', 'off', 'on', 'or', 'the', 'to', 'via', 'with']);

function lexicalTokens(text) {
  return String(text || '').toLowerCase().match(/[\p{L}\p{N}]+/gu) || [];
}

function commonPrefixLength(a, b) {
  const n = Math.min(a.length, b.length);
  let i = 0;
  while (i < n && a[i] === b[i]) i += 1;
  return i;
}

/**
 * Lexical support index over a canonical document (title + every block).
 * Grounding only applies to English / Latin-script text: a model may name a
 * concept of a non-English report in English, which a lexical check cannot
 * verify, so those reports skip the gate (`applies: false`).
 * @param {{ title?: string, language?: string|null, blocks?: Array<{ text?: string }> }|null|undefined} document
 */
export function buildReportTagSupport(document) {
  const parts = [document?.title, ...(document?.blocks || []).map((b) => b?.text)];
  const text = parts.filter(Boolean).join('\n');
  const tokens = lexicalTokens(text);
  if (!tokens.length) return { applies: false, words: new Set(), compact: '' };
  const lang = String(document?.language || '').trim().toLowerCase();
  let applies;
  if (lang) {
    applies = lang === 'en' || lang.startsWith('en-');
  } else {
    const letters = text.match(/\p{L}/gu) || [];
    const latin = letters.filter((ch) => /[a-z]/i.test(ch)).length;
    applies = letters.length > 0 && latin / letters.length >= 0.95;
  }
  return { applies, words: new Set(tokens), compact: tokens.join('') };
}

function tokenSupported(token, words) {
  if (words.has(token)) return true;
  if (token.length < 4) return false;
  // Inflection tolerance only (exploit/exploitation, telecom/telecommunications):
  // a shared prefix of min(6, both lengths) characters, never a synonym.
  for (const w of words) {
    if (w.length < 4) continue;
    if (commonPrefixLength(token, w) >= Math.min(6, token.length, w.length)) return true;
  }
  return false;
}

/**
 * True when every content word of the tag occurs in the report text (or the
 * tag, without separators, occurs as written, e.g. "office365"/"Office 365").
 * A tag the report never discusses (copied from instructions or from general
 * knowledge) is not report context.
 * @param {string} name normalized tag name
 * @param {ReturnType<typeof buildReportTagSupport>|null|undefined} support
 */
export function isReportTagSupported(name, support) {
  if (!support?.applies) return true;
  const tokens = lexicalTokens(name);
  const content = tokens.filter((t) => !TAG_GROUNDING_STOPWORDS.has(t));
  if (!content.length) return false;
  if (content.every((t) => tokenSupported(t, support.words))) return true;
  const joined = tokens.join('');
  return joined.length >= 5 && support.compact.includes(joined);
}

/** Entity types whose names are entities, never report tags. */
export const NAMED_ENTITY_TYPES_NOT_TAGS = Object.freeze(new Set(['threat_actor', 'malware', 'campaign', 'tool']));

/**
 * Tag-normalized names + aliases of named entities (actor / malware /
 * campaign / tool) from the analysis. Products, organizations, sectors and
 * vulnerabilities are not in this set.
 * @param {Array<{ entity_type?: string, name?: string, aliases?: string[] }>} entities
 * @returns {Set<string>}
 */
export function namedEntityTagKeys(entities) {
  const keys = new Set();
  for (const e of entities || []) {
    if (!NAMED_ENTITY_TYPES_NOT_TAGS.has(String(e?.entity_type || ''))) continue;
    for (const n of [e.name, ...(Array.isArray(e.aliases) ? e.aliases : [])]) {
      const parsed = canonicalizeAiTagName(n);
      if (parsed.ok) keys.add(parsed.name);
    }
  }
  return keys;
}

/**
 * Merge chunk tag arrays: normalize, drop junk and tags the report text does
 * not support, unique, rank. Frequency across chunks (a theme several parts of
 * the report carry) then first-seen order (the model lists the most
 * representative first, and chunk 1 holds the title / lead / key findings).
 * Returns up to REPORT_TAG_CANDIDATE_MAX ranked names; persistence links at
 * most REPORT_TAG_MAX of them.
 * @param {Array<string[]|undefined>} tagLists
 * @param {{ support?: ReturnType<typeof buildReportTagSupport>|null, entityNames?: Set<string>|null }} [opts]
 *   entityNames: namedEntityTagKeys() of the same analysis (exact-name match only)
 */
export function mergeReportTags(tagLists, opts = {}) {
  const counts = new Map();
  const first = [];
  const rejected = [];
  for (const list of tagLists || []) {
    if (!Array.isArray(list)) continue;
    for (const raw of list) {
      const s = sanitizeAiTag(raw);
      if (!s.ok) {
        rejected.push({ value: raw, reason: s.reason });
        continue;
      }
      if (opts.entityNames?.has(s.name)) {
        rejected.push({ value: raw, reason: 'entity_name' });
        continue;
      }
      if (!isReportTagSupported(s.name, opts.support)) {
        rejected.push({ value: raw, reason: 'unsupported' });
        continue;
      }
      if (!counts.has(s.name)) {
        counts.set(s.name, 0);
        first.push(s.name);
      }
      counts.set(s.name, counts.get(s.name) + 1);
    }
  }
  const ranked = [...first].sort((a, b) => {
    const d = counts.get(b) - counts.get(a);
    return d !== 0 ? d : first.indexOf(a) - first.indexOf(b);
  });
  return {
    tags: ranked.slice(0, REPORT_TAG_CANDIDATE_MAX),
    rejected,
    proposed: first.length
  };
}

export async function findCatalogTagByNameOrSlug(db, name) {
  const parsed = parseNormalizedTagName(name);
  if (!parsed.ok) return null;
  const slug = normalizeTagSlug(parsed.name);
  const { rows } = await db.query(
    `SELECT id, name, slug, type, category, enabled, created_origin
     FROM tags WHERE name = $1 OR slug = $2
     LIMIT 1`,
    [parsed.name, slug || parsed.name]
  );
  return rows[0] || null;
}

/**
 * Additive tag apply over a ranked suggestion list: reuse catalog rows, create
 * when missing, link once, stop after REPORT_TAG_MAX accepted tags. A disabled
 * catalog tag is skipped without using a slot. Never unlinks existing report
 * tags (analyst-added tags are never touched).
 */
export async function persistAiReportTags(db, reportId, tagNames) {
  const stats = {
    proposed: (tagNames || []).length,
    accepted: 0,
    reused: 0,
    created: 0,
    linked: 0,
    already_linked: 0,
    rejected: []
  };
  const acceptedIds = new Set();
  for (const raw of tagNames || []) {
    if (acceptedIds.size >= REPORT_TAG_MAX) {
      stats.rejected.push({ value: raw, reason: 'over_limit' });
      continue;
    }
    const s = sanitizeAiTag(raw);
    if (!s.ok) {
      stats.rejected.push({ value: raw, reason: s.reason });
      continue;
    }
    let existing = await findCatalogTagByNameOrSlug(db, s.name);
    let created = false;
    if (!existing) {
      try {
        const ensured = await ensureCatalogTag(db, { name: s.name, category: 'custom' });
        existing = ensured.tag;
        created = Boolean(ensured.created);
      } catch (err) {
        if (err?.code === '23505') {
          existing = await findCatalogTagByNameOrSlug(db, s.name);
        } else {
          stats.rejected.push({ value: s.name, reason: 'tag_create_failed' });
          continue;
        }
      }
    }
    if (!existing?.id) {
      stats.rejected.push({ value: s.name, reason: 'tag_unresolved' });
      continue;
    }
    if (existing.enabled === false) {
      stats.rejected.push({ value: s.name, reason: 'tag_disabled' });
      continue;
    }
    acceptedIds.add(Number(existing.id));
    if (created) stats.created += 1;
    else stats.reused += 1;
    const linked = await addReportTag(db, reportId, existing.id);
    if (linked) stats.linked += 1;
    else stats.already_linked += 1;
    stats.accepted += 1;
  }
  return stats;
}

/**
 * Full post-merge persist. Item failures never throw to the caller — the
 * pipeline treats this as optional enrichment.
 */
export async function persistReportIntelligence(db, reportId, aiValue, { log } = {}) {
  const diagnostics = {
    tags_proposed: 0,
    tags_accepted: 0,
    tags_reused: 0,
    tags_created: 0,
    tags_rejected: []
  };
  try {
    const tagStats = await persistAiReportTags(db, reportId, aiValue?.report_tags || []);
    diagnostics.tags_proposed = tagStats.proposed;
    diagnostics.tags_accepted = tagStats.accepted;
    diagnostics.tags_reused = tagStats.reused;
    diagnostics.tags_created = tagStats.created;
    diagnostics.tags_rejected = tagStats.rejected;
    diagnostics.tags_linked = tagStats.linked;
    diagnostics.tags_already_linked = tagStats.already_linked;
  } catch (err) {
    diagnostics.tags_error = err?.message || 'tag persist failed';
    log?.warn?.('report tag enrichment failed (non-fatal)', { reportId, error: err?.message });
  }

  log?.info?.('report intelligence persisted', {
    reportId,
    tags_proposed: diagnostics.tags_proposed,
    tags_accepted: diagnostics.tags_accepted,
    tags_reused: diagnostics.tags_reused,
    tags_created: diagnostics.tags_created,
    tags_rejected: diagnostics.tags_rejected?.length || 0
  });
  return diagnostics;
}

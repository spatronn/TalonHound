/**
 * Report-level AI intelligence: report tags.
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

export const REPORT_TAG_MAX = 5;
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

/**
 * Merge chunk tag arrays: normalize, drop junk, unique, cap at REPORT_TAG_MAX.
 * Frequency then first-seen order when more than the cap survive.
 * @param {Array<string[]|undefined>} tagLists
 */
export function mergeReportTags(tagLists) {
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
    tags: ranked.slice(0, REPORT_TAG_MAX),
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
 * Additive tag apply: reuse catalog rows, create when missing, link once.
 * Never unlinks existing report tags.
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
  for (const raw of tagNames || []) {
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

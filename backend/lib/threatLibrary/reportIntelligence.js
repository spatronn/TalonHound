/**
 * Report-level AI intelligence: tags + MITRE ATT&CK mappings.
 *
 * Tags reuse the global `tags` catalog and `threat_report_tags` links.
 * MITRE IDs are validated against the bundled ATT&CK catalog; names/tactics
 * are always resolved from that catalog, never from the model.
 *
 * Persistence is additive and idempotent: re-analysis never removes analyst
 * (or prior AI) tags/mappings.
 */

import {
  normalizeTagName,
  normalizeTagSlug,
  parseNormalizedTagName
} from '../tagHelpers.js';
import { ensureCatalogTag } from '../tagCatalogService.js';
import { addReportTag } from './reportTags.js';
import {
  loadMitreReference,
  normalizeMitreAttackId,
  resolveCanonicalTechnique
} from '../threatClassifications/mitreReference.js';

export const REPORT_TAG_MAX = 5;
export const REPORT_TAG_NAME_MAX = 40;
export const MITRE_ACCEPT_MIN_CONFIDENCE = 0.75;
export const MITRE_EVIDENCE_MAX = 240;
export const MITRE_MAX_MAPPINGS = 16;

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

export function normalizeMitreEvidence(raw) {
  const s = String(raw || '').replace(/\s+/g, ' ').trim();
  if (!s) return '';
  return s.length > MITRE_EVIDENCE_MAX ? s.slice(0, MITRE_EVIDENCE_MAX) : s;
}

export function parentTechniqueId(techniqueId) {
  const id = normalizeMitreAttackId(techniqueId);
  if (!id || !id.includes('.')) return null;
  return id.split('.')[0];
}

/**
 * Collapse duplicate technique IDs across chunks. Highest confidence wins;
 * evidence is taken from that same row (never concatenated).
 */
export function mergeMitreProposals(lists) {
  const byId = new Map();
  const rejected = [];
  let proposed = 0;
  for (const list of lists || []) {
    if (!Array.isArray(list)) continue;
    for (const raw of list) {
      proposed += 1;
      const item = coerceMitreItem(raw);
      if (!item.ok) {
        rejected.push({ value: raw, reason: item.reason });
        continue;
      }
      const prev = byId.get(item.technique_id);
      if (!prev || item.confidence > prev.confidence) {
        byId.set(item.technique_id, item);
      } else if (item.confidence === prev.confidence && item.evidence.length > prev.evidence.length) {
        byId.set(item.technique_id, { ...prev, evidence: item.evidence });
      }
    }
  }
  return { byId, rejected, proposed };
}

function coerceMitreItem(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, reason: 'malformed' };
  }
  const id = normalizeMitreAttackId(raw.technique_id || raw.attack_id || raw.id);
  if (!id) return { ok: false, reason: 'malformed_id' };
  if (id.startsWith('TA')) return { ok: false, reason: 'tactic_not_technique' };
  const evidence = normalizeMitreEvidence(raw.evidence || raw.evidence_text);
  let confidence = raw.confidence;
  if (confidence == null || confidence === '') confidence = 0;
  const n = Number(confidence);
  if (!Number.isFinite(n)) return { ok: false, reason: 'malformed_confidence' };
  return {
    ok: true,
    technique_id: id,
    evidence,
    confidence: Math.max(0, Math.min(1, n))
  };
}

/**
 * Validate merged proposals against the canonical catalog.
 * Parent technique is dropped when a child sub-technique is also accepted.
 */
export function validateMitreMappings(proposals, reference) {
  const accepted = [];
  const rejected = [];
  const byId = proposals instanceof Map ? proposals : proposals?.byId;
  const entries = byId instanceof Map ? [...byId.values()] : [];

  for (const item of entries) {
    if (!item.evidence) {
      rejected.push({ technique_id: item.technique_id, reason: 'missing_evidence' });
      continue;
    }
    if (item.confidence < MITRE_ACCEPT_MIN_CONFIDENCE) {
      rejected.push({ technique_id: item.technique_id, reason: 'low_confidence', confidence: item.confidence });
      continue;
    }
    const canonical = resolveCanonicalTechnique(reference, item.technique_id);
    if (!canonical) {
      rejected.push({
        technique_id: item.technique_id,
        reason: lookupReason(reference, item.technique_id)
      });
      continue;
    }
    accepted.push({
      ...canonical,
      confidence: item.confidence,
      evidence: item.evidence
    });
  }

  const acceptedIds = new Set(accepted.map((m) => m.technique_id));
  const kept = [];
  for (const m of accepted) {
    if (!m.technique_id.includes('.')) {
      const hasChild = [...acceptedIds].some((id) => id.startsWith(`${m.technique_id}.`));
      if (hasChild) {
        rejected.push({ technique_id: m.technique_id, reason: 'superseded_by_subtechnique' });
        continue;
      }
    }
    kept.push(m);
  }

  kept.sort((a, b) => a.technique_id.localeCompare(b.technique_id, 'en'));
  return { accepted: kept.slice(0, MITRE_MAX_MAPPINGS), rejected };
}

function lookupReason(reference, id) {
  if (!reference) return 'catalog_unavailable';
  if (!normalizeMitreAttackId(id)) return 'malformed_id';
  return 'unknown_id';
}

/**
 * Merge tags + MITRE from validated chunk (or synthesis) payloads.
 */
export function mergeReportIntelligence(parts) {
  const tagMerge = mergeReportTags((parts || []).map((p) => p?.report_tags));
  const mitreMerge = mergeMitreProposals((parts || []).map((p) => p?.mitre_attack));
  return {
    report_tags: tagMerge.tags,
    mitre_proposals: mitreMerge.byId,
    diagnostics: {
      tags_proposed_unique: tagMerge.proposed,
      tags_rejected: tagMerge.rejected,
      mitre_proposed: mitreMerge.proposed,
      mitre_merge_rejected: mitreMerge.rejected
    }
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

export async function persistAiReportMitre(db, reportId, mappings) {
  const stats = { proposed: (mappings || []).length, accepted: 0, upserted: 0 };
  for (const m of mappings || []) {
    const { rowCount } = await db.query(
      `INSERT INTO threat_report_mitre_mappings (
         report_id, attack_id, confidence, evidence_text
       ) VALUES ($1, $2, $3, $4)
       ON CONFLICT (report_id, attack_id) DO UPDATE SET
         confidence = GREATEST(
           COALESCE(threat_report_mitre_mappings.confidence, 0),
           COALESCE(EXCLUDED.confidence, 0)
         ),
         evidence_text = CASE
           WHEN COALESCE(EXCLUDED.confidence, 0) > COALESCE(threat_report_mitre_mappings.confidence, 0)
             THEN EXCLUDED.evidence_text
           WHEN COALESCE(EXCLUDED.confidence, 0) = COALESCE(threat_report_mitre_mappings.confidence, 0)
             AND length(COALESCE(EXCLUDED.evidence_text, '')) > length(COALESCE(threat_report_mitre_mappings.evidence_text, ''))
             THEN EXCLUDED.evidence_text
           ELSE threat_report_mitre_mappings.evidence_text
         END,
         updated_at = NOW()`,
      [reportId, m.technique_id, m.confidence, m.evidence]
    );
    stats.upserted += rowCount > 0 ? 1 : 0;
    stats.accepted += 1;
  }
  return stats;
}

/**
 * Full post-merge persist. Catalog load / item failures never throw to the
 * caller — the pipeline treats this as optional enrichment.
 */
export async function persistReportIntelligence(db, reportId, aiValue, { log, reference } = {}) {
  const diagnostics = {
    tags_proposed: 0,
    tags_accepted: 0,
    tags_reused: 0,
    tags_created: 0,
    tags_rejected: [],
    mitre_proposed: 0,
    mitre_accepted: 0,
    mitre_rejected: []
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

  try {
    const catalog = reference || await loadMitreReference();
    const merged = mergeMitreProposals([aiValue?.mitre_attack]);
    const validated = validateMitreMappings(merged, catalog);
    diagnostics.mitre_proposed = merged.proposed;
    diagnostics.mitre_rejected = [...merged.rejected, ...validated.rejected];
    const mitreStats = await persistAiReportMitre(db, reportId, validated.accepted);
    diagnostics.mitre_accepted = mitreStats.accepted;
  } catch (err) {
    diagnostics.mitre_error = err?.message || 'mitre persist failed';
    log?.warn?.('report MITRE enrichment failed (non-fatal)', { reportId, error: err?.message });
  }

  log?.info?.('report intelligence persisted', {
    reportId,
    tags_proposed: diagnostics.tags_proposed,
    tags_accepted: diagnostics.tags_accepted,
    tags_reused: diagnostics.tags_reused,
    tags_created: diagnostics.tags_created,
    tags_rejected: diagnostics.tags_rejected?.length || 0,
    mitre_proposed: diagnostics.mitre_proposed,
    mitre_accepted: diagnostics.mitre_accepted,
    mitre_rejected: diagnostics.mitre_rejected?.length || 0,
    unknown_ids: (diagnostics.mitre_rejected || []).filter((r) => r.reason === 'unknown_id').length,
    low_confidence: (diagnostics.mitre_rejected || []).filter((r) => r.reason === 'low_confidence').length
  });
  return diagnostics;
}

export function serializeMitreMappingRow(row, reference) {
  const canonical = resolveCanonicalTechnique(reference, row.attack_id) || {
    technique_id: row.attack_id,
    technique_name: null,
    attack_type: null,
    url: null,
    tactics: []
  };
  return {
    technique_id: canonical.technique_id,
    technique_name: canonical.technique_name,
    attack_type: canonical.attack_type,
    url: canonical.url,
    tactics: canonical.tactics,
    confidence: row.confidence == null ? null : Number(row.confidence),
    evidence: row.evidence_text || null
  };
}

export async function loadReportMitreByReportIds(db, reportIds, reference) {
  const ids = [...new Set(
    (Array.isArray(reportIds) ? reportIds : [])
      .map((n) => Number(n))
      .filter((n) => Number.isFinite(n) && n > 0)
  )];
  const out = new Map(ids.map((id) => [id, []]));
  if (!ids.length) return out;
  try {
    const { rows } = await db.query(
      `SELECT report_id, attack_id, confidence, evidence_text, created_at, updated_at
       FROM threat_report_mitre_mappings
       WHERE report_id = ANY($1::bigint[])
       ORDER BY report_id, attack_id`,
      [ids]
    );
    const catalog = reference || await loadMitreReference();
    for (const row of rows) {
      out.get(Number(row.report_id))?.push(serializeMitreMappingRow(row, catalog));
    }
  } catch (err) {
    if (!(err && err.code === '42P01')) throw err;
  }
  return out;
}

export async function loadReportMitreMappings(db, reportId, reference) {
  const map = await loadReportMitreByReportIds(db, [reportId], reference);
  return map.get(Number(reportId)) || [];
}

export async function upsertManualReportMitre(db, reportId, techniqueId, evidence, reference) {
  const catalog = reference || await loadMitreReference();
  const canonical = resolveCanonicalTechnique(catalog, techniqueId);
  if (!canonical) return { ok: false, reason: lookupReason(catalog, techniqueId) };
  await db.query(
    `INSERT INTO threat_report_mitre_mappings (report_id, attack_id, confidence, evidence_text)
     VALUES ($1, $2, NULL, $3)
     ON CONFLICT (report_id, attack_id) DO UPDATE SET
       evidence_text = COALESCE(NULLIF(EXCLUDED.evidence_text, ''), threat_report_mitre_mappings.evidence_text),
       updated_at = NOW()`,
    [reportId, canonical.technique_id, normalizeMitreEvidence(evidence) || null]
  );
  return { ok: true, mapping: (await loadReportMitreMappings(db, reportId, catalog)).find((m) => m.technique_id === canonical.technique_id) };
}

export async function removeReportMitre(db, reportId, techniqueId) {
  const id = normalizeMitreAttackId(techniqueId);
  if (!id) return false;
  const { rowCount } = await db.query(
    `DELETE FROM threat_report_mitre_mappings WHERE report_id = $1 AND attack_id = $2`,
    [reportId, id]
  );
  return rowCount > 0;
}

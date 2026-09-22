/**
 * Batched IOC metadata hydration for the API / MCP read surfaces
 * (search_iocs + REST /api/v1/iocs/search, lookup_ioc, bulk_lookup_iocs,
 * get_ioc_context).
 *
 * One implementation so those paths can never report different
 * classifications / tags for the same IOC. Semantics mirror the single-IOC
 * loaders the IOC Details UI uses:
 *   classifications — loadEffectiveIocClassificationSlugs: junction slugs
 *     unioned across proven file-artifact aliases; when none, the seed row's
 *     legacy ioc_items.threat_classification column.
 *   tags — EFFECTIVE tags: the IOC's own catalog tags (loadCatalogTags: every
 *     origin, manual + integration) UNION tags inherited from active Threat
 *     Library reports linked to the IOC (threatLibrary/reportTagInheritance.js),
 *     both across the same artifact scope, deduplicated by tag name.
 *     tags_detail keeps the IOC's own tags first (unchanged shape) and adds
 *     inherited-only tags with origin 'threat_library'; tag_context carries the
 *     provenance of every effective tag (direct origin and/or report sources).
 *   Classifications are never inherited from reports.
 *
 * Identity anchor is always the ioc_items (id, observable_type) of the row
 * being serialized — never a display/canonicalized hash value.
 *
 * Query budget is constant in the number of rows (no N+1):
 *   ≤1 artifact scope expansion (only when FILE_ARTIFACTS_READ_ENABLED)
 *   ≤1 ioc_items read (types of alias rows / legacy column not already held)
 *   1 junction read, 1 tag read, 1 inherited report-tag read
 */

import { mapIocIdsToArtifactScopedIocIds } from './fileArtifacts/read.js';
import {
  iocPairKey,
  loadIocThreatClassificationSlugs,
  normalizeIocThreatClassificationSlugs
} from './iocThreatClassifications.js';
import { catalogTagFromAggregateRow } from './apiIocService.js';
import { loadInheritedReportTagRows, groupInheritedTagsBySeed } from './threatLibrary/reportTagInheritance.js';

export const THREAT_LIBRARY_TAG_ORIGIN = 'threat_library';

/**
 * Merge an IOC's own tags with its report-inherited tags.
 * @param {object[]} directDetail catalog tags ({ name, type, origin, origins, source_name })
 * @param {Array<{ name: string, type: string|null, reports: Array<{ id: string, title: string, tlp: string|null }> }>} inherited
 */
export function mergeEffectiveTags(directDetail, inherited) {
  const inheritedByName = new Map((inherited || []).map((t) => [t.name, t]));
  const directNames = new Set((directDetail || []).map((t) => t.name));
  const tagsDetail = (directDetail || []).map((t) => (
    inheritedByName.has(t.name)
      ? { ...t, origins: [...new Set([...(t.origins || []), THREAT_LIBRARY_TAG_ORIGIN])] }
      : t
  ));
  for (const t of inherited || []) {
    if (directNames.has(t.name)) continue;
    tagsDetail.push({
      name: t.name,
      type: t.type || null,
      origin: THREAT_LIBRARY_TAG_ORIGIN,
      origins: [THREAT_LIBRARY_TAG_ORIGIN],
      source_name: null
    });
  }
  const tagContext = tagsDetail.map((t) => {
    const sources = [];
    if (directNames.has(t.name)) {
      for (const origin of (t.origins || []).filter((o) => o !== THREAT_LIBRARY_TAG_ORIGIN)) {
        sources.push({
          type: 'direct',
          origin,
          ...(origin === 'integration' && t.source_name ? { source_name: t.source_name } : {})
        });
      }
    }
    for (const rep of inheritedByName.get(t.name)?.reports || []) {
      sources.push({ type: THREAT_LIBRARY_TAG_ORIGIN, report_id: rep.id, title: rep.title, tlp: rep.tlp });
    }
    return { tag: t.name, sources };
  });
  return { tags: tagsDetail.map((t) => t.name), tags_detail: tagsDetail, tag_context: tagContext };
}

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

/**
 * @param {import('pg').Pool|import('pg').PoolClient} pool
 * @param {Array<{ id: number|string, observable_type: string, threat_classification?: string|null }>} rows
 *   Rows that omit the `threat_classification` key get the legacy column read in
 *   the single batched ioc_items query.
 * @returns {Promise<Map<string, { classifications: string[], tags: string[], tags_detail: object[] }>>}
 *   keyed by iocPairKey(id, observable_type)
 */
export async function hydrateIocApiMetadata(pool, rows) {
  const out = new Map();
  const seeds = [];
  const seenSeed = new Set();
  for (const r of Array.isArray(rows) ? rows : []) {
    const id = Number(r?.id);
    const type = String(r?.observable_type ?? '').trim();
    if (!Number.isFinite(id) || id <= 0 || !type) continue;
    const key = iocPairKey(id, type);
    if (seenSeed.has(key)) continue;
    seenSeed.add(key);
    seeds.push({
      id,
      type,
      key,
      hasLegacy: hasOwn(r, 'threat_classification'),
      legacy: r.threat_classification ?? null
    });
  }
  if (!seeds.length) return out;

  // Artifact scope per seed (seed itself when not linked / reads disabled).
  const scopeById = await mapIocIdsToArtifactScopedIocIds(pool, seeds.map((s) => s.id));

  const typeById = new Map(seeds.map((s) => [s.id, s.type]));
  const legacyById = new Map(seeds.filter((s) => s.hasLegacy).map((s) => [s.id, s.legacy]));
  const needRead = new Set();
  for (const s of seeds) {
    if (!s.hasLegacy) needRead.add(s.id);
    for (const scopedId of scopeById.get(s.id) || [s.id]) {
      if (!typeById.has(scopedId)) needRead.add(scopedId);
    }
  }
  if (needRead.size) {
    const { rows: typeRows } = await pool.query(
      `SELECT id, observable_type, threat_classification FROM ioc_items WHERE id = ANY($1::bigint[])`,
      [[...needRead]]
    );
    for (const tr of typeRows) {
      const id = Number(tr.id);
      if (!typeById.has(id)) typeById.set(id, String(tr.observable_type));
      if (!legacyById.has(id)) legacyById.set(id, tr.threat_classification ?? null);
    }
  }

  const scopedPairs = [];
  const tagSeedIds = [];
  const tagIocIds = [];
  const seenPair = new Set();
  for (const s of seeds) {
    for (const scopedId of scopeById.get(s.id) || [s.id]) {
      const scopedType = typeById.get(scopedId);
      if (scopedType) {
        const pk = iocPairKey(scopedId, scopedType);
        if (!seenPair.has(pk)) {
          seenPair.add(pk);
          scopedPairs.push({ id: scopedId, observable_type: scopedType });
        }
      }
      tagSeedIds.push(s.id);
      tagIocIds.push(scopedId);
    }
  }

  const [junctionMap, tagRows, inheritedRows] = await Promise.all([
    loadIocThreatClassificationSlugs(pool, scopedPairs),
    pool.query(
      `SELECT s.seed_id, t.name, t.type,
              array_agg(DISTINCT it.origin) AS origins,
              (array_agg(it.source_name ORDER BY it.origin)
                 FILTER (WHERE it.source_name IS NOT NULL))[1] AS source_name
       FROM (SELECT DISTINCT seed_id, ioc_id
             FROM unnest($1::bigint[], $2::bigint[]) AS u(seed_id, ioc_id)) s
       JOIN ioc_tags it ON it.ioc_id = s.ioc_id
       JOIN tags t ON t.id = it.tag_id
       WHERE t.enabled = TRUE
       GROUP BY s.seed_id, t.name, t.type
       ORDER BY s.seed_id, t.name ASC`,
      [tagSeedIds, tagIocIds]
    ).then((res) => res.rows),
    loadInheritedReportTagRows(pool, tagIocIds)
  ]);
  const inheritedBySeed = groupInheritedTagsBySeed(
    inheritedRows,
    new Map(seeds.map((s) => [s.id, scopeById.get(s.id) || [s.id]]))
  );

  const tagsBySeed = new Map();
  for (const tr of tagRows) {
    const seedId = Number(tr.seed_id);
    if (!tagsBySeed.has(seedId)) tagsBySeed.set(seedId, []);
    tagsBySeed.get(seedId).push(catalogTagFromAggregateRow(tr));
  }

  for (const s of seeds) {
    const union = new Set();
    for (const scopedId of scopeById.get(s.id) || [s.id]) {
      const scopedType = typeById.get(scopedId);
      if (!scopedType) continue;
      for (const slug of junctionMap.get(iocPairKey(scopedId, scopedType)) || []) union.add(slug);
    }
    const classifications = union.size
      ? [...union].sort()
      : normalizeIocThreatClassificationSlugs(legacyById.get(s.id) ?? null);
    const effective = mergeEffectiveTags(tagsBySeed.get(s.id) || [], inheritedBySeed.get(s.id) || []);
    out.set(s.key, {
      classifications,
      tags: effective.tags,
      tags_detail: effective.tags_detail,
      tag_context: effective.tag_context
    });
  }
  return out;
}

/** Empty metadata for a row the hydrator did not see (defensive default). */
export const EMPTY_IOC_API_METADATA = Object.freeze({ classifications: [], tags: [], tags_detail: [], tag_context: [] });

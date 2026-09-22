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
 *   tags — loadCatalogTags: enabled catalog tags of every origin (manual +
 *     integration) across the same artifact scope, grouped by (name, type).
 *
 * Identity anchor is always the ioc_items (id, observable_type) of the row
 * being serialized — never a display/canonicalized hash value.
 *
 * Query budget is constant in the number of rows (no N+1):
 *   ≤1 artifact scope expansion (only when FILE_ARTIFACTS_READ_ENABLED)
 *   ≤1 ioc_items read (types of alias rows / legacy column not already held)
 *   1 junction read, 1 tag read
 */

import { mapIocIdsToArtifactScopedIocIds } from './fileArtifacts/read.js';
import {
  iocPairKey,
  loadIocThreatClassificationSlugs,
  normalizeIocThreatClassificationSlugs
} from './iocThreatClassifications.js';
import { catalogTagFromAggregateRow } from './apiIocService.js';

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

  const [junctionMap, tagRows] = await Promise.all([
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
    ).then((res) => res.rows)
  ]);

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
    const tagsDetail = tagsBySeed.get(s.id) || [];
    out.set(s.key, {
      classifications,
      tags: tagsDetail.map((t) => t.name),
      tags_detail: tagsDetail
    });
  }
  return out;
}

/** Empty metadata for a row the hydrator did not see (defensive default). */
export const EMPTY_IOC_API_METADATA = Object.freeze({ classifications: [], tags: [], tags_detail: [] });

/**
 * Canonical effective IOC threat classification — ONE definition shared by IOC
 * Details, the IOC list, REST / MCP (iocApiMetadata), search CSV export and the
 * list export. The IOC Search DSL `classification` field evaluates the same rule
 * in SQL (iocSearchDsl/classificationPredicate.js); a real-Postgres parity test
 * holds the two together.
 *
 *   effective = (feed classifications − analyst suppressions) ∪ asserted classifications
 *
 * evaluated per IOC identity — the same grouping IOC search pages by: the IOC
 * row, every other ioc_items row of the same (observable_type, observable)
 * (e.g. a feed row plus a manual IOC Source row) and, when
 * FILE_ARTIFACTS_READ_ENABLED, the proven file-artifact aliases (MD5 / SHA1 /
 * SHA256 of one file) with their own same-observable rows.
 *
 * Feed classifications (provider assertions, suppressible), per identity row:
 *   - proposals derived from stored per-feed source evidence through the
 *     controlled feed vocabulary (batchLoadFeedClassifications);
 *   - the importer-stored ioc_items.threat_classification of a FEED-created row
 *     (ioc_source_id IS NULL), unless the value is one of the row's own junction
 *     slugs (then it is the analyst mirror the classification editor writes).
 *     Only feed importers write that column on feed-created rows without a
 *     matching junction row, so its provenance is the creating feed
 *     (ioc_items.source_name).
 * Asserted classifications (not suppressible), per identity row:
 *   - ioc_threat_classifications junction rows — provenance `analyst` for
 *     source_type analyst (classification editor / bulk triage) and manual
 *     (manual IOC create / REST API); `legacy` for anything else (e.g. rows a
 *     historical migration copied from the legacy column, source_type legacy);
 *   - the legacy column of an IOC-Source row (ioc_source_id IS NOT NULL) that has
 *     no junction rows (e.g. an IOC Source default applied by a source move):
 *     provenance `legacy` — it cannot be proven to be an analyst assertion.
 * Suppressions: active `suppress` overrides of any identity row; a source-less
 * suppression hides the slug from every feed, a source-scoped one only that
 * source's assertion. Suppressions never hide asserted classifications.
 */

import { mapIocIdsToArtifactScopedIocIds } from './fileArtifacts/read.js';
import { iocPairKey } from './iocThreatClassifications.js';
import {
  batchLoadFeedClassifications,
  batchLoadThreatClassificationSuppressions,
  buildThreatClassificationEffectiveFields
} from './iocThreatClassificationOverrides.js';
import {
  UNKNOWN_THREAT_CLASSIFICATION,
  normalizeClassificationSlug,
  threatClassificationLabel
} from './threatClassification.js';

/** Junction source_type values that record an explicit analyst / API assertion. */
export const ANALYST_JUNCTION_SOURCE_TYPES = Object.freeze(['analyst', 'manual']);

export const CLASSIFICATION_PROVENANCE = Object.freeze({
  FEED: 'feed',
  ANALYST: 'analyst',
  LEGACY: 'legacy'
});

function legacySlug(raw) {
  const slug = normalizeClassificationSlug(raw, { defaultValue: null });
  return slug && slug !== UNKNOWN_THREAT_CLASSIFICATION ? slug : null;
}

function junctionProvenance(sourceType) {
  return ANALYST_JUNCTION_SOURCE_TYPES.includes(String(sourceType || '').trim().toLowerCase())
    ? CLASSIFICATION_PROVENANCE.ANALYST
    : CLASSIFICATION_PROVENANCE.LEGACY;
}

/**
 * Pure canonical computation for one identity.
 * @param {{ rows: Array<{
 *   threat_classification?: string|null, ioc_source_id?: number|string|null, source_name?: string|null,
 *   junction?: Array<{ slug: string, source_type?: string|null }>,
 *   feed?: Array<{ value: string, source_name?: string|null, source_names?: string[], label?: string }>,
 *   suppressions?: Array<{ classification_slug: string, source_name?: string|null }>
 * }> }} identity
 */
export function computeCanonicalIocClassifications({ rows = [] } = {}) {
  const feedBySlug = new Map();
  const assertedBySlug = new Map();
  const suppressions = [];

  const addFeed = (value, sourceNames, label = null) => {
    const slug = String(value || '').trim().toLowerCase();
    if (!slug || slug === UNKNOWN_THREAT_CLASSIFICATION) return;
    if (!feedBySlug.has(slug)) feedBySlug.set(slug, { value: slug, label, sourceNames: new Set() });
    for (const n of sourceNames) if (n) feedBySlug.get(slug).sourceNames.add(String(n));
  };
  const addAsserted = (slug, provenance) => {
    if (!slug || slug === UNKNOWN_THREAT_CLASSIFICATION) return;
    if (!assertedBySlug.has(slug)) assertedBySlug.set(slug, new Set());
    assertedBySlug.get(slug).add(provenance);
  };

  for (const row of rows) {
    const junction = (row.junction || [])
      .map((j) => ({ slug: String(j.slug || '').trim().toLowerCase(), provenance: junctionProvenance(j.source_type) }))
      .filter((j) => j.slug);
    const junctionSlugs = new Set(junction.map((j) => j.slug));
    for (const j of junction) addAsserted(j.slug, j.provenance);

    const stored = legacySlug(row.threat_classification);
    if (stored && !junctionSlugs.has(stored)) {
      if (row.ioc_source_id == null) addFeed(stored, [row.source_name]);
      else if (!junctionSlugs.size) addAsserted(stored, CLASSIFICATION_PROVENANCE.LEGACY);
    }

    for (const f of row.feed || []) {
      addFeed(f.value, f.source_names || (f.source_name ? [f.source_name] : []), f.label || null);
    }
    suppressions.push(...(row.suppressions || []));
  }

  const suppressAll = new Set();
  const suppressBySource = new Set();
  for (const s of suppressions) {
    const slug = String(s.classification_slug || '').trim().toLowerCase();
    if (!slug) continue;
    const src = s.source_name != null ? String(s.source_name).trim().toLowerCase() : '';
    if (!src) suppressAll.add(slug);
    else suppressBySource.add(`${slug}::${src}`);
  }
  // A feed slug stays visible while at least one asserting source is not suppressed.
  const visibleSources = (slug, sourceNames) => {
    if (suppressAll.has(slug)) return null;
    const names = [...sourceNames].sort();
    if (!names.length) return [];
    const kept = names.filter((n) => !suppressBySource.has(`${slug}::${n.trim().toLowerCase()}`));
    return kept.length ? kept : null;
  };

  const effective = new Map();
  const feedList = [];
  for (const f of feedBySlug.values()) {
    const names = [...f.sourceNames].sort();
    feedList.push({
      value: f.value,
      label: f.label || threatClassificationLabel(f.value),
      origin: 'feed',
      source_name: names[0] || null,
      source_names: names,
      active: true
    });
    const kept = visibleSources(f.value, f.sourceNames);
    if (kept) effective.set(f.value, { feedVisible: true, feedSources: kept, asserted: new Set() });
  }
  for (const [slug, provenances] of assertedBySlug) {
    if (!effective.has(slug)) effective.set(slug, { feedVisible: false, feedSources: [], asserted: new Set() });
    for (const p of provenances) effective.get(slug).asserted.add(p);
  }

  const slugs = [...effective.keys()].sort();
  const classificationContext = slugs.map((slug) => {
    const e = effective.get(slug);
    const sources = e.feedSources.map((name) => ({ type: CLASSIFICATION_PROVENANCE.FEED, source_name: name }));
    if (e.feedVisible && !e.feedSources.length) sources.push({ type: CLASSIFICATION_PROVENANCE.FEED, source_name: null });
    if (e.asserted.has(CLASSIFICATION_PROVENANCE.ANALYST)) sources.push({ type: CLASSIFICATION_PROVENANCE.ANALYST });
    if (e.asserted.has(CLASSIFICATION_PROVENANCE.LEGACY)) sources.push({ type: CLASSIFICATION_PROVENANCE.LEGACY });
    return { classification: slug, sources };
  });

  const effectiveEntries = slugs.map((slug) => {
    const e = effective.get(slug);
    const origins = [];
    if (e.feedVisible) origins.push('feed');
    if (e.asserted.has(CLASSIFICATION_PROVENANCE.ANALYST)) origins.push('analyst');
    if (e.asserted.has(CLASSIFICATION_PROVENANCE.LEGACY)) origins.push('legacy');
    return {
      value: slug,
      label: feedBySlug.get(slug)?.label || threatClassificationLabel(slug),
      origin: origins[0],
      origins,
      source_name: e.feedSources[0] || null,
      active: true
    };
  });

  const assertedOf = (provenance) => [...assertedBySlug.entries()]
    .filter(([, p]) => p.has(provenance))
    .map(([slug]) => slug)
    .sort();

  return {
    classifications: slugs,
    classification_context: classificationContext,
    effective: effectiveEntries,
    feed: feedList.sort((a, b) => (a.value < b.value ? -1 : a.value > b.value ? 1 : 0)),
    analyst: assertedOf(CLASSIFICATION_PROVENANCE.ANALYST),
    legacy: assertedOf(CLASSIFICATION_PROVENANCE.LEGACY),
    suppressions
  };
}

/**
 * IOC Details / list response fields (same shape as buildThreatClassificationEffectiveFields):
 * effective entries carry their real provenance; analyst_threat_classifications
 * lists only analyst-asserted slugs; feed_threat_classifications includes
 * importer-stored feed values.
 */
export function canonicalClassificationResponseFields(canonical) {
  const fields = buildThreatClassificationEffectiveFields({
    effective_threat_classifications: canonical.effective,
    feed_classifications: canonical.feed,
    analyst_additions: canonical.analyst.map((slug) => ({
      value: slug,
      label: threatClassificationLabel(slug),
      origin: 'analyst',
      source_name: null
    })),
    analyst_suppressions: canonical.suppressions.map((row) => ({
      value: String(row.classification_slug || ''),
      label: threatClassificationLabel(row.classification_slug),
      origin: 'suppress',
      source_name: row.source_name || null,
      suppressed_at: row.created_at || null,
      suppressed_by: row.created_by || null
    })).filter((x) => x.value)
  });
  return { ...fields, classification_context: canonical.classification_context };
}

const FILE_HASH_TYPES = Object.freeze(['md5', 'sha1', 'sha256']);

function rowFacts(r) {
  return {
    id: Number(r.id),
    observable_type: String(r.observable_type),
    observable: r.observable ?? null,
    threat_classification: r.threat_classification ?? null,
    ioc_source_id: r.ioc_source_id ?? null,
    source_name: r.source_name ?? null
  };
}

/**
 * Batched canonical classifications for a set of IOC rows. Constant query count
 * in the number of rows: ≤1 artifact scope, 2 ioc_items reads (identity rows +
 * same-observable siblings), 1 junction, 1 feed evidence, 1 suppression.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} pool
 * @param {Array<{ id: number|string, observable_type: string }>} items
 * @param {{ scopeBySeed?: Map<number, number[]> }} [opts] precomputed artifact scope
 * @returns {Promise<Map<string, ReturnType<typeof computeCanonicalIocClassifications>>>}
 *   keyed by iocPairKey(id, observable_type) of the given item
 */
export async function loadCanonicalIocClassifications(pool, items, opts = {}) {
  const out = new Map();
  const seeds = [];
  const seen = new Set();
  for (const it of Array.isArray(items) ? items : []) {
    const id = Number(it?.id);
    const type = String(it?.observable_type ?? '').trim();
    if (!Number.isFinite(id) || id <= 0 || !type) continue;
    const key = iocPairKey(id, type);
    if (seen.has(key)) continue;
    seen.add(key);
    seeds.push({ id, type, key });
  }
  if (!seeds.length) return out;

  const scopeBySeed = opts.scopeBySeed || await mapIocIdsToArtifactScopedIocIds(pool, seeds.map((s) => s.id));

  // 1) Facts of every seed / artifact-alias row, pruned to the right partitions:
  //    non-hash seeds by (observable_type, id); file-hash seeds and aliases by id
  //    within the hash types (a canonical list row may show the primary hash type
  //    on another hash row's id).
  const pairSeeds = seeds.filter((s) => !FILE_HASH_TYPES.includes(s.type));
  const hashIds = new Set(seeds.filter((s) => FILE_HASH_TYPES.includes(s.type)).map((s) => s.id));
  const pairSeedIds = new Set(pairSeeds.map((s) => s.id));
  for (const s of seeds) {
    for (const id of scopeBySeed.get(s.id) || [s.id]) if (!pairSeedIds.has(Number(id))) hashIds.add(Number(id));
  }
  const { rows: baseRows } = await pool.query(
    `SELECT id, observable_type, observable, threat_classification, ioc_source_id, source_name
     FROM ioc_items
     WHERE (observable_type, id) IN (SELECT * FROM unnest($1::text[], $2::bigint[]))
        OR (observable_type = ANY($3::text[]) AND id = ANY($4::bigint[]))`,
    [pairSeeds.map((s) => s.type), pairSeeds.map((s) => s.id), FILE_HASH_TYPES, [...hashIds]]
  );
  const rowById = new Map(baseRows.map((r) => [Number(r.id), rowFacts(r)]));

  // 2) Same-observable sibling rows of every identity row (one indexed lookup).
  const observableKey = (type, value) => `${type}\u0000${value}`;
  const pairsByKey = new Map();
  for (const r of rowById.values()) {
    if (r.observable != null) pairsByKey.set(observableKey(r.observable_type, r.observable), [r.observable_type, r.observable]);
  }
  const siblingsByKey = new Map();
  if (pairsByKey.size) {
    const pairs = [...pairsByKey.values()];
    const { rows: siblingRows } = await pool.query(
      `SELECT id, observable_type, observable, threat_classification, ioc_source_id, source_name
       FROM ioc_items
       WHERE (observable_type, observable) IN (SELECT * FROM unnest($1::text[], $2::text[]))`,
      [pairs.map((p) => p[0]), pairs.map((p) => p[1])]
    );
    for (const r of siblingRows) {
      const facts = rowFacts(r);
      if (!rowById.has(facts.id)) rowById.set(facts.id, facts);
      const k = observableKey(facts.observable_type, facts.observable);
      if (!siblingsByKey.has(k)) siblingsByKey.set(k, new Set());
      siblingsByKey.get(k).add(facts.id);
    }
  }

  const identityOf = (seed) => {
    const ids = new Set();
    for (const id of scopeBySeed.get(seed.id) || [seed.id]) {
      const r = rowById.get(Number(id));
      if (!r) continue;
      ids.add(r.id);
      for (const sib of siblingsByKey.get(observableKey(r.observable_type, r.observable)) || []) ids.add(sib);
    }
    return [...ids].map((id) => rowById.get(id));
  };

  const pairs = [...rowById.values()].map((r) => ({ id: r.id, observable_type: r.observable_type }));
  const [junctionRows, feedMap, suppressMap] = await Promise.all([
    loadJunctionRows(pool, pairs),
    batchLoadFeedClassifications(pool, pairs),
    batchLoadThreatClassificationSuppressions(pool, pairs)
  ]);

  for (const s of seeds) {
    const rows = identityOf(s).map((r) => {
      const pk = iocPairKey(r.id, r.observable_type);
      return {
        ...r,
        junction: junctionRows.get(pk) || [],
        feed: feedMap.get(pk) || [],
        suppressions: suppressMap.get(pk) || []
      };
    });
    out.set(s.key, computeCanonicalIocClassifications({ rows }));
  }
  return out;
}

/** Junction rows with their source_type, one query. */
async function loadJunctionRows(pool, pairs) {
  const map = new Map();
  if (!pairs.length) return map;
  const values = pairs.map((_, i) => `($${i * 2 + 1}::bigint, $${i * 2 + 2}::text)`).join(', ');
  const { rows } = await pool.query(
    `SELECT ioc_id, ioc_observable_type, classification_slug, source_type
     FROM ioc_threat_classifications
     WHERE (ioc_id, ioc_observable_type) IN (VALUES ${values})
     ORDER BY classification_slug ASC`,
    pairs.flatMap((p) => [p.id, p.observable_type])
  );
  for (const r of rows) {
    const key = iocPairKey(r.ioc_id, r.ioc_observable_type);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push({ slug: String(r.classification_slug), source_type: r.source_type ?? null });
  }
  return map;
}

/** Single-IOC convenience (IOC Details / save planning), whole identity included. */
export async function loadCanonicalIocClassification(pool, { id, observable_type: observableType }) {
  const map = await loadCanonicalIocClassifications(pool, [{ id, observable_type: observableType }]);
  return map.get(iocPairKey(id, observableType)) || computeCanonicalIocClassifications({ rows: [] });
}

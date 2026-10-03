/**
 * IOC Search DSL `classification` = the canonical effective classification
 * (lib/iocCanonicalClassifications.js) evaluated in SQL:
 *
 *   effective = (feed classifications − analyst suppressions) ∪ asserted classifications
 *
 * Row-wise membership `(observable_type, id) IN (…)` (the DSL's index-friendly
 * shape — never `EXISTS … OR EXISTS …`), UNION of three branches over the rows of
 * an IOC identity:
 *   asserted  — ioc_threat_classifications junction rows (any source_type), and
 *               the stored column of an IOC-Source row without junction rows;
 *   importer  — the stored column of a feed-created row (ioc_source_id IS NULL),
 *               unless suppressed (a value mirrored by a junction row is matched
 *               by the asserted branch anyway);
 *   evidence  — per-feed source evidence (ioc_feed_source_evidence ⋈
 *               integration_feeds) whose vocabulary proposals
 *               (ioc_feed_evidence_classification_slugs, GIN-indexed, migration
 *               035 — the same vocabulary as feedTagNormalization) contain the
 *               slug, unless suppressed for that source.
 * Suppression scope is the IOC identity (same row, same observable_type +
 * observable, and — with file-artifact reads — the same file artifact).
 *
 * Positive operators match every row of an identity that has the slug (with
 * file-artifact reads the search page groups rows by identity; without them the
 * same-observable rows are expanded here). Negated operators exclude the whole
 * identity (anti-join on the identity closure), so `not_equals` never returns an
 * identity whose effective set contains the slug.
 *
 * Input values match a slug, its canonical normalization (normalizeClassificationSlug,
 * e.g. 'c2' → command_and_control) or a catalog label. Labels resolve in JS from
 * the loaded classification registry so every array is a bound parameter the
 * planner can estimate; only when the registry is not loaded and a value is not
 * slug-shaped does label resolution fall back to the catalog in SQL.
 */

import {
  UNKNOWN_THREAT_CLASSIFICATION,
  legacyClassificationSpellings,
  listCachedThreatClassifications,
  normalizeClassificationSlug
} from '../threatClassification.js';

export const FEED_EVIDENCE_CLASSIFICATION_FN = 'public.ioc_feed_evidence_classification_slugs';

const SLUG_SHAPED = /^[a-z0-9_ -]+$/;

let legacyCache = null;
function legacySpellings() {
  if (!legacyCache) {
    const pairs = legacyClassificationSpellings();
    legacyCache = Object.freeze({
      pairs,
      keys: pairs.map(([raw]) => raw),
      slugs: pairs.map(([, slug]) => slug),
      slugByKey: new Map(pairs)
    });
  }
  return legacyCache;
}

/**
 * DSL input values → target slugs.
 * @returns {{ slugs: string[], unresolvedLabels: string[] }}
 */
export function resolveClassificationTargets(values, { registry = listCachedThreatClassifications() } = {}) {
  const slugs = new Set();
  const unresolvedLabels = [];
  const byLabel = new Map((registry || []).map((e) => [String(e.name || '').trim().toLowerCase(), e.slug]));
  for (const v of values || []) {
    const lower = String(v ?? '').trim().toLowerCase();
    if (!lower) continue;
    if (lower !== UNKNOWN_THREAT_CLASSIFICATION) slugs.add(lower);
    const slug = normalizeClassificationSlug(v, { defaultValue: null });
    if (slug && slug !== UNKNOWN_THREAT_CLASSIFICATION) slugs.add(slug);
    const labelSlug = byLabel.get(lower);
    if (labelSlug && labelSlug !== UNKNOWN_THREAT_CLASSIFICATION) slugs.add(labelSlug);
    else if (!registry && !SLUG_SHAPED.test(lower)) unresolvedLabels.push(lower);
  }
  return { slugs: [...slugs], unresolvedLabels };
}

/**
 * Stored-column spellings that normalizeClassificationSlug resolves to one of
 * `slugs` (alias map + space/hyphen forms), so the indexed column is compared
 * with literal values.
 */
export function storedClassificationSpellings(slugs) {
  const { pairs, slugByKey } = legacySpellings();
  const target = new Set(slugs);
  const out = new Set(pairs.filter(([, slug]) => target.has(slug)).map(([raw]) => raw));
  for (const t of target) {
    for (const v of [t, t.replace(/_/g, ' '), t.replace(/_/g, '-')]) {
      const mapped = slugByKey.get(v);
      if (mapped === undefined || mapped === t) out.add(v);
    }
  }
  return [...out];
}

/**
 * @param {{ bind: (value: unknown) => string, iocAlias: string, operator: string,
 *   values: string[], fileArtifactsReadEnabled: boolean, registry?: Array<{slug:string,name:string}>|null }} args
 */
export function buildEffectiveClassificationPredicate({
  bind,
  iocAlias,
  operator,
  values,
  fileArtifactsReadEnabled,
  registry
}) {
  const legacy = legacySpellings();
  const resolved = resolveClassificationTargets(values, registry === undefined ? {} : { registry });
  const pLegK = bind(legacy.keys);
  const pLegS = bind(legacy.slugs);

  let T;
  let stored;
  if (!resolved.unresolvedLabels.length) {
    T = `${bind(resolved.slugs)}::text[]`;
    stored = `${bind(storedClassificationSpellings(resolved.slugs))}::text[]`;
  } else {
    // Registry not loaded and a label was given: resolve it against the catalog in SQL.
    T = `ARRAY(SELECT tz.x FROM (
          SELECT unnest(${bind(resolved.slugs)}::text[]) AS x
          UNION SELECT tc.slug FROM threat_classifications tc
                 WHERE LOWER(tc.name) = ANY(${bind(resolved.unresolvedLabels)}::text[])
        ) tz WHERE tz.x <> '${UNKNOWN_THREAT_CLASSIFICATION}')`;
    stored = `(ARRAY(SELECT m.k FROM unnest(${pLegK}::text[], ${pLegS}::text[]) AS m(k, s) WHERE m.s = ANY(${T}))
        || ARRAY(SELECT sp.v FROM unnest(${T}) AS tg(x),
                  LATERAL (VALUES (tg.x), (replace(tg.x, '_', ' ')), (replace(tg.x, '_', '-'))) AS sp(v)
                 WHERE NOT (sp.v = ANY(${pLegK}::text[]))))`;
  }

  const storedSlug = (rawExpr) => {
    const folded = `regexp_replace(LOWER(btrim(${rawExpr})), '[[:space:]-]+', '_', 'g')`;
    return `COALESCE((SELECT m.s FROM unnest(${pLegK}::text[], ${pLegS}::text[]) AS m(k, s) WHERE m.k = ${folded} LIMIT 1), ${folded})`;
  };
  const sameIdentity = (oId, oType, xId, xType) => {
    const artifact = fileArtifactsReadEnabled
      ? `
            OR EXISTS (SELECT 1 FROM file_artifact_ioc_links lo
                         JOIN file_artifact_ioc_links lx ON lx.artifact_id = lo.artifact_id
                        WHERE lo.ioc_item_id = ${oId} AND lo.ioc_observable_type = ${oType}
                          AND lx.ioc_item_id = ${xId} AND lx.ioc_observable_type = ${xType})`
      : '';
    return `((${oId} = ${xId} AND ${oType} = ${xType})
            OR EXISTS (SELECT 1 FROM ioc_items oi JOIN ioc_items xi
                          ON xi.observable_type = oi.observable_type AND xi.observable = oi.observable
                        WHERE oi.id = ${oId} AND oi.observable_type = ${oType}
                          AND xi.id = ${xId} AND xi.observable_type = ${xType})${artifact})`;
  };
  const suppressed = (xId, xType, slugExpr, sourceExpr) => `EXISTS (
        SELECT 1 FROM ioc_threat_classification_overrides o
         WHERE o.action = 'suppress' AND o.cleared_at IS NULL
           AND LOWER(btrim(o.classification_slug)) = ${slugExpr}
           AND (COALESCE(btrim(o.source_name), '') = ''
                OR LOWER(btrim(o.source_name)) = LOWER(btrim(${sourceExpr})))
           AND ${sameIdentity('o.ioc_id', 'o.ioc_observable_type', xId, xType)})`;

  const evidenceSlugs = `${FEED_EVIDENCE_CLASSIFICATION_FN}(e.category, e.note)`;
  const membership = `
      SELECT itc.ioc_observable_type, itc.ioc_id
        FROM ioc_threat_classifications itc
       WHERE itc.classification_slug = ANY(${T})
      UNION
      SELECT x.observable_type, x.id
        FROM ioc_items x
       WHERE x.threat_classification = ANY(${stored})
         AND (
           (x.ioc_source_id IS NULL
             AND NOT ${suppressed('x.id', 'x.observable_type', storedSlug('x.threat_classification'), 'x.source_name')})
           OR (x.ioc_source_id IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM ioc_threat_classifications xj
                              WHERE xj.ioc_id = x.id AND xj.ioc_observable_type = x.observable_type))
         )
      UNION
      SELECT e.ioc_observable_type, e.ioc_item_id
        FROM ioc_feed_source_evidence e
        JOIN integration_feeds f ON f.integration_id = e.feed_id
        CROSS JOIN LATERAL unnest(${evidenceSlugs}) AS p(slug)
       WHERE ${evidenceSlugs} && ${T}
         AND ${evidenceSlugs} <> ARRAY[]::text[]
         AND p.slug = ANY(${T})
         AND NOT ${suppressed('e.ioc_item_id', 'e.ioc_observable_type', 'p.slug', 'e.source_name')}`;

  // Identity closure of the membership rows: same-observable rows and, with
  // file-artifact reads, rows of the same file artifact.
  const closure = `
      SELECT z.t, z.id
        FROM (${membership}) AS mm(t, id)
        CROSS JOIN LATERAL (
          SELECT mm.t, mm.id
          UNION
          SELECT s.observable_type, s.id
            FROM ioc_items mi
            JOIN ioc_items s ON s.observable_type = mi.observable_type AND s.observable = mi.observable
           WHERE mi.id = mm.id AND mi.observable_type = mm.t${fileArtifactsReadEnabled ? `
          UNION
          SELECT l2.ioc_observable_type, l2.ioc_item_id
            FROM file_artifact_ioc_links l1
            JOIN file_artifact_ioc_links l2 ON l2.artifact_id = l1.artifact_id
           WHERE l1.ioc_item_id = mm.id AND l1.ioc_observable_type = mm.t` : ''}
        ) AS z(t, id)`;

  const positive = fileArtifactsReadEnabled
    // The search page groups rows by identity, so plain membership is exact.
    ? `(${iocAlias}.observable_type, ${iocAlias}.id) IN (${membership}
    )`
    : `(${iocAlias}.observable_type, ${iocAlias}.id) IN (${closure}
    )`;
  const negative = `NOT EXISTS (
      SELECT 1 FROM (${closure}) AS cx(t, id)
       WHERE cx.t = ${iocAlias}.observable_type AND cx.id = ${iocAlias}.id
    )`;

  switch (operator) {
    case 'equals':
    case 'in':
      return positive;
    case 'not_equals':
    case 'not_in':
      return negative;
    default:
      throw new Error(`Unsupported operator for classification: ${operator}`);
  }
}

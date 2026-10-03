/**
 * Analyst add/suppress overrides for IOC threat classifications.
 * Feed evidence remains immutable; effective =
 *   (feed classifications − active suppressions) ∪ analyst additions
 */

import {
  UNKNOWN_THREAT_CLASSIFICATION,
  lookupThreatClassificationEntry,
  threatClassificationLabel
} from './threatClassification.js';
import {
  buildThreatClassificationEntry,
  buildMultiThreatClassificationResponseFields,
  legacyThreatClassificationColumnValue,
  normalizeIocThreatClassificationSlugs
} from './iocThreatClassifications.js';
import { parseNoteFields, normalizeFeedTags } from './feedTagNormalization.js';

export function classificationOverrideKey(slug, sourceName = null) {
  return `${String(slug || '').toLowerCase()}::${String(sourceName || '').trim().toLowerCase()}`;
}

/**
 * Pure effective-set math.
 * @param {Array<{value:string,label?:string,origin?:string,source_name?:string}>} feedClassifications
 * @param {string[]} analystAdditionSlugs
 * @param {Array<{classification_slug:string,source_name?:string|null}>} activeSuppressions
 */
export function computeEffectiveThreatClassifications({
  feedClassifications = [],
  analystAdditionSlugs = [],
  activeSuppressions = []
} = {}) {
  const suppressAll = new Set();
  const suppressBySource = new Set();
  for (const row of activeSuppressions || []) {
    const slug = String(row.classification_slug || row.value || '').trim().toLowerCase();
    if (!slug) continue;
    const src = row.source_name != null ? String(row.source_name).trim() : '';
    if (!src) suppressAll.add(slug);
    else suppressBySource.add(`${slug}::${src.toLowerCase()}`);
  }

  const visibleFeed = [];
  const seen = new Set();
  for (const item of feedClassifications || []) {
    const value = String(item?.value || '').trim();
    if (!value || value.toLowerCase() === UNKNOWN_THREAT_CLASSIFICATION) continue;
    const key = value.toLowerCase();
    if (suppressAll.has(key)) continue;
    const src = String(item?.source_name || '').trim().toLowerCase();
    if (src && suppressBySource.has(`${key}::${src}`)) continue;
    // If source-specific suppressions exist without a matching source, still show
    // unless an all-source suppress exists (already handled).
    if (seen.has(key)) continue;
    seen.add(key);
    visibleFeed.push({
      value,
      label: item.label || threatClassificationLabel(value),
      origin: 'feed',
      source_name: item.source_name || null,
      active: item.active !== false,
      system_default: Boolean(item.system_default)
    });
  }

  const additions = [];
  for (const slug of normalizeIocThreatClassificationSlugs(analystAdditionSlugs)) {
    if (seen.has(slug)) {
      // Already visible via feed — annotate dual provenance on existing entry
      const existing = visibleFeed.find((x) => x.value.toLowerCase() === slug);
      if (existing) existing.origins = ['feed', 'analyst'];
      continue;
    }
    seen.add(slug);
    const entry = buildThreatClassificationEntry(slug);
    additions.push({
      ...entry,
      origin: 'analyst',
      source_name: null,
      origins: ['analyst']
    });
  }

  for (const item of visibleFeed) {
    if (!item.origins) item.origins = ['feed'];
  }

  return {
    feed_classifications: (feedClassifications || []).map((item) => ({
      value: item.value,
      label: item.label || threatClassificationLabel(item.value),
      origin: 'feed',
      source_name: item.source_name || null,
      active: item.active !== false
    })),
    analyst_additions: normalizeIocThreatClassificationSlugs(analystAdditionSlugs).map((slug) => ({
      ...buildThreatClassificationEntry(slug),
      origin: 'analyst',
      source_name: null
    })),
    analyst_suppressions: (activeSuppressions || []).map((row) => ({
      value: String(row.classification_slug || row.value || ''),
      label: threatClassificationLabel(row.classification_slug || row.value),
      origin: 'suppress',
      source_name: row.source_name || null,
      suppressed_at: row.created_at || row.suppressed_at || null,
      suppressed_by: row.created_by || row.suppressed_by || null
    })).filter((x) => x.value),
    effective_threat_classifications: [...visibleFeed, ...additions]
  };
}

/**
 * Given desired effective slug list + current feed, compute junction adds and suppress slugs.
 */
export function planThreatClassificationEffectiveSave({
  desiredEffectiveSlugs = [],
  feedClassifications = []
} = {}) {
  const desired = normalizeIocThreatClassificationSlugs(desiredEffectiveSlugs);
  const feedSlugs = [];
  const feedSeen = new Set();
  for (const item of feedClassifications || []) {
    const value = String(item?.value || '').trim();
    if (!value || value.toLowerCase() === UNKNOWN_THREAT_CLASSIFICATION) continue;
    const key = value.toLowerCase();
    if (feedSeen.has(key)) continue;
    feedSeen.add(key);
    feedSlugs.push(value);
  }
  const feedSet = new Set(feedSlugs.map((s) => s.toLowerCase()));
  const desiredSet = new Set(desired.map((s) => s.toLowerCase()));

  const additions = desired.filter((slug) => !feedSet.has(slug.toLowerCase()));
  const suppressions = feedSlugs.filter((slug) => !desiredSet.has(slug.toLowerCase()));

  return { additions, suppressions, desired, feedSlugs };
}

export async function listActiveThreatClassificationOverrides(db, iocId, observableType) {
  const { rows } = await db.query(
    `SELECT id, ioc_id, ioc_observable_type, classification_slug, action, source_name,
            created_by, created_at
     FROM ioc_threat_classification_overrides
     WHERE ioc_id = $1
       AND ioc_observable_type = $2
       AND cleared_at IS NULL
     ORDER BY created_at ASC, classification_slug ASC`,
    [iocId, observableType]
  );
  return rows;
}

export async function listActiveThreatClassificationSuppressions(db, iocId, observableType) {
  const rows = await listActiveThreatClassificationOverrides(db, iocId, observableType);
  return rows.filter((r) => r.action === 'suppress');
}

/**
 * Sync add/suppress overrides and junction adds inside an open transaction client.
 */
export async function syncThreatClassificationOverrides(client, {
  iocId,
  observableType,
  additions,
  suppressions,
  actor = null
}) {
  const additionSlugs = normalizeIocThreatClassificationSlugs(additions);
  const suppressSlugs = normalizeIocThreatClassificationSlugs(suppressions);
  const additionSet = new Set(additionSlugs.map((s) => s.toLowerCase()));
  const suppressSet = new Set(suppressSlugs.map((s) => s.toLowerCase()));

  const existing = await listActiveThreatClassificationOverrides(client, iocId, observableType);
  const activeAdds = existing.filter((r) => r.action === 'add');
  const activeSuppress = existing.filter((r) => r.action === 'suppress');

  // Clear obsolete adds
  for (const row of activeAdds) {
    if (!additionSet.has(String(row.classification_slug).toLowerCase())) {
      await client.query(
        `UPDATE ioc_threat_classification_overrides
         SET cleared_at = NOW(), cleared_by = $2
         WHERE id = $1::uuid AND cleared_at IS NULL`,
        [row.id, actor]
      );
    }
  }
  // Clear obsolete suppressions (restore)
  for (const row of activeSuppress) {
    // Only clear slug-level (source_name NULL) suppressions managed by this save path
    if (row.source_name) continue;
    if (!suppressSet.has(String(row.classification_slug).toLowerCase())) {
      await client.query(
        `UPDATE ioc_threat_classification_overrides
         SET cleared_at = NOW(), cleared_by = $2
         WHERE id = $1::uuid AND cleared_at IS NULL`,
        [row.id, actor]
      );
    }
  }

  const existingAddSlugs = new Set(activeAdds.map((r) => String(r.classification_slug).toLowerCase()));
  const existingSuppressSlugs = new Set(
    activeSuppress.filter((r) => !r.source_name).map((r) => String(r.classification_slug).toLowerCase())
  );

  for (const slug of additionSlugs) {
    if (existingAddSlugs.has(slug.toLowerCase())) continue;
    await client.query(
      `INSERT INTO ioc_threat_classification_overrides
         (ioc_id, ioc_observable_type, classification_slug, action, source_name, created_by)
       VALUES ($1, $2, $3, 'add', NULL, $4)`,
      [iocId, observableType, slug, actor]
    );
  }

  for (const slug of suppressSlugs) {
    if (existingSuppressSlugs.has(slug.toLowerCase())) continue;
    await client.query(
      `INSERT INTO ioc_threat_classification_overrides
         (ioc_id, ioc_observable_type, classification_slug, action, source_name, created_by)
       VALUES ($1, $2, $3, 'suppress', NULL, $4)`,
      [iocId, observableType, slug, actor]
    );
  }

  // Keep junction mirrored to analyst additions for list/export/search compatibility
  await client.query(
    `DELETE FROM ioc_threat_classifications WHERE ioc_id = $1 AND ioc_observable_type = $2`,
    [iocId, observableType]
  );
  for (const slug of additionSlugs) {
    await client.query(
      `INSERT INTO ioc_threat_classifications
         (ioc_id, ioc_observable_type, classification_slug, source_type, source_name, created_by, updated_by)
       VALUES ($1, $2, $3, 'analyst', 'ui', $4, $4)
       ON CONFLICT (ioc_id, ioc_observable_type, classification_slug) DO UPDATE
         SET updated_at = NOW(), updated_by = EXCLUDED.updated_by, source_type = 'analyst'`,
      [iocId, observableType, slug, actor]
    );
  }
  const legacyValue = legacyThreatClassificationColumnValue(additionSlugs);
  await client.query(
    `UPDATE ioc_items SET threat_classification = $3 WHERE id = $1 AND observable_type = $2`,
    [iocId, observableType, legacyValue]
  );

  return {
    additions: additionSlugs,
    suppressions: suppressSlugs,
    cleared_adds: activeAdds
      .filter((r) => !additionSet.has(String(r.classification_slug).toLowerCase()))
      .map((r) => r.classification_slug),
    restored_suppressions: activeSuppress
      .filter((r) => !r.source_name && !suppressSet.has(String(r.classification_slug).toLowerCase()))
      .map((r) => r.classification_slug),
    created_adds: additionSlugs.filter((s) => !existingAddSlugs.has(s.toLowerCase())),
    created_suppressions: suppressSlugs.filter((s) => !existingSuppressSlugs.has(s.toLowerCase()))
  };
}

/**
 * Build response bundle for details/API from parts.
 */
export function buildThreatClassificationEffectiveFields(computed) {
  const effective = computed.effective_threat_classifications || [];
  const effectiveSlugs = effective.map((x) => x.value);
  const base = buildMultiThreatClassificationResponseFields(effectiveSlugs);
  // Prefer rich effective entries (with origin) over plain dictionary array
  return {
    ...base,
    threat_classifications: effective.length
      ? effective
      : base.threat_classifications,
    analyst_threat_classifications: computed.analyst_additions || [],
    suppressed_threat_classifications: computed.analyst_suppressions || [],
    effective_threat_classifications: effective,
    feed_threat_classifications: computed.feed_classifications || []
  };
}

export function enrichmentLookupLabel(slug) {
  return lookupThreatClassificationEntry(slug)?.name || threatClassificationLabel(slug);
}

function isOverridesTableMissing(err) {
  return String(err?.message || '').includes('ioc_threat_classification_overrides');
}

function iocPairValues(items) {
  const pairs = (items || [])
    .map((it) => ({ id: Number(it?.id), observable_type: String(it?.observable_type || '').trim() }))
    .filter((p) => Number.isFinite(p.id) && p.id > 0 && p.observable_type);
  return {
    pairs,
    values: pairs.map((_, i) => `($${i * 2 + 1}::bigint, $${i * 2 + 2}::text)`).join(', '),
    params: pairs.flatMap((p) => [p.id, p.observable_type])
  };
}

/**
 * Feed-derived classification proposals per IOC, from stored per-feed source
 * evidence (ioc_feed_source_evidence) through the controlled feed vocabulary
 * (feedTagNormalization.normalizeFeedTags — spelling-only tag/category/signature
 * mapping; raw provider strings never become slugs). One entry per slug; the
 * first asserting source is `source_name`, every asserting source is listed in
 * `source_names`.
 * @returns {Promise<Map<string, Array<{value:string,label:string,active:boolean,origin:'feed',source_name:string|null,source_names:string[]}>>>}
 *   keyed by `${id}|${observable_type}`
 */
export async function batchLoadFeedClassifications(pool, items) {
  const feedMap = new Map();
  if (!items?.length) return feedMap;
  const { pairs, values, params } = iocPairValues(items);
  if (!pairs.length) return feedMap;

  const { rows } = await pool.query(
    `SELECT e.ioc_item_id, e.ioc_observable_type, e.source_name, e.category, e.note, f.key AS feed_key
     FROM ioc_feed_source_evidence e
     JOIN integration_feeds f ON f.integration_id = e.feed_id
     WHERE (e.ioc_item_id, e.ioc_observable_type) IN (VALUES ${values})
     ORDER BY e.created_at ASC, e.id ASC`,
    params
  );

  const evidenceByKey = new Map();
  for (const row of rows) {
    const key = `${Number(row.ioc_item_id)}|${String(row.ioc_observable_type)}`;
    if (!evidenceByKey.has(key)) evidenceByKey.set(key, []);
    evidenceByKey.get(key).push(row);
  }

  for (const [key, evRows] of evidenceByKey.entries()) {
    const bySlug = new Map();
    for (const evRow of evRows) {
      const noteFields = parseNoteFields(evRow.note);
      const rawTagsStr = noteFields.tags || '';
      const rawTags = rawTagsStr ? rawTagsStr.split(',').map((t) => t.trim()).filter(Boolean) : [];
      const { classifications } = normalizeFeedTags({
        sourceName: evRow.source_name,
        rawTags,
        category: evRow.category,
        signature: noteFields.signature || null
      });
      for (const c of classifications) {
        const known = bySlug.get(c.value);
        if (!known) {
          bySlug.set(c.value, { ...c, source_names: c.source_name ? [c.source_name] : [] });
        } else if (c.source_name && !known.source_names.includes(c.source_name)) {
          known.source_names.push(c.source_name);
        }
      }
    }
    if (bySlug.size) feedMap.set(key, [...bySlug.values()]);
  }
  return feedMap;
}

/**
 * Active analyst suppressions per IOC (one query).
 * @returns {Promise<Map<string, object[]>>} keyed by `${id}|${observable_type}`
 */
export async function batchLoadThreatClassificationSuppressions(pool, items) {
  const map = new Map();
  if (!items?.length) return map;
  const { pairs, values, params } = iocPairValues(items);
  if (!pairs.length) return map;

  try {
    const { rows } = await pool.query(
      `SELECT ioc_id, ioc_observable_type, classification_slug, source_name, created_at, created_by
       FROM ioc_threat_classification_overrides
       WHERE action = 'suppress'
         AND cleared_at IS NULL
         AND (ioc_id, ioc_observable_type) IN (VALUES ${values})`,
      params
    );
    for (const row of rows) {
      const key = `${Number(row.ioc_id)}|${String(row.ioc_observable_type)}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(row);
    }
  } catch (err) {
    if (!isOverridesTableMissing(err)) throw err;
  }
  return map;
}

import {
  UNKNOWN_THREAT_CLASSIFICATION,
  lookupThreatClassificationEntry,
  normalizeClassificationSlug,
  threatClassificationLabel,
  validateThreatClassificationSlug
} from './threatClassification.js';

export function parseThreatClassificationInput(raw) {
  if (raw == null) return [];
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!trimmed) return [];
    if (trimmed.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) return parsed;
      } catch {
        /* fall through */
      }
    }
    return trimmed.split(',').map((x) => x.trim()).filter(Boolean);
  }
  return [];
}

/** Normalize multi-select input; empty array = Unknown UI (no stored relations). */
export function normalizeIocThreatClassificationSlugs(raw) {
  const items = parseThreatClassificationInput(raw);
  const seen = new Set();
  const slugs = [];
  for (const item of items) {
    const slug = normalizeClassificationSlug(item, { defaultValue: null });
    if (!slug || slug === UNKNOWN_THREAT_CLASSIFICATION) continue;
    if (!seen.has(slug)) {
      seen.add(slug);
      slugs.push(slug);
    }
  }
  return slugs;
}

export function legacyThreatClassificationColumnValue(slugs) {
  if (!slugs?.length) return UNKNOWN_THREAT_CLASSIFICATION;
  return slugs[0];
}

export function buildThreatClassificationEntry(slug, rowMeta = null) {
  const cached = lookupThreatClassificationEntry(slug);
  const label = rowMeta?.label || rowMeta?.name || cached?.name || threatClassificationLabel(slug);
  return {
    value: slug,
    label,
    active: rowMeta?.active != null ? Boolean(rowMeta.active) : (cached?.active ?? true),
    system_default: rowMeta?.system_default != null
      ? Boolean(rowMeta.system_default)
      : Boolean(cached?.system_default)
  };
}

export function buildThreatClassificationsArray(slugs, rowsBySlug = null) {
  if (!slugs?.length) {
    return [buildThreatClassificationEntry(UNKNOWN_THREAT_CLASSIFICATION)];
  }
  return slugs.map((slug) => {
    const meta = rowsBySlug?.get?.(slug) || rowsBySlug?.[slug] || null;
    return buildThreatClassificationEntry(slug, meta);
  });
}

export function buildMultiThreatClassificationResponseFields(slugs, rowsBySlug = null) {
  const normalized = normalizeIocThreatClassificationSlugs(slugs);
  const threat_classifications = buildThreatClassificationsArray(normalized, rowsBySlug);
  const legacySlug = legacyThreatClassificationColumnValue(normalized);
  const legacyEntry = threat_classifications.find((x) => x.value === legacySlug)
    || buildThreatClassificationEntry(legacySlug);
  return {
    threat_classifications,
    threat_classification: legacyEntry.value,
    threat_classification_label: legacyEntry.label,
    threat_classification_active: legacyEntry.active,
    primary_threat_classification: legacyEntry.value
  };
}

export async function validateIocThreatClassificationSlugs(pool, raw, { requireActive = true } = {}) {
  const slugs = normalizeIocThreatClassificationSlugs(raw);
  if (!slugs.length) return { ok: true, value: [] };
  for (const slug of slugs) {
    const check = await validateThreatClassificationSlug(pool, slug, { requireActive });
    if (!check.ok) return check;
  }
  return { ok: true, value: slugs };
}

function iocPairKey(iocId, observableType) {
  return `${Number(iocId)}|${String(observableType || '')}`;
}

export async function loadIocThreatClassificationSlugs(pool, pairs) {
  const map = new Map();
  if (!pairs?.length) return map;

  const validPairs = pairs
    .map((p) => ({
      id: Number(p?.id ?? p?.ioc_id),
      observable_type: String(p?.observable_type ?? p?.ioc_observable_type ?? '').trim()
    }))
    .filter((p) => Number.isFinite(p.id) && p.id > 0 && p.observable_type);
  if (!validPairs.length) return map;

  const values = validPairs.map((_, i) => `($${i * 2 + 1}::bigint, $${i * 2 + 2}::text)`).join(', ');
  const params = validPairs.flatMap((p) => [p.id, p.observable_type]);
  const { rows } = await pool.query(
    `SELECT ioc_id, ioc_observable_type, classification_slug
     FROM ioc_threat_classifications
     WHERE (ioc_id, ioc_observable_type) IN (VALUES ${values})
     ORDER BY classification_slug ASC`,
    params
  );
  for (const row of rows) {
    const key = iocPairKey(row.ioc_id, row.ioc_observable_type);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(String(row.classification_slug));
  }
  return map;
}

export async function loadIocThreatClassificationDetails(pool, pairs) {
  const slugMap = await loadIocThreatClassificationSlugs(pool, pairs);
  const allSlugs = new Set();
  for (const slugs of slugMap.values()) {
    for (const slug of slugs) allSlugs.add(slug);
  }
  const metaBySlug = new Map();
  if (allSlugs.size) {
    const { rows } = await pool.query(
      `SELECT slug, name, active, system_default FROM threat_classifications WHERE slug = ANY($1::text[])`,
      [[...allSlugs]]
    );
    for (const row of rows) {
      metaBySlug.set(row.slug, row);
    }
  }

  const detailMap = new Map();
  for (const [key, slugs] of slugMap.entries()) {
    const rowsBySlug = new Map(slugs.map((slug) => [slug, metaBySlug.get(slug) || null]));
    detailMap.set(key, buildMultiThreatClassificationResponseFields(slugs, rowsBySlug));
  }
  return detailMap;
}

export async function fetchIocThreatClassificationSlugs(pool, iocId, observableType) {
  const map = await loadIocThreatClassificationSlugs(pool, [{ id: iocId, observable_type: observableType }]);
  return map.get(iocPairKey(iocId, observableType)) || [];
}

/**
 * Effective analyst classification slugs for one IOC: the multi-select junction
 * table when it has rows, otherwise the legacy single-value
 * `ioc_items.threat_classification` column (written by ingestion / pre-multi
 * flows). Mirrors the list + details fallback (`mergeIocThreatMetadataItem`,
 * `resolveAnalystAdditionSlugs`) so an IOC whose classification lives only in
 * the legacy column is not reported as unclassified. Pass
 * `legacyThreatClassification` (the row's column value) to avoid a second read
 * when the caller already holds the row; when it is null/undefined the column
 * is fetched on demand. Feed-only classifications and analyst suppressions are
 * NOT applied here — this is the analyst/native slug set, not the full
 * effective computation used when feed classifications are present.
 */
export async function loadEffectiveIocClassificationSlugs(pool, iocId, observableType, legacyThreatClassification) {
  const junction = await fetchIocThreatClassificationSlugs(pool, iocId, observableType);
  if (junction.length) return junction;
  let legacy = legacyThreatClassification;
  if (legacy == null) {
    const { rows } = await pool.query(
      `SELECT threat_classification FROM ioc_items WHERE id = $1 AND observable_type = $2 LIMIT 1`,
      [iocId, observableType]
    );
    legacy = rows[0]?.threat_classification ?? null;
  }
  return normalizeIocThreatClassificationSlugs(legacy);
}

export async function replaceIocThreatClassifications(pool, {
  iocId,
  observableType,
  slugs,
  sourceType = 'analyst',
  sourceName = null,
  actor = null
}) {
  const normalized = normalizeIocThreatClassificationSlugs(slugs);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `DELETE FROM ioc_threat_classifications WHERE ioc_id = $1 AND ioc_observable_type = $2`,
      [iocId, observableType]
    );
    for (const slug of normalized) {
      await client.query(
        `INSERT INTO ioc_threat_classifications
           (ioc_id, ioc_observable_type, classification_slug, source_type, source_name, created_by, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $6)
         ON CONFLICT (ioc_id, ioc_observable_type, classification_slug) DO UPDATE
           SET updated_at = NOW(), updated_by = EXCLUDED.updated_by, source_type = EXCLUDED.source_type`,
        [iocId, observableType, slug, sourceType, sourceName, actor]
      );
    }
    const legacyValue = legacyThreatClassificationColumnValue(normalized);
    await client.query(
      `UPDATE ioc_items SET threat_classification = $3 WHERE id = $1 AND observable_type = $2`,
      [iocId, observableType, legacyValue]
    );
    await client.query('COMMIT');
    return normalized;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export function diffThreatClassificationSlugs(oldSlugs, newSlugs) {
  const oldSet = new Set(oldSlugs || []);
  const newSet = new Set(newSlugs || []);
  return {
    old_classifications: [...oldSet],
    new_classifications: [...newSet],
    added: [...newSet].filter((x) => !oldSet.has(x)),
    removed: [...oldSet].filter((x) => !newSet.has(x))
  };
}

export function mergeIocThreatMetadataItem(item, detailMap, slugMap) {
  const key = iocPairKey(item?.id, item?.observable_type);
  const fromDetail = detailMap?.get?.(key);
  if (fromDetail) return { ...item, ...fromDetail };

  const slugs = slugMap?.get?.(key);
  if (slugs?.length) return { ...item, ...buildMultiThreatClassificationResponseFields(slugs) };

  if (item?.threat_classification && item.threat_classification !== UNKNOWN_THREAT_CLASSIFICATION) {
    return {
      ...item,
      ...buildMultiThreatClassificationResponseFields([normalizeClassificationSlug(item.threat_classification)])
    };
  }

  return { ...item, ...buildMultiThreatClassificationResponseFields([]) };
}

export function parseThreatClassificationFilterParam(raw) {
  const slugs = normalizeIocThreatClassificationSlugs(parseThreatClassificationInput(raw));
  return slugs.filter((slug) => slug !== UNKNOWN_THREAT_CLASSIFICATION);
}

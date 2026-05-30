/** Cached schema feature flags (reset on process restart). */
const cache = {
  iocConfidenceColumns: null,
  feedDefaultConfidenceColumn: null,
  confidenceProvenanceColumns: null
};

export async function hasIocConfidenceColumns(pool) {
  if (cache.iocConfidenceColumns !== null) return cache.iocConfidenceColumns;
  try {
    const { rows } = await pool.query(
      `SELECT 1
       FROM information_schema.columns
       WHERE table_schema = current_schema()
         AND table_name = 'ioc_items'
         AND column_name = 'source_confidence'
       LIMIT 1`
    );
    cache.iocConfidenceColumns = rows.length > 0;
  } catch {
    cache.iocConfidenceColumns = false;
  }
  return cache.iocConfidenceColumns;
}

export async function hasFeedDefaultConfidenceColumn(pool) {
  if (cache.feedDefaultConfidenceColumn !== null) return cache.feedDefaultConfidenceColumn;
  try {
    const { rows } = await pool.query(
      `SELECT 1
       FROM information_schema.columns
       WHERE table_schema = current_schema()
         AND table_name = 'integration_feeds'
         AND column_name = 'default_confidence'
       LIMIT 1`
    );
    cache.feedDefaultConfidenceColumn = rows.length > 0;
  } catch {
    cache.feedDefaultConfidenceColumn = false;
  }
  return cache.feedDefaultConfidenceColumn;
}

export async function hasConfidenceProvenanceColumns(pool) {
  if (cache.confidenceProvenanceColumns !== null) return cache.confidenceProvenanceColumns;
  try {
    const { rows } = await pool.query(
      `SELECT 1
       FROM information_schema.columns
       WHERE table_schema = current_schema()
         AND table_name = 'ioc_items'
         AND column_name = 'confidence_source'
       LIMIT 1`
    );
    cache.confidenceProvenanceColumns = rows.length > 0;
  } catch {
    cache.confidenceProvenanceColumns = false;
  }
  return cache.confidenceProvenanceColumns;
}

/** SQL fragment for IOC details / confidence queries when columns exist. */
export function iocConfidenceSelectSql(hasColumns, hasProvenance = false) {
  if (!hasColumns) {
    return `
        NULL::text AS source_confidence,
        NULL::text AS feed_default_confidence,
        NULL::text AS analyst_confidence_override,
        NULL::text AS analyst_confidence_override_reason,
        NULL::uuid AS analyst_confidence_overridden_by,
        NULL::timestamptz AS analyst_confidence_overridden_at,
        NULL::text AS overridden_by_email,
        NULL::bigint AS ioc_source_id,
        NULL::text AS ioc_source_name,
        NULL::text AS confidence_source,
        NULL::text AS confidence_source_name,`;
  }
  const provenanceSql = hasProvenance
    ? `
        i.ioc_source_id,
        src.name AS ioc_source_name,
        i.confidence_source,
        i.confidence_source_name,`
    : `
        i.ioc_source_id,
        src.name AS ioc_source_name,
        NULL::text AS confidence_source,
        NULL::text AS confidence_source_name,`;
  return `
        i.source_confidence,
        i.feed_default_confidence,
        i.analyst_confidence_override,
        i.analyst_confidence_override_reason,
        i.analyst_confidence_overridden_by,
        i.analyst_confidence_overridden_at,
        u.username AS overridden_by_email,${provenanceSql}`;
}

export function iocConfidenceJoinSql(hasColumns, hasProvenance = false) {
  const userJoin = hasColumns ? 'LEFT JOIN users u ON u.public_id = i.analyst_confidence_overridden_by' : '';
  const sourceJoin = hasProvenance ? 'LEFT JOIN ioc_sources src ON src.id = i.ioc_source_id' : '';
  return [userJoin, sourceJoin].filter(Boolean).join('\n      ');
}

/** Test helper */
export function resetSchemaCapabilitiesCacheForTests() {
  cache.iocConfidenceColumns = null;
  cache.feedDefaultConfidenceColumn = null;
  cache.confidenceProvenanceColumns = null;
}

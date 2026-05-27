/** Cached schema feature flags (reset on process restart). */
const cache = {
  iocConfidenceColumns: null,
  feedDefaultConfidenceColumn: null
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

/** SQL fragment for IOC details / confidence queries when columns exist. */
export function iocConfidenceSelectSql(hasColumns) {
  if (!hasColumns) {
    return `
        NULL::text AS source_confidence,
        NULL::text AS feed_default_confidence,
        NULL::text AS analyst_confidence_override,
        NULL::text AS analyst_confidence_override_reason,
        NULL::uuid AS analyst_confidence_overridden_by,
        NULL::timestamptz AS analyst_confidence_overridden_at,
        NULL::text AS overridden_by_email,`;
  }
  return `
        i.source_confidence,
        i.feed_default_confidence,
        i.analyst_confidence_override,
        i.analyst_confidence_override_reason,
        i.analyst_confidence_overridden_by,
        i.analyst_confidence_overridden_at,
        u.username AS overridden_by_email,`;
}

export function iocConfidenceJoinSql(hasColumns) {
  return hasColumns ? 'LEFT JOIN users u ON u.public_id = i.analyst_confidence_overridden_by' : '';
}

/** Test helper */
export function resetSchemaCapabilitiesCacheForTests() {
  cache.iocConfidenceColumns = null;
  cache.feedDefaultConfidenceColumn = null;
}

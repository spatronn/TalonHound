/**
 * IOC-scoped hide/restore for feed (integration) source tags.
 * Does not mutate evidence notes or the global tags catalog.
 */

export function normalizeSourceTagKey(tag) {
  return String(tag || '').trim().toLowerCase();
}

export function normalizeSourceNameKey(sourceName) {
  return String(sourceName || '').trim();
}

/**
 * Filter feed_intelligence.tags by active hide overrides for this IOC.
 * Manual/analyst tags are unaffected (they are not in feed_intelligence.tags).
 *
 * @param {{ tags?: Array<{ tag?: string, normalized?: string, source_name?: string }> }} feedIntelligence
 * @param {Array<{ tag_normalized?: string, source_name?: string }>} activeOverrides
 */
export function applySourceTagOverrides(feedIntelligence, activeOverrides = []) {
  const fi = feedIntelligence && typeof feedIntelligence === 'object'
    ? feedIntelligence
    : { tags: [], classifications: [], source_metadata: [] };
  const tags = Array.isArray(fi.tags) ? fi.tags : [];
  const hidden = new Set(
    (activeOverrides || []).map((o) => {
      const tag = normalizeSourceTagKey(o.tag_normalized || o.tag_value || o.tag);
      const src = normalizeSourceNameKey(o.source_name).toLowerCase();
      return `${tag}::${src}`;
    }).filter((k) => !k.startsWith('::') && !k.endsWith('::'))
  );

  if (!hidden.size) {
    return { ...fi, tags };
  }

  return {
    ...fi,
    tags: tags.filter((t) => {
      const tag = normalizeSourceTagKey(t.normalized || t.tag);
      const src = normalizeSourceNameKey(t.source_name).toLowerCase();
      return !hidden.has(`${tag}::${src}`);
    })
  };
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {number} iocId
 */
export async function listActiveSourceTagOverrides(db, iocId) {
  const { rows } = await db.query(
    `SELECT id, ioc_id, ioc_observable_type, tag_value, tag_normalized, source_name,
            action, created_by, created_at
     FROM ioc_source_tag_overrides
     WHERE ioc_id = $1
       AND restored_at IS NULL
     ORDER BY created_at DESC, id DESC`,
    [iocId]
  );
  return rows;
}

/**
 * Idempotent hide: returns { created: boolean, row }
 * @param {import('pg').Pool} pool
 * @param {{
 *   iocId: number,
 *   iocObservableType: string,
 *   tagValue: string,
 *   sourceName: string,
 *   createdBy?: number|null
 * }} opts
 */
export async function hideSourceTag(pool, opts) {
  const iocId = Number(opts.iocId);
  const tagValue = String(opts.tagValue || '').trim();
  const sourceName = normalizeSourceNameKey(opts.sourceName);
  const tagNormalized = normalizeSourceTagKey(tagValue);
  const iocObservableType = String(opts.iocObservableType || '').trim();

  if (!Number.isFinite(iocId) || iocId <= 0) {
    const err = new Error('Invalid IOC id');
    err.code = 'invalid_ioc';
    throw err;
  }
  if (!tagNormalized) {
    const err = new Error('tag is required');
    err.code = 'invalid_tag';
    throw err;
  }
  if (!sourceName) {
    const err = new Error('source is required');
    err.code = 'invalid_source';
    throw err;
  }
  if (!iocObservableType) {
    const err = new Error('IOC type is required');
    err.code = 'invalid_ioc_type';
    throw err;
  }

  const existing = await pool.query(
    `SELECT id, ioc_id, ioc_observable_type, tag_value, tag_normalized, source_name,
            action, created_by, created_at
     FROM ioc_source_tag_overrides
     WHERE ioc_id = $1
       AND tag_normalized = $2
       AND lower(source_name) = lower($3)
       AND restored_at IS NULL
     LIMIT 1`,
    [iocId, tagNormalized, sourceName]
  );
  if (existing.rowCount) {
    return { created: false, row: existing.rows[0] };
  }

  const insert = await pool.query(
    `INSERT INTO ioc_source_tag_overrides (
       ioc_id, ioc_observable_type, tag_value, tag_normalized, source_name,
       action, created_by
     ) VALUES ($1, $2, $3, $4, $5, 'hidden', $6)
     RETURNING id, ioc_id, ioc_observable_type, tag_value, tag_normalized, source_name,
               action, created_by, created_at`,
    [iocId, iocObservableType, tagValue, tagNormalized, sourceName, opts.createdBy ?? null]
  );
  return { created: true, row: insert.rows[0] };
}

/**
 * Idempotent restore: returns { restored: boolean, row }
 */
export async function restoreSourceTag(pool, opts) {
  const iocId = Number(opts.iocId);
  const tagNormalized = normalizeSourceTagKey(opts.tagValue || opts.tagNormalized);
  const sourceName = normalizeSourceNameKey(opts.sourceName);

  if (!Number.isFinite(iocId) || iocId <= 0) {
    const err = new Error('Invalid IOC id');
    err.code = 'invalid_ioc';
    throw err;
  }
  if (!tagNormalized) {
    const err = new Error('tag is required');
    err.code = 'invalid_tag';
    throw err;
  }
  if (!sourceName) {
    const err = new Error('source is required');
    err.code = 'invalid_source';
    throw err;
  }

  const updated = await pool.query(
    `UPDATE ioc_source_tag_overrides
     SET restored_at = NOW(), restored_by = $4
     WHERE ioc_id = $1
       AND tag_normalized = $2
       AND lower(source_name) = lower($3)
       AND restored_at IS NULL
     RETURNING id, ioc_id, ioc_observable_type, tag_value, tag_normalized, source_name,
               action, created_by, created_at, restored_at, restored_by`,
    [iocId, tagNormalized, sourceName, opts.restoredBy ?? null]
  );

  if (updated.rowCount) {
    return { restored: true, row: updated.rows[0] };
  }

  return { restored: false, row: null };
}

/**
 * Whether evidence-derived feed tags include this tag+source for the IOC.
 * @param {Array<{ tag?: string, normalized?: string, source_name?: string }>} feedTags
 */
export function feedTagsIncludeSourceTag(feedTags, tagValue, sourceName) {
  const wantTag = normalizeSourceTagKey(tagValue);
  const wantSrc = normalizeSourceNameKey(sourceName).toLowerCase();
  return (feedTags || []).some((t) => {
    const tag = normalizeSourceTagKey(t.normalized || t.tag);
    const src = normalizeSourceNameKey(t.source_name).toLowerCase();
    return tag === wantTag && src === wantSrc;
  });
}

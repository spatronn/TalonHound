/**
 * Published Feed management: validation, CRUD, membership preview.
 * Extracted from routes/publishedFeeds.js so HTTP + MCP share one path.
 */

import {
  generatePublishedFeedSnapshot,
  normalizeFeedConfig,
  getLatestSnapshotMeta,
  resolveFeedIocTypes,
  resolveFeedFilterMode,
  FEED_FILTER_MODES,
  QUERY_FEED_SNAPSHOT_KEY,
  CURATED_FEED_SNAPSHOT_KEY,
  CURATED_FEED_MAX_IOCS,
  publishedFeedSnapshotIocTypeKey,
  isFixedAllWindowFeed,
  isCuratedModeFeed,
  resolveFormatsInput,
  resolvePublishedFeedFormats,
  resolvePublishedFeedFormat,
  previewPublishedFeedMembership,
  loadCuratedFeedPublicIds
} from './feedPublisherService.js';
import { normalizeFeedIocTypes, feedIocTypesKey } from './feedFormatter.js';
import { parseSearchQuery, isDslError } from './iocSearchDsl/index.js';
import { normalizeIncludeFeedKeys } from './publishedFeedSources.js';
import { pickSafeFields } from './auditRedaction.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function parseBodyArrays(body) {
  const out = { ...body };
  for (const key of ['include_feed_keys', 'include_tags', 'exclude_tags', 'ioc_types', 'curated_ioc_public_ids']) {
    if (out[key] != null && !Array.isArray(out[key])) {
      if (typeof out[key] === 'string') {
        try {
          out[key] = JSON.parse(out[key]);
        } catch {
          out[key] = out[key].split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
        }
      }
    }
  }
  return out;
}

export function resolveIocTypesInput(body) {
  if (body.ioc_types !== undefined) return body.ioc_types;
  if (body.ioc_type !== undefined) return body.ioc_type;
  return undefined;
}

/**
 * Effective filter mode for create/update. Prefers body; on PATCH falls back to
 * persisted mode. Unknown values resolve to basic.
 */
export function resolveFilterModeInput(body, existingRow = null) {
  const raw = body.filter_mode !== undefined
    ? body.filter_mode
    : (existingRow ? existingRow.filter_mode : undefined);
  const mode = String(raw ?? FEED_FILTER_MODES.BASIC).trim().toLowerCase();
  if (mode === FEED_FILTER_MODES.QUERY) return FEED_FILTER_MODES.QUERY;
  if (mode === FEED_FILTER_MODES.CURATED) return FEED_FILTER_MODES.CURATED;
  return FEED_FILTER_MODES.BASIC;
}

/**
 * Validate + normalize an Advanced Query using the IOC List parser.
 * @returns {{ normalized: string } | { error: string, dsl?: object }}
 */
export function validateAdvancedQuery(text) {
  const raw = String(text ?? '');
  if (!raw.trim()) return { error: 'advanced_query is required in query mode' };
  try {
    const { normalizedQuery } = parseSearchQuery(raw);
    return { normalized: normalizedQuery };
  } catch (err) {
    if (isDslError(err)) return { error: err.message, dsl: err.toJSON() };
    return { error: `Invalid advanced_query: ${err.message}` };
  }
}

/**
 * Normalize curated IOC inputs from curated_iocs[{public_id,reason?}] or
 * curated_ioc_public_ids: string[]. Max CURATED_FEED_MAX_IOCS.
 * @returns {{ ok: true, value: { public_id: string, reason: string|null }[] } | { ok: false, error: string }}
 */
export function normalizeCuratedIocInput(body) {
  const out = [];
  const seen = new Set();

  if (Array.isArray(body?.curated_iocs)) {
    for (const item of body.curated_iocs) {
      const publicId = String(item?.public_id ?? item?.ioc_public_id ?? '').trim();
      if (!publicId) continue;
      if (!UUID_RE.test(publicId)) {
        return { ok: false, error: `Invalid curated IOC public_id: ${publicId}` };
      }
      const key = publicId.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      const reason = item?.reason != null ? String(item.reason).trim() || null : null;
      out.push({ public_id: publicId, reason });
    }
  } else if (Array.isArray(body?.curated_ioc_public_ids)) {
    for (const raw of body.curated_ioc_public_ids) {
      const publicId = String(raw || '').trim();
      if (!publicId) continue;
      if (!UUID_RE.test(publicId)) {
        return { ok: false, error: `Invalid curated IOC public_id: ${publicId}` };
      }
      const key = publicId.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ public_id: publicId, reason: null });
    }
  } else if (body?.curated_iocs !== undefined || body?.curated_ioc_public_ids !== undefined) {
    return { ok: false, error: 'curated_iocs / curated_ioc_public_ids must be an array' };
  } else {
    return { ok: true, value: null }; // not provided
  }

  if (out.length > CURATED_FEED_MAX_IOCS) {
    return { ok: false, error: `curated membership exceeds maximum of ${CURATED_FEED_MAX_IOCS}` };
  }
  return { ok: true, value: out };
}

export function validateFeedPayload(body, partial = false, mode = FEED_FILTER_MODES.BASIC) {
  const errors = [];
  if (!partial || body.name !== undefined) {
    if (!String(body.name || '').trim()) errors.push('name is required');
  }
  if (body.filter_mode !== undefined) {
    const fm = String(body.filter_mode).trim().toLowerCase();
    if (
      fm !== FEED_FILTER_MODES.BASIC
      && fm !== FEED_FILTER_MODES.QUERY
      && fm !== FEED_FILTER_MODES.CURATED
    ) {
      errors.push("filter_mode must be 'basic', 'query', or 'curated'");
    }
  }
  // IOC Types / Window / Threat Feeds are Basic-Filters selectors; not required in
  // query or curated mode.
  const iocInput = resolveIocTypesInput(body);
  if (
    mode !== FEED_FILTER_MODES.QUERY
    && mode !== FEED_FILTER_MODES.CURATED
    && (!partial || iocInput !== undefined)
  ) {
    const norm = normalizeFeedIocTypes(iocInput);
    if (!norm.ok) errors.push(norm.error);
  }
  if (body.time_window !== undefined) {
    const tw = String(body.time_window || '').toLowerCase();
    const mapped = ['1d', '3d', '7d', 'all', 'last_1_day', 'last_3_days', 'last_7_days'].includes(tw);
    if (!mapped) errors.push('time_window invalid');
  }
  if (body.refresh_interval_minutes !== undefined) {
    const n = Number(body.refresh_interval_minutes);
    if (!Number.isFinite(n) || n < 5) errors.push('refresh_interval_minutes must be >= 5');
  }
  if (body.formats !== undefined || body.output_format !== undefined || body.format !== undefined) {
    const resolved = resolveFormatsInput(body);
    if (!resolved.ok) errors.push(resolved.error);
  }
  for (const key of ['include_source_metadata', 'include_classification', 'include_enrichment']) {
    if (body[key] !== undefined && typeof body[key] !== 'boolean') {
      errors.push(`${key} must be a boolean`);
    }
  }
  if (mode === FEED_FILTER_MODES.CURATED && !partial) {
    const curated = normalizeCuratedIocInput(body);
    if (!curated.ok) errors.push(curated.error);
  } else if (
    mode === FEED_FILTER_MODES.CURATED
    && (body.curated_iocs !== undefined || body.curated_ioc_public_ids !== undefined)
  ) {
    const curated = normalizeCuratedIocInput(body);
    if (!curated.ok) errors.push(curated.error);
  }
  return errors;
}

export async function resolveIncludeFeedKeys(pool, raw, existingRow = null) {
  const existingKeys = existingRow?.include_feed_keys
    ? (Array.isArray(existingRow.include_feed_keys)
      ? existingRow.include_feed_keys
      : (typeof existingRow.include_feed_keys === 'string'
        ? JSON.parse(existingRow.include_feed_keys)
        : []))
    : [];
  return normalizeIncludeFeedKeys(pool, raw, { existingKeys });
}

export function toPublicFeed(row, extra = {}) {
  if (!row) return null;
  const ioc_types = resolveFeedIocTypes(row);
  const formats = resolvePublishedFeedFormats(row);
  const mode = resolveFeedFilterMode(row);
  const out = {
    id: Number(row.id),
    name: row.name,
    slug: row.slug,
    description: row.description,
    enabled: Boolean(row.enabled),
    filter_mode: mode,
    advanced_query: row.advanced_query != null ? String(row.advanced_query) : null,
    ioc_types,
    formats,
    format: resolvePublishedFeedFormat({ formats }),
    include_source_metadata: row.include_source_metadata !== false,
    include_classification: row.include_classification !== false,
    include_enrichment: row.include_enrichment === true,
    min_confidence: row.min_confidence,
    include_feed_keys: row.include_feed_keys,
    include_tags: row.include_tags,
    exclude_tags: row.exclude_tags,
    exclude_false_positive: Boolean(row.exclude_false_positive),
    exclude_expired: Boolean(row.exclude_expired),
    time_window: row.time_window,
    max_items: row.max_items,
    refresh_interval_minutes: Number(row.refresh_interval_minutes || 15),
    last_generated_at: row.last_generated_at,
    last_status: row.last_status,
    last_error: row.last_error,
    consecutive_failures: Number(row.consecutive_failures || 0),
    failing_since: row.failing_since || null,
    first_failure_error: row.first_failure_error || null,
    created_at: row.created_at,
    updated_at: row.updated_at,
    ...extra
  };
  if (mode === FEED_FILTER_MODES.CURATED) {
    if (extra.curated_ioc_count != null) out.curated_ioc_count = Number(extra.curated_ioc_count);
    if (Array.isArray(extra.curated_ioc_public_ids)) {
      out.curated_ioc_public_ids = extra.curated_ioc_public_ids;
    }
  }
  return out;
}

export function feedAuditSnapshot(row) {
  const pub = toPublicFeed(normalizeFeedConfig(row));
  return pickSafeFields(pub, [
    'id', 'name', 'enabled', 'filter_mode', 'advanced_query', 'ioc_types', 'min_confidence',
    'time_window', 'max_items', 'refresh_interval_minutes', 'exclude_false_positive', 'exclude_expired',
    'formats', 'format', 'include_source_metadata', 'include_classification', 'include_enrichment',
    'curated_ioc_count'
  ]);
}

function slugifyFeedName(name) {
  const base = String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return base || 'feed';
}

export async function generateUniqueFeedSlug(pool, name) {
  const base = slugifyFeedName(name);
  const { rows } = await pool.query(
    'SELECT slug FROM published_feeds WHERE slug = $1 OR slug LIKE $2',
    [base, `${base}-%`]
  );
  const taken = new Set(rows.map((r) => r.slug));
  if (!taken.has(base)) return base;
  for (let i = 2; i < 10000; i += 1) {
    const candidate = `${base}-${i}`;
    if (!taken.has(candidate)) return candidate;
  }
  return `${base}-${Date.now()}`;
}

export async function latestItemCount(pool, feedRow) {
  const feed = normalizeFeedConfig(feedRow);
  if (!feed?.id) return null;
  const key = publishedFeedSnapshotIocTypeKey(feed);
  const window = isFixedAllWindowFeed(feed) ? 'all' : feed.time_window;
  const snapshot = await getLatestSnapshotMeta(pool, feed.id, key, window, resolvePublishedFeedFormat(feed));
  return snapshot?.item_count != null ? Number(snapshot.item_count) : null;
}

async function curatedSummary(pool, feedId, { includeIds = false } = {}) {
  if (includeIds) {
    const ids = await loadCuratedFeedPublicIds(pool, feedId);
    return { curated_ioc_count: ids.length, curated_ioc_public_ids: ids };
  }
  const { rows } = await pool.query(
    'SELECT COUNT(*)::int AS n FROM published_feed_curated_iocs WHERE feed_id = $1',
    [feedId]
  );
  return { curated_ioc_count: Number(rows[0]?.n || 0) };
}

async function replaceCuratedIocs(client, feedId, items, createdBy = null) {
  await client.query('DELETE FROM published_feed_curated_iocs WHERE feed_id = $1', [feedId]);
  if (!items?.length) return;
  for (const item of items) {
    await client.query(
      `INSERT INTO published_feed_curated_iocs (feed_id, ioc_public_id, reason, created_by)
       VALUES ($1, $2::uuid, $3, $4)
       ON CONFLICT (feed_id, ioc_public_id) DO UPDATE SET reason = EXCLUDED.reason`,
      [feedId, item.public_id, item.reason, createdBy]
    );
  }
}

function mapTimeWindow(raw, mode) {
  if (mode === FEED_FILTER_MODES.QUERY || mode === FEED_FILTER_MODES.CURATED) return 'all';
  const tw = String(raw || 'all').toLowerCase();
  return tw === 'last_1_day' ? '1d' : tw === 'last_3_days' ? '3d' : tw === 'last_7_days' ? '7d' : tw;
}

export async function listFeeds(pool) {
  const { rows } = await pool.query(`SELECT * FROM published_feeds ORDER BY created_at DESC`);
  const feeds = [];
  for (const row of rows) {
    const norm = normalizeFeedConfig(row);
    const last_item_count = await latestItemCount(pool, norm);
    const extra = { last_item_count };
    if (resolveFeedFilterMode(norm) === FEED_FILTER_MODES.CURATED) {
      Object.assign(extra, await curatedSummary(pool, norm.id));
    }
    feeds.push(toPublicFeed(norm, extra));
  }
  return { feeds };
}

export async function getFeed(pool, id, { includeCuratedIds = true } = {}) {
  const feedId = Number(id);
  if (!Number.isFinite(feedId)) return { error: { status: 400, message: 'Invalid id' } };
  const { rows } = await pool.query('SELECT * FROM published_feeds WHERE id = $1', [feedId]);
  if (!rows.length) return { error: { status: 404, message: 'Feed not found' } };
  const feed = normalizeFeedConfig(rows[0]);
  const last_item_count = await latestItemCount(pool, rows[0]);
  const extra = { last_item_count };
  if (resolveFeedFilterMode(feed) === FEED_FILTER_MODES.CURATED) {
    Object.assign(extra, await curatedSummary(pool, feed.id, { includeIds: includeCuratedIds }));
  }
  return { feed: toPublicFeed(feed, extra), row: rows[0] };
}

export async function createFeed(pool, rawBody, opts = {}) {
  const body = parseBodyArrays(rawBody || {});
  const mode = resolveFilterModeInput(body);
  const errors = validateFeedPayload(body, false, mode);
  if (errors.length) return { error: { status: 400, message: errors.join('; ') } };

  let advancedQuery = null;
  if (mode === FEED_FILTER_MODES.QUERY) {
    const q = validateAdvancedQuery(body.advanced_query);
    if (q.error) {
      return { error: { status: 400, message: q.error, ...(q.dsl ? { dsl: q.dsl } : {}) } };
    }
    advancedQuery = q.normalized;
  }

  let curatedItems = [];
  if (mode === FEED_FILTER_MODES.CURATED) {
    const curated = normalizeCuratedIocInput(body);
    if (!curated.ok) return { error: { status: 400, message: curated.error } };
    curatedItems = curated.value || [];
  }

  const feedKeys = await resolveIncludeFeedKeys(pool, body.include_feed_keys);
  if (feedKeys.error) return { error: { status: 400, message: feedKeys.error } };

  const timeWindow = mapTimeWindow(body.time_window, mode);
  const iocNorm = normalizeFeedIocTypes(resolveIocTypesInput(body));
  const iocTypes = iocNorm.ok ? iocNorm.value : ['ip'];
  const formatsIn = resolveFormatsInput(body);
  if (!formatsIn.ok) return { error: { status: 400, message: formatsIn.error } };

  if (opts.dryRun) {
    return {
      dry_run: true,
      would_create: {
        name: String(body.name).trim(),
        filter_mode: mode,
        advanced_query: advancedQuery,
        curated_ioc_count: curatedItems.length,
        time_window: timeWindow,
        ioc_types: iocTypes,
        formats: formatsIn.value
      }
    };
  }

  const slug = await generateUniqueFeedSlug(pool, body.name);
  const insertParams = [
    String(body.name).trim(),
    slug,
    body.description || null,
    body.enabled,
    JSON.stringify(iocTypes),
    JSON.stringify(formatsIn.value),
    body.min_confidence ?? null,
    feedKeys.value.length ? JSON.stringify(feedKeys.value) : null,
    body.include_tags ? JSON.stringify(body.include_tags) : null,
    body.exclude_tags ? JSON.stringify(body.exclude_tags) : null,
    body.exclude_false_positive,
    body.exclude_expired,
    timeWindow,
    body.max_items ?? null,
    body.refresh_interval_minutes ?? 15,
    mode,
    advancedQuery,
    body.include_source_metadata ?? null,
    body.include_classification ?? null,
    body.include_enrichment ?? null
  ];
  const insertSql = `INSERT INTO published_feeds (
         name, slug, description, enabled, ioc_types, formats, min_confidence,
         include_feed_keys, include_tags, exclude_tags,
         exclude_false_positive, exclude_expired,
         time_window, max_items, refresh_interval_minutes,
         filter_mode, advanced_query,
         include_source_metadata, include_classification, include_enrichment
       ) VALUES (
         $1, $2, $3, COALESCE($4, TRUE), $5::jsonb, $6::jsonb, $7,
         $8::jsonb, $9::jsonb, $10::jsonb,
         COALESCE($11, TRUE), COALESCE($12, TRUE),
         $13, $14, COALESCE($15, 15),
         $16, $17,
         COALESCE($18, TRUE), COALESCE($19, TRUE), COALESCE($20, FALSE)
       )
       RETURNING *`;

  // Curated creates need a transaction for the membership set; basic/query keep the
  // legacy single-statement path (compatible with route unit-test mocks).
  let rows;
  if (mode === FEED_FILTER_MODES.CURATED) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const inserted = await client.query(insertSql, insertParams);
      rows = inserted.rows;
      await replaceCuratedIocs(client, rows[0].id, curatedItems, opts.createdBy || null);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  } else {
    const inserted = await pool.query(insertSql, insertParams);
    rows = inserted.rows;
  }

  const extra = mode === FEED_FILTER_MODES.CURATED
    ? {
      curated_ioc_count: curatedItems.length,
      curated_ioc_public_ids: curatedItems.map((c) => c.public_id)
    }
    : {};
  return {
    feed: toPublicFeed(normalizeFeedConfig(rows[0]), extra),
    row: rows[0]
  };
}

export async function updateFeed(pool, id, rawBody, opts = {}) {
  const feedId = Number(id);
  if (!Number.isFinite(feedId)) return { error: { status: 400, message: 'Invalid id' } };
  const body = parseBodyArrays(rawBody || {});

  const existingQ = await pool.query('SELECT * FROM published_feeds WHERE id = $1', [feedId]);
  if (!existingQ.rows.length) return { error: { status: 404, message: 'Feed not found' } };
  const existingRow = existingQ.rows[0];
  const existingMode = resolveFeedFilterMode(existingRow);
  const mode = resolveFilterModeInput(body, { filter_mode: existingMode });

  const errors = validateFeedPayload(body, true, mode);
  if (errors.length) return { error: { status: 400, message: errors.join('; ') } };

  let advancedQueryUpdate;
  if (body.filter_mode !== undefined || body.advanced_query !== undefined) {
    if (mode === FEED_FILTER_MODES.QUERY) {
      const sourceText = body.advanced_query !== undefined
        ? body.advanced_query
        : existingRow.advanced_query;
      const q = validateAdvancedQuery(sourceText);
      if (q.error) {
        return { error: { status: 400, message: q.error, ...(q.dsl ? { dsl: q.dsl } : {}) } };
      }
      advancedQueryUpdate = q.normalized;
    } else {
      advancedQueryUpdate = null;
    }
  }

  let curatedReplace = null;
  if (
    mode === FEED_FILTER_MODES.CURATED
    && (body.curated_iocs !== undefined || body.curated_ioc_public_ids !== undefined)
  ) {
    const curated = normalizeCuratedIocInput(body);
    if (!curated.ok) return { error: { status: 400, message: curated.error } };
    curatedReplace = curated.value || [];
  } else if (body.filter_mode !== undefined && mode !== FEED_FILTER_MODES.CURATED) {
    // Leaving curated mode: clear membership set.
    curatedReplace = [];
  }

  if (body.include_feed_keys !== undefined) {
    const feedKeys = await resolveIncludeFeedKeys(pool, body.include_feed_keys, existingRow);
    if (feedKeys.error) return { error: { status: 400, message: feedKeys.error } };
    body.include_feed_keys = feedKeys.value;
  }

  const fields = [];
  const params = [feedId];
  const setField = (col, val, cast = '') => {
    params.push(val);
    fields.push(`${col} = $${params.length}${cast}`);
  };

  if (body.filter_mode !== undefined) setField('filter_mode', mode);
  if (advancedQueryUpdate !== undefined) setField('advanced_query', advancedQueryUpdate);
  if (body.name !== undefined) setField('name', String(body.name).trim());
  if (body.description !== undefined) setField('description', body.description || null);
  if (body.enabled !== undefined) setField('enabled', Boolean(body.enabled));
  const iocInput = resolveIocTypesInput(body);
  if (iocInput !== undefined) {
    const iocNorm = normalizeFeedIocTypes(iocInput);
    const iocTypes = iocNorm.ok
      ? iocNorm.value
      : ((mode === FEED_FILTER_MODES.QUERY || mode === FEED_FILTER_MODES.CURATED) ? ['ip'] : iocNorm.value);
    setField('ioc_types', JSON.stringify(iocTypes), '::jsonb');
  }
  if (body.formats !== undefined || body.format !== undefined || body.output_format !== undefined) {
    const formatsIn = resolveFormatsInput(body, resolvePublishedFeedFormats(existingRow));
    if (!formatsIn.ok) return { error: { status: 400, message: formatsIn.error } };
    setField('formats', JSON.stringify(formatsIn.value), '::jsonb');
  }
  if (body.include_source_metadata !== undefined) setField('include_source_metadata', Boolean(body.include_source_metadata));
  if (body.include_classification !== undefined) setField('include_classification', Boolean(body.include_classification));
  if (body.include_enrichment !== undefined) setField('include_enrichment', Boolean(body.include_enrichment));
  if (body.min_confidence !== undefined) setField('min_confidence', body.min_confidence);
  if (body.include_feed_keys !== undefined) {
    setField('include_feed_keys', JSON.stringify(body.include_feed_keys || []), '::jsonb');
  }
  if (body.include_tags !== undefined) setField('include_tags', JSON.stringify(body.include_tags || []), '::jsonb');
  if (body.exclude_tags !== undefined) setField('exclude_tags', JSON.stringify(body.exclude_tags || []), '::jsonb');
  if (body.exclude_false_positive !== undefined) setField('exclude_false_positive', Boolean(body.exclude_false_positive));
  if (body.exclude_expired !== undefined) setField('exclude_expired', Boolean(body.exclude_expired));
  if (mode === FEED_FILTER_MODES.QUERY || mode === FEED_FILTER_MODES.CURATED) {
    setField('time_window', 'all');
  } else if (body.time_window !== undefined) {
    setField('time_window', mapTimeWindow(body.time_window, mode));
  }
  if (body.max_items !== undefined) setField('max_items', body.max_items);
  if (body.refresh_interval_minutes !== undefined) {
    setField('refresh_interval_minutes', Number(body.refresh_interval_minutes));
  }

  if (!fields.length && curatedReplace === null) {
    return { error: { status: 400, message: 'No fields to update' } };
  }

  if (opts.dryRun) {
    return {
      dry_run: true,
      would_update: {
        id: feedId,
        filter_mode: mode,
        changed_fields: Object.keys(body),
        curated_replace_count: curatedReplace != null ? curatedReplace.length : null
      }
    };
  }

  const before = feedAuditSnapshot(existingRow);
  const runUpdate = async (db) => {
    let rows = [existingRow];
    if (fields.length) {
      const updated = await db.query(
        `UPDATE published_feeds SET ${fields.join(', ')}, updated_at = NOW() WHERE id = $1 RETURNING *`,
        params
      );
      if (!updated.rows.length) {
        return { error: { status: 404, message: 'Feed not found' } };
      }
      rows = updated.rows;
    } else if (curatedReplace !== null) {
      const touched = await db.query(
        `UPDATE published_feeds SET updated_at = NOW() WHERE id = $1 RETURNING *`,
        [feedId]
      );
      rows = touched.rows;
    }
    if (curatedReplace !== null) {
      await replaceCuratedIocs(db, feedId, curatedReplace, opts.createdBy || null);
    }
    return { rows };
  };

  let rows;
  if (curatedReplace !== null) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const outcome = await runUpdate(client);
      if (outcome.error) {
        await client.query('ROLLBACK');
        return { error: outcome.error };
      }
      rows = outcome.rows;
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  } else {
    const outcome = await runUpdate(pool);
    if (outcome.error) return { error: outcome.error };
    rows = outcome.rows;
  }

  const extra = {};
  if (resolveFeedFilterMode(rows[0]) === FEED_FILTER_MODES.CURATED) {
    Object.assign(extra, await curatedSummary(pool, feedId, { includeIds: true }));
  }
  return {
    feed: toPublicFeed(normalizeFeedConfig(rows[0]), extra),
    row: rows[0],
    before
  };
}

/**
 * Preview membership for a proposed definition (admin) or existing feed_id (any auth).
 * Never writes / never regenerates.
 */
export async function previewFeedMembership(pool, rawBody = {}) {
  const body = parseBodyArrays(rawBody || {});
  const limit = body.limit;
  const offset = body.offset ?? body.cursor ?? 0;
  const compareToFeedId = body.compare_to_feed_id ?? null;

  if (body.feed_id != null && Object.keys(body).every(
    (k) => ['feed_id', 'limit', 'offset', 'cursor', 'compare_to_feed_id'].includes(k)
  )) {
    const got = await getFeed(pool, body.feed_id, { includeCuratedIds: true });
    if (got.error) return { error: got.error };
    const feed = {
      ...normalizeFeedConfig(got.row),
      curated_ioc_public_ids: got.feed.curated_ioc_public_ids
    };
    const preview = await previewPublishedFeedMembership(pool, feed, {
      limit,
      offset,
      publicIds: isCuratedModeFeed(feed) ? feed.curated_ioc_public_ids : undefined,
      compareToFeedId
    });
    return { preview };
  }

  // Proposed definition path (name is optional for preview-only).
  const mode = resolveFilterModeInput(body);
  const errors = validateFeedPayload({ ...body, name: body.name || 'preview' }, false, mode)
    .filter((e) => e !== 'name is required');
  let advancedQuery = null;
  if (mode === FEED_FILTER_MODES.QUERY) {
    const q = validateAdvancedQuery(body.advanced_query);
    if (q.error) errors.push(q.error);
    else advancedQuery = q.normalized;
  }
  let curatedIds = [];
  if (mode === FEED_FILTER_MODES.CURATED) {
    const curated = normalizeCuratedIocInput(body);
    if (!curated.ok) errors.push(curated.error);
    else curatedIds = (curated.value || []).map((c) => c.public_id);
  }

  if (errors.length) {
    return {
      preview: {
        filter_mode: mode,
        normalized_query: advancedQuery,
        total: 0,
        counts_by_type: {},
        items: [],
        truncated: false,
        warnings: [],
        diff: null,
        validation_errors: errors
      }
    };
  }

  const feedKeys = body.include_feed_keys !== undefined
    ? await resolveIncludeFeedKeys(pool, body.include_feed_keys)
    : { value: body.include_feed_keys || null };
  if (feedKeys.error) {
    return {
      preview: {
        filter_mode: mode,
        normalized_query: advancedQuery,
        total: 0,
        counts_by_type: {},
        items: [],
        truncated: false,
        warnings: [],
        diff: null,
        validation_errors: [feedKeys.error]
      }
    };
  }

  const iocNorm = normalizeFeedIocTypes(resolveIocTypesInput(body));
  const feed = normalizeFeedConfig({
    filter_mode: mode,
    advanced_query: advancedQuery,
    ioc_types: iocNorm.ok ? iocNorm.value : ['ip'],
    time_window: mapTimeWindow(body.time_window, mode),
    min_confidence: body.min_confidence ?? null,
    include_feed_keys: feedKeys.value,
    include_tags: body.include_tags || null,
    exclude_tags: body.exclude_tags || null,
    exclude_false_positive: body.exclude_false_positive !== false,
    exclude_expired: body.exclude_expired !== false,
    max_items: body.max_items ?? null,
    curated_ioc_public_ids: curatedIds
  });

  const preview = await previewPublishedFeedMembership(pool, feed, {
    limit,
    offset,
    publicIds: mode === FEED_FILTER_MODES.CURATED ? curatedIds : undefined,
    compareToFeedId
  });
  return { preview };
}

export async function listFeedMembership(pool, id, opts = {}) {
  const got = await getFeed(pool, id, { includeCuratedIds: true });
  if (got.error) return { error: got.error };
  const feed = {
    ...normalizeFeedConfig(got.row),
    curated_ioc_public_ids: got.feed.curated_ioc_public_ids
  };
  const preview = await previewPublishedFeedMembership(pool, feed, {
    limit: opts.limit,
    offset: opts.offset ?? 0,
    publicIds: isCuratedModeFeed(feed) ? feed.curated_ioc_public_ids : undefined
  });
  return {
    feed: {
      id: got.feed.id,
      name: got.feed.name,
      filter_mode: got.feed.filter_mode,
      last_status: got.feed.last_status,
      last_generated_at: got.feed.last_generated_at,
      last_error: got.feed.last_error,
      refresh_interval_minutes: got.feed.refresh_interval_minutes
    },
    membership: preview
  };
}

export async function regenerateFeed(pool, id, { force = true } = {}) {
  const feedId = Number(id);
  if (!Number.isFinite(feedId)) return { error: { status: 400, message: 'Invalid id' } };
  const result = await generatePublishedFeedSnapshot(pool, feedId, { force });
  if (result?.reason === 'generation_in_progress') {
    return {
      error: {
        status: 409,
        message: 'Generation already in progress',
        code: 'generation_in_progress',
        regeneration: result
      }
    };
  }
  const got = await getFeed(pool, feedId);
  if (got.error) return { error: got.error };
  return { feed: got.feed, regeneration: result, row: got.row };
}

// Re-exports used by routes/tests that previously imported snapshot keys from the route module.
export {
  FEED_FILTER_MODES,
  QUERY_FEED_SNAPSHOT_KEY,
  CURATED_FEED_SNAPSHOT_KEY,
  feedIocTypesKey
};

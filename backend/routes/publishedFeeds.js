import { requireRole, ROLES } from '../lib/rbac.js';
import { generateFeedAccessToken, hashFeedAccessToken, buildPublicFeedUrl } from '../lib/feedAccessToken.js';
import {
  generatePublishedFeedSnapshot,
  normalizeFeedConfig,
  getLatestSnapshotMeta,
  resolveFeedIocTypes,
  resolveFeedFilterMode,
  FEED_FILTER_MODES,
  QUERY_FEED_SNAPSHOT_KEY
} from '../lib/feedPublisherService.js';
import { normalizeFeedIocTypes, feedIocTypesKey } from '../lib/feedFormatter.js';
import { parseSearchQuery, isDslError } from '../lib/iocSearchDsl/index.js';
import {
  fetchPublishedFeedSourceOptions,
  normalizeIncludeFeedKeys
} from '../lib/publishedFeedSources.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';

function toPublicFeed(row, extra = {}) {
  if (!row) return null;
  const ioc_types = resolveFeedIocTypes(row);
  return {
    id: Number(row.id),
    name: row.name,
    slug: row.slug,
    description: row.description,
    enabled: Boolean(row.enabled),
    filter_mode: resolveFeedFilterMode(row),
    advanced_query: row.advanced_query != null ? String(row.advanced_query) : null,
    ioc_types,
    format: row.format,
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
    created_at: row.created_at,
    updated_at: row.updated_at,
    ...extra
  };
}

function toPublicAccessKey(row) {
  if (!row) return null;
  return {
    id: Number(row.id),
    feed_id: Number(row.feed_id),
    name: row.name,
    enabled: Boolean(row.enabled),
    last_used_at: row.last_used_at,
    last_used_ip: row.last_used_ip,
    created_at: row.created_at,
    revoked_at: row.revoked_at
  };
}

function parseBodyArrays(body) {
  const out = { ...body };
  for (const key of ['include_feed_keys', 'include_tags', 'exclude_tags', 'ioc_types']) {
    if (out[key] != null && !Array.isArray(out[key])) {
      if (typeof out[key] === 'string') {
        try {
          out[key] = JSON.parse(out[key]);
        } catch {
          out[key] = out[key].split(',').map((s) => s.trim()).filter(Boolean);
        }
      }
    }
  }
  return out;
}

/** Accept ioc_types[] (preferred) or legacy scalar ioc_type during transition. */
function resolveIocTypesInput(body) {
  if (body.ioc_types !== undefined) return body.ioc_types;
  if (body.ioc_type !== undefined) return body.ioc_type;
  return undefined;
}

/**
 * Effective filter mode for a create/update. Prefers the request body; on PATCH falls back
 * to the persisted mode. Anything other than 'query' resolves to 'basic'.
 */
function resolveFilterModeInput(body, existingRow = null) {
  const raw = body.filter_mode !== undefined
    ? body.filter_mode
    : (existingRow ? existingRow.filter_mode : undefined);
  const mode = String(raw ?? FEED_FILTER_MODES.BASIC).trim().toLowerCase();
  return mode === FEED_FILTER_MODES.QUERY ? FEED_FILTER_MODES.QUERY : FEED_FILTER_MODES.BASIC;
}

/**
 * Validate + normalize an Advanced Query using the SAME IOC List parser. Non-empty and
 * syntactically valid (fields/operators from the shared allowlist) or an error is returned.
 * @returns {{ normalized: string } | { error: string, dsl?: object }}
 */
function validateAdvancedQuery(text) {
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

async function resolveIncludeFeedKeys(pool, raw, existingRow = null) {
  const existingKeys = existingRow?.include_feed_keys
    ? (Array.isArray(existingRow.include_feed_keys)
      ? existingRow.include_feed_keys
      : (typeof existingRow.include_feed_keys === 'string'
        ? JSON.parse(existingRow.include_feed_keys)
        : []))
    : [];
  return normalizeIncludeFeedKeys(pool, raw, { existingKeys });
}

function validateFeedPayload(body, partial = false, mode = FEED_FILTER_MODES.BASIC) {
  const errors = [];
  if (!partial || body.name !== undefined) {
    if (!String(body.name || '').trim()) errors.push('name is required');
  }
  if (body.filter_mode !== undefined) {
    const fm = String(body.filter_mode).trim().toLowerCase();
    if (fm !== FEED_FILTER_MODES.BASIC && fm !== FEED_FILTER_MODES.QUERY) {
      errors.push("filter_mode must be 'basic' or 'query'");
    }
  }
  // IOC Types / Default Window / Threat Feeds are Basic-Filters selectors; do not require
  // (or reject) them when the feed is in Advanced Query mode.
  const iocInput = resolveIocTypesInput(body);
  if (mode !== FEED_FILTER_MODES.QUERY && (!partial || iocInput !== undefined)) {
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
  if (body.format !== undefined && body.format !== 'txt') {
    errors.push('only txt format is supported');
  }
  return errors;
}

async function latestItemCount(pool, feedRow) {
  const feed = normalizeFeedConfig(feedRow);
  if (!feed?.id) return null;
  const queryMode = resolveFeedFilterMode(feed) === FEED_FILTER_MODES.QUERY;
  const key = queryMode ? QUERY_FEED_SNAPSHOT_KEY : feedIocTypesKey(resolveFeedIocTypes(feed));
  const window = queryMode ? 'all' : feed.time_window;
  const snapshot = await getLatestSnapshotMeta(pool, feed.id, key, window);
  return snapshot?.item_count != null ? Number(snapshot.item_count) : null;
}

function feedAuditSnapshot(row) {
  const pub = toPublicFeed(normalizeFeedConfig(row));
  return pickSafeFields(pub, [
    'id', 'name', 'enabled', 'filter_mode', 'advanced_query', 'ioc_types', 'min_confidence',
    'time_window', 'max_items', 'refresh_interval_minutes', 'exclude_false_positive', 'exclude_expired'
  ]);
}

function accessKeyAuditSnapshot(row) {
  return pickSafeFields(toPublicAccessKey(row), ['id', 'feed_id', 'name', 'enabled']);
}

// Kebab-case slug used in the public pull URL. Mirrors migration 133's backfill.
function slugifyFeedName(name) {
  const base = String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return base || 'feed';
}

/** First free slug of the form base, base-2, base-3, … (unique index is the backstop). */
async function generateUniqueFeedSlug(pool, name) {
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

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function }} audit
 */
export function registerPublishedFeedRoutes(app, pool, audit) {
  app.get('/api/published-feeds/source-options', async (req, res) => {
    try {
      const selectedRaw = req.query?.selected_keys;
      const selectedKeys = selectedRaw
        ? String(selectedRaw).split(',').map((k) => k.trim()).filter(Boolean)
        : [];
      const { sources } = await fetchPublishedFeedSourceOptions(pool, { selectedKeys });
      return res.json({ sources });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list publishable source feeds', detail: err.message });
    }
  });

  app.get('/api/published-feeds', async (_req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT * FROM published_feeds ORDER BY created_at DESC`
      );
      const feeds = [];
      for (const row of rows) {
        const norm = normalizeFeedConfig(row);
        const last_item_count = await latestItemCount(pool, norm);
        feeds.push(toPublicFeed(norm, { last_item_count }));
      }
      return res.json({ feeds });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list published feeds', detail: err.message });
    }
  });

  app.post('/api/published-feeds', requireRole(ROLES.ADMIN), async (req, res) => {
    const body = parseBodyArrays(req.body || {});
    const mode = resolveFilterModeInput(body);
    const errors = validateFeedPayload(body, false, mode);
    if (errors.length) return res.status(400).json({ message: errors.join('; ') });

    // Advanced Query mode: query is the base set; validate it with the IOC List parser.
    let advancedQuery = null;
    if (mode === FEED_FILTER_MODES.QUERY) {
      const q = validateAdvancedQuery(body.advanced_query);
      if (q.error) return res.status(400).json({ message: q.error, ...(q.dsl ? { error: q.dsl } : {}) });
      advancedQuery = q.normalized;
    }

    const feedKeys = await resolveIncludeFeedKeys(pool, body.include_feed_keys);
    if (feedKeys.error) return res.status(400).json({ message: feedKeys.error });

    const tw = String(body.time_window || 'all').toLowerCase();
    const timeWindow = tw === 'last_1_day' ? '1d' : tw === 'last_3_days' ? '3d' : tw === 'last_7_days' ? '7d' : tw;

    try {
      const slug = await generateUniqueFeedSlug(pool, body.name);
      // ioc_types stays a valid non-empty array even in query mode (DB constraint + Basic
      // fields are preserved). It never filters a query-mode feed's base set.
      const iocNorm = normalizeFeedIocTypes(resolveIocTypesInput(body));
      const iocTypes = iocNorm.ok ? iocNorm.value : ['ip'];
      const { rows } = await pool.query(
        `INSERT INTO published_feeds (
           name, slug, description, enabled, ioc_types, format, min_confidence,
           include_feed_keys, include_tags, exclude_tags,
           exclude_false_positive, exclude_expired,
           time_window, max_items, refresh_interval_minutes,
           filter_mode, advanced_query
         ) VALUES (
           $1, $2, $3, COALESCE($4, TRUE), $5::jsonb, COALESCE($6, 'txt'), $7,
           $8::jsonb, $9::jsonb, $10::jsonb,
           COALESCE($11, TRUE), COALESCE($12, TRUE),
           $13, $14, COALESCE($15, 15),
           $16, $17
         )
         RETURNING *`,
        [
          String(body.name).trim(),
          slug,
          body.description || null,
          body.enabled,
          JSON.stringify(iocTypes),
          body.format || 'txt',
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
          advancedQuery
        ]
      );
      const feed = toPublicFeed(normalizeFeedConfig(rows[0]));
      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.FEED_CREATED,
        entityType: AUDIT_ENTITY.FEED,
        entityId: String(feed.id),
        entityDisplay: feed.name,
        severity: AUDIT_SEVERITY.INFO,
        after: feedAuditSnapshot(rows[0])
      });
      return res.status(201).json({ feed });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to create published feed', detail: err.message });
    }
  });

  app.get('/api/published-feeds/:id', async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    try {
      const { rows } = await pool.query('SELECT * FROM published_feeds WHERE id = $1', [id]);
      if (!rows.length) return res.status(404).json({ message: 'Feed not found' });
      const feed = normalizeFeedConfig(rows[0]);
      const last_item_count = await latestItemCount(pool, rows[0]);
      return res.json({ feed: toPublicFeed(feed, { last_item_count }) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to fetch feed', detail: err.message });
    }
  });

  app.patch('/api/published-feeds/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    const body = parseBodyArrays(req.body || {});

    // Load the existing feed up front: the effective filter mode (and thus which fields are
    // required/validated) can depend on the persisted mode when the body omits filter_mode.
    const existingQ = await pool.query('SELECT * FROM published_feeds WHERE id = $1', [id]);
    if (!existingQ.rows.length) return res.status(404).json({ message: 'Feed not found' });
    const existingRow = existingQ.rows[0];
    const existingMode = resolveFeedFilterMode(existingRow);
    const mode = resolveFilterModeInput(body, { filter_mode: existingMode });

    const errors = validateFeedPayload(body, true, mode);
    if (errors.length) return res.status(400).json({ message: errors.join('; ') });

    // Resolve + validate the Advanced Query when the effective mode is 'query'. The query
    // text may come from the body or, if unchanged, from the persisted row.
    let advancedQueryUpdate; // undefined = leave column untouched
    if (body.filter_mode !== undefined || body.advanced_query !== undefined) {
      if (mode === FEED_FILTER_MODES.QUERY) {
        const sourceText = body.advanced_query !== undefined
          ? body.advanced_query
          : existingRow.advanced_query;
        const q = validateAdvancedQuery(sourceText);
        if (q.error) return res.status(400).json({ message: q.error, ...(q.dsl ? { error: q.dsl } : {}) });
        advancedQueryUpdate = q.normalized;
      } else {
        // Basic mode: the Advanced Query is inert; clear it so the row stays unambiguous.
        advancedQueryUpdate = null;
      }
    }

    if (body.include_feed_keys !== undefined) {
      const feedKeys = await resolveIncludeFeedKeys(pool, body.include_feed_keys, existingRow);
      if (feedKeys.error) return res.status(400).json({ message: feedKeys.error });
      body.include_feed_keys = feedKeys.value;
    }

    const fields = [];
    const params = [id];
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
      // In query mode ioc_types is preserved-but-inert; keep a valid array for the DB.
      const iocTypes = iocNorm.ok ? iocNorm.value : (mode === FEED_FILTER_MODES.QUERY ? ['ip'] : iocNorm.value);
      setField('ioc_types', JSON.stringify(iocTypes), '::jsonb');
    }
    if (body.format !== undefined) setField('format', body.format);
    if (body.min_confidence !== undefined) setField('min_confidence', body.min_confidence);
    if (body.include_feed_keys !== undefined) {
      setField('include_feed_keys', JSON.stringify(body.include_feed_keys || []), '::jsonb');
    }
    if (body.include_tags !== undefined) setField('include_tags', JSON.stringify(body.include_tags || []), '::jsonb');
    if (body.exclude_tags !== undefined) setField('exclude_tags', JSON.stringify(body.exclude_tags || []), '::jsonb');
    if (body.exclude_false_positive !== undefined) setField('exclude_false_positive', Boolean(body.exclude_false_positive));
    if (body.exclude_expired !== undefined) setField('exclude_expired', Boolean(body.exclude_expired));
    if (body.time_window !== undefined) {
      const tw = String(body.time_window).toLowerCase();
      const mapped = tw === 'last_1_day' ? '1d' : tw === 'last_3_days' ? '3d' : tw === 'last_7_days' ? '7d' : tw;
      setField('time_window', mapped);
    }
    if (body.max_items !== undefined) setField('max_items', body.max_items);
    if (body.refresh_interval_minutes !== undefined) setField('refresh_interval_minutes', Number(body.refresh_interval_minutes));

    if (!fields.length) return res.status(400).json({ message: 'No fields to update' });

    try {
      const beforeQ = await pool.query('SELECT * FROM published_feeds WHERE id = $1', [id]);
      if (!beforeQ.rows.length) return res.status(404).json({ message: 'Feed not found' });
      const before = feedAuditSnapshot(beforeQ.rows[0]);

      const { rows } = await pool.query(
        `UPDATE published_feeds SET ${fields.join(', ')}, updated_at = NOW() WHERE id = $1 RETURNING *`,
        params
      );
      if (!rows.length) return res.status(404).json({ message: 'Feed not found' });
      const feed = toPublicFeed(normalizeFeedConfig(rows[0]));
      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.FEED_UPDATED,
        entityType: AUDIT_ENTITY.FEED,
        entityId: String(feed.id),
        entityDisplay: feed.name,
        severity: AUDIT_SEVERITY.INFO,
        before,
        after: feedAuditSnapshot(rows[0]),
        metadata: { changed_fields: Object.keys(body) }
      });
      return res.json({ feed });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update feed', detail: err.message });
    }
  });

  app.delete('/api/published-feeds/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    try {
      const beforeQ = await pool.query('SELECT * FROM published_feeds WHERE id = $1', [id]);
      if (!beforeQ.rows.length) return res.status(404).json({ message: 'Feed not found' });
      const before = feedAuditSnapshot(beforeQ.rows[0]);

      const { rowCount } = await pool.query('DELETE FROM published_feeds WHERE id = $1', [id]);
      if (!rowCount) return res.status(404).json({ message: 'Feed not found' });

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.FEED_DELETED,
        entityType: AUDIT_ENTITY.FEED,
        entityId: String(id),
        entityDisplay: before?.name,
        severity: AUDIT_SEVERITY.WARNING,
        before
      });
      return res.json({ ok: true });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to delete feed', detail: err.message });
    }
  });

  app.post('/api/published-feeds/:id/regenerate', requireRole(ROLES.ADMIN), async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: 'Invalid id' });
    try {
      const result = await generatePublishedFeedSnapshot(pool, id, { force: true });
      if (result?.reason === 'generation_in_progress') {
        return res.status(409).json({
          message: 'Generation already in progress',
          code: 'generation_in_progress',
          regeneration: result
        });
      }
      const { rows } = await pool.query('SELECT * FROM published_feeds WHERE id = $1', [id]);
      const last_item_count = await latestItemCount(pool, rows[0]);
      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.FEED_RUN_TRIGGERED,
        entityType: AUDIT_ENTITY.FEED,
        entityId: String(id),
        entityDisplay: rows[0]?.name,
        severity: AUDIT_SEVERITY.INFO,
        metadata: { regeneration: pickSafeFields(result, ['status', 'item_count', 'generated_at', 'last_status', 'reason']) }
      });
      return res.json({
        feed: toPublicFeed(normalizeFeedConfig(rows[0]), { last_item_count }),
        regeneration: result
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to regenerate feed', detail: err.message });
    }
  });

  app.get('/api/published-feeds/:id/access-keys', async (req, res) => {
    const feedId = Number(req.params.id);
    if (!Number.isFinite(feedId)) return res.status(400).json({ message: 'Invalid id' });
    try {
      const { rows } = await pool.query(
        `SELECT id, feed_id, name, enabled, last_used_at, last_used_ip, created_at, revoked_at
         FROM published_feed_access_keys
         WHERE feed_id = $1
         ORDER BY created_at DESC`,
        [feedId]
      );
      return res.json({ access_keys: rows.map(toPublicAccessKey) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list access keys', detail: err.message });
    }
  });

  app.post('/api/published-feeds/:id/access-keys', requireRole(ROLES.ADMIN), async (req, res) => {
    const feedId = Number(req.params.id);
    const name = String(req.body?.name || '').trim();
    if (!Number.isFinite(feedId)) return res.status(400).json({ message: 'Invalid id' });
    if (!name) return res.status(400).json({ message: 'name is required' });

    try {
      const feedQ = await pool.query('SELECT id, enabled FROM published_feeds WHERE id = $1', [feedId]);
      if (!feedQ.rows.length) return res.status(404).json({ message: 'Feed not found' });

      const rawToken = generateFeedAccessToken();
      const tokenHash = hashFeedAccessToken(rawToken);
      const { rows } = await pool.query(
        `INSERT INTO published_feed_access_keys (feed_id, name, token_hash, enabled)
         VALUES ($1, $2, $3, COALESCE($4, TRUE))
         RETURNING id, feed_id, name, enabled, last_used_at, last_used_ip, created_at, revoked_at`,
        [feedId, name, tokenHash, req.body?.enabled]
      );

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.FEED_ACCESS_KEY_CREATED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(rows[0].id),
        entityDisplay: rows[0].name,
        severity: AUDIT_SEVERITY.WARNING,
        after: accessKeyAuditSnapshot(rows[0]),
        metadata: { feed_id: feedId, masked_key: `${rawToken.slice(0, 8)}…` }
      });

      return res.status(201).json({
        access_key: toPublicAccessKey(rows[0]),
        token: rawToken,
        feed_url: buildPublicFeedUrl(req, rawToken)
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to create access key', detail: err.message });
    }
  });

  app.patch('/api/published-feeds/:id/access-keys/:keyId', requireRole(ROLES.ADMIN), async (req, res) => {
    const feedId = Number(req.params.id);
    const keyId = Number(req.params.keyId);
    if (!Number.isFinite(feedId) || !Number.isFinite(keyId)) {
      return res.status(400).json({ message: 'Invalid id' });
    }
    const enabled = req.body?.enabled;
    const name = req.body?.name != null ? String(req.body.name).trim() : undefined;
    if (enabled === undefined && name === undefined) {
      return res.status(400).json({ message: 'Nothing to update' });
    }

    try {
      const beforeQ = await pool.query(
        'SELECT id, feed_id, name, enabled FROM published_feed_access_keys WHERE id = $1 AND feed_id = $2 AND revoked_at IS NULL',
        [keyId, feedId]
      );
      if (!beforeQ.rows.length) return res.status(404).json({ message: 'Access key not found' });
      const before = accessKeyAuditSnapshot(beforeQ.rows[0]);

      const params = [keyId, feedId];
      const sets = [];
      if (name !== undefined) {
        params.push(name);
        sets.push(`name = $${params.length}`);
      }
      if (enabled !== undefined) {
        params.push(Boolean(enabled));
        sets.push(`enabled = $${params.length}`);
      }
      const { rows } = await pool.query(
        `UPDATE published_feed_access_keys SET ${sets.join(', ')}
         WHERE id = $1 AND feed_id = $2 AND revoked_at IS NULL
         RETURNING id, feed_id, name, enabled, last_used_at, last_used_ip, created_at, revoked_at`,
        params
      );
      if (!rows.length) return res.status(404).json({ message: 'Access key not found' });
      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.FEED_ACCESS_KEY_UPDATED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(rows[0].id),
        entityDisplay: rows[0].name,
        severity: AUDIT_SEVERITY.INFO,
        before,
        after: accessKeyAuditSnapshot(rows[0])
      });
      return res.json({ access_key: toPublicAccessKey(rows[0]) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update access key', detail: err.message });
    }
  });

  app.post('/api/published-feeds/:id/access-keys/:keyId/rotate', requireRole(ROLES.ADMIN), async (req, res) => {
    const feedId = Number(req.params.id);
    const keyId = Number(req.params.keyId);
    if (!Number.isFinite(feedId) || !Number.isFinite(keyId)) {
      return res.status(400).json({ message: 'Invalid id' });
    }

    try {
      const existing = await pool.query(
        `SELECT id FROM published_feed_access_keys WHERE id = $1 AND feed_id = $2 AND revoked_at IS NULL`,
        [keyId, feedId]
      );
      if (!existing.rows.length) return res.status(404).json({ message: 'Access key not found' });

      const rawToken = generateFeedAccessToken();
      const tokenHash = hashFeedAccessToken(rawToken);
      const { rows } = await pool.query(
        `UPDATE published_feed_access_keys SET token_hash = $3 WHERE id = $1 AND feed_id = $2
         RETURNING id, feed_id, name, enabled, last_used_at, last_used_ip, created_at, revoked_at`,
        [keyId, feedId, tokenHash]
      );

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.API_KEY_ROTATED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(rows[0].id),
        entityDisplay: rows[0].name,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { feed_id: feedId, masked_key: `${rawToken.slice(0, 8)}…` }
      });

      return res.json({
        access_key: toPublicAccessKey(rows[0]),
        token: rawToken,
        feed_url: buildPublicFeedUrl(req, rawToken)
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to rotate access key', detail: err.message });
    }
  });

  app.post('/api/published-feeds/:id/access-keys/:keyId/revoke', requireRole(ROLES.ADMIN), async (req, res) => {
    const feedId = Number(req.params.id);
    const keyId = Number(req.params.keyId);
    if (!Number.isFinite(feedId) || !Number.isFinite(keyId)) {
      return res.status(400).json({ message: 'Invalid id' });
    }

    try {
      const beforeQ = await pool.query(
        'SELECT id, feed_id, name, enabled FROM published_feed_access_keys WHERE id = $1 AND feed_id = $2 AND revoked_at IS NULL',
        [keyId, feedId]
      );
      if (!beforeQ.rows.length) return res.status(404).json({ message: 'Access key not found' });

      const { rows } = await pool.query(
        `UPDATE published_feed_access_keys
         SET enabled = FALSE, revoked_at = NOW()
         WHERE id = $1 AND feed_id = $2 AND revoked_at IS NULL
         RETURNING id, feed_id, name, enabled, last_used_at, last_used_ip, created_at, revoked_at`,
        [keyId, feedId]
      );
      if (!rows.length) return res.status(404).json({ message: 'Access key not found' });

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.FEED_ACCESS_KEY_REVOKED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(rows[0].id),
        entityDisplay: rows[0].name,
        severity: AUDIT_SEVERITY.CRITICAL,
        before: accessKeyAuditSnapshot(beforeQ.rows[0]),
        after: accessKeyAuditSnapshot(rows[0])
      });

      return res.json({ access_key: toPublicAccessKey(rows[0]) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to revoke access key', detail: err.message });
    }
  });
}

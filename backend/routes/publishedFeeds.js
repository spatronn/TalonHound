import { requireRole, ROLES } from '../lib/rbac.js';
import { generateFeedAccessToken, hashFeedAccessToken, buildPublicFeedUrl } from '../lib/feedAccessToken.js';
import { generatePublishedFeedSnapshot, normalizeFeedConfig, getLatestSnapshot } from '../lib/feedPublisherService.js';
import { FEED_IOC_TYPES } from '../lib/feedFormatter.js';
import {
  fetchPublishedFeedSourceOptions,
  normalizeIncludeFeedKeys
} from '../lib/publishedFeedSources.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';

function toPublicFeed(row, extra = {}) {
  if (!row) return null;
  return {
    id: Number(row.id),
    name: row.name,
    description: row.description,
    enabled: Boolean(row.enabled),
    ioc_type: row.ioc_type,
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
  for (const key of ['include_feed_keys', 'include_tags', 'exclude_tags']) {
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

function validateFeedPayload(body, partial = false) {
  const errors = [];
  if (!partial || body.name !== undefined) {
    if (!String(body.name || '').trim()) errors.push('name is required');
  }
  if (!partial || body.ioc_type !== undefined) {
    if (!FEED_IOC_TYPES.includes(String(body.ioc_type || '').toLowerCase())) {
      errors.push('ioc_type must be ip, domain, url, or hash');
    }
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
  const snapshot = await getLatestSnapshot(pool, feed.id, feed.ioc_type, feed.time_window);
  return snapshot?.item_count != null ? Number(snapshot.item_count) : null;
}

function feedAuditSnapshot(row) {
  const pub = toPublicFeed(normalizeFeedConfig(row));
  return pickSafeFields(pub, [
    'id', 'name', 'enabled', 'ioc_type', 'min_confidence', 'time_window',
    'max_items', 'refresh_interval_minutes', 'exclude_false_positive', 'exclude_expired'
  ]);
}

function accessKeyAuditSnapshot(row) {
  return pickSafeFields(toPublicAccessKey(row), ['id', 'feed_id', 'name', 'enabled']);
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
    const errors = validateFeedPayload(body, false);
    if (errors.length) return res.status(400).json({ message: errors.join('; ') });

    const feedKeys = await resolveIncludeFeedKeys(pool, body.include_feed_keys);
    if (feedKeys.error) return res.status(400).json({ message: feedKeys.error });

    const tw = String(body.time_window || 'all').toLowerCase();
    const timeWindow = tw === 'last_1_day' ? '1d' : tw === 'last_3_days' ? '3d' : tw === 'last_7_days' ? '7d' : tw;

    try {
      const { rows } = await pool.query(
        `INSERT INTO published_feeds (
           name, description, enabled, ioc_type, format, min_confidence,
           include_feed_keys, include_tags, exclude_tags,
           exclude_false_positive, exclude_expired,
           time_window, max_items, refresh_interval_minutes
         ) VALUES (
           $1, $2, COALESCE($3, TRUE), $4, COALESCE($5, 'txt'), $6,
           $7::jsonb, $8::jsonb, $9::jsonb,
           COALESCE($10, TRUE), COALESCE($11, TRUE),
           $12, $13, COALESCE($14, 15)
         )
         RETURNING *`,
        [
          String(body.name).trim(),
          body.description || null,
          body.enabled,
          String(body.ioc_type).toLowerCase(),
          body.format || 'txt',
          body.min_confidence ?? null,
          feedKeys.value.length ? JSON.stringify(feedKeys.value) : null,
          body.include_tags ? JSON.stringify(body.include_tags) : null,
          body.exclude_tags ? JSON.stringify(body.exclude_tags) : null,
          body.exclude_false_positive,
          body.exclude_expired,
          timeWindow,
          body.max_items ?? null,
          body.refresh_interval_minutes ?? 15
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
    const errors = validateFeedPayload(body, true);
    if (errors.length) return res.status(400).json({ message: errors.join('; ') });

    if (body.include_feed_keys !== undefined) {
      const existingQ = await pool.query('SELECT include_feed_keys FROM published_feeds WHERE id = $1', [id]);
      if (!existingQ.rows.length) return res.status(404).json({ message: 'Feed not found' });
      const feedKeys = await resolveIncludeFeedKeys(pool, body.include_feed_keys, existingQ.rows[0]);
      if (feedKeys.error) return res.status(400).json({ message: feedKeys.error });
      body.include_feed_keys = feedKeys.value;
    }

    const fields = [];
    const params = [id];
    const setField = (col, val, cast = '') => {
      params.push(val);
      fields.push(`${col} = $${params.length}${cast}`);
    };

    if (body.name !== undefined) setField('name', String(body.name).trim());
    if (body.description !== undefined) setField('description', body.description || null);
    if (body.enabled !== undefined) setField('enabled', Boolean(body.enabled));
    if (body.ioc_type !== undefined) setField('ioc_type', String(body.ioc_type).toLowerCase());
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
      const { rows } = await pool.query('SELECT * FROM published_feeds WHERE id = $1', [id]);
      const last_item_count = await latestItemCount(pool, rows[0]);
      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.FEED_RUN_TRIGGERED,
        entityType: AUDIT_ENTITY.FEED,
        entityId: String(id),
        entityDisplay: rows[0]?.name,
        severity: AUDIT_SEVERITY.INFO,
        metadata: { regeneration: pickSafeFields(result, ['status', 'item_count', 'generated_at']) }
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

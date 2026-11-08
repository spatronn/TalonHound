import { requireRole, ROLES } from '../lib/rbac.js';
import { generateFeedAccessToken, hashFeedAccessToken, buildPublicFeedUrl } from '../lib/feedAccessToken.js';
import {
  fetchPublishedFeedSourceOptions
} from '../lib/publishedFeedSources.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';
import { getPublishedFeedArtifactConfig, removeFeedArtifacts } from '../lib/publishedFeedArtifact/store.js';
import {
  toPublicFeed,
  feedAuditSnapshot,
  listFeeds,
  getFeed,
  createFeed,
  updateFeed,
  previewFeedMembership,
  listFeedMembership,
  regenerateFeed,
  parseBodyArrays
} from '../lib/publishedFeedManagementService.js';

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
      const { feeds } = await listFeeds(pool);
      return res.json({ feeds });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list published feeds', detail: err.message });
    }
  });

  // Preview proposed (admin) or existing feed_id (any authenticated) membership.
  // Registered before /:id so Express does not treat "preview" as an id.
  app.post('/api/published-feeds/preview', async (req, res) => {
    try {
      const body = parseBodyArrays(req.body || {});
      const isExistingOnly = body.feed_id != null && Object.keys(body).every(
        (k) => ['feed_id', 'limit', 'offset', 'cursor', 'compare_to_feed_id'].includes(k)
      );
      if (!isExistingOnly) {
        // Proposed definition preview = create-capable users (admin).
        const role = String(req.user?.role || '').toLowerCase();
        if (role !== ROLES.ADMIN) {
          return res.status(403).json({ message: 'Admin role required to preview a proposed feed definition' });
        }
      }
      const result = await previewFeedMembership(pool, body);
      if (result.error) {
        return res.status(result.error.status || 400).json({ message: result.error.message });
      }
      return res.json(result.preview);
    } catch (err) {
      return res.status(500).json({ message: 'Failed to preview feed membership', detail: err.message });
    }
  });

  app.post('/api/published-feeds', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const result = await createFeed(pool, req.body || {}, {
        createdBy: req.user?.publicId || req.user?.public_id || null
      });
      if (result.error) {
        return res.status(result.error.status || 400).json({
          message: result.error.message,
          ...(result.error.dsl ? { error: result.error.dsl } : {})
        });
      }
      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.FEED_CREATED,
        entityType: AUDIT_ENTITY.FEED,
        entityId: String(result.feed.id),
        entityDisplay: result.feed.name,
        severity: AUDIT_SEVERITY.INFO,
        after: feedAuditSnapshot(result.row)
      });
      return res.status(201).json({ feed: result.feed });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to create published feed', detail: err.message });
    }
  });

  app.get('/api/published-feeds/:id', async (req, res) => {
    try {
      const result = await getFeed(pool, req.params.id, { includeCuratedIds: true });
      if (result.error) {
        return res.status(result.error.status || 400).json({ message: result.error.message });
      }
      return res.json({ feed: result.feed });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to fetch feed', detail: err.message });
    }
  });

  app.get('/api/published-feeds/:id/membership', async (req, res) => {
    try {
      const result = await listFeedMembership(pool, req.params.id, {
        limit: req.query.limit,
        offset: req.query.offset
      });
      if (result.error) {
        return res.status(result.error.status || 400).json({ message: result.error.message });
      }
      return res.json(result);
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list feed membership', detail: err.message });
    }
  });

  app.patch('/api/published-feeds/:id', requireRole(ROLES.ADMIN), async (req, res) => {
    try {
      const result = await updateFeed(pool, req.params.id, req.body || {}, {
        createdBy: req.user?.publicId || req.user?.public_id || null
      });
      if (result.error) {
        return res.status(result.error.status || 400).json({
          message: result.error.message,
          ...(result.error.dsl ? { error: result.error.dsl } : {})
        });
      }
      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.FEED_UPDATED,
        entityType: AUDIT_ENTITY.FEED,
        entityId: String(result.feed.id),
        entityDisplay: result.feed.name,
        severity: AUDIT_SEVERITY.INFO,
        before: result.before,
        after: feedAuditSnapshot(result.row),
        metadata: { changed_fields: Object.keys(req.body || {}) }
      });
      return res.json({ feed: result.feed });
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

      removeFeedArtifacts(getPublishedFeedArtifactConfig(), id).catch(() => {});

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
    try {
      const result = await regenerateFeed(pool, req.params.id, { force: true });
      if (result.error) {
        return res.status(result.error.status || 500).json({
          message: result.error.message,
          code: result.error.code,
          regeneration: result.error.regeneration
        });
      }
      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.FEED_RUN_TRIGGERED,
        entityType: AUDIT_ENTITY.FEED,
        entityId: String(result.feed.id),
        entityDisplay: result.feed.name,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          regeneration: pickSafeFields(result.regeneration, [
            'status', 'item_count', 'generated_at', 'last_status', 'reason'
          ])
        }
      });
      return res.json({
        feed: result.feed,
        regeneration: result.regeneration
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to regenerate feed', detail: err.message });
    }
  });

  app.get('/api/published-feeds/:id/access-keys', requireRole(ROLES.ADMIN), async (req, res) => {
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

// Re-export helpers tests may still import from the route module.
export {
  toPublicFeed,
  parseBodyArrays,
  validateFeedPayload,
  validateAdvancedQuery,
  resolveFilterModeInput,
  FEED_FILTER_MODES
} from '../lib/publishedFeedManagementService.js';

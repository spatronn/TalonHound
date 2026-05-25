import { requireRole, ROLES } from '../lib/rbac.js';
import { generateFeedAccessToken, hashFeedAccessToken, buildPublicFeedUrl } from '../lib/feedAccessToken.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';

const FEED_ACCESS_TYPE = 'feed_access';

function toPublicApiKey(row) {
  if (!row) return null;
  const revoked = Boolean(row.revoked_at);
  return {
    id: Number(row.id),
    key_type: FEED_ACCESS_TYPE,
    feed_id: Number(row.feed_id),
    name: row.name,
    enabled: Boolean(row.enabled),
    last_used_at: row.last_used_at,
    last_used_ip: row.last_used_ip,
    created_at: row.created_at,
    revoked_at: row.revoked_at,
    feed_name: row.feed_name,
    feed_ioc_type: row.feed_ioc_type,
    status: revoked ? 'revoked' : row.enabled ? 'active' : 'disabled'
  };
}

function apiKeyAuditSnapshot(row) {
  return pickSafeFields(toPublicApiKey(row), ['id', 'feed_id', 'name', 'enabled', 'feed_name', 'feed_ioc_type', 'status']);
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ auditSuccess: Function }} audit
 */
export function registerApiKeyRoutes(app, pool, audit) {
  app.get('/api/api-keys', async (_req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT
           k.id,
           k.feed_id,
           k.name,
           k.enabled,
           k.last_used_at,
           k.last_used_ip,
           k.created_at,
           k.revoked_at,
           f.name AS feed_name,
           f.ioc_type AS feed_ioc_type
         FROM published_feed_access_keys k
         JOIN published_feeds f ON f.id = k.feed_id
         ORDER BY k.created_at DESC`
      );
      return res.json({ api_keys: rows.map(toPublicApiKey) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list API keys', detail: err.message });
    }
  });

  app.post('/api/api-keys', requireRole(ROLES.ADMIN), async (req, res) => {
    const keyType = String(req.body?.key_type || FEED_ACCESS_TYPE).trim().toLowerCase();
    const feedId = Number(req.body?.feed_id);
    const name = String(req.body?.name || '').trim();
    const enabled = req.body?.enabled !== false;

    if (keyType !== FEED_ACCESS_TYPE) {
      return res.status(400).json({ message: 'Only feed_access key type is supported in MVP' });
    }
    if (!Number.isFinite(feedId) || feedId <= 0) {
      return res.status(400).json({ message: 'feed_id is required' });
    }
    if (!name) return res.status(400).json({ message: 'name is required' });

    try {
      const feedQ = await pool.query('SELECT id, enabled, ioc_type, name FROM published_feeds WHERE id = $1', [feedId]);
      if (!feedQ.rows.length) return res.status(404).json({ message: 'Published feed not found' });

      const rawToken = generateFeedAccessToken();
      const tokenHash = hashFeedAccessToken(rawToken);
      const { rows } = await pool.query(
        `INSERT INTO published_feed_access_keys (feed_id, name, token_hash, enabled)
         VALUES ($1, $2, $3, $4)
         RETURNING id, feed_id, name, enabled, last_used_at, last_used_ip, created_at, revoked_at`,
        [feedId, name, tokenHash, enabled]
      );
      const key = toPublicApiKey({
        ...rows[0],
        feed_name: feedQ.rows[0].name,
        feed_ioc_type: feedQ.rows[0].ioc_type
      });

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.API_KEY_CREATED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(key.id),
        entityDisplay: key.name,
        severity: AUDIT_SEVERITY.WARNING,
        after: apiKeyAuditSnapshot({ ...rows[0], feed_name: feedQ.rows[0].name, feed_ioc_type: feedQ.rows[0].ioc_type }),
        metadata: { feed_id: feedId, feed_name: feedQ.rows[0].name, masked_key: `${rawToken.slice(0, 8)}…` }
      });

      return res.status(201).json({
        api_key: key,
        token: rawToken,
        feed_url: buildPublicFeedUrl(req, rawToken)
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to create API key', detail: err.message });
    }
  });

  app.patch('/api/api-keys/:keyId', requireRole(ROLES.ADMIN), async (req, res) => {
    const keyId = Number(req.params.keyId);
    if (!Number.isFinite(keyId)) return res.status(400).json({ message: 'Invalid key id' });

    const enabled = req.body?.enabled;
    const name = req.body?.name != null ? String(req.body.name).trim() : undefined;
    if (enabled === undefined && name === undefined) {
      return res.status(400).json({ message: 'Nothing to update' });
    }

    try {
      const beforeQ = await pool.query(
        `SELECT k.*, f.name AS feed_name, f.ioc_type AS feed_ioc_type
         FROM published_feed_access_keys k
         JOIN published_feeds f ON f.id = k.feed_id
         WHERE k.id = $1 AND k.revoked_at IS NULL`,
        [keyId]
      );
      if (!beforeQ.rows.length) return res.status(404).json({ message: 'API key not found' });
      const before = apiKeyAuditSnapshot(beforeQ.rows[0]);

      const params = [keyId];
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
         WHERE id = $1 AND revoked_at IS NULL
         RETURNING id, feed_id, name, enabled, last_used_at, last_used_ip, created_at, revoked_at`,
        params
      );
      if (!rows.length) return res.status(404).json({ message: 'API key not found' });
      const feedQ = await pool.query('SELECT name, ioc_type FROM published_feeds WHERE id = $1', [rows[0].feed_id]);
      const key = toPublicApiKey({
        ...rows[0],
        feed_name: feedQ.rows[0]?.name,
        feed_ioc_type: feedQ.rows[0]?.ioc_type
      });

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.API_KEY_UPDATED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(key.id),
        entityDisplay: key.name,
        severity: AUDIT_SEVERITY.INFO,
        before,
        after: apiKeyAuditSnapshot({ ...rows[0], feed_name: feedQ.rows[0]?.name, feed_ioc_type: feedQ.rows[0]?.ioc_type }),
        metadata: { changed_fields: { name: name !== undefined, enabled: enabled !== undefined } }
      });

      return res.json({ api_key: key });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update API key', detail: err.message });
    }
  });

  app.post('/api/api-keys/:keyId/rotate', requireRole(ROLES.ADMIN), async (req, res) => {
    const keyId = Number(req.params.keyId);
    if (!Number.isFinite(keyId)) return res.status(400).json({ message: 'Invalid key id' });

    try {
      const existing = await pool.query(
        `SELECT k.id, k.feed_id, k.name, k.enabled, f.name AS feed_name, f.ioc_type AS feed_ioc_type
         FROM published_feed_access_keys k
         JOIN published_feeds f ON f.id = k.feed_id
         WHERE k.id = $1 AND k.revoked_at IS NULL`,
        [keyId]
      );
      if (!existing.rows.length) return res.status(404).json({ message: 'API key not found' });

      const rawToken = generateFeedAccessToken();
      const tokenHash = hashFeedAccessToken(rawToken);
      const { rows } = await pool.query(
        `UPDATE published_feed_access_keys SET token_hash = $2 WHERE id = $1
         RETURNING id, feed_id, name, enabled, last_used_at, last_used_ip, created_at, revoked_at`,
        [keyId, tokenHash]
      );
      const meta = existing.rows[0];
      const key = toPublicApiKey({
        ...rows[0],
        feed_name: meta.feed_name,
        feed_ioc_type: meta.feed_ioc_type
      });

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.API_KEY_ROTATED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(key.id),
        entityDisplay: key.name,
        severity: AUDIT_SEVERITY.WARNING,
        after: apiKeyAuditSnapshot({ ...rows[0], feed_name: meta.feed_name, feed_ioc_type: meta.feed_ioc_type }),
        metadata: { feed_id: key.feed_id, masked_key: `${rawToken.slice(0, 8)}…` }
      });

      return res.json({
        api_key: key,
        token: rawToken,
        feed_url: buildPublicFeedUrl(req, rawToken)
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to rotate API key', detail: err.message });
    }
  });

  app.post('/api/api-keys/:keyId/revoke', requireRole(ROLES.ADMIN), async (req, res) => {
    const keyId = Number(req.params.keyId);
    if (!Number.isFinite(keyId)) return res.status(400).json({ message: 'Invalid key id' });

    try {
      const beforeQ = await pool.query(
        `SELECT k.*, f.name AS feed_name, f.ioc_type AS feed_ioc_type
         FROM published_feed_access_keys k
         JOIN published_feeds f ON f.id = k.feed_id
         WHERE k.id = $1 AND k.revoked_at IS NULL`,
        [keyId]
      );
      if (!beforeQ.rows.length) return res.status(404).json({ message: 'API key not found' });
      const before = apiKeyAuditSnapshot(beforeQ.rows[0]);

      const { rows } = await pool.query(
        `UPDATE published_feed_access_keys
         SET enabled = FALSE, revoked_at = NOW()
         WHERE id = $1 AND revoked_at IS NULL
         RETURNING id, feed_id, name, enabled, last_used_at, last_used_ip, created_at, revoked_at`,
        [keyId]
      );
      if (!rows.length) return res.status(404).json({ message: 'API key not found' });
      const feedQ = await pool.query('SELECT name, ioc_type FROM published_feeds WHERE id = $1', [rows[0].feed_id]);
      const key = toPublicApiKey({
        ...rows[0],
        feed_name: feedQ.rows[0]?.name,
        feed_ioc_type: feedQ.rows[0]?.ioc_type
      });

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.API_KEY_DELETED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(key.id),
        entityDisplay: key.name,
        severity: AUDIT_SEVERITY.CRITICAL,
        before,
        after: apiKeyAuditSnapshot({ ...rows[0], feed_name: feedQ.rows[0]?.name, feed_ioc_type: feedQ.rows[0]?.ioc_type }),
        metadata: { revoked: true }
      });

      return res.json({ api_key: key });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to revoke API key', detail: err.message });
    }
  });
}

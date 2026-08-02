import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';
import {
  PUBLISHED_FEED_KEY_TYPE,
  LEGACY_FEED_ACCESS_KEY_TYPE,
  PUBLISHED_FEED_KEY_PREFIX,
  generatePublishedFeedApiKey,
  hashApiKey,
  lastFourOf,
  maskApiKey,
  keyStatus,
  isRevealableKeyRow
} from '../lib/publishedFeedApiKey.js';
import {
  encryptApiKeySecret,
  decryptApiKeySecret,
  isApiKeyEncryptionConfigured
} from '../lib/apiKeyEncryption.js';
import { resolveFeedIocTypes } from '../lib/feedPublisherService.js';

const LEGACY_REVEAL_MESSAGE = 'This legacy key cannot be revealed.';

const LIST_COLUMNS = `
  k.id, k.feed_id, k.name, k.key_type, k.key_prefix, k.last_four,
  k.enabled, k.expires_at, k.last_used_at, k.last_used_ip,
  k.created_at, k.revoked_at, k.deleted_at,
  (k.secret_ciphertext IS NOT NULL) AS has_secret,
  f.name AS feed_name, f.ioc_types AS feed_ioc_types, f.slug AS feed_slug`;

function typeLabel(keyType) {
  return keyType === PUBLISHED_FEED_KEY_TYPE ? 'Published Feed' : 'Feed Access (legacy)';
}

/** Public (never includes the plaintext secret). */
function toPublicApiKey(row) {
  if (!row) return null;
  const keyType = row.key_type || LEGACY_FEED_ACCESS_KEY_TYPE;
  const revealable = keyType === PUBLISHED_FEED_KEY_TYPE && Boolean(row.has_secret);
  // Legacy feed_access tokens have no th_pf_ prefix; show a neutral mask for them.
  const maskedKey = keyType === PUBLISHED_FEED_KEY_TYPE
    ? maskApiKey({ key_prefix: row.key_prefix, last_four: row.last_four })
    : '••••••••';
  return {
    id: Number(row.id),
    name: row.name,
    key_type: keyType,
    key_type_label: typeLabel(keyType),
    masked_key: maskedKey,
    revealable,
    enabled: Boolean(row.enabled),
    status: keyStatus(row),
    expires_at: row.expires_at || null,
    last_used_at: row.last_used_at || null,
    last_used_ip: row.last_used_ip || null,
    created_at: row.created_at,
    revoked_at: row.revoked_at || null,
    // Legacy feed-bound keys keep their feed context for display.
    feed_id: row.feed_id != null ? Number(row.feed_id) : null,
    feed_name: row.feed_name || null,
    feed_ioc_types: Array.isArray(row.feed_ioc_types)
      ? row.feed_ioc_types
      : (row.feed_ioc_types ? resolveFeedIocTypes({ ioc_types: row.feed_ioc_types }) : null),
    feed_slug: row.feed_slug || null
  };
}

function apiKeyAuditSnapshot(row) {
  return pickSafeFields(toPublicApiKey(row), [
    'id', 'name', 'key_type', 'status', 'revealable', 'enabled', 'feed_id', 'feed_name'
  ]);
}

/** Never cache responses that carry a plaintext secret. */
function noStore(res) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
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
        `SELECT ${LIST_COLUMNS}
         FROM published_feed_access_keys k
         LEFT JOIN published_feeds f ON f.id = k.feed_id
         WHERE k.deleted_at IS NULL
         ORDER BY k.created_at DESC`
      );
      return res.json({ api_keys: rows.map(toPublicApiKey) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list API keys', detail: err.message });
    }
  });

  // Create a revealable Published Feed key (not bound to a single feed).
  app.post('/api/api-keys', requireRole(ROLES.ADMIN), async (req, res) => {
    const keyType = String(req.body?.key_type || PUBLISHED_FEED_KEY_TYPE).trim().toLowerCase();
    const name = String(req.body?.name || '').trim();
    const enabled = req.body?.enabled !== false;

    if (keyType !== PUBLISHED_FEED_KEY_TYPE) {
      return res.status(400).json({ message: 'Only the Published Feed key type can be created here' });
    }
    if (!name) return res.status(400).json({ message: 'name is required' });
    if (!isApiKeyEncryptionConfigured()) {
      return res.status(503).json({
        message: 'API_KEY_ENCRYPTION_KEY is not configured; cannot create revealable keys'
      });
    }

    try {
      const rawKey = generatePublishedFeedApiKey();
      const tokenHash = hashApiKey(rawKey);
      const { ciphertext, nonce, tag } = encryptApiKeySecret(rawKey);

      const insertQ = await pool.query(
        `INSERT INTO published_feed_access_keys
           (feed_id, name, token_hash, key_type, key_prefix, last_four,
            secret_ciphertext, secret_nonce, secret_tag, enabled, created_by)
         VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id`,
        [
          name,
          tokenHash,
          PUBLISHED_FEED_KEY_TYPE,
          PUBLISHED_FEED_KEY_PREFIX,
          lastFourOf(rawKey),
          ciphertext,
          nonce,
          tag,
          enabled,
          req.user?.email || req.user?.username || null
        ]
      );
      const { rows } = await pool.query(
        `SELECT ${LIST_COLUMNS} FROM published_feed_access_keys k
         LEFT JOIN published_feeds f ON f.id = k.feed_id WHERE k.id = $1`,
        [insertQ.rows[0].id]
      );
      const key = toPublicApiKey(rows[0]);

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.API_KEY_CREATED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(key.id),
        entityDisplay: key.name,
        severity: AUDIT_SEVERITY.WARNING,
        after: apiKeyAuditSnapshot(rows[0]),
        metadata: { key_type: PUBLISHED_FEED_KEY_TYPE, masked_key: key.masked_key }
      });

      noStore(res);
      return res.status(201).json({ api_key: key, token: rawKey });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to create API key', detail: err.message });
    }
  });

  // Reveal the plaintext secret of a revealable key (admin only, audited, never cached).
  app.get('/api/api-keys/:keyId/reveal', requireRole(ROLES.ADMIN), async (req, res) => {
    const keyId = Number(req.params.keyId);
    if (!Number.isFinite(keyId)) return res.status(400).json({ message: 'Invalid key id' });

    try {
      const { rows } = await pool.query(
        `SELECT ${LIST_COLUMNS}, k.secret_ciphertext, k.secret_nonce, k.secret_tag
         FROM published_feed_access_keys k
         LEFT JOIN published_feeds f ON f.id = k.feed_id
         WHERE k.id = $1 AND k.deleted_at IS NULL`,
        [keyId]
      );
      if (!rows.length) return res.status(404).json({ message: 'API key not found' });
      const row = rows[0];

      if (!isRevealableKeyRow(row)) {
        return res.status(409).json({ message: LEGACY_REVEAL_MESSAGE, revealable: false });
      }
      if (!isApiKeyEncryptionConfigured()) {
        return res.status(503).json({ message: 'API_KEY_ENCRYPTION_KEY is not configured' });
      }

      let plaintext;
      try {
        plaintext = decryptApiKeySecret({
          ciphertext: row.secret_ciphertext,
          nonce: row.secret_nonce,
          tag: row.secret_tag
        });
      } catch {
        // Do not leak ciphertext/key material in the error.
        return res.status(500).json({ message: 'Failed to decrypt API key' });
      }

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.API_KEY_REVEALED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(row.id),
        entityDisplay: row.name,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { key_type: row.key_type, masked_key: maskApiKey(row) }
      });

      noStore(res);
      return res.json({ api_key: toPublicApiKey(row), token: plaintext });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to reveal API key', detail: err.message });
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
      // Deleted keys are gone for good: never match them here.
      const beforeQ = await pool.query(
        `SELECT ${LIST_COLUMNS}
         FROM published_feed_access_keys k
         LEFT JOIN published_feeds f ON f.id = k.feed_id
         WHERE k.id = $1 AND k.deleted_at IS NULL`,
        [keyId]
      );
      if (!beforeQ.rows.length) return res.status(404).json({ message: 'API key not found' });
      const beforeRow = beforeQ.rows[0];
      const before = apiKeyAuditSnapshot(beforeRow);

      // Enforce the enable/disable state machine server-side (do not trust the UI):
      // enable only applies to a currently-disabled key; disable only to an active one.
      // Expired keys cannot be toggled.
      if (enabled !== undefined) {
        const currentStatus = keyStatus(beforeRow);
        if (currentStatus === 'expired') {
          return res.status(409).json({ message: 'Expired keys cannot be enabled or disabled' });
        }
        if (Boolean(enabled) === Boolean(beforeRow.enabled)) {
          return res.status(409).json({
            message: `API key is already ${beforeRow.enabled ? 'enabled' : 'disabled'}`
          });
        }
      }

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

      await pool.query(
        `UPDATE published_feed_access_keys SET ${sets.join(', ')}
         WHERE id = $1 AND deleted_at IS NULL`,
        params
      );
      const afterQ = await pool.query(
        `SELECT ${LIST_COLUMNS}
         FROM published_feed_access_keys k
         LEFT JOIN published_feeds f ON f.id = k.feed_id
         WHERE k.id = $1`,
        [keyId]
      );
      const key = toPublicApiKey(afterQ.rows[0]);

      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.API_KEY_UPDATED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(key.id),
        entityDisplay: key.name,
        severity: AUDIT_SEVERITY.INFO,
        before,
        after: apiKeyAuditSnapshot(afterQ.rows[0]),
        metadata: { changed_fields: { name: name !== undefined, enabled: enabled !== undefined } }
      });

      return res.json({ api_key: key });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update API key', detail: err.message });
    }
  });

  // Delete (soft-delete): irreversible. The key is stamped deleted_at/deleted_by,
  // hidden from the list, and rejected by every auth path. Works for both
  // Published Feed and legacy Feed Access keys.
  app.delete('/api/api-keys/:keyId', requireRole(ROLES.ADMIN), async (req, res) => {
    const keyId = Number(req.params.keyId);
    if (!Number.isFinite(keyId)) return res.status(400).json({ message: 'Invalid key id' });

    try {
      const beforeQ = await pool.query(
        `SELECT ${LIST_COLUMNS}
         FROM published_feed_access_keys k
         LEFT JOIN published_feeds f ON f.id = k.feed_id
         WHERE k.id = $1 AND k.deleted_at IS NULL`,
        [keyId]
      );
      if (!beforeQ.rows.length) return res.status(404).json({ message: 'API key not found' });
      const beforeRow = beforeQ.rows[0];
      const actor = req.user?.email || req.user?.username || null;

      await pool.query(
        `UPDATE published_feed_access_keys
         SET enabled = FALSE, deleted_at = NOW(), deleted_by = $2
         WHERE id = $1 AND deleted_at IS NULL`,
        [keyId, actor]
      );

      // Audit records only safe metadata — never the key secret/material.
      audit?.auditSuccess({
        req,
        action: AUDIT_ACTION.API_KEY_DELETED,
        entityType: AUDIT_ENTITY.API_KEY,
        entityId: String(beforeRow.id),
        entityDisplay: beforeRow.name,
        severity: AUDIT_SEVERITY.CRITICAL,
        before: apiKeyAuditSnapshot(beforeRow),
        metadata: {
          key_id: Number(beforeRow.id),
          name: beforeRow.name,
          key_type: beforeRow.key_type || LEGACY_FEED_ACCESS_KEY_TYPE
        }
      });

      return res.json({ ok: true, id: Number(beforeRow.id) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to delete API key', detail: err.message });
    }
  });
}

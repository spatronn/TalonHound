import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import { pickSafeFields } from '../lib/auditRedaction.js';
import {
  ACCESS_PROFILE,
  LEGACY_FEED_ACCESS_KEY_TYPE,
  PUBLISHED_FEED_KEY_TYPE,
  IOC_MANAGEMENT_KEY_TYPE,
  generateApiKeyForProfile,
  hashApiKey,
  lastFourOf,
  maskApiKey,
  keyStatus,
  isRevealableKeyRow
} from '../lib/publishedFeedApiKey.js';
import {
  getAccessProfile,
  scopesForAccessProfile,
  profileLabel,
  profilePermissionSummary,
  listCreatableAccessProfiles,
  normalizeScopes,
  profileRequiresOwner,
  isMcpAccessProfile
} from '../lib/apiKeyProfiles.js';
import {
  encryptApiKeySecret,
  decryptApiKeySecret,
  isApiKeyEncryptionConfigured
} from '../lib/apiKeyEncryption.js';
import { resolveFeedIocTypes } from '../lib/feedPublisherService.js';

const LEGACY_REVEAL_MESSAGE = 'This legacy key cannot be revealed.';
const OWNER_PUBLIC_ID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const LIST_COLUMNS = `
  k.id, k.feed_id, k.name, k.key_type, k.key_prefix, k.last_four, k.scopes,
  k.enabled, k.expires_at, k.last_used_at, k.last_used_ip,
  k.created_at, k.revoked_at, k.deleted_at, k.owner_user_id,
  (k.secret_ciphertext IS NOT NULL) AS has_secret,
  f.name AS feed_name, f.ioc_types AS feed_ioc_types, f.slug AS feed_slug,
  u.public_id AS owner_public_id, u.username AS owner_username,
  u.username AS owner_email, u.role AS owner_role`;

const LIST_FROM = `
  FROM published_feed_access_keys k
  LEFT JOIN published_feeds f ON f.id = k.feed_id
  LEFT JOIN users u ON u.id = k.owner_user_id`;

/** Public (never includes the plaintext secret). */
function toPublicApiKey(row) {
  if (!row) return null;
  const keyType = row.key_type || LEGACY_FEED_ACCESS_KEY_TYPE;
  const profile = getAccessProfile(keyType);
  const revealable = isRevealableKeyRow({
    key_type: keyType,
    secret_ciphertext: row.has_secret ? true : row.secret_ciphertext
  }) && Boolean(row.has_secret);
  const scopes = normalizeScopes(row.scopes?.length ? row.scopes : profile?.scopes);
  // Legacy feed_access tokens have no th_ prefix; show a neutral mask for them.
  const maskedKey = profile?.key_prefix
    ? maskApiKey({ key_prefix: row.key_prefix || profile.key_prefix, last_four: row.last_four, key_type: keyType })
    : '••••••••';
  const out = {
    id: Number(row.id),
    name: row.name,
    key_type: keyType,
    access_profile: keyType,
    key_type_label: profileLabel(keyType),
    permission_summary: profilePermissionSummary(keyType),
    scopes,
    masked_key: maskedKey,
    revealable,
    enabled: Boolean(row.enabled),
    status: keyStatus(row),
    expires_at: row.expires_at || null,
    last_used_at: row.last_used_at || null,
    last_used_ip: row.last_used_ip || null,
    created_at: row.created_at,
    revoked_at: row.revoked_at || null,
    feed_id: row.feed_id != null ? Number(row.feed_id) : null,
    feed_name: row.feed_name || null,
    feed_ioc_types: Array.isArray(row.feed_ioc_types)
      ? row.feed_ioc_types
      : (row.feed_ioc_types ? resolveFeedIocTypes({ ioc_types: row.feed_ioc_types }) : null),
    feed_slug: row.feed_slug || null
  };
  if (row.owner_user_id != null) {
    out.owner_user_id = Number(row.owner_user_id);
  }
  if (row.owner_public_id) out.owner_public_id = row.owner_public_id;
  if (row.owner_username) out.owner_username = row.owner_username;
  if (row.owner_role) out.owner_role = row.owner_role;
  return out;
}

function apiKeyAuditSnapshot(row) {
  return pickSafeFields(toPublicApiKey(row), [
    'id', 'name', 'key_type', 'access_profile', 'scopes', 'status', 'revealable', 'enabled',
    'feed_id', 'feed_name', 'owner_user_id', 'owner_public_id', 'owner_username', 'owner_role'
  ]);
}

/**
 * Resolve accountable owner for MCP access profiles.
 * @returns {Promise<{ ok: true, ownerUserId: number|null } | { ok: false, status: number, message: string }>}
 */
async function resolveOwnerForCreate(pool, profile, body) {
  const hasOwnerUserId = body?.owner_user_id != null && String(body.owner_user_id).trim() !== '';
  const hasOwnerPublicId = body?.owner_public_id != null && String(body.owner_public_id).trim() !== '';

  if (!profileRequiresOwner(profile.id)) {
    // Non-MCP profiles ignore owner fields when present.
    return { ok: true, ownerUserId: null };
  }

  if (!hasOwnerUserId && !hasOwnerPublicId) {
    return {
      ok: false,
      status: 400,
      message: 'owner_user_id or owner_public_id is required for MCP access profiles'
    };
  }

  let rows;
  if (hasOwnerUserId) {
    const id = Number(body.owner_user_id);
    if (!Number.isFinite(id) || id <= 0) {
      return { ok: false, status: 400, message: 'owner_user_id must be a positive number' };
    }
    ({ rows } = await pool.query(
      `SELECT id, status FROM users WHERE id = $1`,
      [id]
    ));
  } else {
    const publicId = String(body.owner_public_id).trim();
    if (!OWNER_PUBLIC_ID_RE.test(publicId)) {
      return { ok: false, status: 400, message: 'owner_public_id must be a valid UUID' };
    }
    ({ rows } = await pool.query(
      `SELECT id, status FROM users WHERE public_id = $1::uuid`,
      [publicId]
    ));
  }

  const owner = rows[0];
  if (!owner) {
    return { ok: false, status: 400, message: 'Owner user not found' };
  }
  const status = String(owner.status || '').trim().toLowerCase();
  if (status && status !== 'active') {
    return { ok: false, status: 400, message: 'Owner user is not active' };
  }
  return { ok: true, ownerUserId: Number(owner.id) };
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
  app.get('/api/api-keys/profiles', requireRole(ROLES.ADMIN), (_req, res) => {
    return res.json({
      profiles: listCreatableAccessProfiles().map((p) => ({
        id: p.id,
        label: p.label,
        description: p.description,
        permission_summary: p.permission_summary,
        scopes: [...p.scopes],
        requires_owner: Boolean(p.requiresOwner),
        is_mcp: isMcpAccessProfile(p.id)
      }))
    });
  });

  // Global inventory (Administration → API Keys) — admin-only; never returns plaintext secrets.
  app.get('/api/api-keys', requireRole(ROLES.ADMIN), async (_req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT ${LIST_COLUMNS}
         ${LIST_FROM}
         WHERE k.deleted_at IS NULL
         ORDER BY k.created_at DESC`
      );
      return res.json({ api_keys: rows.map(toPublicApiKey) });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list API keys', detail: err.message });
    }
  });

  // Create a revealable key for a fixed access profile (not bound to a single feed).
  app.post('/api/api-keys', requireRole(ROLES.ADMIN), async (req, res) => {
    const profileRaw = String(
      req.body?.access_profile || req.body?.key_type || PUBLISHED_FEED_KEY_TYPE
    ).trim().toLowerCase();
    const name = String(req.body?.name || '').trim();
    const enabled = req.body?.enabled !== false;
    const profile = getAccessProfile(profileRaw);

    if (!profile?.creatable) {
      return res.status(400).json({
        message: `access_profile must be ${listCreatableAccessProfiles().map((p) => p.id).join(', ')}`
      });
    }
    if (!name) return res.status(400).json({ message: 'name is required' });
    if (!isApiKeyEncryptionConfigured()) {
      return res.status(503).json({
        message: 'API_KEY_ENCRYPTION_KEY is not configured; cannot create revealable keys'
      });
    }

    try {
      const ownerResolved = await resolveOwnerForCreate(pool, profile, req.body);
      if (!ownerResolved.ok) {
        return res.status(ownerResolved.status).json({ message: ownerResolved.message });
      }

      const rawKey = generateApiKeyForProfile(profile.id);
      const tokenHash = hashApiKey(rawKey);
      const scopes = scopesForAccessProfile(profile.id);
      const { ciphertext, nonce, tag } = encryptApiKeySecret(rawKey);

      const insertQ = await pool.query(
        `INSERT INTO published_feed_access_keys
           (feed_id, name, token_hash, key_type, key_prefix, last_four, scopes,
            secret_ciphertext, secret_nonce, secret_tag, enabled, created_by, owner_user_id)
         VALUES (NULL, $1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12)
         RETURNING id`,
        [
          name,
          tokenHash,
          profile.id,
          profile.key_prefix,
          lastFourOf(rawKey),
          JSON.stringify(scopes),
          ciphertext,
          nonce,
          tag,
          enabled,
          req.user?.email || req.user?.username || null,
          ownerResolved.ownerUserId
        ]
      );
      const { rows } = await pool.query(
        `SELECT ${LIST_COLUMNS} ${LIST_FROM} WHERE k.id = $1`,
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
        metadata: {
          key_type: profile.id,
          access_profile: profile.id,
          scopes,
          masked_key: key.masked_key,
          owner_user_id: ownerResolved.ownerUserId,
          is_mcp: isMcpAccessProfile(profile.id)
        }
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
         ${LIST_FROM}
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
      const beforeQ = await pool.query(
        `SELECT ${LIST_COLUMNS}
         ${LIST_FROM}
         WHERE k.id = $1 AND k.deleted_at IS NULL`,
        [keyId]
      );
      if (!beforeQ.rows.length) return res.status(404).json({ message: 'API key not found' });
      const beforeRow = beforeQ.rows[0];
      const before = apiKeyAuditSnapshot(beforeRow);

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
         ${LIST_FROM}
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

  app.delete('/api/api-keys/:keyId', requireRole(ROLES.ADMIN), async (req, res) => {
    const keyId = Number(req.params.keyId);
    if (!Number.isFinite(keyId)) return res.status(400).json({ message: 'Invalid key id' });

    try {
      const beforeQ = await pool.query(
        `SELECT ${LIST_COLUMNS}
         ${LIST_FROM}
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

// Re-export for tests / callers that referenced the old constant name.
export { ACCESS_PROFILE, PUBLISHED_FEED_KEY_TYPE, IOC_MANAGEMENT_KEY_TYPE };

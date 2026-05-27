import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import {
  validateExpirationPolicyInput,
  formatExpirationSummary,
  getFeedPolicy,
  recomputeIocGlobalStatus,
  resolveFeedIdByKey,
  computePolicyExpiresAt,
  resolveMembershipStatus
} from '../lib/iocExpiration.js';
import { pickSafeFields } from '../lib/auditRedaction.js';

const POLICY_AUDIT_FIELDS = ['enabled', 'expiration_mode', 'ttl_days', 'grace_days', 'observable_type'];

/** JSON-safe policy payload (avoids BigInt / Date serialization errors on res.json). */
export function serializeExpirationPolicy(row, feedId) {
  if (!row) return null;
  const updatedAt = row.updated_at;
  return {
    feed_id: String(row.feed_id || feedId || ''),
    observable_type: row.observable_type || 'all',
    enabled: Boolean(row.enabled),
    expiration_mode: row.expiration_mode || 'never',
    ttl_days: row.ttl_days == null ? null : Number(row.ttl_days),
    grace_days: row.grace_days == null ? null : Number(row.grace_days),
    updated_at: updatedAt instanceof Date ? updatedAt.toISOString() : (updatedAt || null)
  };
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {ReturnType<import('../lib/auditLogService.js').createAuditLogService>} audit
 */
export function registerIocExpirationRoutes(app, pool, audit) {
  app.get('/api/threat-feeds/:feedKey/expiration-policy', async (req, res) => {
    try {
      const feedKey = String(req.params.feedKey || '').trim();
      const feedId = await resolveFeedIdByKey(pool, feedKey);
      if (!feedId) return res.status(404).json({ success: false, error: 'Feed not found' });

      const feedQ = await pool.query(
        'SELECT key, integration_id, name, feed_update_mode FROM integration_feeds WHERE key = $1',
        [feedKey]
      );
      const policy = await getFeedPolicy(pool, feedId);
      const policyOut = serializeExpirationPolicy(
        policy,
        feedId
      ) || {
        feed_id: String(feedId),
        observable_type: 'all',
        enabled: false,
        expiration_mode: 'never',
        ttl_days: null,
        grace_days: null,
        updated_at: null
      };
      return res.json({
        success: true,
        feed_key: feedKey,
        feed_id: String(feedId),
        feed_update_mode: feedQ.rows[0]?.feed_update_mode || 'incremental',
        policy: policyOut,
        summary: formatExpirationSummary(policyOut)
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Failed to load expiration policy', detail: err.message });
    }
  });

  app.patch('/api/threat-feeds/:feedKey/expiration-policy', async (req, res) => {
    try {
      const feedKey = String(req.params.feedKey || '').trim();
      const feedQ = await pool.query(
        'SELECT key, integration_id, feed_update_mode FROM integration_feeds WHERE key = $1',
        [feedKey]
      );
      if (!feedQ.rowCount) return res.status(404).json({ success: false, error: 'Feed not found' });

      const feedId = feedQ.rows[0].integration_id;
      const validation = validateExpirationPolicyInput(req.body, feedQ.rows[0].feed_update_mode);
      if (!validation.ok) {
        const msg = validation.errors[0] || 'Invalid expiration policy';
        return res.status(400).json({ success: false, error: msg, errors: validation.errors });
      }

      const prev = await getFeedPolicy(pool, feedId, validation.normalized.observable_type);
      const n = validation.normalized;

      const { rows } = await pool.query(
        `INSERT INTO threat_feed_expiration_policies (
           feed_id, observable_type, enabled, expiration_mode, ttl_days, grace_days, updated_at
         ) VALUES ($1::uuid, $2, $3, $4, $5, $6, NOW())
         ON CONFLICT (feed_id, observable_type)
         DO UPDATE SET
           enabled = EXCLUDED.enabled,
           expiration_mode = EXCLUDED.expiration_mode,
           ttl_days = EXCLUDED.ttl_days,
           grace_days = EXCLUDED.grace_days,
           updated_at = NOW()
         RETURNING *`,
        [feedId, n.observable_type, n.enabled, n.expiration_mode, n.ttl_days, n.grace_days]
      );

      const action = !prev
        ? 'threat_feed.expiration_policy.created'
        : (n.enabled ? 'threat_feed.expiration_policy.updated' : 'threat_feed.expiration_policy.disabled');

      const policyOut = serializeExpirationPolicy(rows[0], feedId);

      await audit.auditSuccess({
        req,
        action,
        entityType: AUDIT_ENTITY.INTEGRATION,
        entityId: feedKey,
        entityDisplay: feedKey,
        before: pickSafeFields(prev, POLICY_AUDIT_FIELDS),
        after: pickSafeFields(rows[0], POLICY_AUDIT_FIELDS),
        metadata: { feed_id: feedId, summary: formatExpirationSummary(policyOut) }
      });

      return res.status(200).json({
        success: true,
        policy: policyOut,
        summary: formatExpirationSummary(policyOut)
      });
    } catch (err) {
      console.error('[expiration-policy] PATCH failed', err?.message || err);
      return res.status(500).json({ success: false, error: 'Failed to update expiration policy', detail: err.message });
    }
  });

  app.patch('/api/ioc/:id/status-override', async (req, res) => {
    const iocId = Number(req.params.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      return res.status(400).json({ message: 'Invalid IOC id' });
    }

    const observableType = String(req.body?.observable_type || req.query?.observable_type || '').trim();
    if (!observableType) {
      return res.status(400).json({ message: 'observable_type is required in body or query' });
    }

    try {
      const prevQ = await pool.query(
        `SELECT id, observable_type, status, manual_status_override, manual_status, manual_expires_at, manual_override_reason
         FROM ioc_items WHERE id = $1 AND observable_type = $2`,
        [iocId, observableType]
      );
      if (!prevQ.rowCount) return res.status(404).json({ message: 'IOC not found' });

      const prev = prevQ.rows[0];
      const clear = req.body?.manual_status_override === false;
      const reason = String(req.body?.reason || '').trim() || null;
      const userId = req.user?.publicId && /^[0-9a-f-]{36}$/i.test(req.user.publicId) ? req.user.publicId : null;

      if (clear) {
        await pool.query(
          `UPDATE ioc_items
           SET manual_status_override = FALSE,
               manual_status = NULL,
               manual_expires_at = NULL,
               manual_override_reason = $3,
               manual_override_by_user_id = $4::uuid,
               manual_override_at = NOW()
           WHERE id = $1 AND observable_type = $2`,
          [iocId, observableType, reason, userId]
        );
        await recomputeIocGlobalStatus(pool, iocId, observableType, {
          audit,
          actor: { actor_type: 'user', source: 'web' }
        });
        await audit.auditSuccess({
          req,
          action: 'ioc.override_cleared',
          entityType: AUDIT_ENTITY.IOC,
          entityId: String(iocId),
          before: pickSafeFields(prev, POLICY_AUDIT_FIELDS),
          after: { manual_status_override: false },
          metadata: { reason, observable_type: observableType }
        });
        return res.json({ ok: true, cleared: true });
      }

      const manualStatus = String(req.body?.manual_status || '').trim();
      if (!['active', 'expired'].includes(manualStatus)) {
        return res.status(400).json({ message: 'manual_status must be active or expired' });
      }

      const manualExpiresAt = req.body?.manual_expires_at || null;

      await pool.query(
        `UPDATE ioc_items
         SET manual_status_override = TRUE,
             manual_status = $3,
             manual_expires_at = $4,
             manual_override_reason = $5,
             manual_override_by_user_id = $6::uuid,
             manual_override_at = NOW(),
             status = $3,
             expires_at = $4,
             expired_at = CASE WHEN $3 = 'expired' THEN COALESCE(expired_at, NOW()) ELSE NULL END,
             expiration_reason = COALESCE($5, 'manual_override')
         WHERE id = $1 AND observable_type = $2`,
        [iocId, observableType, manualStatus, manualExpiresAt, reason, userId]
      );

      const action = manualStatus === 'active' ? 'ioc.reactivated_by_user' : 'ioc.override_set';
      await audit.auditSuccess({
        req,
        action,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(iocId),
        before: pickSafeFields(prev),
        after: {
          manual_status_override: true,
          manual_status: manualStatus,
          manual_expires_at: manualExpiresAt,
          reason
        },
        metadata: { observable_type: observableType }
      });

      return res.json({ ok: true, status: manualStatus });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update IOC status override', detail: err.message });
    }
  });

  app.patch('/api/ioc/:id/feed-memberships/:membershipId/expiration-override', async (req, res) => {
    const iocId = Number(req.params.id);
    const membershipId = Number(req.params.membershipId);
    if (!Number.isFinite(iocId) || !Number.isFinite(membershipId)) {
      return res.status(400).json({ message: 'Invalid id' });
    }

    const observableType = String(req.body?.observable_type || req.query?.observable_type || '').trim();
    if (!observableType) {
      return res.status(400).json({ message: 'observable_type is required' });
    }

    try {
      const prevQ = await pool.query(
        `SELECT * FROM ioc_feed_memberships
         WHERE id = $1 AND ioc_item_id = $2 AND ioc_observable_type = $3`,
        [membershipId, iocId, observableType]
      );
      if (!prevQ.rowCount) return res.status(404).json({ message: 'Membership not found' });

      const prev = prevQ.rows[0];
      const reason = String(req.body?.reason || '').trim() || null;
      const userId = req.user?.publicId && /^[0-9a-f-]{36}$/i.test(req.user.publicId) ? req.user.publicId : null;
      const clear = req.body?.override_enabled === false;

      if (clear) {
        await pool.query(
          `UPDATE ioc_feed_memberships
           SET override_enabled = FALSE,
               override_expires_at = NULL,
               override_status = NULL,
               override_reason = $2,
               override_by_user_id = $3::uuid,
               override_at = NOW(),
               updated_at = NOW()
           WHERE id = $1`,
          [membershipId, reason, userId]
        );
        const policy = await getFeedPolicy(pool, prev.feed_id);
        const policyExpiresAt = computePolicyExpiresAt(policy, {
          firstSeenInFeed: prev.first_seen_in_feed,
          lastSeenInFeed: prev.last_seen_in_feed,
          missingSince: prev.missing_since
        });
        const status = resolveMembershipStatus({ ...prev, override_enabled: false, policy_expires_at: policyExpiresAt });
        await pool.query(
          `UPDATE ioc_feed_memberships
           SET policy_expires_at = $2, expires_at = $2, status = $3, updated_at = NOW()
           WHERE id = $1`,
          [membershipId, policyExpiresAt, status]
        );
        await recomputeIocGlobalStatus(pool, iocId, observableType, { audit, actor: { actor_type: 'user' } });
        await audit.auditSuccess({
          req,
          action: 'ioc_feed_membership.override_cleared',
          entityType: 'ioc_feed_membership',
          entityId: String(membershipId),
          before: pickSafeFields(prev),
          after: { override_enabled: false },
          metadata: { ioc_item_id: iocId, reason }
        });
        return res.json({ ok: true, cleared: true });
      }

      const overrideEnabled = req.body?.override_enabled !== false;
      const overrideStatus = req.body?.override_status == null ? null : String(req.body.override_status).trim();
      const overrideExpiresAt = req.body?.override_expires_at || null;

      if (overrideStatus && !['active', 'expired'].includes(overrideStatus)) {
        return res.status(400).json({ message: 'override_status must be active, expired, or null' });
      }

      let expiresAt = overrideExpiresAt;
      if (overrideStatus === 'expired' && !expiresAt) expiresAt = new Date();
      if (overrideStatus === 'active') expiresAt = overrideExpiresAt || null;

      await pool.query(
        `UPDATE ioc_feed_memberships
         SET override_enabled = $2,
             override_status = $3,
             override_expires_at = $4,
             override_reason = $5,
             override_by_user_id = $6::uuid,
             override_at = NOW(),
             expires_at = $4,
             status = COALESCE($3, status),
             expired_at = CASE WHEN $3 = 'expired' THEN COALESCE(expired_at, NOW()) ELSE NULL END,
             updated_at = NOW()
         WHERE id = $1`,
        [membershipId, overrideEnabled, overrideStatus, expiresAt, reason, userId]
      );

      await recomputeIocGlobalStatus(pool, iocId, observableType, { audit, actor: { actor_type: 'user' } });

      const action = overrideStatus === 'expired'
        ? 'ioc_feed_membership.expired_by_user'
        : 'ioc_feed_membership.override_set';

      await audit.auditSuccess({
        req,
        action,
        entityType: 'ioc_feed_membership',
        entityId: String(membershipId),
        before: pickSafeFields(prev),
        after: {
          override_enabled: overrideEnabled,
          override_status: overrideStatus,
          override_expires_at: expiresAt,
          reason
        },
        metadata: { ioc_item_id: iocId, feed_id: prev.feed_id }
      });

      return res.json({ ok: true });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to update membership override', detail: err.message });
    }
  });

  app.get('/api/ioc/:id/feed-memberships', async (req, res) => {
    const iocId = Number(req.params.id);
    const observableType = String(req.query?.observable_type || '').trim();
    if (!Number.isFinite(iocId) || !observableType) {
      return res.status(400).json({ message: 'Invalid id or observable_type' });
    }
    try {
      const { rows } = await pool.query(
        `SELECT m.*, f.key AS feed_key, f.name AS feed_name
         FROM ioc_feed_memberships m
         JOIN integration_feeds f ON f.integration_id = m.feed_id
         WHERE m.ioc_item_id = $1 AND m.ioc_observable_type = $2
         ORDER BY m.last_seen_in_feed DESC`,
        [iocId, observableType]
      );
      return res.json({ memberships: rows });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list feed memberships', detail: err.message });
    }
  });
}

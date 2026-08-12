import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import {
  validateExpirationPolicyInput,
  formatExpirationSummary,
  getFeedPolicy,
  recomputeIocGlobalStatus,
  resolveFeedIdByKey,
  computePolicyExpiresAt,
  resolveMembershipStatus,
  canonicalExpirationMode
} from '../lib/iocExpiration.js';
import { pickSafeFields } from '../lib/auditRedaction.js';
import { assertCustomFeedSettingsAllowed } from '../lib/customThreatFeedAccess.js';
import {
  buildIocExpirationAuditPayload,
  buildMembershipExpirationAuditPayload,
  formatIocEntityDisplay
} from '../lib/auditIocContext.js';
import { evaluateIocStatusOverrideRequest } from '../lib/iocStatusOverrideGuards.js';
import { parseManualExpirationInput } from '../lib/iocSourceValidation.js';
import { validateExpirationTypePolicies } from '../lib/feedExpirationPolicy.js';

const POLICY_AUDIT_FIELDS = ['enabled', 'expiration_mode', 'ttl_days', 'grace_days', 'observable_type'];
const IOC_STATUS_AUDIT_FIELDS = [
  'status', 'manual_status_override', 'manual_status', 'manual_expires_at',
  'manual_override_reason', 'expires_at', 'expired_at', 'expiration_reason'
];
const MEMBERSHIP_AUDIT_FIELDS = [
  'status', 'override_enabled', 'override_status', 'override_expires_at', 'override_reason'
];

function tsField(v) {
  if (v == null) return null;
  return v instanceof Date ? v.toISOString() : v;
}

export function serializeIocStatus(row) {
  if (!row) return null;
  return {
    id: Number(row.id),
    observable_type: row.observable_type,
    status: row.status || 'active',
    manual_status_override: Boolean(row.manual_status_override),
    manual_status: row.manual_status || null,
    manual_expires_at: tsField(row.manual_expires_at),
    manual_override_reason: row.manual_override_reason || null,
    manual_override_at: tsField(row.manual_override_at),
    expires_at: tsField(row.expires_at),
    expired_at: tsField(row.expired_at),
    expiration_reason: row.expiration_reason || null
  };
}

export function serializeMembership(row) {
  if (!row) return null;
  return {
    id: Number(row.id),
    feed_id: row.feed_id ? String(row.feed_id) : null,
    status: row.status || 'active',
    override_enabled: Boolean(row.override_enabled),
    override_status: row.override_status || null,
    override_expires_at: tsField(row.override_expires_at),
    override_reason: row.override_reason || null,
    override_at: tsField(row.override_at),
    expires_at: tsField(row.expires_at),
    expired_at: tsField(row.expired_at)
  };
}

async function fetchIocStatusRow(pool, iocId, observableType) {
  const { rows } = await pool.query(
    `SELECT id, observable, observable_type, status, expires_at, expired_at, expiration_reason,
            manual_status_override, manual_status, manual_expires_at,
            manual_override_reason, manual_override_at
     FROM ioc_items WHERE id = $1 AND observable_type = $2`,
    [iocId, observableType]
  );
  return rows[0] || null;
}

async function fetchMembershipRow(pool, membershipId, iocId, observableType) {
  const { rows } = await pool.query(
    `SELECT m.*, f.key AS feed_key, f.name AS feed_name, i.observable
     FROM ioc_feed_memberships m
     JOIN integration_feeds f ON f.integration_id = m.feed_id
     JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
     WHERE m.id = $1 AND m.ioc_item_id = $2 AND m.ioc_observable_type = $3`,
    [membershipId, iocId, observableType]
  );
  return rows[0] || null;
}

/** JSON-safe policy payload (avoids BigInt / Date serialization errors on res.json). */
export function serializeExpirationPolicy(row, feedId) {
  if (!row) return null;
  const updatedAt = row.updated_at;
  return {
    feed_id: String(row.feed_id || feedId || ''),
    observable_type: row.observable_type || 'all',
    enabled: Boolean(row.enabled),
    expiration_mode: canonicalExpirationMode(row.expiration_mode),
    ttl_days: row.ttl_days == null ? null : Number(row.ttl_days),
    grace_days: row.grace_days == null ? null : Number(row.grace_days),
    updated_at: updatedAt instanceof Date ? updatedAt.toISOString() : (updatedAt || null)
  };
}

/** JSON-safe IOC-type override payload. */
export function serializeExpirationTypePolicy(row) {
  if (!row) return null;
  return {
    ioc_type: row.ioc_type,
    mode: row.mode,
    ttl_days: row.ttl_days == null ? null : Number(row.ttl_days)
  };
}

async function fetchExpirationTypePolicies(db, feedId) {
  const { rows } = await db.query(
    `SELECT ioc_type, mode, ttl_days
     FROM integration_feed_expiration_type_policies
     WHERE feed_id = $1::uuid
     ORDER BY ioc_type`,
    [feedId]
  );
  return rows.map(serializeExpirationTypePolicy);
}

/**
 * Upsert/delete IOC-type overrides for a feed. An entry with mode 'inherit'
 * removes any stored override (inherit == "no override row"). Runs inside the
 * caller-provided client/transaction.
 */
async function applyExpirationTypePolicies(client, feedId, normalizedEntries) {
  for (const entry of normalizedEntries) {
    if (entry.mode === 'inherit') {
      await client.query(
        `DELETE FROM integration_feed_expiration_type_policies
         WHERE feed_id = $1::uuid AND ioc_type = $2`,
        [feedId, entry.ioc_type]
      );
      continue;
    }
    await client.query(
      `INSERT INTO integration_feed_expiration_type_policies (feed_id, ioc_type, mode, ttl_days, updated_at)
       VALUES ($1::uuid, $2, $3, $4, NOW())
       ON CONFLICT (feed_id, ioc_type)
       DO UPDATE SET mode = EXCLUDED.mode, ttl_days = EXCLUDED.ttl_days, updated_at = NOW()`,
      [feedId, entry.ioc_type, entry.mode, entry.ttl_days]
    );
  }
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
      const expirationTypePolicies = await fetchExpirationTypePolicies(pool, feedId);
      return res.json({
        success: true,
        feed_key: feedKey,
        feed_id: String(feedId),
        feed_update_mode: feedQ.rows[0]?.feed_update_mode || 'incremental',
        policy: policyOut,
        summary: formatExpirationSummary(policyOut),
        expiration_type_policies: expirationTypePolicies
      });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Failed to load expiration policy', detail: err.message });
    }
  });

  app.patch('/api/threat-feeds/:feedKey/expiration-policy', async (req, res) => {
    try {
      const feedKey = String(req.params.feedKey || '').trim();
      if (!assertCustomFeedSettingsAllowed(req, feedKey, res)) return;
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

      const hasTypePolicies = req.body?.expiration_type_policies !== undefined;
      const typeValidation = validateExpirationTypePolicies(req.body?.expiration_type_policies);
      if (!typeValidation.ok) {
        const msg = typeValidation.errors[0] || 'Invalid IOC type override policy';
        return res.status(400).json({ success: false, error: msg, errors: typeValidation.errors });
      }

      const prev = await getFeedPolicy(pool, feedId, validation.normalized.observable_type);
      const n = validation.normalized;

      const client = await pool.connect();
      let rows;
      let expirationTypePolicies;
      try {
        await client.query('BEGIN');
        ({ rows } = await client.query(
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
        ));

        if (hasTypePolicies) {
          await applyExpirationTypePolicies(client, feedId, typeValidation.normalized);
        }
        expirationTypePolicies = await fetchExpirationTypePolicies(client, feedId);
        await client.query('COMMIT');
      } catch (txErr) {
        await client.query('ROLLBACK').catch(() => {});
        throw txErr;
      } finally {
        client.release();
      }

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
        metadata: {
          feed_id: feedId,
          summary: formatExpirationSummary(policyOut),
          ...(hasTypePolicies ? { type_overrides: expirationTypePolicies } : {})
        }
      });

      return res.status(200).json({
        success: true,
        policy: policyOut,
        summary: formatExpirationSummary(policyOut),
        expiration_type_policies: expirationTypePolicies
      });
    } catch (err) {
      console.error('[expiration-policy] PATCH failed', err?.message || err);
      return res.status(500).json({ success: false, error: 'Failed to update expiration policy', detail: err.message });
    }
  });

  app.patch('/api/ioc/:id/status-override', async (req, res) => {
    const iocId = Number(req.params.id);
    if (!Number.isFinite(iocId) || iocId <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid IOC id' });
    }

    const observableType = String(req.body?.observable_type || req.query?.observable_type || '').trim();
    if (!observableType) {
      return res.status(400).json({ success: false, error: 'observable_type is required in body or query' });
    }

    try {
      const prev = await fetchIocStatusRow(pool, iocId, observableType);
      if (!prev) return res.status(404).json({ success: false, error: 'IOC not found' });

      const clear = req.body?.manual_status_override === false;
      const reason = String(req.body?.reason || '').trim() || null;
      const userId = req.user?.publicId && /^[0-9a-f-]{36}$/i.test(req.user.publicId) ? req.user.publicId : null;

      const noopCheck = evaluateIocStatusOverrideRequest(prev, req.body);
      if (noopCheck.noop) {
        const iocOut = serializeIocStatus(prev);
        return res.status(200).json({
          success: true,
          noop: true,
          message: noopCheck.message || 'No change required',
          ioc: iocOut
        });
      }

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
        const iocOut = serializeIocStatus(await fetchIocStatusRow(pool, iocId, observableType));
        await audit.auditSuccess({
          req,
          action: 'ioc.override_cleared',
          entityType: AUDIT_ENTITY.IOC,
          entityId: String(iocId),
          before: pickSafeFields(prev, IOC_STATUS_AUDIT_FIELDS),
          after: pickSafeFields(iocOut, IOC_STATUS_AUDIT_FIELDS),
          metadata: { reason, observable_type: observableType }
        });
        return res.status(200).json({ success: true, ioc: iocOut });
      }

      const manualStatus = String(req.body?.manual_status || '').trim();
      if (!['active', 'expired'].includes(manualStatus)) {
        return res.status(400).json({ success: false, error: 'manual_status must be active or expired' });
      }

      if (!reason) {
        return res.status(400).json({ success: false, error: 'Reason is required' });
      }

      const prevStatus = String(prev.status || 'active').trim().toLowerCase();
      const isReactivate = manualStatus === 'active' && prevStatus === 'expired';
      let manualExpiresAt = null;
      let reactivateExpiration = null;

      if (req.body?.expiration_policy) {
        const parsed = parseManualExpirationInput(req.body);
        if (!parsed.ok) {
          return res.status(400).json({ success: false, error: parsed.error });
        }
        manualExpiresAt = parsed.manual_expires_at;
        reactivateExpiration = {
          expiration_policy: parsed.policy,
          expire_days: parsed.expire_days ?? null,
          expires_at: parsed.manual_expires_at
        };
      } else if (req.body?.manual_expires_at !== undefined && req.body?.manual_expires_at !== null && req.body?.manual_expires_at !== '') {
        const d = new Date(req.body.manual_expires_at);
        if (Number.isNaN(d.getTime())) {
          return res.status(400).json({ success: false, error: 'manual_expires_at must be a valid ISO date/time' });
        }
        if (d.getTime() <= Date.now()) {
          return res.status(400).json({ success: false, error: 'manual_expires_at must be in the future' });
        }
        manualExpiresAt = d.toISOString();
      } else if (isReactivate) {
        return res.status(400).json({ success: false, error: 'expiration_policy is required when reactivating an IOC' });
      } else if (manualStatus === 'active') {
        manualExpiresAt = null;
      }

      await pool.query(
        `UPDATE ioc_items
         SET manual_status_override = TRUE,
             manual_status = $3,
             manual_expires_at = $4,
             manual_override_reason = $5,
             manual_override_by_user_id = $6::uuid,
             manual_override_at = NOW()
         WHERE id = $1 AND observable_type = $2`,
        [iocId, observableType, manualStatus, manualExpiresAt, reason, userId]
      );

      await recomputeIocGlobalStatus(pool, iocId, observableType, {
        audit,
        actor: { actor_type: 'user', source: 'web' }
      });

      const iocOut = serializeIocStatus(await fetchIocStatusRow(pool, iocId, observableType));
      const action = manualStatus === 'active'
        ? AUDIT_ACTION.IOC_REACTIVATED_BY_USER
        : 'ioc.expired';
      const expirationAudit = manualStatus === 'expired'
        ? buildIocExpirationAuditPayload({
          iocId,
          observable: prev?.observable,
          observableType,
          oldStatus: prev?.status || 'active',
          newStatus: iocOut?.status || 'expired',
          oldExpiresAt: prev?.expires_at,
          expiredAt: iocOut?.expired_at,
          newExpiresAt: iocOut?.expires_at,
          reason: reason || 'manual_override',
          actor: { actor_type: 'user', source: 'web' }
        })
        : null;

      const reactivateMetadata = isReactivate && reactivateExpiration
        ? {
          reason,
          observable_type: observableType,
          ioc_value: prev?.observable,
          old_status: prev?.status || 'expired',
          new_status: iocOut?.status || 'active',
          old_expires_at: prev?.expires_at,
          expires_at: iocOut?.expires_at,
          expiration_policy: reactivateExpiration.expiration_policy,
          expire_days: reactivateExpiration.expire_days,
          policy_expires_at: reactivateExpiration.expires_at
        }
        : null;

      await audit.auditSuccess({
        req,
        action,
        entityType: AUDIT_ENTITY.IOC,
        entityId: String(iocId),
        entityDisplay: expirationAudit?.entityDisplay || formatIocEntityDisplay(observableType, prev?.observable),
        before: expirationAudit?.before || pickSafeFields(prev, IOC_STATUS_AUDIT_FIELDS),
        after: expirationAudit?.after || pickSafeFields(iocOut, IOC_STATUS_AUDIT_FIELDS),
        metadata: expirationAudit?.metadata || reactivateMetadata || { reason, observable_type: observableType, ioc_value: prev?.observable }
      });

      return res.status(200).json({ success: true, ioc: iocOut });
    } catch (err) {
      console.error('[ioc-status-override] PATCH failed', err?.message || err);
      return res.status(500).json({ success: false, error: 'Failed to update IOC status override', detail: err.message });
    }
  });

  app.patch('/api/ioc/:id/feed-memberships/:membershipId/expiration-override', async (req, res) => {
    const iocId = Number(req.params.id);
    const membershipId = Number(req.params.membershipId);
    if (!Number.isFinite(iocId) || !Number.isFinite(membershipId)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }

    const observableType = String(req.body?.observable_type || req.query?.observable_type || '').trim();
    if (!observableType) {
      return res.status(400).json({ success: false, error: 'observable_type is required' });
    }

    try {
      const prev = await fetchMembershipRow(pool, membershipId, iocId, observableType);
      if (!prev) return res.status(404).json({ success: false, error: 'Membership not found' });

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
        const membershipOut = serializeMembership(await fetchMembershipRow(pool, membershipId, iocId, observableType));
        const iocOut = serializeIocStatus(await fetchIocStatusRow(pool, iocId, observableType));
        await audit.auditSuccess({
          req,
          action: 'ioc_feed_membership.override_cleared',
          entityType: 'ioc_feed_membership',
          entityId: String(membershipId),
          before: pickSafeFields(prev, MEMBERSHIP_AUDIT_FIELDS),
          after: pickSafeFields(membershipOut, MEMBERSHIP_AUDIT_FIELDS),
          metadata: { ioc_item_id: iocId, reason }
        });
        return res.status(200).json({ success: true, membership: membershipOut, ioc: iocOut });
      }

      if (!reason) {
        return res.status(400).json({ success: false, error: 'Reason is required' });
      }

      const overrideEnabled = req.body?.override_enabled !== false;
      const overrideStatus = req.body?.override_status == null ? null : String(req.body.override_status).trim();
      let overrideExpiresAt = req.body?.override_expires_at || null;

      if (overrideStatus && !['active', 'expired'].includes(overrideStatus)) {
        return res.status(400).json({ success: false, error: 'override_status must be active, expired, or null' });
      }

      if (overrideExpiresAt) {
        const d = new Date(overrideExpiresAt);
        if (Number.isNaN(d.getTime())) {
          return res.status(400).json({ success: false, error: 'override_expires_at must be a valid ISO date/time' });
        }
        overrideExpiresAt = d.toISOString();
      }

      let expiresAt = overrideExpiresAt;
      if (overrideStatus === 'expired' && !expiresAt) expiresAt = new Date().toISOString();
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

      const membershipOut = serializeMembership(await fetchMembershipRow(pool, membershipId, iocId, observableType));
      const iocOut = serializeIocStatus(await fetchIocStatusRow(pool, iocId, observableType));

      const action = overrideStatus === 'expired'
        ? 'ioc_feed_membership.expired_by_user'
        : 'ioc_feed_membership.override_set';

      const expirationAudit = overrideStatus === 'expired'
        ? buildMembershipExpirationAuditPayload({
          membershipId,
          iocId,
          observable: prev?.observable,
          observableType,
          feedId: prev?.feed_id,
          feedName: prev?.feed_name,
          oldStatus: prev?.status || 'active',
          newStatus: membershipOut?.status || 'expired',
          oldExpiresAt: prev?.expires_at,
          expiredAt: membershipOut?.expired_at,
          reason: reason || 'manual_override',
          actor: { actor_type: 'user', source: 'web' }
        })
        : null;

      await audit.auditSuccess({
        req,
        action,
        entityType: 'ioc_feed_membership',
        entityId: String(membershipId),
        entityDisplay: expirationAudit?.entityDisplay,
        before: expirationAudit?.before || pickSafeFields(prev, MEMBERSHIP_AUDIT_FIELDS),
        after: expirationAudit?.after || pickSafeFields(membershipOut, MEMBERSHIP_AUDIT_FIELDS),
        metadata: expirationAudit?.metadata || {
          ioc_item_id: iocId,
          ioc_id: iocId,
          ioc_value: prev?.observable,
          ioc_observable_type: observableType,
          feed_id: prev?.feed_id,
          feed_name: prev?.feed_name,
          membership_id: membershipId,
          reason
        }
      });

      return res.status(200).json({ success: true, membership: membershipOut, ioc: iocOut });
    } catch (err) {
      console.error('[ioc-membership-override] PATCH failed', err?.message || err);
      return res.status(500).json({ success: false, error: 'Failed to update membership override', detail: err.message });
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

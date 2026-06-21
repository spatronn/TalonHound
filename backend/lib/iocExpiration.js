/**
 * Feed-based IOC expiration: memberships, policies, global status recompute.
 */

import {
  buildIocExpirationAuditPayload,
  formatMembershipEntityDisplay
} from './auditIocContext.js';
import {
  createImportOptimizationContext,
  enterImportOptimizationContext,
  getImportOptimizationContext,
  isIocSuppressedFromIndex,
  resolveFeedPolicyFromContext,
  scheduleDeferredIocRecompute
} from './importOptimizationContext.js';

export const EXPIRATION_MODES = Object.freeze([
  'never',
  'fixed_ttl',
  'last_seen_ttl',
  'missing_from_feed_ttl'
]);

export const MEMBERSHIP_STATUSES = Object.freeze(['active', 'expired']);
export const IOC_STATUSES = Object.freeze(['active', 'expired', 'disabled', 'suppressed']);

/** integration_feeds.key → source_name match rules */
export const FEED_SOURCE_RULES = Object.freeze([
  { key: 'usom-trcert', exact: 'USOM:TR-CERT' },
  { key: 'urlhaus-abusech', exact: 'URLhaus:abuse.ch' },
  { key: 'threatfox-abusech', exact: 'ThreatFox:abuse.ch' },
  { key: 'malwarebazaar-abusech', exact: 'MalwareBazaar:abuse.ch' },
  { key: 'et-blockrules', prefix: 'EmergingThreats:' },
  { key: 'phishtank-opendnsrr', includes: ['phishtank', 'PhishTank'] }
]);

const feedMetaCache = { at: 0, rows: [] };
const FEED_META_TTL_MS = 60_000;

function addDays(base, days) {
  const d = base instanceof Date ? new Date(base.getTime()) : new Date(base);
  if (!Number.isFinite(days) || days <= 0) return null;
  d.setUTCDate(d.getUTCDate() + Number(days));
  return d;
}

export function sourceNameMatchesFeed(sourceName, feedKey) {
  const sn = String(sourceName || '');
  const rule = FEED_SOURCE_RULES.find((r) => r.key === feedKey);
  if (!rule) return false;
  if (rule.exact) return sn === rule.exact;
  if (rule.prefix) return sn.startsWith(rule.prefix);
  if (rule.includes) return rule.includes.some((p) => sn.includes(p));
  return false;
}

export function feedKeyForSourceName(sourceName) {
  const hit = FEED_SOURCE_RULES.find((r) => sourceNameMatchesFeed(sourceName, r.key));
  return hit?.key || null;
}

export function formatExpirationSummary(policy) {
  if (!policy || policy.enabled === false) return 'Disabled';
  const mode = String(policy.expiration_mode || 'never');
  if (mode === 'never') return 'Never';
  const ttl = policy.ttl_days != null ? `${policy.ttl_days}d` : '';
  const grace = policy.grace_days != null ? `${policy.grace_days}d` : '';
  if (mode === 'fixed_ttl') return ttl ? `${ttl} fixed` : 'fixed';
  if (mode === 'last_seen_ttl') return ttl ? `${ttl} last_seen` : 'last_seen';
  if (mode === 'missing_from_feed_ttl') return grace ? `${grace} missing_from_feed` : 'missing_from_feed';
  return mode;
}

export function validateExpirationPolicyInput(body, feedUpdateMode = 'incremental') {
  const errors = [];
  const enabled = Boolean(body?.enabled);
  const mode = String(body?.expiration_mode || 'never').trim();
  const ttlDays = body?.ttl_days == null || body?.ttl_days === '' ? null : Number(body.ttl_days);
  const graceDays = body?.grace_days == null || body?.grace_days === '' ? null : Number(body.grace_days);

  if (!EXPIRATION_MODES.includes(mode)) {
    errors.push(`expiration_mode must be one of: ${EXPIRATION_MODES.join(', ')}`);
  }

  if (enabled && mode === 'never') {
    // allowed: enabled with never = no expiry but flag on
  }

  if (enabled && (mode === 'fixed_ttl' || mode === 'last_seen_ttl')) {
    if (!Number.isInteger(ttlDays) || ttlDays <= 0) {
      errors.push('ttl_days is required and must be a positive integer for fixed_ttl and last_seen_ttl');
    }
  }

  if (enabled && mode === 'missing_from_feed_ttl') {
    const g = graceDays ?? ttlDays;
    if (!Number.isInteger(g) || g <= 0) {
      errors.push('grace_days (or ttl_days) is required and must be a positive integer for missing_from_feed_ttl');
    }
    if (feedUpdateMode !== 'snapshot') {
      errors.push('missing_from_feed_ttl is only supported for snapshot/full-list feeds');
    }
  }

  if (ttlDays != null && (!Number.isInteger(ttlDays) || ttlDays <= 0)) {
    errors.push('ttl_days must be a positive integer when provided');
  }
  if (graceDays != null && (!Number.isInteger(graceDays) || graceDays <= 0)) {
    errors.push('grace_days must be a positive integer when provided');
  }

  return {
    ok: errors.length === 0,
    errors,
    normalized: {
      observable_type: String(body?.observable_type || 'all').trim() || 'all',
      enabled,
      expiration_mode: mode,
      ttl_days: ttlDays,
      grace_days: graceDays
    }
  };
}

export function computePolicyExpiresAt(policy, { firstSeenInFeed, lastSeenInFeed, missingSince }) {
  if (!policy?.enabled || policy.expiration_mode === 'never') return null;

  const mode = policy.expiration_mode;
  const ttl = Number(policy.ttl_days);
  const grace = Number(policy.grace_days ?? policy.ttl_days);

  if (mode === 'fixed_ttl' && firstSeenInFeed && Number.isFinite(ttl) && ttl > 0) {
    return addDays(firstSeenInFeed, ttl);
  }
  if (mode === 'last_seen_ttl' && lastSeenInFeed && Number.isFinite(ttl) && ttl > 0) {
    return addDays(lastSeenInFeed, ttl);
  }
  if (mode === 'missing_from_feed_ttl' && missingSince && Number.isFinite(grace) && grace > 0) {
    return addDays(missingSince, grace);
  }
  return null;
}

export function resolveEffectiveExpiresAt(membership) {
  if (membership?.override_enabled) {
    if (membership.override_expires_at) return membership.override_expires_at;
    if (membership.override_status === 'expired') return new Date(0);
    if (membership.override_status === 'active') return null;
  }
  return membership?.policy_expires_at ?? null;
}

export function resolveMembershipStatus(membership, now = new Date()) {
  if (membership?.override_enabled && membership.override_status) {
    return membership.override_status;
  }
  const exp = resolveEffectiveExpiresAt(membership);
  if (exp && new Date(exp).getTime() <= now.getTime()) {
    return 'expired';
  }
  return 'active';
}

async function loadFeedMeta(client) {
  const now = Date.now();
  if (feedMetaCache.rows.length && now - feedMetaCache.at < FEED_META_TTL_MS) {
    return feedMetaCache.rows;
  }
  const { rows } = await client.query(`
    SELECT key, integration_id AS feed_id, feed_update_mode, name, feed_kind
    FROM integration_feeds
  `);
  feedMetaCache.at = now;
  feedMetaCache.rows = rows;
  return rows;
}

export async function resolveFeedIdBySourceName(client, sourceName) {
  const feeds = await loadFeedMeta(client);
  const key = feedKeyForSourceName(sourceName);
  if (key) {
    const row = feeds.find((f) => f.key === key);
    if (row) return row.feed_id || null;
  }
  const sn = String(sourceName || '').trim();
  if (!sn) return null;
  const custom = feeds.find((f) => String(f.feed_kind || '') === 'custom' && f.name === sn);
  return custom?.feed_id || null;
}

export async function resolveFeedIdByKey(client, feedKey) {
  const feeds = await loadFeedMeta(client);
  const row = feeds.find((f) => f.key === feedKey);
  return row?.feed_id || null;
}

export async function getFeedPolicy(client, feedId, observableType = 'all', opts = {}) {
  const ctx = opts.importContext || getImportOptimizationContext();
  if (ctx) {
    return resolveFeedPolicyFromContext(ctx, feedId, observableType);
  }
  const { rows } = await client.query(
    `SELECT * FROM threat_feed_expiration_policies
     WHERE feed_id = $1::uuid AND observable_type IN ($2, 'all')
     ORDER BY CASE WHEN observable_type = $2 THEN 0 ELSE 1 END
     LIMIT 1`,
    [feedId, observableType]
  );
  return rows[0] || null;
}

async function queryIocSuppressedFromDb(client, observable, observableType) {
  const { rows } = await client.query(
    `SELECT 1 FROM ioc_suppressions
     WHERE lower(ioc_value) = lower($1)
       AND lower(ioc_type) = lower($2)
       AND active = TRUE
       AND (expires_at IS NULL OR expires_at > NOW())
     LIMIT 1`,
    [observable, observableType]
  );
  return rows.length > 0;
}

export async function isIocSuppressed(client, observable, observableType, opts = {}) {
  const ctx = opts.importContext || getImportOptimizationContext();
  if (ctx?.suppressionIndex) {
    return isIocSuppressedFromIndex(ctx.suppressionIndex, observable, observableType);
  }
  return queryIocSuppressedFromDb(client, observable, observableType);
}

export async function flushDeferredIocRecomputes(client, ctx = getImportOptimizationContext()) {
  if (!ctx?.deferredRecomputes?.size) return { flushed: 0 };
  const entries = [...ctx.deferredRecomputes.values()];
  ctx.deferredRecomputes.clear();
  for (const entry of entries) {
    await recomputeIocGlobalStatus(client, entry.iocItemId, entry.observableType, {
      audit: entry.audit,
      actor: entry.actor,
      importContext: ctx
    });
  }
  return { flushed: entries.length };
}

export async function withImportOptimizationContext(client, fn) {
  const active = getImportOptimizationContext();
  if (active) {
    return fn(active);
  }
  const ctx = await createImportOptimizationContext(client);
  return enterImportOptimizationContext(ctx, async () => {
    try {
      const result = await fn(ctx);
      await flushDeferredIocRecomputes(client, ctx);
      return result;
    } catch (err) {
      ctx.deferredRecomputes.clear();
      throw err;
    }
  });
}

export async function recomputeIocGlobalStatus(client, iocItemId, observableType, opts = {}) {
  const { rows } = await client.query(
    `SELECT id, observable, observable_type, status, manual_status_override, manual_status,
            manual_expires_at, expires_at, expired_at, expiration_reason
     FROM ioc_items
     WHERE id = $1 AND observable_type = $2
     LIMIT 1`,
    [iocItemId, observableType]
  );
  const ioc = rows[0];
  if (!ioc) return { changed: false, reason: 'not_found' };

  const audit = opts.audit;
  const actor = opts.actor || { actor_type: 'system', source: 'worker' };

  if (await isIocSuppressed(client, ioc.observable, ioc.observable_type, opts)) {
    if (ioc.status !== 'suppressed') {
      await client.query(
        `UPDATE ioc_items SET status = 'suppressed' WHERE id = $1 AND observable_type = $2`,
        [iocItemId, observableType]
      );
      if (audit?.auditLog) {
        await audit.auditLog({
          action: 'ioc.status.changed',
          entityType: 'ioc',
          entityId: String(iocItemId),
          before: { status: ioc.status },
          after: { status: 'suppressed' },
          metadata: { actor_type: actor.actor_type, ioc_observable_type: observableType, reason: 'suppression_active' },
          source: actor.source || 'system'
        });
      }
      return { changed: true, status: 'suppressed' };
    }
    return { changed: false, status: 'suppressed' };
  }

  if (ioc.status === 'disabled') {
    return { changed: false, status: 'disabled' };
  }

  if (ioc.manual_status_override) {
    const manualStatus = ioc.manual_status || 'active';
    const manualExp = ioc.manual_expires_at;
    let nextStatus = manualStatus;
    if (manualExp && new Date(manualExp).getTime() <= Date.now()) {
      nextStatus = 'expired';
    }
    const patch = {
      status: nextStatus,
      expires_at: manualExp,
      expired_at: nextStatus === 'expired' ? (ioc.expired_at || new Date()) : null,
      expiration_reason: ioc.manual_override_reason || 'manual_override'
    };
    if (ioc.status !== patch.status || String(ioc.expires_at || '') !== String(patch.expires_at || '')) {
      await client.query(
        `UPDATE ioc_items
         SET status = $3, expires_at = $4, expired_at = $5, expiration_reason = $6
         WHERE id = $1 AND observable_type = $2`,
        [iocItemId, observableType, patch.status, patch.expires_at, patch.expired_at, patch.expiration_reason]
      );
      return { changed: true, status: patch.status };
    }
    return { changed: false, status: patch.status };
  }

  const memQ = await client.query(
    `SELECT m.status, m.purged_at
     FROM ioc_feed_memberships m
     INNER JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
     WHERE i.observable = $1 AND i.observable_type = $2`,
    [ioc.observable, observableType]
  );
  const memberships = memQ.rows || [];
  let nextStatus = 'expired';
  let minExpires = null;
  if (!memberships.length) {
    nextStatus = 'active';
  } else if (memberships.some((m) => String(m.status) === 'active' && !m.purged_at)) {
    nextStatus = 'active';
  }

  const expQ = await client.query(
    `SELECT MIN(m.expires_at) AS min_exp
     FROM ioc_feed_memberships m
     INNER JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
     WHERE i.observable = $1 AND i.observable_type = $2
       AND m.status = 'active' AND m.purged_at IS NULL AND m.expires_at IS NOT NULL`,
    [ioc.observable, observableType]
  );
  minExpires = expQ.rows[0]?.min_exp || null;

  const expiredAt = nextStatus === 'expired' ? (ioc.expired_at || new Date()) : null;
  const expirationReason = nextStatus === 'expired' ? 'all_feed_memberships_expired' : null;

  if (ioc.status === nextStatus
    && String(ioc.expires_at || '') === String(minExpires || '')
    && (nextStatus !== 'expired' || ioc.expired_at)) {
    return { changed: false, status: nextStatus };
  }

  await client.query(
    `UPDATE ioc_items
     SET status = $3, expires_at = $4, expired_at = $5, expiration_reason = $6
     WHERE observable = $1 AND observable_type = $2`,
    [ioc.observable, observableType, nextStatus, minExpires, expiredAt, expirationReason]
  );

  if (audit?.auditLog) {
    const expiredMemberships = Array.isArray(opts.expiredMemberships) ? opts.expiredMemberships : [];
    const workerMembershipExpiry = expiredMemberships.length > 0;

    if (!(workerMembershipExpiry && nextStatus !== 'expired')) {
      const action = nextStatus === 'expired' ? 'ioc.expired' : 'ioc.status.changed';
      const auditPayload = nextStatus === 'expired'
        ? buildIocExpirationAuditPayload({
          iocId: iocItemId,
          observable: ioc.observable,
          observableType,
          oldStatus: ioc.status,
          newStatus: nextStatus,
          oldExpiresAt: ioc.expires_at,
          expiredAt,
          newExpiresAt: minExpires,
          reason: expirationReason || 'expires_at_reached',
          actor,
          affectedFeeds: expiredMemberships.map((membership) => ({
            membershipId: membership.membershipId,
            feedId: membership.feedId,
            feedName: membership.feedName,
            oldExpiresAt: membership.oldExpiresAt,
            expiredAt: membership.expiredAt,
            reason: membership.reason
          }))
        })
        : {
          entityDisplay: null,
          metadata: { actor_type: actor.actor_type, ioc_observable_type: observableType }
        };

      await audit.auditLog({
        action,
        entityType: 'ioc',
        entityId: String(iocItemId),
        entityDisplay: auditPayload.entityDisplay,
        before: auditPayload.before || { status: ioc.status, expires_at: ioc.expires_at },
        after: auditPayload.after || { status: nextStatus, expires_at: minExpires, expired_at: expiredAt },
        metadata: auditPayload.metadata,
        source: actor.source || 'expiration-worker'
      });
    }
  }

  return { changed: true, status: nextStatus };
}

export function computeMembershipFieldPatch(m, policy, now = new Date()) {
  const policyExpiresAt = computePolicyExpiresAt(policy, {
    firstSeenInFeed: m.first_seen_in_feed,
    lastSeenInFeed: m.last_seen_in_feed,
    missingSince: m.missing_since
  });

  let expiresAt = policyExpiresAt;
  if (m.override_enabled) {
    if (m.override_expires_at) expiresAt = m.override_expires_at;
    else if (m.override_status === 'active') expiresAt = null;
    else if (m.override_status === 'expired') expiresAt = new Date(0);
  }

  const status = resolveMembershipStatus({ ...m, policy_expires_at: policyExpiresAt, expires_at: expiresAt }, now);
  const expiredAt = status === 'expired' ? (m.expired_at || now) : null;
  const expirationReason = status === 'expired'
    ? (m.override_enabled && m.override_status === 'expired' ? 'manual_override' : (policy?.expiration_mode || 'policy'))
    : null;

  return {
    policyExpiresAt,
    expiresAt,
    status,
    expiredAt,
    expirationReason,
    missingSince: m.missing_since
  };
}

export function membershipComputedFieldsUnchanged(m, patch) {
  return String(m.policy_expires_at || '') === String(patch.policyExpiresAt || '')
    && String(m.expires_at || '') === String(patch.expiresAt || '')
    && String(m.status || '') === String(patch.status || '')
    && String(m.expired_at || '') === String(patch.expiredAt || '')
    && String(m.expiration_reason || '') === String(patch.expirationReason || '')
    && String(m.missing_since || '') === String(patch.missingSince || '');
}

async function applyMembershipComputedFields(client, membershipId, policy, now = new Date(), membershipRow = null) {
  const m = membershipRow || (await client.query('SELECT * FROM ioc_feed_memberships WHERE id = $1', [membershipId])).rows[0];
  if (!m) return null;

  const patch = computeMembershipFieldPatch(m, policy, now);
  if (membershipComputedFieldsUnchanged(m, patch)) {
    return { membershipId, ...patch, skipped: true };
  }

  const upd = await client.query(
    `UPDATE ioc_feed_memberships
     SET policy_expires_at = $2, expires_at = $3, status = $4, expired_at = $5,
         expiration_reason = $6, missing_since = $7, updated_at = NOW()
     WHERE id = $1
       AND (
         policy_expires_at IS DISTINCT FROM $2
         OR expires_at IS DISTINCT FROM $3
         OR status IS DISTINCT FROM $4
         OR expired_at IS DISTINCT FROM $5
         OR expiration_reason IS DISTINCT FROM $6
         OR missing_since IS DISTINCT FROM $7
       )`,
    [membershipId, patch.policyExpiresAt, patch.expiresAt, patch.status, patch.expiredAt, patch.expirationReason, patch.missingSince]
  );

  return { membershipId, ...patch, updated: Number(upd.rowCount || 0) > 0 };
}

export async function upsertMembershipOnImport(client, {
  iocItemId,
  observableType,
  feedId,
  seenAt = new Date(),
  explicitConfidence = null,
  audit = null,
  actor = { actor_type: 'feed_import', source: 'integration' }
}) {
  if (!iocItemId || !observableType || !feedId) return null;

  const importCtx = getImportOptimizationContext();
  const policy = await getFeedPolicy(client, feedId, observableType, { importContext: importCtx });
  const now = seenAt instanceof Date ? seenAt : new Date(seenAt);

  const existing = await client.query(
    `SELECT * FROM ioc_feed_memberships
     WHERE ioc_item_id = $1 AND ioc_observable_type = $2 AND feed_id = $3::uuid`,
    [iocItemId, observableType, feedId]
  );

  let membershipId;
  let reactivated = false;
  let membershipRow = null;
  let membershipTouched = false;

  if (!existing.rowCount) {
    const ins = await client.query(
      `INSERT INTO ioc_feed_memberships (
         ioc_item_id, ioc_observable_type, feed_id,
         first_seen_in_feed, last_seen_in_feed, missing_since, status
       ) VALUES ($1, $2, $3::uuid, $4, $4, NULL, 'active')
       RETURNING *`,
      [iocItemId, observableType, feedId, now]
    );
    membershipRow = ins.rows[0];
    membershipId = membershipRow.id;
    membershipTouched = true;
  } else {
    const row = existing.rows[0];
    membershipId = row.id;
    const wasExpired = row.status === 'expired';
    const wasPurged = row.status === 'purged';
    const clearMissing = true;

    if (row.override_enabled) {
      const upd = await client.query(
        `UPDATE ioc_feed_memberships
         SET last_seen_in_feed = $2,
             missing_since = CASE WHEN $3 THEN NULL ELSE missing_since END,
             updated_at = NOW()
         WHERE id = $1
           AND (
             last_seen_in_feed IS DISTINCT FROM $2
             OR ($3 AND missing_since IS NOT NULL)
           )
         RETURNING *`,
        [membershipId, now, clearMissing]
      );
      if (upd.rowCount) {
        membershipRow = upd.rows[0];
        membershipTouched = true;
      } else {
        membershipRow = row;
      }
    } else {
      const upd = await client.query(
        `UPDATE ioc_feed_memberships
         SET last_seen_in_feed = $2,
             missing_since = NULL,
             status = 'active',
             expired_at = NULL,
             expiration_reason = NULL,
             purged_at = NULL,
             purged_by = NULL,
             purged_by_username = NULL,
             purge_reason = NULL,
             updated_at = NOW()
         WHERE id = $1
           AND (
             last_seen_in_feed IS DISTINCT FROM $2
             OR missing_since IS NOT NULL
             OR status IS DISTINCT FROM 'active'
             OR expired_at IS NOT NULL
             OR expiration_reason IS NOT NULL
             OR purged_at IS NOT NULL
             OR purged_by IS NOT NULL
             OR purged_by_username IS NOT NULL
             OR purge_reason IS NOT NULL
           )
         RETURNING *`,
        [membershipId, now]
      );
      if (upd.rowCount) {
        membershipRow = upd.rows[0];
        membershipTouched = true;
        if (wasExpired || wasPurged) reactivated = true;
      } else {
        membershipRow = row;
      }
    }
  }

  const computed = await applyMembershipComputedFields(client, membershipId, policy, now, membershipRow);
  if (computed?.updated) membershipTouched = true;

  const explicit = explicitConfidence != null ? String(explicitConfidence).trim().toLowerCase() : '';
  if (['low', 'medium', 'high'].includes(explicit)) {
    try {
      const confUpd = await client.query(
        `UPDATE ioc_feed_memberships
         SET explicit_confidence = $2, updated_at = NOW()
         WHERE id = $1
           AND explicit_confidence IS DISTINCT FROM $2`,
        [membershipId, explicit]
      );
      if (confUpd.rowCount) membershipTouched = true;
    } catch (err) {
      if (err?.code !== '42703') throw err;
    }
  }

  if (reactivated && audit?.auditLog) {
    await audit.auditLog({
      action: 'ioc_feed_membership.reactivated_by_feed',
      entityType: 'ioc_feed_membership',
      entityId: String(membershipId),
      metadata: { feed_id: feedId, ioc_item_id: iocItemId, actor_type: actor.actor_type },
      source: actor.source || 'integration'
    });
  }

  if (reactivated || !importCtx) {
    await recomputeIocGlobalStatus(client, iocItemId, observableType, {
      audit,
      actor,
      importContext: importCtx
    });
  } else if (membershipTouched) {
    scheduleDeferredIocRecompute(importCtx, { iocItemId, observableType, audit, actor });
  }

  return membershipId;
}

export async function finalizeSnapshotFeedRun(client, {
  feedId,
  seenKeys,
  audit = null
}) {
  const feeds = await loadFeedMeta(client);
  const feed = feeds.find((f) => f.feed_id === feedId);
  if (!feed || feed.feed_update_mode !== 'snapshot') return { marked: 0 };

  const policy = await getFeedPolicy(client, feedId);
  if (!policy?.enabled || policy.expiration_mode !== 'missing_from_feed_ttl') {
    return { marked: 0 };
  }

  const seenArr = [...seenKeys];
  if (!seenArr.length) return { marked: 0 };

  const { rows: activeRows } = await client.query(
    `SELECT m.id, m.ioc_item_id, m.ioc_observable_type
     FROM ioc_feed_memberships m
     WHERE m.feed_id = $1::uuid AND m.status = 'active'`,
    [feedId]
  );

  let marked = 0;
  const now = new Date();
  for (const row of activeRows) {
    const key = `${row.ioc_observable_type}|${row.ioc_item_id}`;
    if (seenKeys.has(key)) continue;

    await client.query(
      `UPDATE ioc_feed_memberships
       SET missing_since = COALESCE(missing_since, $2), updated_at = NOW()
       WHERE id = $1
         AND missing_since IS NULL`,
      [row.id, now]
    );
    await applyMembershipComputedFields(client, row.id, policy, now);
    const importCtx = getImportOptimizationContext();
    if (importCtx) {
      scheduleDeferredIocRecompute(importCtx, {
        iocItemId: row.ioc_item_id,
        observableType: row.ioc_observable_type,
        audit
      });
    } else {
      await recomputeIocGlobalStatus(client, row.ioc_item_id, row.ioc_observable_type, { audit });
    }
    marked += 1;
  }
  return { marked };
}

export async function runExpirationWorkerBatch(client, opts = {}) {
  const batchSize = Math.max(Number(opts.batchSize || 500), 1);
  const audit = opts.audit || null;
  const now = new Date();
  const workerActor = { actor_type: 'system', source: 'expiration-worker' };

  const { rows } = await client.query(
    `SELECT m.id, m.ioc_item_id, m.ioc_observable_type, m.feed_id, m.status, m.expires_at, m.expiration_reason,
            i.observable,
            f.name AS feed_name
     FROM ioc_feed_memberships m
     JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
     LEFT JOIN integration_feeds f ON f.integration_id = m.feed_id
     WHERE m.status = 'active'
       AND m.expires_at IS NOT NULL
       AND m.expires_at <= NOW()
     ORDER BY m.expires_at ASC
     LIMIT $1
     FOR UPDATE OF m SKIP LOCKED`,
    [batchSize]
  );

  let expiredMemberships = 0;
  const iocTouches = new Map();

  for (const row of rows) {
    const expiredAt = now.toISOString();
    await client.query(
      `UPDATE ioc_feed_memberships
       SET status = 'expired', expired_at = COALESCE(expired_at, NOW()),
           expiration_reason = COALESCE(expiration_reason, $2), updated_at = NOW()
       WHERE id = $1 AND status = 'active'`,
      [row.id, row.expiration_reason || 'policy_ttl']
    );
    expiredMemberships += 1;
    const touchKey = `${row.ioc_observable_type}|${row.ioc_item_id}`;
    if (!iocTouches.has(touchKey)) {
      iocTouches.set(touchKey, {
        iocItemId: row.ioc_item_id,
        observableType: row.ioc_observable_type,
        expiredMemberships: []
      });
    }
    iocTouches.get(touchKey).expiredMemberships.push({
      membershipId: row.id,
      feedId: row.feed_id,
      feedName: row.feed_name,
      oldExpiresAt: row.expires_at,
      expiredAt,
      reason: row.expiration_reason || 'policy_ttl'
    });
  }

  let iocRecomputed = 0;
  let iocGlobalExpired = 0;
  for (const touch of iocTouches.values()) {
    const res = await recomputeIocGlobalStatus(client, touch.iocItemId, touch.observableType, {
      audit,
      actor: workerActor,
      expiredMemberships: touch.expiredMemberships
    });
    if (res.changed) {
      iocRecomputed += 1;
      if (res.status === 'expired') iocGlobalExpired += 1;
    }
  }

  return { expiredMemberships, iocRecomputed, iocGlobalExpired, batchCount: rows.length };
}

export function activeIocSql(alias = 'i') {
  return `COALESCE(${alias}.status, 'active') = 'active'`;
}

/** Called after import insert/duplicate to refresh feed membership. */
export async function syncSnapshotFeedFromEntries(client, feedKey, entries, mapEntry, options = {}) {
  return withImportOptimizationContext(client, async () => {
    const { signal } = options;
    if (signal?.aborted) {
      const err = new Error('Integration job aborted');
      err.name = 'IntegrationJobAbortedError';
      throw err;
    }

    const feedId = await resolveFeedIdByKey(client, feedKey);
    if (!feedId || !entries?.length) return { synced: 0, markedMissing: 0 };

    const seenKeys = new Set();
    for (const raw of entries) {
      if (signal?.aborted) {
        const err = new Error('Integration job aborted');
        err.name = 'IntegrationJobAbortedError';
        throw err;
      }
      const e = mapEntry(raw);
      if (!e?.observable || !e?.observableType) continue;
      const membershipId = await syncMembershipAfterIocImport(client, {
        observable: e.observable,
        observableType: e.observableType,
        sourceName: e.sourceName,
        sourceUrl: e.sourceUrl ?? null,
        explicitConfidence: e.explicitConfidence ?? e.confidence ?? null,
        category: e.category ?? null,
        seenAt: e.seenAt
      });
      if (!membershipId) continue;
      const { rows } = await client.query(
        'SELECT ioc_item_id, ioc_observable_type FROM ioc_feed_memberships WHERE id = $1',
        [membershipId]
      );
      if (rows[0]) {
        seenKeys.add(`${rows[0].ioc_observable_type}|${rows[0].ioc_item_id}`);
      }
    }

    const { marked } = await finalizeSnapshotFeedRun(client, { feedId, seenKeys });
    return { synced: seenKeys.size, markedMissing: marked };
  });
}

export async function syncMembershipAfterIocImport(client, {
  observable,
  observableType,
  sourceName,
  sourceUrl = null,
  explicitConfidence = null,
  confidence = null,
  category = null,
  seenAt = new Date()
}) {
  const feedId = await resolveFeedIdBySourceName(client, sourceName);
  if (!feedId) return null;

  const resolvedConfidence = explicitConfidence ?? confidence ?? null;

  const { rows } = await client.query(
    `SELECT id, observable_type
     FROM ioc_items
     WHERE observable = $1
       AND observable_type = $2
     ORDER BY created_at ASC
     LIMIT 1`,
    [observable, observableType]
  );
  const row = rows[0];
  if (!row) return null;

  const membershipId = await upsertMembershipOnImport(client, {
    iocItemId: row.id,
    observableType: row.observable_type,
    feedId,
    seenAt,
    explicitConfidence: resolvedConfidence
  });
  return membershipId;
}

function normIocStatus(status) {
  return String(status || 'active').trim().toLowerCase();
}

function pgIocTypeFromMatchType(iocType) {
  const t = String(iocType || '').trim().toLowerCase();
  if (t === 'ipv4') return 'ip';
  return t;
}

/**
 * On correlation match reactivation: extend TTL from match time using feed policy days.
 * Respects enabled flag; returns null when policy does not define a finite TTL.
 */
export function computeMatchReactivationExpiresAt(policy, now = new Date()) {
  if (!policy?.enabled || policy.expiration_mode === 'never') return null;
  const mode = String(policy.expiration_mode || '');
  const ttl = Number(policy.ttl_days);
  const grace = Number(policy.grace_days ?? policy.ttl_days);
  if (mode === 'missing_from_feed_ttl') {
    if (!Number.isFinite(grace) || grace <= 0) return null;
    return addDays(now, grace);
  }
  if (mode === 'fixed_ttl' || mode === 'last_seen_ttl') {
    if (!Number.isFinite(ttl) || ttl <= 0) return null;
    return addDays(now, ttl);
  }
  return null;
}

async function reactivateMembershipOnMatch(client, membershipRow, policy, matchAt, audit, actor) {
  const now = matchAt instanceof Date ? matchAt : new Date(matchAt);
  const membershipId = membershipRow.id;

  if (membershipRow.override_enabled) {
    if (membershipRow.override_status === 'expired') {
      return { changed: false, reason: 'membership_override_expired' };
    }
    await client.query(
      `UPDATE ioc_feed_memberships
       SET last_seen_in_feed = $2,
           missing_since = NULL,
           updated_at = NOW()
       WHERE id = $1`,
      [membershipId, now]
    );
    await applyMembershipComputedFields(client, membershipId, policy, now);
  } else {
    const expiresAt = computeMatchReactivationExpiresAt(policy, now);
    await client.query(
      `UPDATE ioc_feed_memberships
       SET status = 'active',
           expired_at = NULL,
           expiration_reason = NULL,
           last_seen_in_feed = $2,
           missing_since = NULL,
           policy_expires_at = $3,
           expires_at = $3,
           updated_at = NOW()
       WHERE id = $1`,
      [membershipId, now, expiresAt]
    );
  }

  if (audit?.auditLog) {
    await audit.auditLog({
      action: 'ioc_feed_membership.reactivated_by_match',
      entityType: 'ioc_feed_membership',
      entityId: String(membershipId),
      entityDisplay: formatMembershipEntityDisplay({
        observableType: membershipRow.ioc_observable_type,
        observable: membershipRow.observable,
        feedName: membershipRow.feed_name,
        membershipId
      }),
      before: { status: 'expired' },
      after: { status: 'active' },
      metadata: {
        actor_type: actor.actor_type,
        feed_id: membershipRow.feed_id,
        feed_name: membershipRow.feed_name,
        ioc_item_id: membershipRow.ioc_item_id,
        reason: 'correlation_match'
      },
      source: actor.source || 'ioc-correlation'
    });
  }

  return { changed: true };
}

/**
 * Expired IOC matched in realtime/retro correlation → reactivate using feed policy TTL from match time.
 * Skips IOCs with manual_status_override = expired. Detection proceeds either way.
 */
export async function reactivateIocOnCorrelationMatch(client, {
  observable,
  observableType,
  sourceName = null,
  matchAt = new Date(),
  detectionType = 'realtime',
  audit = null,
  actor = { actor_type: 'system', source: 'ioc-correlation' }
}) {
  const pgType = pgIocTypeFromMatchType(observableType);
  const value = String(observable || '').trim();
  if (!value || !pgType) return { reactivated: false, reason: 'invalid_input' };

  const { rows } = await client.query(
    `SELECT id, observable, observable_type, status, expires_at, expired_at, expiration_reason,
            manual_status_override, manual_status, manual_expires_at
     FROM ioc_items
     WHERE lower(observable) = lower($1)
       AND lower(observable_type) = lower($2)
     ORDER BY created_at ASC
     LIMIT 1`,
    [value, pgType]
  );
  const ioc = rows[0];
  if (!ioc) return { reactivated: false, reason: 'not_found' };
  if (normIocStatus(ioc.status) !== 'expired') {
    return { reactivated: false, reason: 'not_expired', iocId: ioc.id };
  }
  if (ioc.manual_status_override && normIocStatus(ioc.manual_status) === 'expired') {
    return { reactivated: false, reason: 'manual_override_expired', iocId: ioc.id };
  }

  const feedId = sourceName ? await resolveFeedIdBySourceName(client, sourceName) : null;
  const now = matchAt instanceof Date ? matchAt : new Date(matchAt);

  let membershipSql = `
    SELECT m.*, i.observable, f.name AS feed_name
    FROM ioc_feed_memberships m
    JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
    LEFT JOIN integration_feeds f ON f.integration_id = m.feed_id
    WHERE m.ioc_item_id = $1 AND m.ioc_observable_type = $2 AND m.status = 'expired'
  `;
  const membershipParams = [ioc.id, ioc.observable_type];
  if (feedId) {
    membershipParams.push(feedId);
    membershipSql += ` AND m.feed_id = $3::uuid`;
  }

  const { rows: memberships } = await client.query(membershipSql, membershipParams);
  let targets = memberships.filter((m) => !(m.override_enabled && m.override_status === 'expired'));

  if (!targets.length) {
    const allQ = await client.query(
      `SELECT m.*, i.observable, f.name AS feed_name
       FROM ioc_feed_memberships m
       JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
       LEFT JOIN integration_feeds f ON f.integration_id = m.feed_id
       WHERE m.ioc_item_id = $1 AND m.ioc_observable_type = $2 AND m.status = 'expired'
         AND NOT (m.override_enabled AND m.override_status = 'expired')`,
      [ioc.id, ioc.observable_type]
    );
    targets = allQ.rows || [];
  }

  let membershipChanges = 0;
  for (const m of targets) {
    const policy = await getFeedPolicy(client, m.feed_id, ioc.observable_type);
    const res = await reactivateMembershipOnMatch(client, m, policy, now, audit, actor);
    if (res.changed) membershipChanges += 1;
  }

  if (!targets.length && !membershipChanges) {
    const countQ = await client.query(
      `SELECT COUNT(*)::int AS c FROM ioc_feed_memberships
       WHERE ioc_item_id = $1 AND ioc_observable_type = $2`,
      [ioc.id, ioc.observable_type]
    );
    if (Number(countQ.rows[0]?.c || 0) > 0) {
      return { reactivated: false, reason: 'no_reactivatable_membership', iocId: ioc.id };
    }
  }

  await client.query(
    `UPDATE ioc_items
     SET reactivated_by_match_at = $3
     WHERE id = $1 AND observable_type = $2`,
    [ioc.id, ioc.observable_type, now.toISOString()]
  );

  const recompute = await recomputeIocGlobalStatus(client, ioc.id, ioc.observable_type, { audit: null, actor });

  const updatedQ = await client.query(
    `SELECT status, expires_at, expired_at FROM ioc_items WHERE id = $1 AND observable_type = $2`,
    [ioc.id, ioc.observable_type]
  );
  const updated = updatedQ.rows[0] || {};

  if (audit?.auditLog) {
    const auditPayload = buildIocExpirationAuditPayload({
      iocId: ioc.id,
      observable: ioc.observable,
      observableType: ioc.observable_type,
      oldStatus: ioc.status,
      newStatus: updated.status || recompute.status || 'active',
      oldExpiresAt: ioc.expires_at,
      expiredAt: null,
      newExpiresAt: updated.expires_at,
      reason: 'correlation_match',
      actor
    });
    auditPayload.metadata.detection_type = detectionType;
    auditPayload.metadata.memberships_reactivated = membershipChanges;
    if (feedId) auditPayload.metadata.feed_id = String(feedId);

    await audit.auditLog({
      action: 'ioc.reactivated_by_match',
      entityType: 'ioc',
      entityId: String(ioc.id),
      entityDisplay: auditPayload.entityDisplay,
      before: auditPayload.before,
      after: auditPayload.after,
      metadata: auditPayload.metadata,
      source: actor.source || 'ioc-correlation'
    });
  }

  return {
    reactivated: true,
    iocId: ioc.id,
    observable: ioc.observable,
    observableType: ioc.observable_type,
    sourceName: sourceName || null,
    membershipChanges,
    status: recompute.status || 'active'
  };
}

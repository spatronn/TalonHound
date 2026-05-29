/**
 * Feed-based IOC expiration: memberships, policies, global status recompute.
 */

import {
  buildIocExpirationAuditPayload,
  buildMembershipExpirationAuditPayload
} from './auditIocContext.js';

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
    SELECT key, integration_id AS feed_id, feed_update_mode, name
    FROM integration_feeds
  `);
  feedMetaCache.at = now;
  feedMetaCache.rows = rows;
  return rows;
}

export async function resolveFeedIdBySourceName(client, sourceName) {
  const feeds = await loadFeedMeta(client);
  const key = feedKeyForSourceName(sourceName);
  if (!key) return null;
  const row = feeds.find((f) => f.key === key);
  return row?.feed_id || null;
}

export async function resolveFeedIdByKey(client, feedKey) {
  const feeds = await loadFeedMeta(client);
  const row = feeds.find((f) => f.key === feedKey);
  return row?.feed_id || null;
}

export async function getFeedPolicy(client, feedId, observableType = 'all') {
  const { rows } = await client.query(
    `SELECT * FROM threat_feed_expiration_policies
     WHERE feed_id = $1::uuid AND observable_type IN ($2, 'all')
     ORDER BY CASE WHEN observable_type = $2 THEN 0 ELSE 1 END
     LIMIT 1`,
    [feedId, observableType]
  );
  return rows[0] || null;
}

export async function isIocSuppressed(client, observable, observableType) {
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

  if (await isIocSuppressed(client, ioc.observable, ioc.observable_type)) {
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
    `SELECT status FROM ioc_feed_memberships
     WHERE ioc_item_id = $1 AND ioc_observable_type = $2`,
    [iocItemId, observableType]
  );
  const memberships = memQ.rows || [];
  let nextStatus = 'expired';
  let minExpires = null;
  if (!memberships.length) {
    nextStatus = 'active';
  } else if (memberships.some((m) => m.status === 'active')) {
    nextStatus = 'active';
  }

  const expQ = await client.query(
    `SELECT MIN(expires_at) AS min_exp FROM ioc_feed_memberships
     WHERE ioc_item_id = $1 AND ioc_observable_type = $2 AND status = 'active' AND expires_at IS NOT NULL`,
    [iocItemId, observableType]
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
     WHERE id = $1 AND observable_type = $2`,
    [iocItemId, observableType, nextStatus, minExpires, expiredAt, expirationReason]
  );

  if (audit?.auditLog) {
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
        actor
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

  return { changed: true, status: nextStatus };
}

async function applyMembershipComputedFields(client, membershipId, policy, now = new Date()) {
  const { rows } = await client.query('SELECT * FROM ioc_feed_memberships WHERE id = $1', [membershipId]);
  const m = rows[0];
  if (!m) return null;

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

  await client.query(
    `UPDATE ioc_feed_memberships
     SET policy_expires_at = $2, expires_at = $3, status = $4, expired_at = $5,
         expiration_reason = $6, missing_since = $7, updated_at = NOW()
     WHERE id = $1`,
    [membershipId, policyExpiresAt, expiresAt, status, expiredAt, expirationReason, m.missing_since]
  );

  return { membershipId, status, policyExpiresAt, expiresAt };
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

  const policy = await getFeedPolicy(client, feedId, observableType);
  const now = seenAt instanceof Date ? seenAt : new Date(seenAt);

  const existing = await client.query(
    `SELECT * FROM ioc_feed_memberships
     WHERE ioc_item_id = $1 AND ioc_observable_type = $2 AND feed_id = $3::uuid`,
    [iocItemId, observableType, feedId]
  );

  let membershipId;
  let reactivated = false;

  if (!existing.rowCount) {
    const ins = await client.query(
      `INSERT INTO ioc_feed_memberships (
         ioc_item_id, ioc_observable_type, feed_id,
         first_seen_in_feed, last_seen_in_feed, missing_since, status
       ) VALUES ($1, $2, $3::uuid, $4, $4, NULL, 'active')
       RETURNING id`,
      [iocItemId, observableType, feedId, now]
    );
    membershipId = ins.rows[0].id;
  } else {
    const row = existing.rows[0];
    membershipId = row.id;
    const wasExpired = row.status === 'expired';
    const clearMissing = true;

    if (row.override_enabled) {
      await client.query(
        `UPDATE ioc_feed_memberships
         SET last_seen_in_feed = $2,
             missing_since = CASE WHEN $3 THEN NULL ELSE missing_since END,
             updated_at = NOW()
         WHERE id = $1`,
        [membershipId, now, clearMissing]
      );
    } else {
      await client.query(
        `UPDATE ioc_feed_memberships
         SET last_seen_in_feed = $2,
             missing_since = NULL,
             status = 'active',
             expired_at = NULL,
             expiration_reason = NULL,
             updated_at = NOW()
         WHERE id = $1`,
        [membershipId, now]
      );
      if (wasExpired) reactivated = true;
    }
  }

  await applyMembershipComputedFields(client, membershipId, policy, now);

  const explicit = explicitConfidence != null ? String(explicitConfidence).trim().toLowerCase() : '';
  if (['low', 'medium', 'high'].includes(explicit)) {
    try {
      await client.query(
        `UPDATE ioc_feed_memberships
         SET explicit_confidence = $2, updated_at = NOW()
         WHERE id = $1`,
        [membershipId, explicit]
      );
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

  await recomputeIocGlobalStatus(client, iocItemId, observableType, { audit, actor });
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
       WHERE id = $1`,
      [row.id, now]
    );
    await applyMembershipComputedFields(client, row.id, policy, now);
    await recomputeIocGlobalStatus(client, row.ioc_item_id, row.ioc_observable_type, { audit });
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
  const iocTouches = new Set();

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
    iocTouches.add(`${row.ioc_observable_type}|${row.ioc_item_id}`);

    if (audit?.auditLog) {
      const auditPayload = buildMembershipExpirationAuditPayload({
        membershipId: row.id,
        iocId: row.ioc_item_id,
        observable: row.observable,
        observableType: row.ioc_observable_type,
        feedId: row.feed_id,
        feedName: row.feed_name,
        oldExpiresAt: row.expires_at,
        expiredAt,
        reason: row.expiration_reason || 'policy_ttl',
        actor: workerActor
      });

      await audit.auditLog({
        action: 'ioc_feed_membership.expired',
        entityType: 'ioc_feed_membership',
        entityId: String(row.id),
        entityDisplay: auditPayload.entityDisplay,
        before: auditPayload.before,
        after: auditPayload.after,
        metadata: auditPayload.metadata,
        source: workerActor.source
      });
    }
  }

  let iocRecomputed = 0;
  let iocGlobalExpired = 0;
  for (const key of iocTouches) {
    const [observableType, iocItemId] = key.split('|');
    const res = await recomputeIocGlobalStatus(client, Number(iocItemId), observableType, {
      audit,
      actor: workerActor
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
      confidence: e.confidence ?? null,
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
}

export async function syncMembershipAfterIocImport(client, {
  observable,
  observableType,
  sourceName,
  sourceUrl = null,
  explicitConfidence = null,
  category = null,
  seenAt = new Date()
}) {
  const feedId = await resolveFeedIdBySourceName(client, sourceName);
  if (!feedId) return null;

  const { rows } = await client.query(
    `SELECT id, observable_type
     FROM ioc_items
     WHERE observable = $1
       AND observable_type = $2
       AND source_name = $3
       AND COALESCE(source_url, '') = COALESCE($4, '')
       AND COALESCE(category, '') = COALESCE($5, '')
     ORDER BY created_at DESC
     LIMIT 1`,
    [observable, observableType, sourceName, sourceUrl, category]
  );
  const row = rows[0];
  if (!row) return null;

  const membershipId = await upsertMembershipOnImport(client, {
    iocItemId: row.id,
    observableType: row.observable_type,
    feedId,
    seenAt,
    explicitConfidence
  });
  return membershipId;
}

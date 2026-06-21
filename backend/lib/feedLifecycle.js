import { recomputeIocGlobalStatus } from './iocExpiration.js';

export const FEED_KIND = Object.freeze({
  BUILT_IN: 'built_in',
  CUSTOM: 'custom'
});

export async function loadIntegrationFeedByKey(client, feedKey) {
  const key = String(feedKey || '').trim();
  if (!key) return null;
  const { rows } = await client.query(
    `SELECT key, integration_id, name, active, feed_kind, archived_at
     FROM integration_feeds
     WHERE key = $1
     LIMIT 1`,
    [key]
  );
  return rows[0] || null;
}

export function isFeedArchived(feed) {
  return Boolean(feed?.archived_at);
}

export function isBuiltInFeed(feed) {
  return String(feed?.feed_kind || FEED_KIND.BUILT_IN).toLowerCase() === FEED_KIND.BUILT_IN;
}

/**
 * Preview impact of purging active memberships for a feed (dry run).
 */
export async function previewFeedDataPurge(client, feedKey) {
  const feed = await loadIntegrationFeedByKey(client, feedKey);
  if (!feed) return { ok: false, status: 404, message: 'Feed not found' };
  if (isFeedArchived(feed)) {
    return { ok: false, status: 409, message: 'Archived feeds cannot be purged from this view.' };
  }

  const feedId = feed.integration_id;
  const { rows } = await client.query(
    `WITH feed_active AS (
       SELECT m.ioc_item_id, m.ioc_observable_type
       FROM ioc_feed_memberships m
       WHERE m.feed_id = $1::uuid AND m.status = 'active'
     ),
     analyzed AS (
       SELECT
         fa.ioc_item_id,
         fa.ioc_observable_type,
         EXISTS (
           SELECT 1
           FROM ioc_feed_memberships m2
           WHERE m2.ioc_item_id = fa.ioc_item_id
             AND m2.ioc_observable_type = fa.ioc_observable_type
             AND m2.status = 'active'
             AND m2.feed_id <> $1::uuid
         ) AS has_other_feed,
         EXISTS (
           SELECT 1
           FROM ioc_items i
           WHERE i.id = fa.ioc_item_id
             AND i.observable_type = fa.ioc_observable_type
             AND i.ioc_source_id IS NOT NULL
         ) AS has_manual_source
       FROM feed_active fa
     )
     SELECT
       (SELECT COUNT(*)::int FROM ioc_feed_memberships WHERE feed_id = $1::uuid AND status = 'active') AS active_memberships,
       COUNT(*)::int AS affected_iocs,
       COUNT(*) FILTER (WHERE NOT has_other_feed AND NOT has_manual_source)::int AS iocs_only_from_this_feed,
       COUNT(*) FILTER (WHERE has_other_feed OR has_manual_source)::int AS iocs_shared_with_other_sources
     FROM analyzed`,
    [feedId]
  );

  const stats = rows[0] || {};
  return {
    ok: true,
    preview: {
      feed_id: feedId,
      feed_key: feed.key,
      feed_name: feed.name,
      active_memberships: Number(stats.active_memberships || 0),
      iocs_only_from_this_feed: Number(stats.iocs_only_from_this_feed || 0),
      iocs_shared_with_other_sources: Number(stats.iocs_shared_with_other_sources || 0),
      incidents_deleted: 0,
      events_deleted: 0,
      will_preserve_history: true
    }
  };
}

/**
 * Soft-purge active feed memberships and recompute affected IOC global status.
 */
export async function purgeFeedData(client, feedKey, { actor, audit, reason = 'feed_data_purge' } = {}) {
  const feed = await loadIntegrationFeedByKey(client, feedKey);
  if (!feed) return { ok: false, status: 404, message: 'Feed not found' };
  if (isFeedArchived(feed)) {
    return { ok: false, status: 409, message: 'Archived feeds cannot be purged.' };
  }

  const feedId = feed.integration_id;
  const previewResult = await previewFeedDataPurge(client, feedKey);
  if (!previewResult.ok) return previewResult;

  const { rows: activeRows } = await client.query(
    `SELECT id, ioc_item_id, ioc_observable_type
     FROM ioc_feed_memberships
     WHERE feed_id = $1::uuid AND status = 'active'`,
    [feedId]
  );

  if (!activeRows.length) {
    return {
      ok: true,
      result: {
        feed_id: feedId,
        feed_key: feed.key,
        feed_name: feed.name,
        active_memberships_removed: 0,
        iocs_expired_or_removed: 0,
        iocs_kept_active_due_to_other_sources: 0,
        preserved_incidents: true,
        preserved_events: true
      }
    };
  }

  const purgeRes = await client.query(
    `UPDATE ioc_feed_memberships
     SET status = 'purged',
         purged_at = NOW(),
         purged_by = $2,
         purged_by_username = $3,
         purge_reason = $4,
         missing_since = NULL,
         expires_at = NULL,
         expired_at = NULL,
         expiration_reason = $4,
         updated_at = NOW()
     WHERE feed_id = $1::uuid AND status = 'active'
     RETURNING id, ioc_item_id, ioc_observable_type`,
    [feedId, actor?.userId || null, actor?.username || null, reason]
  );

  const touched = new Map();
  for (const row of purgeRes.rows) {
    const k = `${row.ioc_observable_type}|${row.ioc_item_id}`;
    touched.set(k, { iocItemId: row.ioc_item_id, observableType: row.ioc_observable_type });
  }

  let iocsExpired = 0;
  let iocsKeptActive = 0;
  for (const touch of touched.values()) {
    const before = await client.query(
      `SELECT status FROM ioc_items WHERE id = $1 AND observable_type = $2`,
      [touch.iocItemId, touch.observableType]
    );
    const prevStatus = before.rows[0]?.status;
    const recompute = await recomputeIocGlobalStatus(client, touch.iocItemId, touch.observableType, {
      audit,
      actor: actor || { actor_type: 'user', source: 'api' }
    });
    if (recompute.status === 'expired' && prevStatus !== 'expired') iocsExpired += 1;
    else if (recompute.status === 'active') iocsKeptActive += 1;
  }

  const result = {
    feed_id: feedId,
    feed_key: feed.key,
    feed_name: feed.name,
    active_memberships_removed: purgeRes.rowCount,
    iocs_expired_or_removed: iocsExpired,
    iocs_kept_active_due_to_other_sources: iocsKeptActive,
    preserved_incidents: true,
    preserved_events: true,
    performed_by: actor?.username || null
  };

  return { ok: true, result, preview: previewResult.preview };
}

export async function archiveIntegrationFeed(client, feedKey, { actor } = {}) {
  const feed = await loadIntegrationFeedByKey(client, feedKey);
  if (!feed) return { ok: false, status: 404, message: 'Feed not found' };
  if (isBuiltInFeed(feed)) {
    return { ok: false, status: 403, message: 'Built-in feeds cannot be archived.' };
  }
  if (isFeedArchived(feed)) {
    return { ok: false, status: 409, message: 'Feed is already archived.' };
  }

  const { rows } = await client.query(
    `UPDATE integration_feeds
     SET archived_at = NOW(),
         archived_by = $2,
         archived_by_username = $3,
         active = FALSE,
         updated_at = NOW()
     WHERE key = $1
     RETURNING key, integration_id, name, feed_kind, active, archived_at`,
    [feedKey, actor?.userId || null, actor?.username || null]
  );

  return { ok: true, feed: rows[0] };
}

export async function restoreIntegrationFeed(client, feedKey) {
  const feed = await loadIntegrationFeedByKey(client, feedKey);
  if (!feed) return { ok: false, status: 404, message: 'Feed not found' };
  if (!isFeedArchived(feed)) {
    return { ok: false, status: 409, message: 'Feed is not archived.' };
  }

  const { rows } = await client.query(
    `UPDATE integration_feeds
     SET archived_at = NULL,
         archived_by = NULL,
         archived_by_username = NULL,
         updated_at = NOW()
     WHERE key = $1
     RETURNING key, integration_id, name, feed_kind, active, archived_at`,
    [feedKey]
  );

  return { ok: true, feed: rows[0] };
}

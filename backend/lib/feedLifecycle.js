import { recomputeIocGlobalStatus } from './iocExpiration.js';
import { fetchLookupTombstoneRowsForObservable } from './iocActiveSources.js';
import { pushIocLookupTombstones } from './clickhouse.js';
import { invalidateIocStatsCache } from './iocStatsCache.js';

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

export function computeReimportPossible(feed) {
  if (!feed) return false;
  const enabled = feed.active !== false;
  const archived = isFeedArchived(feed);
  return Boolean(enabled && !archived);
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
       WHERE m.feed_id = $1::uuid AND m.status = 'active' AND m.purged_at IS NULL
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
             AND m2.purged_at IS NULL
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
       (SELECT COUNT(*)::int FROM ioc_feed_memberships WHERE feed_id = $1::uuid AND status = 'active' AND purged_at IS NULL) AS active_memberships,
       COUNT(*)::int AS affected_iocs,
       COUNT(*) FILTER (WHERE NOT has_other_feed AND NOT has_manual_source)::int AS iocs_only_from_this_feed,
       COUNT(*) FILTER (WHERE has_other_feed OR has_manual_source)::int AS iocs_shared_with_other_sources
     FROM analyzed`,
    [feedId]
  );

  const stats = rows[0] || {};
  const feedEnabled = feed.active !== false;
  const feedArchived = isFeedArchived(feed);
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
      will_preserve_history: true,
      history_preserved: true,
      feed_enabled: feedEnabled,
      feed_archived: feedArchived,
      reimport_possible: computeReimportPossible(feed)
    }
  };
}

export const FEED_PURGE_JOB_NAME = 'feed_data_purge';
export const FEED_PURGE_RUN_JOB_TYPE = 'feed_data_purge';
export const DEFAULT_FEED_PURGE_BATCH_SIZE = 1000;

export function validatePurgeConfirmName(feedName, confirmName) {
  const expected = String(feedName || '').trim();
  const provided = String(confirmName || '').trim();
  return expected.length > 0 && provided === expected;
}

export async function findActivePurgeJobForFeed(client, feedKey) {
  const key = String(feedKey || '').trim();
  if (!key) return null;
  const { rows } = await client.query(
    `SELECT job_id, status, queued_at, started_at
     FROM integration_queue_jobs
     WHERE integration_key = $1
       AND job_name = $2
       AND status IN ('queued', 'running')
     ORDER BY COALESCE(started_at, queued_at) DESC
     LIMIT 1`,
    [key, FEED_PURGE_JOB_NAME]
  );
  return rows[0] || null;
}

export async function insertFeedPurgeAudit(client, {
  action,
  status = 'success',
  severity = 'warning',
  entityId,
  entityDisplay,
  actorPublicId = null,
  actorUsername = null,
  metadata = null,
  source = 'worker'
}) {
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const actorUuid = actorPublicId && UUID_RE.test(String(actorPublicId)) ? String(actorPublicId) : null;
  await client.query(
    `INSERT INTO audit_logs (
       actor_user_id, actor_username, actor_email, actor_role,
       action, entity_type, entity_id, entity_display,
       severity, status, source, metadata
     ) VALUES (
       $1::uuid, $2, $3, 'analyst',
       $4, 'integration', $5, $6,
       $7, $8, $9, $10::jsonb
     )`,
    [
      actorUuid,
      actorUsername ? String(actorUsername).slice(0, 255) : null,
      actorUsername ? String(actorUsername).slice(0, 255) : null,
      String(action || '').slice(0, 128),
      entityId != null ? String(entityId).slice(0, 255) : null,
      entityDisplay != null ? String(entityDisplay).slice(0, 512) : null,
      String(severity || 'warning').slice(0, 32),
      String(status || 'success').slice(0, 32),
      String(source || 'worker').slice(0, 64),
      metadata ? JSON.stringify(metadata) : null
    ]
  ).catch((err) => {
    console.warn('[feed-purge] audit insert failed:', err?.message || err);
  });
}

function throwIfAborted(signal) {
  if (signal?.aborted) {
    const err = new Error('Feed purge job aborted');
    err.name = 'AbortError';
    throw err;
  }
}

/**
 * Soft-purge active feed memberships in batches and recompute affected IOC global status.
 */
export async function purgeFeedDataInBatches(client, feedKey, {
  actor,
  audit,
  reason = 'feed_data_purge',
  batchSize = DEFAULT_FEED_PURGE_BATCH_SIZE,
  onProgress,
  signal
} = {}) {
  const feed = await loadIntegrationFeedByKey(client, feedKey);
  if (!feed) return { ok: false, status: 404, message: 'Feed not found' };
  if (isFeedArchived(feed)) {
    return { ok: false, status: 409, message: 'Archived feeds cannot be purged.' };
  }

  const previewResult = await previewFeedDataPurge(client, feedKey);
  if (!previewResult.ok) return previewResult;

  const feedId = feed.integration_id;
  const effectiveBatchSize = Math.max(Number(batchSize) || DEFAULT_FEED_PURGE_BATCH_SIZE, 100);
  let activeMembershipsRemoved = 0;
  let iocsExpired = 0;
  let iocsKeptActive = 0;
  const expiredObservables = new Set();
  const actorUserId = actor?.userId || null;
  const actorUsername = actor?.username || null;

  while (true) {
    throwIfAborted(signal);
    const { rows: batchRows } = await client.query(
      `SELECT id, ioc_item_id, ioc_observable_type
       FROM ioc_feed_memberships
       WHERE feed_id = $1::uuid AND status = 'active' AND purged_at IS NULL
       ORDER BY id
       LIMIT $2`,
      [feedId, effectiveBatchSize]
    );
    if (!batchRows.length) break;

    await client.query('BEGIN');
    try {
      const ids = batchRows.map((row) => row.id);
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
         WHERE id = ANY($1::bigint[])
         RETURNING id, ioc_item_id, ioc_observable_type`,
        [ids, actorUserId, actorUsername, reason]
      );

      const touched = new Map();
      for (const row of purgeRes.rows) {
        const key = `${row.ioc_observable_type}|${row.ioc_item_id}`;
        touched.set(key, { iocItemId: row.ioc_item_id, observableType: row.ioc_observable_type });
      }

      for (const touch of touched.values()) {
        throwIfAborted(signal);
        const before = await client.query(
          `SELECT status FROM ioc_items WHERE id = $1 AND observable_type = $2`,
          [touch.iocItemId, touch.observableType]
        );
        const prevStatus = before.rows[0]?.status;
        const recompute = await recomputeIocGlobalStatus(client, touch.iocItemId, touch.observableType, {
          audit,
          actor: actor || { actor_type: 'user', source: 'worker' }
        });
        if (recompute.status === 'expired' && prevStatus !== 'expired') {
          iocsExpired += 1;
          const obsRow = await client.query(
            `SELECT observable, observable_type FROM ioc_items WHERE id = $1 AND observable_type = $2 LIMIT 1`,
            [touch.iocItemId, touch.observableType]
          );
          const obs = obsRow.rows[0];
          if (obs?.observable && obs?.observable_type) {
            expiredObservables.add(`${obs.observable_type}\u0000${obs.observable}`);
          }
        } else if (recompute.status === 'active') iocsKeptActive += 1;
      }

      await client.query('COMMIT');
      activeMembershipsRemoved += purgeRes.rowCount;

      if (typeof onProgress === 'function') {
        await onProgress({
          active_memberships_purged: activeMembershipsRemoved,
          iocs_expired_or_removed: iocsExpired,
          iocs_kept_active_due_to_other_sources: iocsKeptActive
        });
      }
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    }
  }

  if (expiredObservables.size > 0) {
    try {
      const tombstoneRows = [];
      for (const key of expiredObservables) {
        const [observableType, observable] = key.split('\u0000');
        const rows = await fetchLookupTombstoneRowsForObservable(client, observable, observableType);
        tombstoneRows.push(...rows);
      }
      if (tombstoneRows.length) {
        await pushIocLookupTombstones(tombstoneRows);
      }
    } catch (err) {
      console.warn('[feed-purge] ClickHouse lookup tombstone push failed:', err?.message || err);
    }
  }

  invalidateIocStatsCache();

  const result = {
    feed_id: feedId,
    feed_key: feed.key,
    feed_name: feed.name,
    active_memberships_purged: activeMembershipsRemoved,
    active_memberships_removed: activeMembershipsRemoved,
    iocs_expired_or_removed: iocsExpired,
    iocs_kept_active_due_to_other_sources: iocsKeptActive,
    incidents_deleted: 0,
    events_deleted: 0,
    history_preserved: true,
    preserved_incidents: true,
    preserved_events: true,
    performed_by: actorUsername || null
  };

  return { ok: true, result, preview: previewResult.preview };
}

/**
 * Soft-purge active feed memberships and recompute affected IOC global status.
 */
export async function purgeFeedData(client, feedKey, options = {}) {
  const batchSize = Number(process.env.FEED_PURGE_BATCH_SIZE || DEFAULT_FEED_PURGE_BATCH_SIZE);
  return purgeFeedDataInBatches(client, feedKey, { ...options, batchSize });
}

export async function runFeedDataPurgeJob(pool, job, { signal } = {}) {
  const payload = job?.data || {};
  const feedKey = String(payload.integration_key || payload.feed_key || '').trim();
  const jobId = String(job?.id || '');
  const actor = {
    userId: payload.requested_by_user_id || null,
    username: payload.requested_by || payload.requested_by_username || 'system',
    actor_type: 'user',
    source: 'worker'
  };

  let runId = null;
  const runInsert = await pool.query(
    `INSERT INTO integration_runs (job_type, status, started_at, triggered_by)
     VALUES ($1, 'running', NOW(), $2)
     RETURNING id`,
    [FEED_PURGE_RUN_JOB_TYPE, actor.username || 'feed-purge']
  );
  runId = runInsert.rows[0]?.id;

  const client = await pool.connect();
  try {
    const batchSize = Math.max(Number(process.env.FEED_PURGE_BATCH_SIZE || DEFAULT_FEED_PURGE_BATCH_SIZE), 100);
    const purgeResult = await purgeFeedDataInBatches(client, feedKey, {
      actor,
      audit: null,
      reason: String(payload.reason || 'feed_data_purge').trim() || 'feed_data_purge',
      batchSize,
      signal,
      onProgress: async (progress) => {
        if (!jobId) return;
        await pool.query(
          `UPDATE integration_queue_jobs
           SET records_processed = $2, updated_at = NOW()
           WHERE job_id = $1`,
          [jobId, Number(progress.active_memberships_purged || 0)]
        );
      }
    });

    if (!purgeResult.ok) {
      throw Object.assign(new Error(purgeResult.message || 'Feed purge failed'), { status: purgeResult.status });
    }

    if (runId) {
      await pool.query(
        `UPDATE integration_runs
         SET status = 'success',
             finished_at = NOW(),
             records_processed = $2,
             error_message = NULL
         WHERE id = $1`,
        [runId, Number(purgeResult.result.active_memberships_purged || 0)]
      );
    }

    await insertFeedPurgeAudit(pool, {
      action: 'feed.data_purged',
      status: 'success',
      severity: 'warning',
      entityId: purgeResult.result.feed_id,
      entityDisplay: purgeResult.result.feed_name,
      actorPublicId: actor.userId,
      actorUsername: actor.username,
      metadata: {
        feed_id: purgeResult.result.feed_id,
        feed_name: purgeResult.result.feed_name,
        job_id: jobId,
        requested_by: actor.username,
        active_memberships_to_purge: purgeResult.preview?.active_memberships ?? null,
        iocs_to_expire_or_remove: purgeResult.preview?.iocs_only_from_this_feed ?? null,
        iocs_shared_with_other_sources: purgeResult.preview?.iocs_shared_with_other_sources ?? null,
        active_memberships_purged: purgeResult.result.active_memberships_purged,
        iocs_expired_or_removed: purgeResult.result.iocs_expired_or_removed,
        iocs_kept_active_due_to_other_sources: purgeResult.result.iocs_kept_active_due_to_other_sources,
        status: 'completed'
      }
    });

    return {
      metrics: {
        records_processed: purgeResult.result.active_memberships_purged,
        records_inserted: 0,
        records_updated: purgeResult.result.iocs_expired_or_removed,
        records_skipped: purgeResult.result.iocs_kept_active_due_to_other_sources
      },
      result: purgeResult.result
    };
  } catch (err) {
    if (runId) {
      await pool.query(
        `UPDATE integration_runs
         SET status = 'failed', finished_at = NOW(), error_message = $2
         WHERE id = $1`,
        [runId, String(err?.message || 'Feed purge failed').slice(0, 4000)]
      );
    }
    await insertFeedPurgeAudit(pool, {
      action: 'feed.data_purge.failed',
      status: 'failed',
      severity: 'warning',
      entityId: payload.feed_id || feedKey,
      entityDisplay: payload.feed_name || feedKey,
      actorPublicId: actor.userId,
      actorUsername: actor.username,
      metadata: {
        feed_key: feedKey,
        feed_name: payload.feed_name || feedKey,
        job_id: jobId,
        requested_by: actor.username,
        status: 'failed',
        error: String(err?.message || 'Feed purge failed').slice(0, 500)
      }
    });
    throw err;
  } finally {
    client.release();
  }
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

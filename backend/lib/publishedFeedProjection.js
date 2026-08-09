// Phase 2 Published Feed projection helpers.
//
// One row per published identity per (feed, window). Stores normalized TXT value +
// optional public JSON item + content fingerprint so incremental refresh can:
//   * detect semantic no-ops
//   * stream artifacts from an ordered projection scan (P1 writers)
// without re-joining millions of IOC/membership/tag/enrichment rows every tick.

import crypto from 'crypto';
import { confidenceToScore } from './feedFormatter.js';

export const PROJECTION_STATUS = {
  ABSENT: 'absent',
  BOOTSTRAPPING: 'bootstrapping',
  READY: 'ready',
  FAILED: 'failed',
  STALE: 'stale'
};

export function confidenceRank(confidence) {
  return confidenceToScore(confidence);
}

/** Stable identity for projection PK — matches streaming base dedup grain. */
export function projectionIdentityKey(observable, observableType, { artifactId = null } = {}) {
  if (artifactId) return `a:${artifactId}`;
  return `o:${String(observableType || '').toLowerCase()}:${String(observable || '').toLowerCase()}`;
}

/** Fingerprint of the public bytes for one item (TXT value and/or JSON item body). */
export function projectionContentFingerprint({ txtValue, itemJson }) {
  const payload = JSON.stringify({
    v: String(txtValue || ''),
    j: itemJson == null ? null : itemJson
  });
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex').slice(0, 32);
}

export function isProjectionReady(feed) {
  return String(feed?.projection_status || '') === PROJECTION_STATUS.READY;
}

/**
 * Whether this feed can use incremental projection refresh (vs full rebuild).
 * Conservative: capped feeds, sliding windows, and force/config changes rebuild.
 * @param {string} [snapshotWindow] the snapshot window being generated ('1d'|'3d'|'7d'|'all')
 */
export function canUseIncrementalRefresh(feed, { force = false, filtersChanged = false, snapshotWindow = null } = {}) {
  if (force || filtersChanged) return false;
  if (!isProjectionReady(feed)) return false;
  if (feed?.max_items != null && Number.isFinite(Number(feed.max_items))) return false;
  const window = String(snapshotWindow || feed?.time_window || 'all').toLowerCase();
  // Sliding windows age out without writes — incremental change clocks miss them.
  if (window && window !== 'all') return false;
  return true;
}

/** Feature gate — default OFF until operators enable after bootstrap. */
export function isPublishedFeedIncrementalEnabled() {
  const v = String(process.env.PUBLISHED_FEED_INCREMENTAL_ENABLED ?? 'false').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

/**
 * Optional allowlist for controlled rollout.
 * When PUBLISHED_FEED_INCREMENTAL_FEED_IDS is set (comma-separated feed ids), only those
 * feeds may enter incremental/bootstrap. Empty/unset = all feeds (once global flag is on).
 */
export function isPublishedFeedIncrementalAllowedForFeed(feedId) {
  const raw = String(process.env.PUBLISHED_FEED_INCREMENTAL_FEED_IDS || '').trim();
  if (!raw) return true;
  const id = Number(feedId);
  if (!Number.isFinite(id) || id <= 0) return false;
  const allowed = new Set(
    raw.split(/[,\s]+/).map((x) => Number(x)).filter((n) => Number.isFinite(n) && n > 0)
  );
  return allowed.has(id);
}

/**
 * Effective incremental enablement for one feed (global flag ∧ allowlist).
 */
export function isIncrementalEnabledForFeed(feedId) {
  return isPublishedFeedIncrementalEnabled() && isPublishedFeedIncrementalAllowedForFeed(feedId);
}

/**
 * Upsert a batch of projection rows. Idempotent on (feed_id, window, identity_key).
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {Array<object>} rows
 */
export async function upsertProjectionBatch(db, rows) {
  if (!rows?.length) return 0;
  // Unnest-style multi VALUES keeps batch size bounded by caller.
  const values = [];
  const params = [];
  let i = 1;
  for (const r of rows) {
    values.push(
      `($${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++},$${i++}::jsonb,$${i++},NOW())`
    );
    params.push(
      r.feed_id,
      r.snapshot_window ?? r.window,
      r.identity_key,
      r.ioc_item_id,
      r.observable,
      r.observable_type,
      r.recency_ts,
      r.confidence ?? null,
      r.category ?? null,
      r.confidence_rank ?? confidenceRank(r.confidence),
      r.txt_value,
      r.item_json == null ? null : JSON.stringify(r.item_json),
      r.content_fingerprint
    );
  }
  const sql = `
    INSERT INTO published_feed_items (
      feed_id, snapshot_window, identity_key, ioc_item_id, observable, observable_type,
      recency_ts, confidence, category, confidence_rank, txt_value, item_json,
      content_fingerprint, updated_at
    ) VALUES ${values.join(',')}
    ON CONFLICT (feed_id, snapshot_window, identity_key) DO UPDATE SET
      ioc_item_id = EXCLUDED.ioc_item_id,
      observable = EXCLUDED.observable,
      observable_type = EXCLUDED.observable_type,
      recency_ts = EXCLUDED.recency_ts,
      confidence = EXCLUDED.confidence,
      category = EXCLUDED.category,
      confidence_rank = EXCLUDED.confidence_rank,
      txt_value = EXCLUDED.txt_value,
      item_json = EXCLUDED.item_json,
      content_fingerprint = EXCLUDED.content_fingerprint,
      updated_at = NOW()
    WHERE published_feed_items.content_fingerprint IS DISTINCT FROM EXCLUDED.content_fingerprint
       OR published_feed_items.ioc_item_id IS DISTINCT FROM EXCLUDED.ioc_item_id
       OR published_feed_items.recency_ts IS DISTINCT FROM EXCLUDED.recency_ts
       OR published_feed_items.txt_value IS DISTINCT FROM EXCLUDED.txt_value`;
  const res = await db.query(sql, params);
  return res.rowCount || 0;
}

export async function deleteProjectionIdentities(db, feedId, window, identityKeys) {
  if (!identityKeys?.length) return 0;
  const res = await db.query(
    `DELETE FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2 AND identity_key = ANY($3::text[])`,
    [feedId, window, identityKeys]
  );
  return res.rowCount || 0;
}

export async function clearFeedProjection(db, feedId) {
  await db.query(`DELETE FROM published_feed_items WHERE feed_id = $1`, [feedId]);
}

export async function setFeedProjectionState(db, feedId, patch) {
  const cols = [];
  const params = [feedId];
  const add = (name, val) => {
    params.push(val);
    cols.push(`${name} = $${params.length}`);
  };
  if (patch.projection_status != null) add('projection_status', patch.projection_status);
  if (patch.projection_cutoff !== undefined) add('projection_cutoff', patch.projection_cutoff);
  if (patch.projection_built_at !== undefined) add('projection_built_at', patch.projection_built_at);
  if (patch.last_refresh_checked_at !== undefined) add('last_refresh_checked_at', patch.last_refresh_checked_at);
  if (patch.last_refresh_mode !== undefined) add('last_refresh_mode', patch.last_refresh_mode);
  if (patch.last_refresh_ms !== undefined) add('last_refresh_ms', patch.last_refresh_ms);
  if (patch.last_changed_count !== undefined) add('last_changed_count', patch.last_changed_count);
  if (!cols.length) return;
  await db.query(
    `UPDATE published_feeds SET ${cols.join(', ')}, updated_at = updated_at WHERE id = $1`,
    params
  );
}

/**
 * Mark refresh check without dirtying filtersHash watermark (do NOT bump updated_at).
 * Fixes Phase-1 skip path that previously set updated_at=NOW() on no-op and defeated
 * the next watermark check.
 */
export async function touchFeedRefreshChecked(db, feedId, { mode, ms = 0, changed = 0 } = {}) {
  await db.query(
    `UPDATE published_feeds
     SET last_generated_at = NOW(),
         last_refresh_checked_at = NOW(),
         last_refresh_mode = $2,
         last_refresh_ms = $3,
         last_changed_count = $4,
         last_status = COALESCE(last_status, 'success')
     WHERE id = $1`,
    [feedId, mode || 'noop', ms, changed]
  );
}

/** Ordered projection SQL for server-side cursor artifact generation. */
export function buildProjectionScanSql(feedId, window) {
  return {
    sql: `
      SELECT identity_key, ioc_item_id, observable, observable_type, recency_ts,
             confidence, category, txt_value, item_json, content_fingerprint
      FROM published_feed_items
      WHERE feed_id = $1 AND snapshot_window = $2
      ORDER BY recency_ts DESC NULLS LAST, confidence_rank DESC, observable ASC`,
    params: [feedId, window]
  };
}

export async function countProjectionItems(db, feedId, window) {
  const { rows } = await db.query(
    `SELECT COUNT(*)::bigint AS n FROM published_feed_items WHERE feed_id = $1 AND snapshot_window = $2`,
    [feedId, window]
  );
  return Number(rows[0]?.n || 0);
}

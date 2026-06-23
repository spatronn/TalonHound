import crypto from 'crypto';
import {
  FEED_WINDOWS,
  buildPlainTextFeed,
  confidenceToScore,
  observableTypesForFeedIocType
} from './feedFormatter.js';
import { FEED_SOURCE_RULES } from './iocExpiration.js';

const FEED_IOC_EXPIRY_DAYS = Math.max(Number(process.env.FEED_IOC_EXPIRY_DAYS || 90), 1);
const FEED_EXPORT_MAX_LIMIT = Math.max(Number(process.env.FEED_EXPORT_MAX_LIMIT || 100000), 1);

export { FEED_EXPORT_MAX_LIMIT };

const WINDOW_INTERVALS = {
  '1d': '1 day',
  '3d': '3 days',
  '7d': '7 days',
  all: null
};

function parseJsonArray(val) {
  if (val == null) return null;
  if (Array.isArray(val)) return val.map((x) => String(x).trim()).filter(Boolean);
  if (typeof val === 'string') {
    try {
      const parsed = JSON.parse(val);
      if (Array.isArray(parsed)) return parsed.map((x) => String(x).trim()).filter(Boolean);
    } catch {
      return val.split(',').map((x) => x.trim()).filter(Boolean);
    }
  }
  return null;
}

function normalizeTimeWindow(value) {
  const v = String(value || 'all').trim().toLowerCase();
  if (v === 'last_1_day' || v === '1d') return '1d';
  if (v === 'last_3_days' || v === '3d') return '3d';
  if (v === 'last_7_days' || v === '7d') return '7d';
  if (v === 'all') return 'all';
  return null;
}

export function normalizeFeedConfig(row) {
  if (!row) return null;
  return {
    ...row,
    id: Number(row.id),
    time_window: normalizeTimeWindow(row.time_window) || 'all',
    include_feed_keys: parseJsonArray(row.include_feed_keys),
    include_tags: parseJsonArray(row.include_tags),
    exclude_tags: parseJsonArray(row.exclude_tags)
  };
}

export function filtersHash(feed, window) {
  const payload = {
    ioc_type: feed.ioc_type,
    window,
    min_confidence: feed.min_confidence,
    include_feed_keys: feed.include_feed_keys,
    include_tags: feed.include_tags,
    exclude_tags: feed.exclude_tags,
    exclude_false_positive: feed.exclude_false_positive,
    exclude_expired: feed.exclude_expired,
    max_items: feed.max_items
  };
  return crypto.createHash('sha256').update(JSON.stringify(payload), 'utf8').digest('hex').slice(0, 16);
}

function buildFeedKeySourceSql(feedKeys, params) {
  if (!feedKeys?.length) return '';
  const keys = feedKeys.map((k) => String(k).trim()).filter(Boolean);
  if (!keys.length) return '';

  const parts = [];
  for (const key of keys) {
    const rule = FEED_SOURCE_RULES.find((r) => r.key === key);
    if (!rule) continue;
    if (rule.exact) {
      params.push(rule.exact);
      parts.push(`i.source_name = $${params.length}`);
    } else if (rule.prefix) {
      params.push(`${rule.prefix}%`);
      parts.push(`i.source_name LIKE $${params.length}`);
    } else if (rule.includes) {
      for (const fragment of rule.includes) {
        params.push(`%${fragment}%`);
        parts.push(`i.source_name ILIKE $${params.length}`);
      }
    }
  }
  if (!parts.length) return '';
  return ` AND (${parts.join(' OR ')}) `;
}

async function fetchIocRows(pool, feed, window) {
  const types = observableTypesForFeedIocType(feed.ioc_type);
  if (!types.length) return [];

  const params = [];
  const typePlaceholders = types.map((t) => {
    params.push(t);
    return `$${params.length}`;
  });

  let sql = `
    SELECT DISTINCT ON (lower(i.observable))
      i.observable,
      i.observable_type,
      i.confidence,
      i.category,
      i.source_name,
      COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) AS recency_ts
    FROM ioc_items i
    WHERE i.observable_type IN (${typePlaceholders.join(', ')})
  `;

  const interval = WINDOW_INTERVALS[window];
  if (interval) {
    params.push(interval);
    sql += ` AND COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) >= NOW() - $${params.length}::interval `;
  }

  if (feed.min_confidence != null && Number.isFinite(Number(feed.min_confidence))) {
    sql += ` AND (
      CASE LOWER(COALESCE(i.confidence, ''))
        WHEN 'high' THEN 100
        WHEN 'medium' THEN 50
        WHEN 'low' THEN 25
        ELSE 0
      END
    ) >= ${Number(feed.min_confidence)} `;
  }

  sql += buildFeedKeySourceSql(feed.include_feed_keys, params);

  if (feed.exclude_false_positive) {
    sql += `
      AND NOT EXISTS (
        SELECT 1 FROM ioc_activity a
        WHERE lower(a.ioc_value) = lower(i.observable)
          AND lower(a.ioc_type) = lower(i.observable_type)
          AND a.verdict = 'FP'
      )
      AND COALESCE(i.category, '') NOT ILIKE '%false%positive%'
      AND lower(COALESCE(i.category, '')) <> 'fp'
    `;
  }

  if (feed.exclude_expired !== false) {
    sql += ` AND COALESCE(i.status, 'active') = 'active' `;
  }

  if (feed.include_tags?.length) {
    params.push(feed.include_tags.map((t) => t.toLowerCase()));
    sql += `
      AND EXISTS (
        SELECT 1
        FROM ioc_tags it
        JOIN tags tg ON tg.id = it.tag_id
        WHERE it.ioc_id = i.id
          AND it.ioc_observable_type = i.observable_type
          AND tg.enabled = TRUE
          AND lower(tg.name) = ANY($${params.length}::text[])
      )
    `;
  }

  if (feed.exclude_tags?.length) {
    params.push(feed.exclude_tags.map((t) => t.toLowerCase()));
    sql += `
      AND NOT EXISTS (
        SELECT 1
        FROM ioc_tags it
        JOIN tags tg ON tg.id = it.tag_id
        WHERE it.ioc_id = i.id
          AND it.ioc_observable_type = i.observable_type
          AND lower(tg.name) = ANY($${params.length}::text[])
      )
    `;
  }

  sql += `
    ORDER BY lower(i.observable),
      COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) DESC,
      CASE LOWER(COALESCE(i.confidence, '')) WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
      i.observable ASC
  `;

  const { rows } = await pool.query(sql, params);
  return rows.filter((r) => confidenceToScore(r.confidence) >= (feed.min_confidence ?? 0) || feed.min_confidence == null);
}

/** Conservative export fingerprint — same filters as fetchIocRows without DISTINCT ON sort cost. */
export async function fetchIocExportFingerprint(pool, feed, window) {
  const types = observableTypesForFeedIocType(feed.ioc_type);
  if (!types.length) {
    return { itemCount: 0, maxRecency: null, filtersHash: filtersHash(feed, window) };
  }

  const params = [];
  const typePlaceholders = types.map((t) => {
    params.push(t);
    return `$${params.length}`;
  });

  let sql = `
    SELECT COUNT(DISTINCT lower(i.observable))::bigint AS item_count,
           MAX(COALESCE(i.last_seen_log, i.last_seen_at, i.created_at)) AS max_recency
    FROM ioc_items i
    WHERE i.observable_type IN (${typePlaceholders.join(', ')})
  `;

  const interval = WINDOW_INTERVALS[window];
  if (interval) {
    params.push(interval);
    sql += ` AND COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) >= NOW() - $${params.length}::interval `;
  }

  if (feed.min_confidence != null && Number.isFinite(Number(feed.min_confidence))) {
    sql += ` AND (
      CASE LOWER(COALESCE(i.confidence, ''))
        WHEN 'high' THEN 100
        WHEN 'medium' THEN 50
        WHEN 'low' THEN 25
        ELSE 0
      END
    ) >= ${Number(feed.min_confidence)} `;
  }

  sql += buildFeedKeySourceSql(feed.include_feed_keys, params);

  if (feed.exclude_false_positive) {
    sql += `
      AND NOT EXISTS (
        SELECT 1 FROM ioc_activity a
        WHERE lower(a.ioc_value) = lower(i.observable)
          AND lower(a.ioc_type) = lower(i.observable_type)
          AND a.verdict = 'FP'
      )
      AND COALESCE(i.category, '') NOT ILIKE '%false%positive%'
      AND lower(COALESCE(i.category, '')) <> 'fp'
    `;
  }

  if (feed.exclude_expired !== false) {
    sql += ` AND COALESCE(i.status, 'active') = 'active' `;
  }

  if (feed.include_tags?.length) {
    params.push(feed.include_tags.map((t) => t.toLowerCase()));
    sql += `
      AND EXISTS (
        SELECT 1
        FROM ioc_tags it
        JOIN tags tg ON tg.id = it.tag_id
        WHERE it.ioc_id = i.id
          AND it.ioc_observable_type = i.observable_type
          AND tg.enabled = TRUE
          AND lower(tg.name) = ANY($${params.length}::text[])
      )
    `;
  }

  if (feed.exclude_tags?.length) {
    params.push(feed.exclude_tags.map((t) => t.toLowerCase()));
    sql += `
      AND NOT EXISTS (
        SELECT 1
        FROM ioc_tags it
        JOIN tags tg ON tg.id = it.tag_id
        WHERE it.ioc_id = i.id
          AND it.ioc_observable_type = i.observable_type
          AND lower(tg.name) = ANY($${params.length}::text[])
      )
    `;
  }

  const { rows } = await pool.query(sql, params);
  const maxRecency = rows[0]?.max_recency;
  return {
    itemCount: Number(rows[0]?.item_count || 0),
    maxRecency: maxRecency instanceof Date ? maxRecency.toISOString() : (maxRecency ? String(maxRecency) : null),
    filtersHash: filtersHash(feed, window)
  };
}

function exportFingerprintKey(fingerprint) {
  return JSON.stringify({
    itemCount: fingerprint?.itemCount ?? 0,
    maxRecency: fingerprint?.maxRecency ?? null,
    filtersHash: fingerprint?.filtersHash ?? null
  });
}

const FEED_IOC_PARTITION_TABLE = {
  ip: 'ioc_ip',
  domain: 'ioc_domain',
  url: 'ioc_url',
  hash: 'ioc_file_hash'
};

function feedHasSourceFilters(feed) {
  return Boolean(
    feed.include_feed_keys?.length
    || feed.include_tags?.length
    || feed.exclude_tags?.length
    || (feed.min_confidence != null && Number.isFinite(Number(feed.min_confidence)))
  );
}

function normalizeWatermarkTs(value) {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export function watermarkKey(watermark) {
  if (!watermark) return null;
  return JSON.stringify({
    max_id: Number(watermark.max_id || 0),
    max_ts: normalizeWatermarkTs(watermark.max_ts),
    active_count: Number(watermark.active_count || 0)
  });
}

/** Cheap partition-level watermark — one partition table, no parent ioc_items scan. */
export async function fetchCheapIocWatermark(pool, feed) {
  const table = FEED_IOC_PARTITION_TABLE[String(feed?.ioc_type || '').toLowerCase()];
  if (!table) {
    return { max_id: 0, max_ts: null, active_count: 0 };
  }

  const types = observableTypesForFeedIocType(feed.ioc_type);
  const params = [];
  let typeClause = '';
  if (types.length === 1) {
    params.push(types[0]);
    typeClause = `AND observable_type = $${params.length}`;
  } else if (types.length > 1) {
    params.push(types);
    typeClause = `AND observable_type = ANY($${params.length}::text[])`;
  }

  const { rows } = await pool.query(
    `SELECT COALESCE(MAX(id), 0)::bigint AS max_id,
            MAX(COALESCE(last_seen_log, last_seen_at, created_at)) AS max_ts,
            COUNT(*)::bigint AS active_count
     FROM ${table}
     WHERE COALESCE(status, 'active') = 'active'
       ${typeClause}`,
    params
  );

  return {
    max_id: Number(rows[0]?.max_id || 0),
    max_ts: normalizeWatermarkTs(rows[0]?.max_ts),
    active_count: Number(rows[0]?.active_count || 0)
  };
}

async function fetchLatestIntegrationFinishedAt(pool) {
  const { rows } = await pool.query(
    `SELECT MAX(finished_at) AS latest_finished_at
     FROM integration_runs
     WHERE status = 'success' AND finished_at IS NOT NULL`
  );
  const ts = rows[0]?.latest_finished_at;
  return ts instanceof Date ? ts.toISOString() : (ts ? String(ts) : null);
}

export function canSkipPublishedFeedRegeneration({
  feed,
  window,
  latestSnapshot,
  watermark,
  latestIntegrationFinishedAt,
  force = false
}) {
  if (force || !latestSnapshot?.content_hash) return { skip: false };

  const filters_hash = filtersHash(feed, window);
  if (latestSnapshot.params?.filters_hash !== filters_hash) return { skip: false };

  const feedUpdatedAt = feed.updated_at instanceof Date
    ? feed.updated_at.toISOString()
    : (feed.updated_at ? String(feed.updated_at) : null);
  if (latestSnapshot.params?.feed_updated_at !== feedUpdatedAt) return { skip: false };

  if (feedHasSourceFilters(feed)) return { skip: false };

  if (watermarkKey(latestSnapshot.params?.ioc_watermark) !== watermarkKey(watermark)) {
    return { skip: false };
  }

  const snapshotGeneratedAt = latestSnapshot.generated_at instanceof Date
    ? latestSnapshot.generated_at.toISOString()
    : (latestSnapshot.generated_at ? String(latestSnapshot.generated_at) : null);
  if (latestIntegrationFinishedAt && snapshotGeneratedAt
    && latestIntegrationFinishedAt > snapshotGeneratedAt) {
    return { skip: false };
  }

  return { skip: true, reason: 'unchanged_watermark' };
}

async function withTransaction(pool, fn) {
  if (typeof pool.connect !== 'function') {
    return fn(pool);
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // ignore rollback failures; preserve original error
    }
    throw err;
  } finally {
    client.release();
  }
}

export async function persistPublishedFeedSnapshot(pool, snapshot) {
  const feedId = Number(snapshot.feedId);
  const paramsJson = snapshot.paramsJson || {};
  const iocType = String(paramsJson.ioc_type || '');
  const window = String(paramsJson.window || '');
  const status = String(snapshot.status || 'success');
  const paramsText = JSON.stringify(paramsJson);

  return withTransaction(pool, async (client) => {
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtext($1)::bigint)',
      [`published_feed_snapshots:${feedId}:${iocType}:${window}`]
    );

    if (status !== 'success') {
      const { rows } = await client.query(
        `SELECT id
         FROM published_feed_snapshots
         WHERE feed_id = $1
           AND status = 'failed'
           AND params->>'ioc_type' = $2
           AND params->>'window' = $3
         ORDER BY generated_at DESC
         LIMIT 1
         FOR UPDATE`,
        [feedId, iocType, window]
      );

      if (rows[0]?.id) {
        await client.query(
          `UPDATE published_feed_snapshots
           SET generated_at = NOW(),
               item_count = 0,
               content_hash = NULL,
               content = '',
               status = 'failed',
               error_message = $2,
               params = $3::jsonb
           WHERE id = $1`,
          [rows[0].id, snapshot.errorMessage || null, paramsText]
        );
        return;
      }

      await client.query(
        `INSERT INTO published_feed_snapshots
           (feed_id, item_count, content_hash, content, status, error_message, params)
         VALUES ($1, 0, NULL, '', 'failed', $2, $3::jsonb)`,
        [feedId, snapshot.errorMessage || null, paramsText]
      );
      return;
    }

    const { rows } = await client.query(
      `SELECT id, content_hash
       FROM published_feed_snapshots
       WHERE feed_id = $1
         AND status = 'success'
         AND params->>'ioc_type' = $2
         AND params->>'window' = $3
       ORDER BY generated_at DESC
       LIMIT 1
       FOR UPDATE`,
      [feedId, iocType, window]
    );

    if (!rows[0]?.id) {
      await client.query(
        `INSERT INTO published_feed_snapshots
           (feed_id, item_count, content_hash, content, status, error_message, params)
         VALUES ($1, $2, $3, $4, 'success', NULL, $5::jsonb)`,
        [feedId, snapshot.itemCount, snapshot.contentHash, snapshot.content, paramsText]
      );
      return;
    }

    if (rows[0].content_hash === snapshot.contentHash) {
      return { skipped: true, reason: 'unchanged_hash' };
    }

    await client.query(
      `UPDATE published_feed_snapshots
       SET generated_at = NOW(),
           item_count = $2,
           content_hash = $3,
           content = $4,
           status = 'success',
           error_message = NULL,
           params = $5::jsonb
       WHERE id = $1`,
      [rows[0].id, snapshot.itemCount, snapshot.contentHash, snapshot.content, paramsText]
    );
  });
}

export async function generatePublishedFeedSnapshot(pool, feedId, options = {}) {
  const id = Number(feedId);
  if (!Number.isFinite(id) || id <= 0) {
    throw new Error('Invalid feed id');
  }

  const { rows: feedRows } = await pool.query('SELECT * FROM published_feeds WHERE id = $1', [id]);
  if (!feedRows.length) throw new Error('Feed not found');
  const feed = normalizeFeedConfig(feedRows[0]);

  const windows = options.window ? [normalizeTimeWindow(options.window)].filter(Boolean) : FEED_WINDOWS;
  const results = [];
  const latestIntegrationFinishedAt = options.force
    ? null
    : await fetchLatestIntegrationFinishedAt(pool);
  const cheapWatermark = options.force ? null : await fetchCheapIocWatermark(pool, feed);
  const feedUpdatedAt = feed.updated_at instanceof Date
    ? feed.updated_at.toISOString()
    : (feed.updated_at ? String(feed.updated_at) : null);

  for (const window of windows) {
    try {
      const filters_hash = filtersHash(feed, window);

      if (!options.force) {
        const latest = await getLatestSnapshot(pool, id, feed.ioc_type, window);
        const skipCheck = canSkipPublishedFeedRegeneration({
          feed,
          window,
          latestSnapshot: latest,
          watermark: cheapWatermark,
          latestIntegrationFinishedAt,
          force: options.force
        });
        if (skipCheck.skip) {
          results.push({
            window,
            status: 'success',
            item_count: latest?.item_count ?? 0,
            skipped: true,
            reason: skipCheck.reason
          });
          continue;
        }
      }

      const fingerprint = await fetchIocExportFingerprint(pool, feed, window);
      const fingerprintKey = exportFingerprintKey(fingerprint);

      if (!options.force) {
        const latest = await getLatestSnapshot(pool, id, feed.ioc_type, window);
        const prevKey = latest?.params?.export_fingerprint;
        if (latest?.content_hash && latest.params?.filters_hash === filters_hash && prevKey === fingerprintKey) {
          results.push({ window, status: 'success', item_count: latest.item_count, skipped: true, reason: 'unchanged_fingerprint' });
          continue;
        }
      }

      const iocRows = await fetchIocRows(pool, feed, window);
      const genMax = feed.max_items != null ? Math.min(Number(feed.max_items), FEED_EXPORT_MAX_LIMIT) : null;
      const { content, content_hash, item_count } = buildPlainTextFeed(iocRows, feed.ioc_type, genMax);
      const paramsJson = {
        ioc_type: feed.ioc_type,
        window,
        filters_hash,
        export_fingerprint: fingerprintKey,
        feed_updated_at: feedUpdatedAt,
        ioc_watermark: cheapWatermark || await fetchCheapIocWatermark(pool, feed)
      };

      await persistPublishedFeedSnapshot(pool, {
        feedId: id,
        itemCount: item_count,
        contentHash: content_hash,
        content,
        status: 'success',
        paramsJson
      });

      results.push({ window, status: 'success', item_count });
    } catch (err) {
      const msg = String(err?.message || err);
      const paramsJson = { ioc_type: feed.ioc_type, window, filters_hash: filtersHash(feed, window) };
      await persistPublishedFeedSnapshot(pool, {
        feedId: id,
        itemCount: 0,
        contentHash: null,
        content: '',
        status: 'failed',
        errorMessage: msg,
        paramsJson
      });
      results.push({ window, status: 'failed', error: msg });
    }
  }

  const failed = results.filter((r) => r.status === 'failed');
  const lastStatus = failed.length === results.length ? 'failed' : failed.length ? 'partial' : 'success';
  const lastError = failed.length ? failed.map((f) => `${f.window}: ${f.error}`).join('; ') : null;
  const allSkipped = results.length > 0 && results.every((r) => r.skipped);

  if (!allSkipped) {
    await pool.query(
      `UPDATE published_feeds
       SET last_generated_at = NOW(),
           last_status = $2,
           last_error = $3,
           updated_at = NOW()
       WHERE id = $1`,
      [id, lastStatus, lastError]
    );
  } else {
    await pool.query(
      `UPDATE published_feeds
       SET last_generated_at = NOW(),
           last_status = COALESCE(last_status, 'success'),
           updated_at = NOW()
       WHERE id = $1`,
      [id]
    );
  }

  return { feed_id: id, results, last_status: lastStatus, last_error: lastError };
}

export async function regenerateAllEnabledFeeds(pool) {
  const { rows } = await pool.query(
    `SELECT id, refresh_interval_minutes, last_generated_at
     FROM published_feeds
     WHERE enabled = TRUE`
  );
  const now = Date.now();
  const due = rows.filter((r) => {
    const intervalMs = Math.max(Number(r.refresh_interval_minutes || 15), 5) * 60 * 1000;
    if (!r.last_generated_at) return true;
    return now - new Date(r.last_generated_at).getTime() >= intervalMs;
  });

  for (const row of due) {
    try {
      const result = await generatePublishedFeedSnapshot(pool, row.id);
      const skipped = result.results?.filter((r) => r.skipped)?.length ?? 0;
      const total = result.results?.length ?? 0;
      if (skipped === total && total > 0) {
        console.log(`[published-feeds] feed=${row.id} skipped all windows (${skipped}/${total})`);
      }
    } catch (err) {
      console.error('[published-feeds] scheduled regenerate failed', row.id, err?.message || err);
    }
  }
}

export async function getLatestSnapshot(pool, feedId, iocType, window) {
  const { rows } = await pool.query(
    `SELECT id, content, content_hash, item_count, generated_at, params
     FROM published_feed_snapshots
     WHERE feed_id = $1
       AND status = 'success'
       AND params->>'ioc_type' = $2
       AND params->>'window' = $3
     ORDER BY generated_at DESC
     LIMIT 1`,
    [Number(feedId), String(iocType), String(window)]
  );
  return rows[0] || null;
}

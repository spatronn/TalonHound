// Phase 2 incremental change detection + membership evaluation for Published Feeds.
//
// Detects IOC identities touched since the feed's projection_cutoff using:
//   * ioc_items.updated_at (migration 149 + tag-touch triggers)
//   * ioc_feed_memberships.updated_at
//   * enrichment table updated_at (only when include_enrichment)
//   * file_artifacts.updated_at (hash-canonical feeds)
//   * tags catalog watermark (name/enabled flips)
//
// Then reuses the same feed WHERE / query SQL as full generation, scoped to candidate
// ids, to decide enter / stay / leave. Projection upserts feed into P1 artifact writers.

import {
  shouldCanonicalizePublishedHashFeed,
  resolveJsonIncludeFlags,
  isJsonFormatFeed,
  buildStreamingBaseSql
} from './feedPublisherService.js';
import { normalizeFeedLine, feedCategoryForObservableType, normalizeFeedIocTypes } from './feedFormatter.js';
import { normalizePublishedIoc } from './publishedFeedJson.js';
import { fetchPublishedFeedItemMetadata, metaKey } from './publishedFeedJsonData.js';
import { feedHasStixFormat } from './publishedFeedFormats.js';
import {
  projectionIdentityKey,
  projectionPartitionMetadata,
  projectionContentFingerprint,
  confidenceRank,
  upsertProjectionBatch,
  deleteProjectionIdentities,
  canUseIncrementalRefresh,
  isPublishedFeedIncrementalEnabled,
  isPublishedFeedIncrementalAllowedForFeed,
  isIncrementalEnabledForFeed,
  isProjectionReady,
  PROJECTION_STATUS,
  setFeedProjectionState,
  touchFeedRefreshChecked,
  buildProjectionScanSql,
  clearFeedProjection
} from './publishedFeedProjection.js';
import { createServiceLogger } from './appLogger.js';

const log = createServiceLogger('published-feeds');
const DIRTY_BATCH = Math.min(
  Math.max(Number(process.env.PUBLISHED_FEED_DIRTY_BATCH || 4000), 100),
  4000
);

/**
 * Capture a cutoff watermark. Changes at/after this instant remain for the next cycle
 * (we use exclusive lower bound: changed_at > cutoff).
 */
export function captureCutoffNow() {
  return new Date();
}

/** Structured item_json is required for JSON and STIX, independently of the other format. */
export function feedNeedsStructuredSerializerInput(feed) {
  return isJsonFormatFeed(feed) || feedHasStixFormat(feed);
}

/**
 * Collect distinct ioc_item ids touched since cutoff (exclusive). Bounded by LIMIT.
 * Returns { ids: number[], truncated: boolean, sources: object, deletes?: object[] }.
 */
export async function collectDirtyIocIds(db, feed, cutoff, {
  limit = 100000,
  candidateCutoff = captureCutoffNow()
} = {}) {
  if (!cutoff) return { ids: [], truncated: false, sources: {}, deletes: [], forceFull: true };
  const ids = new Set();
  const deletes = [];
  const sources = {
    ioc_items: 0,
    memberships: 0,
    enrichment: 0,
    file_artifacts: 0,
    deletes: 0,
    tags_catalog: false
  };
  let truncated = false;
  const addRows = (rows, source) => {
    for (const r of rows) {
      const id = Number(r.id);
      if (!Number.isFinite(id)) continue;
      if (ids.size >= limit) { truncated = true; return; }
      if (!ids.has(id)) {
        ids.add(id);
        sources[source] = (sources[source] || 0) + 1;
      }
    }
  };

  // Catalog watermark: if tags renamed/enabled since cutoff, force full (membership
  // filters + JSON tags can affect unbounded identities).
  const { rows: catRows } = await db.query(
    `SELECT watermark FROM published_feed_global_watermarks WHERE key = 'tags_catalog'`
  );
  if (
    catRows[0]?.watermark
    && new Date(catRows[0].watermark) > cutoff
    && new Date(catRows[0].watermark) <= candidateCutoff
  ) {
    sources.tags_catalog = true;
    return { ids: [], truncated: false, sources, deletes: [], forceFull: true, reason: 'tags_catalog' };
  }

  // Hard DELETE tombstones (migration 151). Also expand to living siblings so
  // duplicate-observable / hash-canonical winners can be re-selected.
  const { rows: delRows } = await db.query(
    `SELECT ioc_item_id, observable, observable_type, artifact_id, deleted_at
     FROM published_feed_ioc_deletes
     WHERE deleted_at > $1 AND deleted_at <= $3
     ORDER BY deleted_at ASC
     LIMIT $2`,
    [cutoff, limit + 1, candidateCutoff]
  );
  if (delRows.length > limit) truncated = true;
  for (const d of delRows.slice(0, limit)) {
    const id = Number(d.ioc_item_id);
    deletes.push({
      ioc_item_id: id,
      observable: d.observable,
      observable_type: d.observable_type,
      artifact_id: d.artifact_id || null,
      deleted_at: d.deleted_at
    });
    if (Number.isFinite(id) && !ids.has(id) && ids.size < limit) {
      ids.add(id);
      sources.deletes += 1;
    }
  }
  if (!truncated && deletes.length) {
    const obsPairs = deletes.map((d) => [String(d.observable || '').toLowerCase(), d.observable_type]);
    const arts = [...new Set(deletes.map((d) => d.artifact_id).filter(Boolean))];
    if (obsPairs.length) {
      const { rows: sib } = await db.query(
        `SELECT id FROM ioc_items
         WHERE (lower(observable), observable_type) IN (
           SELECT lower(x.obs), x.otype
           FROM unnest($1::text[], $2::text[]) AS x(obs, otype)
         )
         LIMIT $3`,
        [
          obsPairs.map((p) => p[0]),
          obsPairs.map((p) => p[1]),
          Math.max(limit - ids.size, 1)
        ]
      );
      addRows(sib, 'ioc_items');
    }
    if (!truncated && arts.length) {
      const { rows: artSib } = await db.query(
        `SELECT fal.ioc_item_id AS id
         FROM file_artifact_ioc_links fal
         WHERE fal.artifact_id = ANY($1::uuid[])
         LIMIT $2`,
        [arts, Math.max(limit - ids.size, 1)]
      );
      addRows(artSib, 'file_artifacts');
    }
  }

  const { rows: iocRows } = await db.query(
    `SELECT id FROM ioc_items
     WHERE updated_at IS NOT NULL AND updated_at > $1 AND updated_at <= $3
     ORDER BY updated_at ASC
     LIMIT $2`,
    [cutoff, limit + 1, candidateCutoff]
  );
  if (iocRows.length > limit) truncated = true;
  addRows(iocRows.slice(0, limit), 'ioc_items');

  if (!truncated) {
    const { rows: memRows } = await db.query(
      `SELECT DISTINCT m.ioc_item_id AS id
       FROM ioc_feed_memberships m
       WHERE m.updated_at > $1 AND m.updated_at <= $3
       ORDER BY m.ioc_item_id
       LIMIT $2`,
      [cutoff, limit + 1, candidateCutoff]
    );
    if (memRows.length > limit) truncated = true;
    addRows(memRows.slice(0, limit), 'memberships');
  }

  const flags = resolveJsonIncludeFlags(feed);
  if (!truncated && flags.includeEnrichment) {
    const enrichSql = [
      `SELECT i.id FROM ioc_enrichments e
         JOIN ioc_items i ON lower(i.observable) = lower(e.ioc_value)
        WHERE e.updated_at > $1 AND e.updated_at <= $3 LIMIT $2`,
      `SELECT i.id FROM ioc_ip_enrichment e
         JOIN ioc_items i ON i.observable = e.ip AND i.observable_type = 'ip'
        WHERE e.updated_at > $1 AND e.updated_at <= $3 LIMIT $2`,
      `SELECT i.id FROM ioc_abuseipdb_enrichment e
         JOIN ioc_items i ON i.observable = e.ip AND i.observable_type = 'ip'
        WHERE e.updated_at > $1 AND e.updated_at <= $3 LIMIT $2`,
      `SELECT i.id FROM ioc_domain_enrichment e
         JOIN ioc_items i ON lower(i.observable) = lower(e.observable_value) AND i.observable_type = 'domain'
        WHERE e.updated_at > $1 AND e.updated_at <= $3 LIMIT $2`,
      `SELECT i.id FROM ioc_spamhaus_drop_enrichment e
         JOIN ioc_items i ON i.observable = e.lookup_ip AND i.observable_type = 'ip'
        WHERE e.updated_at > $1 AND e.updated_at <= $3 LIMIT $2`
    ];
    for (const sql of enrichSql) {
      if (truncated) break;
      const { rows } = await db.query(sql, [
        cutoff,
        Math.max(limit - ids.size, 1),
        candidateCutoff
      ]);
      addRows(rows, 'enrichment');
    }
  }

  if (!truncated && shouldCanonicalizePublishedHashFeed(feed)) {
    const { rows: faRows } = await db.query(
      `SELECT fal.ioc_item_id AS id
       FROM file_artifacts fa
       JOIN file_artifact_ioc_links fal ON fal.artifact_id = fa.id
       WHERE fa.updated_at > $1 AND fa.updated_at <= $3
       LIMIT $2`,
      [cutoff, Math.max(limit - ids.size, 1), candidateCutoff]
    );
    addRows(faRows, 'file_artifacts');
  }

  return {
    ids: [...ids],
    deletes,
    truncated,
    sources,
    forceFull: truncated
  };
}

/**
 * Re-evaluate candidate IOC identities against the feed's full filter/query predicate.
 * Expands to lower(observable)+type and injects that restriction into the same streaming
 * base SQL (DISTINCT ON / hash collapse) so winners match full generation for those
 * identities — without scanning the rest of the feed.
 */
export async function evaluateCandidatesAgainstFeed(db, feed, window, candidateIds, { deletes = [] } = {}) {
  const lowerValues = new Set();
  const types = new Set();
  if (candidateIds?.length) {
    const { rows: idents } = await db.query(
      `SELECT DISTINCT lower(observable) AS obs, observable_type AS otype
       FROM ioc_items WHERE id = ANY($1::bigint[])`,
      [candidateIds]
    );
    for (const r of idents) {
      lowerValues.add(r.obs);
      types.add(r.otype);
    }
  }
  for (const d of deletes || []) {
    lowerValues.add(String(d.observable || '').toLowerCase());
    if (d.observable_type) types.add(d.observable_type);
  }
  if (!lowerValues.size) return [];
  const { sql, params } = buildStreamingBaseSql(feed, window, {
    lowerValues: [...lowerValues],
    types: [...types]
  });
  const { rows } = await db.query(sql, params);
  return rows;
}

/**
 * Expand candidate ids to sibling identities currently in the projection (for leave detection)
 * and to lower(observable) siblings that share published identity.
 * Optional `deletes` supplies tombstone identity when the IOC row is already gone.
 */
export async function expandCandidateContext(db, feedId, window, candidateIds, { deletes = [] } = {}) {
  if (!candidateIds?.length && !deletes?.length) {
    return { candidateIds: [], projectedKeys: [], siblingIds: [] };
  }
  const ids = candidateIds?.length ? candidateIds : [];
  const projectedKeys = new Set();
  const siblingIds = new Set();

  if (ids.length) {
    const { rows: proj } = await db.query(
      `SELECT identity_key, ioc_item_id FROM published_feed_items
       WHERE feed_id = $1 AND snapshot_window = $2 AND ioc_item_id = ANY($3::bigint[])`,
      [feedId, window, ids]
    );
    for (const r of proj) projectedKeys.add(r.identity_key);

    const { rows: sib } = await db.query(
      `SELECT i2.id
       FROM ioc_items i1
       JOIN ioc_items i2
         ON lower(i2.observable) = lower(i1.observable)
        AND i2.observable_type = i1.observable_type
       WHERE i1.id = ANY($1::bigint[])`,
      [ids]
    );
    for (const r of sib) siblingIds.add(Number(r.id));
  }

  if (deletes?.length) {
    const keys = [];
    const obs = [];
    const types = [];
    const arts = [];
    for (const d of deletes) {
      keys.push(projectionIdentityKey(d.observable, d.observable_type, {
        artifactId: d.artifact_id || null
      }));
      keys.push(projectionIdentityKey(d.observable, d.observable_type));
      obs.push(String(d.observable || '').toLowerCase());
      types.push(d.observable_type);
      if (d.artifact_id) arts.push(d.artifact_id);
    }
    const { rows: byKey } = await db.query(
      `SELECT identity_key FROM published_feed_items
       WHERE feed_id = $1 AND snapshot_window = $2 AND identity_key = ANY($3::text[])`,
      [feedId, window, [...new Set(keys)]]
    );
    for (const r of byKey) projectedKeys.add(r.identity_key);

    const { rows: byObs } = await db.query(
      `SELECT id FROM ioc_items
       WHERE (lower(observable), observable_type) IN (
         SELECT x.obs, x.otype FROM unnest($1::text[], $2::text[]) AS x(obs, otype)
       )`,
      [obs, types]
    );
    for (const r of byObs) siblingIds.add(Number(r.id));

    if (arts.length) {
      const { rows: byArt } = await db.query(
        `SELECT fal.ioc_item_id AS id
         FROM file_artifact_ioc_links fal
         WHERE fal.artifact_id = ANY($1::uuid[])`,
        [arts]
      );
      for (const r of byArt) siblingIds.add(Number(r.id));
    }
  }

  return {
    candidateIds: ids,
    projectedKeys: [...projectedKeys],
    siblingIds: [...siblingIds]
  };
}

/**
 * Build projection row payloads for matched streaming-shaped rows (with JSON metadata).
 */
export async function buildProjectionRowsForMatched(db, feed, window, matchedRows, formatTypes) {
  if (!matchedRows?.length) return [];
  const flags = resolveJsonIncludeFlags(feed);
  const needsStructuredItem = feedNeedsStructuredSerializerInput(feed);
  const norm = normalizeFeedIocTypes(formatTypes);
  const types = norm.ok ? norm.value : [];
  const multi = types.length !== 1;
  const lineTypeFor = (observableType) => (multi
    ? (feedCategoryForObservableType(observableType) || types[0])
    : types[0]);

  const items = [];
  for (const row of matchedRows) {
    const value = normalizeFeedLine(row, lineTypeFor(row.observable_type));
    if (!value) continue;
    items.push({
      value,
      observable_type: row.observable_type,
      row
    });
  }
  if (!items.length) return [];

  let metaByKey = new Map();
  if (needsStructuredItem) {
    metaByKey = await fetchPublishedFeedItemMetadata(
      db,
      items.map((it) => ({ value: it.value, observable_type: it.observable_type })),
      flags
    );
  }

  const out = [];
  for (const it of items) {
    const row = it.row;
    const itemJson = needsStructuredItem
      ? normalizePublishedIoc(
        {
          value: it.value,
          observable_type: row.observable_type,
          category: row.category,
          confidence: row.confidence
        },
        metaByKey.get(metaKey(row.observable_type, it.value)) || {
          imported_at: row.created_at,
          sources: [],
          tags: [],
          enrichment: {}
        },
        flags
      )
      : null;
    const fp = projectionContentFingerprint({ txtValue: it.value, itemJson });
    const partition = projectionPartitionMetadata({
      partition_identity: row.partition_identity || null,
      observable: it.value,
      observable_type: row.observable_type
    }, feed);
    out.push({
      feed_id: feed.id,
      window,
      identity_key: projectionIdentityKey(it.value, row.observable_type),
      ioc_item_id: Number(row.id),
      observable: it.value,
      observable_type: row.observable_type,
      recency_ts: row.recency_ts,
      confidence: row.confidence,
      category: row.category,
      confidence_rank: confidenceRank(row.confidence),
      txt_value: it.value,
      item_json: itemJson,
      content_fingerprint: fp,
      ...partition
    });
  }
  return out;
}

/**
 * Apply incremental projection updates for dirty candidates.
 * @returns {{ entered, updated, removed, unchanged, artifactDirty, forceFull, reason? }}
 */
export async function applyIncrementalProjectionUpdate(db, feed, window, formatTypes, dirty) {
  if (dirty.forceFull) {
    return {
      entered: 0, updated: 0, removed: 0, unchanged: 0,
      artifactDirty: false, forceFull: true, reason: dirty.reason || 'dirty_truncated'
    };
  }
  if (!dirty.ids?.length && !dirty.deletes?.length) {
    return {
      entered: 0, updated: 0, removed: 0, unchanged: 0,
      artifactDirty: false, forceFull: false
    };
  }

  const deletes = dirty.deletes || [];
  const ctx = await expandCandidateContext(db, feed.id, window, dirty.ids || [], { deletes });
  const evalIds = [...new Set([...(dirty.ids || []), ...ctx.siblingIds])];
  const matched = await evaluateCandidatesAgainstFeed(db, feed, window, evalIds, { deletes });
  const matchedIds = new Set(matched.map((r) => Number(r.id)));
  const newRows = await buildProjectionRowsForMatched(db, feed, window, matched, formatTypes);
  const newKeys = new Set(newRows.map((r) => r.identity_key));

  // Existing projection rows that involve these candidates (by ioc id or identity).
  const { rows: existing } = await db.query(
    `SELECT identity_key, ioc_item_id, content_fingerprint, recency_ts,
            partition_identity, chunk_key
     FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2
       AND (ioc_item_id = ANY($3::bigint[]) OR identity_key = ANY($4::text[]))`,
    [feed.id, window, evalIds.length ? evalIds : [0], [...newKeys, ...ctx.projectedKeys]]
  );
  const existingByKey = new Map(existing.map((r) => [r.identity_key, r]));

  // Leaves: projected identities tied to candidates that no longer match and aren't in newKeys.
  const leaveKeys = [];
  for (const e of existing) {
    if (!newKeys.has(e.identity_key) && !matchedIds.has(Number(e.ioc_item_id))) {
      // Still leave if the projected ioc is in the dirty/sibling set and didn't rematch.
      if (evalIds.includes(Number(e.ioc_item_id)) || ctx.projectedKeys.includes(e.identity_key)) {
        leaveKeys.push(e.identity_key);
      }
    }
  }
  // Stronger leave rule: any existing key for a dirty identity whose lower(value) winner is gone.
  for (const key of ctx.projectedKeys) {
    if (!newKeys.has(key) && !leaveKeys.includes(key)) leaveKeys.push(key);
  }

  const removed = await deleteProjectionIdentities(db, feed.id, window, leaveKeys);

  let entered = 0;
  let updated = 0;
  let unchanged = 0;
  const toUpsert = [];
  for (const row of newRows) {
    const prev = existingByKey.get(row.identity_key);
    if (!prev) {
      entered += 1;
      toUpsert.push(row);
    } else if (
      prev.content_fingerprint !== row.content_fingerprint
      || Number(prev.ioc_item_id) !== Number(row.ioc_item_id)
      || new Date(prev.recency_ts || 0).getTime() !== new Date(row.recency_ts || 0).getTime()
      || prev.partition_identity !== row.partition_identity
      || Number(prev.chunk_key) !== Number(row.chunk_key)
    ) {
      updated += 1;
      toUpsert.push(row);
    } else {
      unchanged += 1;
    }
  }

  for (let i = 0; i < toUpsert.length; i += DIRTY_BATCH) {
    await upsertProjectionBatch(db, toUpsert.slice(i, i + DIRTY_BATCH));
  }

  const affectedChunks = new Set();
  for (const row of existing) {
    if (row.chunk_key != null) affectedChunks.add(Number(row.chunk_key));
  }
  for (const row of newRows) {
    if (row.chunk_key != null) affectedChunks.add(Number(row.chunk_key));
  }

  return {
    entered,
    updated,
    removed,
    unchanged,
    artifactDirty: entered + updated + removed > 0,
    forceFull: false,
    affectedChunkKeys: [...affectedChunks].sort((a, b) => a - b)
  };
}

/**
 * Decide refresh mode for a feed tick.
 * @returns {'noop'|'incremental'|'full'|'bootstrap'}
 */
export function decideRefreshMode(feed, {
  force = false,
  filtersChanged = false,
  incrementalEnabled = isIncrementalEnabledForFeed(feed?.id),
  streamingEnabled = false,
  snapshotWindow = null
} = {}) {
  if (!streamingEnabled) return 'full';
  if (force || filtersChanged) return isProjectionReady(feed) ? 'full' : (incrementalEnabled ? 'bootstrap' : 'full');
  if (!incrementalEnabled) return isProjectionReady(feed) ? 'full' : 'full';
  if (!isProjectionReady(feed)) return 'bootstrap';
  if (!canUseIncrementalRefresh(feed, { force, filtersChanged, snapshotWindow })) return 'full';
  return 'incremental';
}

export {
  canUseIncrementalRefresh,
  isPublishedFeedIncrementalEnabled,
  isPublishedFeedIncrementalAllowedForFeed,
  isIncrementalEnabledForFeed,
  isProjectionReady,
  PROJECTION_STATUS,
  setFeedProjectionState,
  touchFeedRefreshChecked,
  buildProjectionScanSql,
  clearFeedProjection,
  upsertProjectionBatch,
  projectionContentFingerprint,
  projectionIdentityKey
};

export function logRefreshMetrics(payload) {
  log.info('published feed refresh', payload);
}

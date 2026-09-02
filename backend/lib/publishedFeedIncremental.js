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
  buildStreamingBaseSql,
  resolveFeedIocTypes
} from './feedPublisherService.js';
import {
  normalizeFeedLine,
  feedCategoryForObservableType,
  normalizeFeedIocTypes,
  observableTypesForFeedIocTypes
} from './feedFormatter.js';
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
  BASE_PROJECTION_WINDOW,
  setFeedProjectionState,
  touchFeedRefreshChecked,
  buildProjectionScanSql,
  clearFeedProjection,
  adjustProjectionItemCount
} from './publishedFeedProjection.js';
import {
  SLIDING_WINDOWS,
  isSlidingWindow,
  collectBoundaryDepartures,
  computeAffectedChunksByWindow,
  windowNeedsArtifactRefresh,
  isSlidingWindowIncrementalEnabled,
  countProjectionItemsForWindow
} from './publishedFeedWindowEligibility.js';
import { createServiceLogger } from './appLogger.js';

/** Local single-window resolution (avoids tighter coupling for tick prep). */
function configuredArtifactWindow(feed) {
  const mode = String(feed?.filter_mode || 'basic').trim().toLowerCase();
  if (mode === 'query') return 'all';
  const v = String(feed?.time_window || 'all').trim().toLowerCase();
  if (v === '1d' || v === '3d' || v === '7d' || v === 'all') return v;
  return 'all';
}

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
/**
 * Observable types this feed can ever emit. Empty → unscoped (query-mode / unknown).
 * Used to prune dirty polls so Domain ticks do not scan hash/IP partitions and vice versa.
 */
export function feedDirtyObservableTypes(feed) {
  try {
    const categories = resolveFeedIocTypes(feed);
    if (!categories.length) return [];
    return observableTypesForFeedIocTypes(categories);
  } catch {
    return [];
  }
}

export async function collectDirtyIocIds(db, feed, cutoff, {
  limit = 100000,
  candidateCutoff = captureCutoffNow()
} = {}) {
  if (!cutoff) return { ids: [], truncated: false, sources: {}, deletes: [], forceFull: true, typeById: {} };
  const ids = new Set();
  // Track observable_type per dirty id so downstream identity resolution can prune the
  // partitioned ioc_items table (PK is (observable_type, id)) instead of scanning every
  // partition. Every collection source can supply the type cheaply.
  const typeById = new Map();
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
      if (r.observable_type != null && !typeById.has(id)) typeById.set(id, r.observable_type);
    }
  };

  const typeScope = feedDirtyObservableTypes(feed);
  const scoped = typeScope.length > 0;

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
  const delSql = scoped
    ? `SELECT ioc_item_id, observable, observable_type, artifact_id, deleted_at
       FROM published_feed_ioc_deletes
       WHERE deleted_at > $1 AND deleted_at <= $3
         AND observable_type = ANY($4::text[])
       ORDER BY deleted_at ASC
       LIMIT $2`
    : `SELECT ioc_item_id, observable, observable_type, artifact_id, deleted_at
       FROM published_feed_ioc_deletes
       WHERE deleted_at > $1 AND deleted_at <= $3
       ORDER BY deleted_at ASC
       LIMIT $2`;
  const delParams = scoped
    ? [cutoff, limit + 1, candidateCutoff, typeScope]
    : [cutoff, limit + 1, candidateCutoff];
  const { rows: delRows } = await db.query(delSql, delParams);
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
    if (Number.isFinite(id) && d.observable_type != null && !typeById.has(id)) {
      typeById.set(id, d.observable_type);
    }
  }
  if (!truncated && deletes.length) {
    const obsPairs = deletes.map((d) => [String(d.observable || '').toLowerCase(), d.observable_type]);
    const arts = [...new Set(deletes.map((d) => d.artifact_id).filter(Boolean))];
    if (obsPairs.length) {
      const { rows: sib } = await db.query(
        `SELECT id, observable_type FROM ioc_items
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
        `SELECT fal.ioc_item_id AS id, fal.ioc_observable_type AS observable_type
         FROM file_artifact_ioc_links fal
         WHERE fal.artifact_id = ANY($1::uuid[])
         LIMIT $2`,
        [arts, Math.max(limit - ids.size, 1)]
      );
      addRows(artSib, 'file_artifacts');
    }
  }

  const iocSql = scoped
    ? `SELECT id, observable_type FROM ioc_items
       WHERE updated_at IS NOT NULL AND updated_at > $1 AND updated_at <= $3
         AND observable_type = ANY($4::text[])
       ORDER BY updated_at ASC
       LIMIT $2`
    : `SELECT id, observable_type FROM ioc_items
       WHERE updated_at IS NOT NULL AND updated_at > $1 AND updated_at <= $3
       ORDER BY updated_at ASC
       LIMIT $2`;
  const iocParams = scoped
    ? [cutoff, limit + 1, candidateCutoff, typeScope]
    : [cutoff, limit + 1, candidateCutoff];
  const { rows: iocRows } = await db.query(iocSql, iocParams);
  if (iocRows.length > limit) truncated = true;
  addRows(iocRows.slice(0, limit), 'ioc_items');

  if (!truncated) {
    const memSql = scoped
      ? `SELECT DISTINCT m.ioc_item_id AS id, m.ioc_observable_type AS observable_type
         FROM ioc_feed_memberships m
         WHERE m.updated_at > $1 AND m.updated_at <= $3
           AND m.ioc_observable_type = ANY($4::text[])
         ORDER BY m.ioc_item_id
         LIMIT $2`
      : `SELECT DISTINCT m.ioc_item_id AS id, m.ioc_observable_type AS observable_type
         FROM ioc_feed_memberships m
         WHERE m.updated_at > $1 AND m.updated_at <= $3
         ORDER BY m.ioc_item_id
         LIMIT $2`;
    const memParams = scoped
      ? [cutoff, limit + 1, candidateCutoff, typeScope]
      : [cutoff, limit + 1, candidateCutoff];
    const { rows: memRows } = await db.query(memSql, memParams);
    if (memRows.length > limit) truncated = true;
    addRows(memRows.slice(0, limit), 'memberships');
  }

  const flags = resolveJsonIncludeFlags(feed);
  if (!truncated && flags.includeEnrichment) {
    const typeClause = scoped ? ' AND i.observable_type = ANY($4::text[])' : '';
    const enrichSql = [
      `SELECT i.id, i.observable_type FROM ioc_enrichments e
         JOIN ioc_items i ON lower(i.observable) = lower(e.ioc_value)
        WHERE e.updated_at > $1 AND e.updated_at <= $3${typeClause} LIMIT $2`,
      `SELECT i.id, i.observable_type FROM ioc_ip_enrichment e
         JOIN ioc_items i ON i.observable = e.ip AND i.observable_type = 'ip'
        WHERE e.updated_at > $1 AND e.updated_at <= $3${typeClause} LIMIT $2`,
      `SELECT i.id, i.observable_type FROM ioc_abuseipdb_enrichment e
         JOIN ioc_items i ON i.observable = e.ip AND i.observable_type = 'ip'
        WHERE e.updated_at > $1 AND e.updated_at <= $3${typeClause} LIMIT $2`,
      `SELECT i.id, i.observable_type FROM ioc_domain_enrichment e
         JOIN ioc_items i ON lower(i.observable) = lower(e.observable_value) AND i.observable_type = 'domain'
        WHERE e.updated_at > $1 AND e.updated_at <= $3${typeClause} LIMIT $2`,
      `SELECT i.id, i.observable_type FROM ioc_spamhaus_drop_enrichment e
         JOIN ioc_items i ON i.observable = e.lookup_ip AND i.observable_type = 'ip'
        WHERE e.updated_at > $1 AND e.updated_at <= $3${typeClause} LIMIT $2`
    ];
    for (const sql of enrichSql) {
      if (truncated) break;
      const params = scoped
        ? [cutoff, Math.max(limit - ids.size, 1), candidateCutoff, typeScope]
        : [cutoff, Math.max(limit - ids.size, 1), candidateCutoff];
      const { rows } = await db.query(sql, params);
      addRows(rows, 'enrichment');
    }
  }

  if (!truncated && shouldCanonicalizePublishedHashFeed(feed)) {
    const faTypeClause = scoped ? ' AND fal.ioc_observable_type = ANY($4::text[])' : '';
    const { rows: faRows } = await db.query(
      `SELECT fal.ioc_item_id AS id, fal.ioc_observable_type AS observable_type
       FROM file_artifacts fa
       JOIN file_artifact_ioc_links fal ON fal.artifact_id = fa.id
       WHERE fa.updated_at > $1 AND fa.updated_at <= $3${faTypeClause}
       LIMIT $2`,
      scoped
        ? [cutoff, Math.max(limit - ids.size, 1), candidateCutoff, typeScope]
        : [cutoff, Math.max(limit - ids.size, 1), candidateCutoff]
    );
    addRows(faRows, 'file_artifacts');
  }

  return {
    ids: [...ids],
    typeById: Object.fromEntries(typeById),
    deletes,
    truncated,
    sources,
    forceFull: truncated,
    type_scope: scoped ? typeScope : null
  };
}

/**
 * Resolve a bounded set of dirty ioc ids to their canonical identity pairs
 * (lower(observable), observable_type). When the observable_type of every id is known
 * (threaded from collectDirtyIocIds), constrain by observable_type so PostgreSQL prunes
 * the ioc_items partitions and PK-seeks instead of Seq-Scanning every partition.
 */
export async function resolveDirtyIdentities(db, ids, typeById = {}) {
  if (!ids?.length) return [];
  const knownTypes = [...new Set(ids.map((id) => typeById?.[id]).filter((t) => t != null))];
  const knowAllTypes = knownTypes.length > 0 && ids.every((id) => typeById?.[id] != null);
  if (knowAllTypes) {
    const { rows } = await db.query(
      `SELECT DISTINCT lower(observable) AS obs, observable_type AS otype
       FROM ioc_items
       WHERE observable_type = ANY($2::text[]) AND id = ANY($1::bigint[])`,
      [ids, knownTypes]
    );
    return rows;
  }
  const { rows } = await db.query(
    `SELECT DISTINCT lower(observable) AS obs, observable_type AS otype
     FROM ioc_items WHERE id = ANY($1::bigint[])`,
    [ids]
  );
  return rows;
}

/**
 * Re-evaluate candidate IOC identities against the feed's full filter/query predicate.
 * Expands to lower(observable)+type and injects that restriction into the same streaming
 * base SQL (DISTINCT ON / hash collapse) so winners match full generation for those
 * identities — without scanning the rest of the feed.
 */
export async function evaluateCandidatesAgainstFeed(db, feed, window, candidateIds, { deletes = [], typeById = {} } = {}) {
  const lowerValues = new Set();
  const types = new Set();
  if (candidateIds?.length) {
    const idents = await resolveDirtyIdentities(db, candidateIds, typeById);
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
 * Collect the projection identities affected by the dirty candidates, for leave/winner-switch
 * detection. Returns `projectedKeys` (canonical identity_keys currently in the projection for
 * these candidates — found by ioc_item_id and by canonical identity_key, without scanning
 * ioc_items) plus `siblingIds`/`siblingTypeById` from the low-volume delete/tombstone path.
 * Optional `deletes` supplies tombstone identity when the IOC row is already gone.
 */
export async function expandCandidateContext(db, feedId, window, candidateIds, { deletes = [], dirtyIdentities = null, typeById = {} } = {}) {
  if (!candidateIds?.length && !deletes?.length) {
    return { candidateIds: [], projectedKeys: [], siblingIds: [], siblingTypeById: {} };
  }
  const ids = candidateIds?.length ? candidateIds : [];
  const projectedKeys = new Set();
  const siblingIds = new Set();
  const siblingTypeById = new Map();

  if (ids.length) {
    // (1) Identities currently projected under a dirty id itself (indexed by
    // idx_pf_items_feed_ioc). Also covers the rare case where an id's observable changed:
    // the old projected identity is still found by ioc_item_id.
    const { rows: proj } = await db.query(
      `SELECT identity_key FROM published_feed_items
       WHERE feed_id = $1 AND snapshot_window = $2 AND ioc_item_id = ANY($3::bigint[])`,
      [feedId, window, ids]
    );
    for (const r of proj) projectedKeys.add(r.identity_key);

    // (2) Identities currently projected for the dirty candidates' CANONICAL keys,
    // regardless of which sibling row is the stored representative. identity_key is a pure
    // function of (lower(observable), observable_type) and is invariant across canonical
    // siblings and winner-switches, so this indexed lookup on the projection PK
    // (feed_id, snapshot_window, identity_key) replaces the old i1 JOIN i2 sibling
    // self-join that scanned the entire partitioned ioc_items table.
    const identities = dirtyIdentities || await resolveDirtyIdentities(db, ids, typeById);
    const dirtyKeys = [...new Set(identities.map((r) => projectionIdentityKey(r.obs, r.otype)))];
    if (dirtyKeys.length) {
      const { rows: byIdentity } = await db.query(
        `SELECT identity_key FROM published_feed_items
         WHERE feed_id = $1 AND snapshot_window = $2 AND identity_key = ANY($3::text[])`,
        [feedId, window, dirtyKeys]
      );
      for (const r of byIdentity) projectedKeys.add(r.identity_key);
    }
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
      `SELECT id, observable_type FROM ioc_items
       WHERE (lower(observable), observable_type) IN (
         SELECT x.obs, x.otype FROM unnest($1::text[], $2::text[]) AS x(obs, otype)
       )`,
      [obs, types]
    );
    for (const r of byObs) {
      siblingIds.add(Number(r.id));
      if (r.observable_type != null) siblingTypeById.set(Number(r.id), r.observable_type);
    }

    if (arts.length) {
      const { rows: byArt } = await db.query(
        `SELECT fal.ioc_item_id AS id, fal.ioc_observable_type AS observable_type
         FROM file_artifact_ioc_links fal
         WHERE fal.artifact_id = ANY($1::uuid[])`,
        [arts]
      );
      for (const r of byArt) {
        siblingIds.add(Number(r.id));
        if (r.observable_type != null) siblingTypeById.set(Number(r.id), r.observable_type);
      }
    }
  }

  return {
    candidateIds: ids,
    projectedKeys: [...projectedKeys],
    siblingIds: [...siblingIds],
    siblingTypeById: Object.fromEntries(siblingTypeById)
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
  const projectionWindow = isSlidingWindowIncrementalEnabled()
    ? BASE_PROJECTION_WINDOW
    : window;
  if (dirty.forceFull) {
    return {
      entered: 0, updated: 0, removed: 0, unchanged: 0,
      artifactDirty: false, forceFull: true, reason: dirty.reason || 'dirty_truncated',
      affectedChunkKeys: [], touchedRows: []
    };
  }
  if (!dirty.ids?.length && !dirty.deletes?.length) {
    return {
      entered: 0, updated: 0, removed: 0, unchanged: 0,
      artifactDirty: false, forceFull: false,
      affectedChunkKeys: [], touchedRows: []
    };
  }

  const deletes = dirty.deletes || [];
  const typeById = dirty.typeById || {};
  const dirtyIdentities = await resolveDirtyIdentities(db, dirty.ids || [], typeById);
  const ctx = await expandCandidateContext(db, feed.id, projectionWindow, dirty.ids || [], {
    deletes, dirtyIdentities, typeById
  });
  const evalIds = [...new Set([...(dirty.ids || []), ...ctx.siblingIds])];
  const evalTypeById = { ...typeById, ...(ctx.siblingTypeById || {}) };
  const evalWindow = isSlidingWindowIncrementalEnabled() ? BASE_PROJECTION_WINDOW : window;
  const matched = await evaluateCandidatesAgainstFeed(db, feed, evalWindow, evalIds, {
    deletes, typeById: evalTypeById
  });
  const matchedIds = new Set(matched.map((r) => Number(r.id)));
  const newRows = await buildProjectionRowsForMatched(db, feed, projectionWindow, matched, formatTypes);
  const newKeys = new Set(newRows.map((r) => r.identity_key));

  const { rows: existing } = await db.query(
    `SELECT identity_key, ioc_item_id, content_fingerprint, recency_ts,
            partition_identity, chunk_key
     FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2
       AND (ioc_item_id = ANY($3::bigint[]) OR identity_key = ANY($4::text[]))`,
    [feed.id, projectionWindow, evalIds.length ? evalIds : [0], [...newKeys, ...ctx.projectedKeys]]
  );
  const existingByKey = new Map(existing.map((r) => [r.identity_key, r]));

  const leaveKeys = [];
  for (const e of existing) {
    if (!newKeys.has(e.identity_key) && !matchedIds.has(Number(e.ioc_item_id))) {
      if (evalIds.includes(Number(e.ioc_item_id)) || ctx.projectedKeys.includes(e.identity_key)) {
        leaveKeys.push(e.identity_key);
      }
    }
  }
  for (const key of ctx.projectedKeys) {
    if (!newKeys.has(key) && !leaveKeys.includes(key)) leaveKeys.push(key);
  }

  const removed = await deleteProjectionIdentities(db, feed.id, projectionWindow, leaveKeys);

  let entered = 0;
  let updated = 0;
  let unchanged = 0;
  const toUpsert = [];
  const touchedRows = [];
  for (const row of newRows) {
    const prev = existingByKey.get(row.identity_key);
    if (!prev) {
      entered += 1;
      toUpsert.push(row);
      touchedRows.push({
        identity_key: row.identity_key,
        chunk_key: row.chunk_key,
        recency_ts: row.recency_ts,
        prev_recency_ts: null
      });
    } else if (
      prev.content_fingerprint !== row.content_fingerprint
      || Number(prev.ioc_item_id) !== Number(row.ioc_item_id)
      || new Date(prev.recency_ts || 0).getTime() !== new Date(row.recency_ts || 0).getTime()
      || prev.partition_identity !== row.partition_identity
      || Number(prev.chunk_key) !== Number(row.chunk_key)
    ) {
      updated += 1;
      toUpsert.push(row);
      touchedRows.push({
        identity_key: row.identity_key,
        chunk_key: row.chunk_key ?? prev.chunk_key,
        recency_ts: row.recency_ts,
        prev_recency_ts: prev.recency_ts
      });
    } else {
      unchanged += 1;
    }
  }

  for (let i = 0; i < toUpsert.length; i += DIRTY_BATCH) {
    await upsertProjectionBatch(db, toUpsert.slice(i, i + DIRTY_BATCH));
  }

  const netDelta = entered - removed;
  if (netDelta !== 0 && feed?.id != null) {
    const nextCount = await adjustProjectionItemCount(db, feed.id, netDelta);
    if (nextCount != null) feed.projection_item_count = nextCount;
  }

  const affectedChunks = new Set();
  for (const row of existing) {
    if (row.chunk_key != null) affectedChunks.add(Number(row.chunk_key));
  }
  for (const row of newRows) {
    if (row.chunk_key != null) affectedChunks.add(Number(row.chunk_key));
  }
  for (const key of leaveKeys) {
    const prev = existingByKey.get(key);
    if (prev?.chunk_key != null) affectedChunks.add(Number(prev.chunk_key));
    touchedRows.push({
      identity_key: key,
      chunk_key: prev?.chunk_key ?? null,
      recency_ts: null,
      prev_recency_ts: prev?.recency_ts ?? null
    });
  }

  return {
    entered,
    updated,
    removed,
    unchanged,
    artifactDirty: entered + updated + removed > 0,
    forceFull: false,
    affectedChunkKeys: [...affectedChunks].sort((a, b) => a - b),
    touchedRows
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

/**
 * Prepare one incremental feed tick: dirty poll, boundary departures, base projection update.
 * Call once per feed before per-window artifact generation.
 */
export async function prepareIncrementalFeedTick(db, feed, formatTypes, {
  cutoff,
  candidateCutoff
} = {}) {
  const W = candidateCutoff || captureCutoffNow();
  let dirty = await collectDirtyIocIds(db, feed, cutoff, { candidateCutoff: W });
  if (feed.projection_pending_cutoff && !dirty.forceFull) {
    dirty = { ...dirty, forceFull: true, reason: 'pending_publication_recovery' };
  }

  // Public single-window contract: only the feed's configured artifact window matters.
  // Internal projection remains snapshot_window='all'; alternate public windows are not maintained.
  const artifactWindow = configuredArtifactWindow(feed);

  const boundaries = {};
  let boundaryCandidates = 0;
  if (
    isSlidingWindowIncrementalEnabled()
    && cutoff
    && isSlidingWindow(artifactWindow)
  ) {
    boundaries[artifactWindow] = await collectBoundaryDepartures(
      db, feed.id, cutoff, W, artifactWindow
    );
    boundaryCandidates = boundaries[artifactWindow].length;
  }

  if (dirty.forceFull) {
    return {
      forceFull: true,
      dirty,
      boundaries,
      candidateCutoff: W,
      boundary_candidates: boundaryCandidates,
      artifactWindow
    };
  }

  const hasDirty = (dirty.ids?.length || 0) > 0 || (dirty.deletes?.length || 0) > 0;
  if (!hasDirty && boundaryCandidates === 0) {
    return {
      noop: true,
      dirty,
      boundaries,
      candidateCutoff: W,
      boundary_candidates: 0,
      artifactWindow
    };
  }

  let delta = {
    entered: 0,
    updated: 0,
    removed: 0,
    unchanged: 0,
    artifactDirty: false,
    affectedChunkKeys: [],
    touchedRows: []
  };

  if (hasDirty) {
    delta = await applyIncrementalProjectionUpdate(
      db,
      feed,
      BASE_PROJECTION_WINDOW,
      formatTypes,
      dirty
    );
    if (delta.forceFull) {
      return {
        forceFull: true,
        dirty,
        boundaries,
        candidateCutoff: W,
        boundary_candidates: boundaryCandidates,
        reason: delta.reason,
        artifactWindow
      };
    }
  }

  const affectedChunksByWindow = computeAffectedChunksByWindow(
    delta, boundaries, delta.touchedRows, W
  );
  const windowRefreshNeeded = {
    [artifactWindow]: windowNeedsArtifactRefresh(
      artifactWindow, delta, boundaries, affectedChunksByWindow
    )
  };

  return {
    noop: false,
    dirty,
    boundaries,
    delta,
    affectedChunksByWindow,
    windowRefreshNeeded,
    candidateCutoff: W,
    boundary_candidates: boundaryCandidates,
    artifactWindow
  };
}

export {
  BASE_PROJECTION_WINDOW,
  countProjectionItemsForWindow,
  isSlidingWindowIncrementalEnabled
};

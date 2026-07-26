// Streaming, batched reader for export jobs.
//
// The worker calls buildExportBatchQuery() to fetch one keyset page of base rows, then
// enrichExportBatch() to attach one-to-many data (tags, classifications) and the
// analyst source timestamps — all via a fixed number of batch queries per page, never
// per-IOC. Nothing loads the full result set into memory.

import {
  CANONICAL_FIRST_SEEN_AGG_SQL,
  CANONICAL_LAST_CHANGED_AGG_SQL,
  resolvePlatformImportTimestamp,
  resolveSourceChangeTimestamps
} from '../iocListTimestamps.js';

// Build one keyset batch of base rows.
//   whereSql/dslParams : compiled DSL predicate (references alias i)
//   cutoff             : snapshot_cutoff timestamp (stable export boundary)
//   cursor             : { t, id } from the previous batch's last row, or null
//   batchSize          : max rows to return
export function buildExportBatchQuery({ whereSql, dslParams, cutoff, cursor, batchSize }) {
  const params = [...dslParams];
  params.push(cutoff);
  const cutoffIdx = params.length;

  let keyset = '';
  if (cursor) {
    params.push(cursor.t);
    params.push(String(cursor.id));
    keyset = ` AND (i.created_at, i.id) < ($${params.length - 1}::timestamptz, $${params.length}::bigint)`;
  }

  params.push(batchSize);
  const limitIdx = params.length;

  const sql = `
    SELECT i.id, i.observable, i.observable_type,
           COALESCE(i.status, 'active') AS status,
           i.source_name, i.confidence,
           i.first_seen_at, i.created_at,
           ta.name AS threat_actor_name
    FROM ioc_items i
    LEFT JOIN threat_actors ta ON ta.id = i.threat_actor_id
    WHERE ${whereSql} AND i.created_at <= $${cutoffIdx}::timestamptz${keyset}
    ORDER BY i.created_at DESC, i.id DESC
    LIMIT $${limitIdx}`;

  return { sql, params };
}

// Attach tags, classifications and analyst source timestamps to a batch of base rows.
// ioc_id in ioc_tags / ioc_threat_classifications / ioc_feed_memberships equals the
// item id, which is globally unique (shared sequence), so a single id array keys each
// batch lookup.
export async function enrichExportBatch(db, baseRows) {
  if (baseRows.length === 0) return [];
  const ids = baseRows.map((r) => Number(r.id));

  const [tagsRes, classRes, tsRes] = await Promise.all([
    db.query(
      `SELECT it.ioc_id, ARRAY_AGG(DISTINCT t.name ORDER BY t.name) AS names
         FROM ioc_tags it JOIN tags t ON t.id = it.tag_id
        WHERE it.ioc_id = ANY($1::bigint[])
        GROUP BY it.ioc_id`,
      [ids]
    ),
    db.query(
      `SELECT itc.ioc_id,
              ARRAY_AGG(DISTINCT COALESCE(tc.name, itc.classification_slug) ORDER BY COALESCE(tc.name, itc.classification_slug)) AS names
         FROM ioc_threat_classifications itc
         LEFT JOIN threat_classifications tc ON tc.slug = itc.classification_slug
        WHERE itc.ioc_id = ANY($1::bigint[])
        GROUP BY itc.ioc_id`,
      [ids]
    ),
    db.query(
      `SELECT m.ioc_item_id,
              ${CANONICAL_FIRST_SEEN_AGG_SQL} AS first_seen_in_source,
              ${CANONICAL_LAST_CHANGED_AGG_SQL} AS last_changed_in_source
         FROM ioc_feed_memberships m
        WHERE m.ioc_item_id = ANY($1::bigint[])
        GROUP BY m.ioc_item_id`,
      [ids]
    )
  ]);

  const tagMap = new Map(tagsRes.rows.map((r) => [Number(r.ioc_id), r.names || []]));
  const classMap = new Map(classRes.rows.map((r) => [Number(r.ioc_id), r.names || []]));
  const tsMap = new Map(
    tsRes.rows.map((r) => [
      Number(r.ioc_item_id),
      { first_seen_in_source: r.first_seen_in_source, last_changed_in_source: r.last_changed_in_source }
    ])
  );

  return baseRows.map((row) => {
    const id = Number(row.id);
    const ts = tsMap.get(id) || {};
    const platform = resolvePlatformImportTimestamp({ item_created_at: row.created_at });
    const source = resolveSourceChangeTimestamps({
      first_seen_in_source: ts.first_seen_in_source,
      last_changed_in_source: ts.last_changed_in_source,
      item_created_at: row.created_at
    });
    return {
      observable: row.observable,
      observable_type: row.observable_type,
      status: row.status,
      source_name: row.source_name,
      confidence: row.confidence,
      threat_actor_name: row.threat_actor_name,
      first_seen_at: row.first_seen_at,
      created_at: platform.created_at,
      imported_at: platform.imported_at,
      tags: tagMap.get(id) || [],
      classifications: classMap.get(id) || [],
      first_seen_in_source: source.first_seen_in_source || row.first_seen_at || row.created_at,
      last_changed_in_source: source.last_changed_in_source
    };
  });
}

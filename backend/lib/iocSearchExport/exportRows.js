// Streaming reader for export jobs.
//
// The worker builds the export query once with buildExportQuery(), opens a server-side
// cursor over it (see exportStream.js), and FETCHes fixed-size pages. Each page is passed
// to enrichExportBatch() to attach one-to-many data (tags, classifications) and the
// analyst source timestamps — all via a fixed number of batch queries per page, never
// per-IOC. Nothing loads the full result set into Node memory.

import {
  CANONICAL_FIRST_SEEN_AGG_SQL,
  CANONICAL_LAST_CHANGED_AGG_SQL,
  resolvePlatformImportTimestamp,
  resolveSourceChangeTimestamps
} from '../iocListTimestamps.js';
import { isFileArtifactsReadEnabled } from '../fileArtifacts/flags.js';

// Build the full export query for the matched set — executed exactly ONCE by
// streamExportToSink through a NO SCROLL server-side cursor, then streamed in FETCH-sized
// pages. This deliberately carries no LIMIT and no keyset predicate:
//
//   * A cursor gives bounded Node memory (one FETCH page at a time) with the SAME output
//     rows and ordering as a full scan, so nothing is materialized in Node.
//   * The previous design re-ran this query once per keyset page. With FILE_ARTIFACTS read
//     enabled the query aggregates the whole matched set (GROUP BY identity_key), so paging
//     re-computed a full parallel hash-join + GroupAggregate + Sort on EVERY batch —
//     O(batches × full_set) work, and each pass allocated a large dynamic-shared-memory
//     segment for the parallel Sort/Hash. On a broad predicate (e.g. `ioc contains ".com"`)
//     that segment exceeds Docker's default 64 MB /dev/shm and Postgres aborts with
//     "could not resize shared memory segment ... No space left on device". Running the
//     query once under a cursor computes the aggregate a single time and (because Postgres
//     does not parallelize cursor-driven execution) avoids the parallel DSM segment entirely.
//
// Deterministic order is preserved exactly:
//   non-FA: ORDER BY i.created_at DESC, i.id DESC
//   FA:     ORDER BY g.platform_imported_at DESC, g.id DESC
//
//   whereSql/dslParams : compiled DSL predicate (references alias i)
//   cutoff             : snapshot_cutoff timestamp (stable export boundary)
export function buildExportQuery({ whereSql, dslParams, cutoff }) {
  const params = [...dslParams];
  params.push(cutoff);
  const cutoffIdx = params.length;

  if (!isFileArtifactsReadEnabled()) {
    const sql = `
    SELECT i.id, i.observable, i.observable_type,
           COALESCE(i.status, 'active') AS status,
           i.source_name, i.confidence,
           i.first_seen_at, i.created_at,
           ta.name AS threat_actor_name
    FROM ioc_items i
    LEFT JOIN threat_actors ta ON ta.id = i.threat_actor_id
    WHERE ${whereSql} AND i.created_at <= $${cutoffIdx}::timestamptz
    ORDER BY i.created_at DESC, i.id DESC`;
    return { sql, params };
  }

  // Canonical identity export (1 artifact = 1 row), ordered by platform_imported_at + representative id.
  const sql = `
    WITH matched AS (
      SELECT i.id, i.public_id, i.observable, i.observable_type,
             COALESCE(i.status, 'active') AS status,
             i.source_name, i.confidence, i.first_seen_at, i.created_at, i.threat_actor_id
      FROM ioc_items i
      WHERE ${whereSql} AND i.created_at <= $${cutoffIdx}::timestamptz
    ),
    ann AS (
      SELECT m.*,
             CASE
               WHEN fa.id IS NULL THEN NULL
               WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL THEN fa.merged_into_artifact_id
               ELSE fa.id
             END AS artifact_id,
             faph.hash_type AS primary_hash_type,
             faph.normalized_hash_value AS primary_hash_value,
             CASE
               WHEN fa.id IS NULL THEN 'o:' || m.observable_type || ':' || LOWER(m.observable)
               WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL
                 THEN 'a:' || fa.merged_into_artifact_id::text
               ELSE 'a:' || fa.id::text
             END AS identity_key
      FROM matched m
      LEFT JOIN file_artifact_ioc_links fal
        ON fal.ioc_item_id = m.id AND fal.ioc_observable_type = m.observable_type
      LEFT JOIN file_artifacts fa ON fa.id = fal.artifact_id
      LEFT JOIN file_artifact_hashes faph
        ON faph.artifact_id = COALESCE(
             CASE WHEN fa.status = 'merged' THEN fa.merged_into_artifact_id ELSE fa.id END,
             fa.id
           )
       AND faph.is_primary = TRUE
    ),
    grouped AS (
      SELECT
        identity_key,
        MIN(created_at) AS platform_imported_at,
        (ARRAY_AGG(id ORDER BY created_at ASC, id ASC))[1]::bigint AS id,
        COALESCE(
          (ARRAY_AGG(primary_hash_value) FILTER (WHERE primary_hash_value IS NOT NULL))[1],
          (ARRAY_AGG(observable ORDER BY created_at ASC, id ASC))[1]
        ) AS observable,
        COALESCE(
          (ARRAY_AGG(primary_hash_type) FILTER (WHERE primary_hash_type IS NOT NULL))[1],
          (ARRAY_AGG(observable_type ORDER BY created_at ASC, id ASC))[1]
        ) AS observable_type,
        (ARRAY_AGG(status ORDER BY created_at DESC))[1] AS status,
        (ARRAY_AGG(source_name ORDER BY created_at ASC, id ASC))[1] AS source_name,
        (ARRAY_AGG(confidence ORDER BY created_at ASC, id ASC))[1] AS confidence,
        MIN(first_seen_at) AS first_seen_at,
        (ARRAY_AGG(threat_actor_id ORDER BY id ASC))[1] AS threat_actor_id,
        (ARRAY_AGG(artifact_id) FILTER (WHERE artifact_id IS NOT NULL))[1] AS artifact_id,
        (ARRAY_AGG(primary_hash_type) FILTER (WHERE primary_hash_type IS NOT NULL))[1] AS primary_hash_type,
        (ARRAY_AGG(primary_hash_value) FILTER (WHERE primary_hash_value IS NOT NULL))[1] AS primary_hash_value,
        ARRAY_AGG(DISTINCT public_id::text) AS linked_ioc_public_ids
      FROM ann
      GROUP BY identity_key
    )
    SELECT g.id, g.observable, g.observable_type, g.status, g.source_name, g.confidence,
           g.first_seen_at, g.platform_imported_at AS created_at,
           ta.name AS threat_actor_name,
           g.artifact_id, g.primary_hash_type, g.primary_hash_value,
           g.linked_ioc_public_ids
    FROM grouped g
    LEFT JOIN threat_actors ta ON ta.id = g.threat_actor_id
    ORDER BY g.platform_imported_at DESC, g.id DESC`;

  return { sql, params };
}

// Attach tags, classifications and analyst source timestamps to a batch of base rows.
// ioc_id in ioc_tags / ioc_threat_classifications / ioc_feed_memberships equals the
// item id, which is globally unique (shared sequence), so a single id array keys each
// batch lookup.
export async function enrichExportBatch(db, baseRows) {
  if (baseRows.length === 0) return [];
  const ids = baseRows.map((r) => Number(r.id));
  const artifactIds = [...new Set(
    baseRows.map((r) => r.artifact_id).filter(Boolean).map(String)
  )];

  const [tagsRes, classRes, actorRes, tsRes, hashesRes] = await Promise.all([
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
      `SELECT ita.ioc_id,
              ARRAY_AGG(DISTINCT ta.name ORDER BY ta.name) AS names
         FROM ioc_threat_actors ita
         JOIN threat_actors ta ON ta.id = ita.threat_actor_id
        WHERE ita.ioc_id = ANY($1::bigint[])
        GROUP BY ita.ioc_id`,
      [ids]
    ).catch((err) => {
      if (String(err?.message || '').includes('ioc_threat_actors')) return { rows: [] };
      throw err;
    }),
    db.query(
      `SELECT m.ioc_item_id,
              ${CANONICAL_FIRST_SEEN_AGG_SQL} AS first_seen_in_source,
              ${CANONICAL_LAST_CHANGED_AGG_SQL} AS last_changed_in_source
         FROM ioc_feed_memberships m
        WHERE m.ioc_item_id = ANY($1::bigint[])
        GROUP BY m.ioc_item_id`,
      [ids]
    ),
    artifactIds.length && isFileArtifactsReadEnabled()
      ? db.query(
        `SELECT artifact_id, hash_type, normalized_hash_value, is_primary
           FROM file_artifact_hashes
          WHERE artifact_id = ANY($1::uuid[])
          ORDER BY artifact_id,
                   CASE hash_type WHEN 'sha256' THEN 0 WHEN 'sha1' THEN 1 WHEN 'md5' THEN 2 ELSE 9 END`,
        [artifactIds]
      )
      : Promise.resolve({ rows: [] })
  ]);

  const tagMap = new Map(tagsRes.rows.map((r) => [Number(r.ioc_id), r.names || []]));
  const classMap = new Map(classRes.rows.map((r) => [Number(r.ioc_id), r.names || []]));
  const actorMap = new Map((actorRes.rows || []).map((r) => [Number(r.ioc_id), r.names || []]));
  const tsMap = new Map(
    tsRes.rows.map((r) => [
      Number(r.ioc_item_id),
      { first_seen_in_source: r.first_seen_in_source, last_changed_in_source: r.last_changed_in_source }
    ])
  );
  const knownByArtifact = new Map();
  for (const r of hashesRes.rows || []) {
    const key = String(r.artifact_id);
    if (!knownByArtifact.has(key)) knownByArtifact.set(key, []);
    knownByArtifact.get(key).push({
      hash_type: r.hash_type,
      value: r.normalized_hash_value,
      is_primary: Boolean(r.is_primary)
    });
  }

  return baseRows.map((row) => {
    const id = Number(row.id);
    const ts = tsMap.get(id) || {};
    const platform = resolvePlatformImportTimestamp({ item_created_at: row.created_at });
    const source = resolveSourceChangeTimestamps({
      first_seen_in_source: ts.first_seen_in_source,
      last_changed_in_source: ts.last_changed_in_source,
      item_created_at: row.created_at
    });
    const artKey = row.artifact_id ? String(row.artifact_id) : null;
    const actorNames = actorMap.get(id);
    const threatActorName = actorNames?.length
      ? actorNames.join(', ')
      : (row.threat_actor_name || null);
    return {
      observable: row.observable,
      observable_type: row.observable_type,
      status: row.status,
      source_name: row.source_name,
      confidence: row.confidence,
      threat_actor_name: threatActorName,
      first_seen_at: row.first_seen_at,
      created_at: platform.created_at,
      imported_at: platform.imported_at,
      tags: tagMap.get(id) || [],
      classifications: classMap.get(id) || [],
      first_seen_in_source: source.first_seen_in_source || row.first_seen_at || row.created_at,
      last_changed_in_source: source.last_changed_in_source,
      artifact_id: row.artifact_id || null,
      primary_hash_type: row.primary_hash_type || null,
      primary_hash_value: row.primary_hash_value || null,
      linked_ioc_public_ids: row.linked_ioc_public_ids || null,
      known_hashes: artKey ? (knownByArtifact.get(artKey) || []) : []
    };
  });
}

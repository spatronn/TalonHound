/**
 * SQL fragments + JS helpers for canonical IOC list identity.
 * When FILE_ARTIFACTS_READ_ENABLED: group by resolved file artifact (else legacy type+value).
 * Platform import timestamp for an artifact row = MIN(created_at) across linked IOCs.
 */

import { isFileArtifactsReadEnabled } from './flags.js';

/** Hash type rank for canonical representative (lower = preferred). */
export function hashTypeRankSql(expr = 'observable_type') {
  return `CASE LOWER(${expr})
    WHEN 'sha256' THEN 0
    WHEN 'sha1' THEN 1
    WHEN 'md5' THEN 2
    ELSE 9
  END`;
}

/**
 * LEFT JOIN chain from ioc_items alias `i` → resolved artifact_id + primary hash.
 * Safe when file_artifact tables missing only if caller does not use when flag off.
 *
 * @param {string} itemAlias
 */
export function artifactAnnotateJoinSql(itemAlias = 'i') {
  return `
    LEFT JOIN file_artifact_ioc_links fal
      ON fal.ioc_item_id = ${itemAlias}.id
     AND fal.ioc_observable_type = ${itemAlias}.observable_type
    LEFT JOIN file_artifacts fa
      ON fa.id = fal.artifact_id
    LEFT JOIN file_artifact_hashes faph
      ON faph.artifact_id = COALESCE(fa.merged_into_artifact_id, fa.id)
     AND faph.is_primary = TRUE
  `;
}

/**
 * Expression: resolved active/merged-follow artifact UUID or NULL.
 * @param {string} [_itemAlias]
 */
export function resolvedArtifactIdSql(_itemAlias = 'i') {
  return `CASE
    WHEN fa.id IS NULL THEN NULL
    WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL THEN fa.merged_into_artifact_id
    ELSE fa.id
  END`;
}

/**
 * identity_key expression given artifact id SQL expr and item alias.
 * @param {{ artifactIdExpr: string, itemAlias?: string, forceLegacy?: boolean }} opts
 */
export function identityKeySql(opts) {
  const alias = opts.itemAlias || 'i';
  if (opts.forceLegacy || !isFileArtifactsReadEnabled()) {
    return `('o:' || ${alias}.observable_type || ':' || LOWER(${alias}.observable))`;
  }
  const art = opts.artifactIdExpr || resolvedArtifactIdSql(alias);
  return `(CASE
    WHEN (${art}) IS NOT NULL THEN 'a:' || (${art})::text
    ELSE 'o:' || ${alias}.observable_type || ':' || LOWER(${alias}.observable)
  END)`;
}

/**
 * Build GROUP BY identity_key SELECT list from an annotated row set alias.
 * Annotated rows must expose: id, public_id, observable, observable_type, source_name,
 * confidence, category, threat_classification, threat_actor_id, note, created_at, status,
 * identity_key, artifact_id, primary_hash_type, primary_hash_value
 *
 * @param {string} fromAlias
 */
export function buildIdentityGroupedSelectSql(fromAlias = 'ann') {
  const rank = hashTypeRankSql(`${fromAlias}.observable_type`);
  return `
        SELECT
          ${fromAlias}.identity_key,
          MIN(${fromAlias}.created_at) AS first_seen_at,
          MAX(${fromAlias}.created_at) AS last_seen_at,
          MIN(${fromAlias}.created_at) AS platform_imported_at,
          (ARRAY_AGG(${fromAlias}.id ORDER BY
            CASE WHEN ${fromAlias}.primary_hash_value IS NOT NULL
              AND LOWER(${fromAlias}.observable) = LOWER(${fromAlias}.primary_hash_value)
              AND LOWER(${fromAlias}.observable_type) = LOWER(${fromAlias}.primary_hash_type)
              THEN 0 ELSE 1 END,
            ${rank},
            ${fromAlias}.created_at ASC,
            ${fromAlias}.id ASC
          ))[1]::int AS id,
          (ARRAY_AGG(${fromAlias}.public_id::text ORDER BY
            CASE WHEN ${fromAlias}.primary_hash_value IS NOT NULL
              AND LOWER(${fromAlias}.observable) = LOWER(${fromAlias}.primary_hash_value)
              AND LOWER(${fromAlias}.observable_type) = LOWER(${fromAlias}.primary_hash_type)
              THEN 0 ELSE 1 END,
            ${rank},
            ${fromAlias}.created_at ASC,
            ${fromAlias}.id ASC
          ))[1] AS public_id,
          COALESCE(
            (ARRAY_AGG(${fromAlias}.primary_hash_value ORDER BY
              CASE WHEN ${fromAlias}.primary_hash_value IS NOT NULL THEN 0 ELSE 1 END,
              ${fromAlias}.id ASC
            ) FILTER (WHERE ${fromAlias}.primary_hash_value IS NOT NULL))[1],
            (ARRAY_AGG(${fromAlias}.observable ORDER BY ${rank}, ${fromAlias}.created_at ASC, ${fromAlias}.id ASC))[1]
          ) AS observable,
          COALESCE(
            (ARRAY_AGG(${fromAlias}.primary_hash_type ORDER BY
              CASE WHEN ${fromAlias}.primary_hash_type IS NOT NULL THEN 0 ELSE 1 END,
              ${fromAlias}.id ASC
            ) FILTER (WHERE ${fromAlias}.primary_hash_type IS NOT NULL))[1],
            (ARRAY_AGG(${fromAlias}.observable_type ORDER BY ${rank}, ${fromAlias}.created_at ASC, ${fromAlias}.id ASC))[1]
          ) AS observable_type,
          (ARRAY_AGG(COALESCE(${fromAlias}.status, 'active') ORDER BY ${fromAlias}.created_at DESC))[1] AS status,
          COUNT(*)::int AS source_count,
          ARRAY_AGG(DISTINCT ${fromAlias}.source_name ORDER BY ${fromAlias}.source_name)
            FILTER (WHERE ${fromAlias}.source_name IS NOT NULL) AS source_names,
          ARRAY_AGG(DISTINCT ${fromAlias}.confidence ORDER BY ${fromAlias}.confidence)
            FILTER (WHERE ${fromAlias}.confidence IS NOT NULL) AS confidence_set,
          ARRAY_AGG(DISTINCT COALESCE(${fromAlias}.category, '') ORDER BY COALESCE(${fromAlias}.category, ''))
            FILTER (WHERE ${fromAlias}.category IS NOT NULL AND ${fromAlias}.category <> '') AS category_set,
          (ARRAY_AGG(${fromAlias}.threat_classification ORDER BY ${fromAlias}.id ASC))[1] AS threat_classification,
          (ARRAY_AGG(${fromAlias}.threat_actor_id ORDER BY ${fromAlias}.id ASC))[1] AS threat_actor_id,
          (ARRAY_AGG(${fromAlias}.artifact_id ORDER BY
            CASE WHEN ${fromAlias}.artifact_id IS NOT NULL THEN 0 ELSE 1 END, ${fromAlias}.id ASC
          ))[1] AS artifact_id
        FROM ${fromAlias}
        GROUP BY ${fromAlias}.identity_key
  `;
}

/**
 * Annotate SELECT list columns for filtered/combined rows (alias `f`).
 * When read flag off, artifact columns are NULL and identity is legacy.
 *
 * @param {string} itemAlias
 */
export function buildAnnotatedSelectSql(itemAlias = 'f') {
  const readOn = isFileArtifactsReadEnabled();
  if (!readOn) {
    return `
        SELECT
          ${itemAlias}.*,
          NULL::uuid AS artifact_id,
          NULL::text AS primary_hash_type,
          NULL::text AS primary_hash_value,
          ('o:' || ${itemAlias}.observable_type || ':' || LOWER(${itemAlias}.observable)) AS identity_key
        FROM ${itemAlias}
    `;
  }
  const art = resolvedArtifactIdSql(itemAlias);
  return `
        SELECT
          ${itemAlias}.*,
          (${art}) AS artifact_id,
          faph.hash_type AS primary_hash_type,
          faph.normalized_hash_value AS primary_hash_value,
          (CASE
            WHEN (${art}) IS NOT NULL THEN 'a:' || (${art})::text
            ELSE 'o:' || ${itemAlias}.observable_type || ':' || LOWER(${itemAlias}.observable)
          END) AS identity_key
        FROM ${itemAlias}
        ${artifactAnnotateJoinSql(itemAlias)}
  `;
}

/**
 * Legacy GROUP BY observable, observable_type (flag off / fallback).
 * @param {string} fromAlias
 */
export function buildLegacyGroupedSelectSql(fromAlias = 'filtered') {
  return `
        SELECT
          MIN(id)::int AS id,
          (ARRAY_AGG(public_id ORDER BY id ASC))[1]::text AS public_id,
          observable,
          observable_type,
          MIN(created_at) AS first_seen_at,
          MAX(created_at) AS last_seen_at,
          MIN(created_at) AS platform_imported_at,
          (ARRAY_AGG(COALESCE(status, 'active') ORDER BY created_at DESC))[1] AS status,
          COUNT(*)::int AS source_count,
          ARRAY_AGG(DISTINCT source_name ORDER BY source_name) AS source_names,
          ARRAY_AGG(DISTINCT confidence ORDER BY confidence) AS confidence_set,
          ARRAY_AGG(DISTINCT COALESCE(category, '') ORDER BY COALESCE(category, ''))
            FILTER (WHERE category IS NOT NULL AND category <> '') AS category_set,
          (ARRAY_AGG(threat_classification ORDER BY id ASC))[1] AS threat_classification,
          (ARRAY_AGG(threat_actor_id ORDER BY id ASC))[1] AS threat_actor_id,
          NULL::uuid AS artifact_id,
          ('o:' || observable_type || ':' || LOWER(observable)) AS identity_key
        FROM ${fromAlias}
        GROUP BY observable, observable_type
  `;
}

/**
 * Build `grouped AS (...)` CTE body for list pipeline.
 */
export function buildGroupedCteBody() {
  if (!isFileArtifactsReadEnabled()) {
    return buildLegacyGroupedSelectSql('filtered');
  }
  return `
        WITH ann AS (
          ${buildAnnotatedSelectSql('filtered')}
        )
        ${buildIdentityGroupedSelectSql('ann')}
  `;
}

/**
 * Active browse page: canonicalize in SQL, then LIMIT/OFFSET on identity rows.
 * Candidate window bounds index walk (perf); pagination correctness does not use JS dedupe.
 *
 * Params: $1 candidateLimit, $2 browseCap, $3 pageLimit, $4 pageOffset
 */
export function buildCanonicalActiveBrowsePageSql() {
  const grouped = buildGroupedCteBody();
  return `
    WITH recent AS (
      SELECT
        id, public_id, observable, observable_type, created_at, status, ioc_source_id,
        source_name, confidence, category, threat_classification, threat_actor_id, note
      FROM ioc_items
      ORDER BY created_at DESC
      LIMIT $1
    ),
    filtered AS (
      SELECT
        r.id, r.public_id, r.observable, r.observable_type, r.created_at, r.status,
        r.source_name, r.confidence, r.category, r.threat_classification, r.threat_actor_id, r.note
      FROM recent r
      WHERE COALESCE(r.status, 'active') = 'active'
        AND (
          r.ioc_source_id IS NOT NULL
          OR EXISTS (
            SELECT 1
              FROM ioc_feed_memberships m
             WHERE m.ioc_item_id = r.id
               AND m.ioc_observable_type = r.observable_type
               AND m.status = 'active'
               AND m.purged_at IS NULL
          )
        )
    ),
    grouped AS (
      ${grouped}
    ),
    capped AS (
      SELECT *
      FROM grouped
      ORDER BY platform_imported_at DESC, identity_key ASC
      LIMIT $2
    )
    SELECT
      id, public_id, observable, observable_type,
      platform_imported_at AS created_at,
      platform_imported_at AS imported_at,
      platform_imported_at AS first_seen_at,
      platform_imported_at AS last_seen_at,
      artifact_id, identity_key, status,
      source_count, source_names, confidence_set, category_set
    FROM capped
    ORDER BY platform_imported_at DESC, identity_key ASC
    LIMIT $3 OFFSET $4
  `;
}

/**
 * JS identity key for browse oversample rows (when SQL annotation not used).
 * @param {{ public_id?: string, observable_type?: string, observable?: string, artifact_id?: string|null }} row
 * @param {Map<string,string>} [artifactByPublicId]
 */
export function identityKeyForRow(row, artifactByPublicId) {
  if (isFileArtifactsReadEnabled() && artifactByPublicId) {
    const art = row.artifact_id || artifactByPublicId.get(String(row.public_id || ''));
    if (art) return `a:${art}`;
  }
  if (isFileArtifactsReadEnabled() && row.artifact_id) {
    return `a:${row.artifact_id}`;
  }
  return `o:${row.observable_type}:${String(row.observable || '').toLowerCase()}`;
}

/**
 * Canonicalize an in-memory list of IOC rows by identity (pre-pagination).
 * Prefer primary-hash row; platform time = min created_at.
 *
 * @param {Array<object>} rows
 * @param {Map<string,string>} artifactByPublicId
 * @param {Map<string,{hash_type:string,normalized_hash_value:string}>} [primaryByArtifact]
 */
export function canonicalizeRowsByIdentity(rows, artifactByPublicId, primaryByArtifact = new Map()) {
  const groups = new Map();
  const rank = (t) => {
    const x = String(t || '').toLowerCase();
    if (x === 'sha256') return 0;
    if (x === 'sha1') return 1;
    if (x === 'md5') return 2;
    return 9;
  };

  for (const row of rows || []) {
    const artId = row.artifact_id || artifactByPublicId?.get(String(row.public_id || '')) || null;
    const key = identityKeyForRow({ ...row, artifact_id: artId }, artifactByPublicId);
    const primary = artId ? primaryByArtifact.get(String(artId)) : null;
    let g = groups.get(key);
    if (!g) {
      g = {
        rows: [],
        artifact_id: artId,
        min_created: row.created_at,
        sources: new Set(),
        conf: new Set(),
        cat: new Set()
      };
      groups.set(key, g);
    }
    g.rows.push(row);
    if (row.created_at && (!g.min_created || row.created_at < g.min_created)) {
      g.min_created = row.created_at;
    }
    if (row.source_name) g.sources.add(row.source_name);
    if (row.confidence) g.conf.add(row.confidence);
    if (row.category) g.cat.add(row.category);
    if (artId) g.artifact_id = artId;
    g.primary = primary || g.primary;
  }

  const out = [];
  for (const [, g] of groups) {
    const sorted = [...g.rows].sort((a, b) => {
      const aPri = g.primary
        && String(a.observable).toLowerCase() === String(g.primary.normalized_hash_value).toLowerCase()
        && String(a.observable_type).toLowerCase() === String(g.primary.hash_type).toLowerCase()
        ? 0 : 1;
      const bPri = g.primary
        && String(b.observable).toLowerCase() === String(g.primary.normalized_hash_value).toLowerCase()
        && String(b.observable_type).toLowerCase() === String(g.primary.hash_type).toLowerCase()
        ? 0 : 1;
      if (aPri !== bPri) return aPri - bPri;
      const dr = rank(a.observable_type) - rank(b.observable_type);
      if (dr !== 0) return dr;
      const ta = a.created_at ? new Date(a.created_at).getTime() : 0;
      const tb = b.created_at ? new Date(b.created_at).getTime() : 0;
      if (ta !== tb) return ta - tb;
      return Number(a.id) - Number(b.id);
    });
    const rep = sorted[0];
    const primaryMatch = g.primary
      ? sorted.find((r) =>
        String(r.observable).toLowerCase() === String(g.primary.normalized_hash_value).toLowerCase()
        && String(r.observable_type).toLowerCase() === String(g.primary.hash_type).toLowerCase()
      )
      : null;
    const observable = g.primary?.normalized_hash_value || rep.observable;
    const observable_type = g.primary?.hash_type || rep.observable_type;
    const public_id = primaryMatch?.public_id
      || g.primary?.canonical_public_id
      || rep.public_id;
    const id = primaryMatch?.id
      || g.primary?.canonical_ioc_id
      || rep.id;
    out.push({
      ...rep,
      id,
      public_id,
      observable,
      observable_type,
      ip: observable,
      created_at: g.min_created || rep.created_at,
      imported_at: g.min_created || rep.created_at,
      first_seen_at: g.min_created || rep.created_at,
      last_seen_at: g.min_created || rep.created_at,
      status: rep.status || 'active',
      source_count: g.sources.size || rep.source_count || 0,
      source_names: g.sources.size ? [...g.sources].sort() : (rep.source_names || []),
      confidence_set: g.conf.size ? [...g.conf].sort() : (rep.confidence_set || []),
      category_set: g.cat.size ? [...g.cat].sort() : (rep.category_set || []),
      artifact_id: g.artifact_id || null,
      identity_key: identityKeyForRow({ ...rep, artifact_id: g.artifact_id }, artifactByPublicId)
    });
  }

  // Stable sort: platform import DESC, identity_key ASC
  out.sort((a, b) => {
    const ta = a.created_at ? new Date(a.created_at).getTime() : 0;
    const tb = b.created_at ? new Date(b.created_at).getTime() : 0;
    if (ta !== tb) return tb - ta;
    return String(a.identity_key || '').localeCompare(String(b.identity_key || ''));
  });
  return out;
}

/**
 * Load artifact map + primary hashes for a set of public_ids.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string[]} publicIds
 */
export async function loadArtifactMapsForPublicIds(db, publicIds) {
  const { mapPublicIdsToArtifactIds } = await import('./read.js');
  const map = await mapPublicIdsToArtifactIds(db, publicIds);
  const artifactIds = [...new Set([...map.values()])];
  const primaryByArtifact = new Map();
  if (artifactIds.length && isFileArtifactsReadEnabled()) {
    const { rows } = await db.query(
      `SELECT h.artifact_id, h.hash_type, h.normalized_hash_value,
              cl.ioc_public_id AS canonical_public_id,
              cl.ioc_item_id AS canonical_ioc_id
       FROM file_artifact_hashes h
       LEFT JOIN LATERAL (
         SELECT l.ioc_public_id, l.ioc_item_id
         FROM file_artifact_ioc_links l
         WHERE l.artifact_id = h.artifact_id
         ORDER BY l.is_canonical_ioc DESC NULLS LAST,
           CASE l.ioc_observable_type
             WHEN 'sha256' THEN 0 WHEN 'sha1' THEN 1 WHEN 'md5' THEN 2 ELSE 9
           END,
           l.ioc_item_id ASC
         LIMIT 1
       ) cl ON TRUE
       WHERE h.artifact_id = ANY($1::uuid[]) AND h.is_primary = TRUE`,
      [artifactIds]
    );
    for (const r of rows) {
      primaryByArtifact.set(String(r.artifact_id), {
        hash_type: r.hash_type,
        normalized_hash_value: r.normalized_hash_value,
        canonical_public_id: r.canonical_public_id ? String(r.canonical_public_id) : null,
        canonical_ioc_id: r.canonical_ioc_id != null ? Number(r.canonical_ioc_id) : null
      });
    }
  }
  return { artifactByPublicId: map, primaryByArtifact };
}

/**
 * Threat Actor → IOC discovery (read-only).
 *
 * Mirrors malware family discovery semantics with the threat-actor canonical
 * association sources:
 *   - analyst: ioc_threat_actors rows for the actor (analyst-managed)
 *   - source:  ioc_source_attributions linked to the actor (entity_kind =
 *              'threat_actor', entity_id), current assertions by default;
 *              active analyst suppressions honored
 *
 * IOC identity grain = (observable_type, observable). Deduplication, filtering,
 * sorting and paging run in SQL from actor indexes (never a full ioc_items scan).
 */

import { normalizeTagSlug } from '../tagHelpers.js';
import {
  DISCOVERY_DEFAULT_LIMIT,
  DISCOVERY_EVIDENCE_PER_IOC,
  DISCOVERY_MAX_OFFSET,
  attributionOrigin,
  loadRepresentativeRows,
  parseDiscoveryOptions,
  relationshipScopesOf,
  scopeFlagsSql,
  scopeHavingSql
} from '../malwareFamilies/iocDiscovery.js';

const DIRECT_KINDS = ['directly_attributed_to'];

/**
 * Resolve a catalog actor by UUID, or exact name / slug / alias (inactive
 * included so historical associations stay discoverable). Never fuzzy.
 */
export async function resolveActorReference(client, { id = null, name = null } = {}) {
  const idText = String(id || '').trim();
  if (idText) {
    if (!/^[0-9a-f-]{36}$/i.test(idText)) {
      return { ok: false, code: 'INVALID_ID', error: 'threat_actor_id must be a UUID' };
    }
    const { rows } = await client.query(
      `SELECT id, name, slug, aliases, description, active, catalog_sources
       FROM threat_actors WHERE id = $1::uuid`,
      [idText]
    );
    if (!rows[0]) return { ok: false, code: 'NOT_FOUND', error: 'Threat actor not found' };
    return { ok: true, actor: rows[0], matched_by: 'id' };
  }

  const key = String(name || '').trim().toLowerCase();
  if (!key) {
    return { ok: false, code: 'MISSING_REFERENCE', error: 'threat_actor_id or threat_actor name is required' };
  }
  const slug = normalizeTagSlug(key) || '';
  const { rows } = await client.query(
    `SELECT id, name, slug, aliases, description, active, catalog_sources
     FROM threat_actors
     WHERE lower(name) = $1
        OR slug = $2
        OR EXISTS (SELECT 1 FROM unnest(COALESCE(aliases, '{}'::text[])) a WHERE lower(a) = $1)
     LIMIT 10`,
    [key, slug]
  );
  if (rows.length === 1) {
    const matchedBy = String(rows[0].name || '').toLowerCase() === key
      ? 'name'
      : (rows[0].slug === slug ? 'slug' : 'alias');
    return { ok: true, actor: rows[0], matched_by: matchedBy };
  }
  if (rows.length > 1) {
    return {
      ok: false,
      code: 'AMBIGUOUS',
      error: `"${name}" matches more than one threat actor; use threat_actor_id`,
      candidates: rows.map((row) => ({ id: row.id, name: row.name }))
    };
  }
  return { ok: false, code: 'NOT_FOUND', error: `No catalog threat actor named "${name}"`, label_key: key };
}

/**
 * Link CTE: one row per association (analyst link or source assertion).
 * Params: $1 actor uuid|null, $2 unused (label reserved), $3 include analyst,
 * $4 include source, $5 lifecycle, $6 association filter.
 */
function linksCteSql() {
  return `
  links AS (
    SELECT ita.ioc_id, ita.ioc_observable_type, 'analyst'::text AS origin,
           NULL::text AS feed_key, NULL::text AS source_name, NULL::text AS evidence_ref_type,
           NULL::text AS evidence_ref_id, NULL::text AS evidence_title, NULL::text AS evidence_url,
           NULL::text AS association_kind, NULL::text AS source_label,
           NULL::text AS assertion_status, ita.created_at AS linked_at
    FROM ioc_threat_actors ita
    WHERE $1::uuid IS NOT NULL
      AND $3::boolean
      AND $5::text = 'current'
      AND ita.threat_actor_id = $1::uuid
    UNION ALL
    SELECT a.ioc_id, a.ioc_observable_type, 'source'::text AS origin,
           a.feed_key, a.source_name, a.evidence_ref_type,
           a.evidence_ref_id, a.evidence_title, a.evidence_url,
           a.association_kind, a.source_label,
           a.assertion_status, a.last_ingested_at AS linked_at
    FROM ioc_source_attributions a
    WHERE a.entity_kind = 'threat_actor'
      AND $4::boolean
      AND (
        ($1::uuid IS NOT NULL AND a.entity_id = $1::uuid)
        OR ($1::uuid IS NULL AND $2::text IS NOT NULL AND a.source_label_normalized = $2::text)
      )
      AND (
        ($5::text = 'current' AND a.assertion_status = 'current')
        OR ($5::text = 'historical' AND a.assertion_status <> 'current')
      )
      AND (
        $6::text = 'all'
        OR ($6::text = 'pulse_context' AND a.association_kind = 'associated_via_source_pulse')
        OR ($6::text = 'direct' AND a.association_kind = ANY('{${DIRECT_KINDS.join(',')}}'::text[]))
      )
      AND NOT (
        a.assertion_status = 'current'
        AND EXISTS (
          SELECT 1 FROM ioc_attribution_overrides o
          WHERE o.cleared_at IS NULL
            AND o.action = 'suppress'
            AND o.ioc_id = a.ioc_id
            AND o.ioc_observable_type = a.ioc_observable_type
            AND o.entity_kind = a.entity_kind
            AND (o.feed_key IS NULL OR o.feed_key = a.feed_key)
            AND (o.evidence_ref_type IS NULL OR o.evidence_ref_type = a.evidence_ref_type)
            AND (o.evidence_ref_id IS NULL OR o.evidence_ref_id = a.evidence_ref_id)
            AND (
              (o.entity_id IS NOT NULL AND o.entity_id = a.entity_id)
              OR (o.source_label_normalized IS NOT NULL AND o.source_label_normalized = a.source_label_normalized)
            )
        )
      )
  )`;
}

function baseParams(target, opts) {
  const includeAnalyst = Boolean(target.actorId) && opts.origin !== 'source' && opts.association === 'all';
  const includeSource = opts.origin !== 'analyst';
  return [
    target.actorId || null,
    null,
    includeAnalyst,
    includeSource,
    opts.lifecycle,
    opts.association
  ];
}

export async function queryDiscoveryPage(client, target, opts) {
  const params = baseParams(target, opts);
  params.push(opts.observableTypes.length ? opts.observableTypes : null); // $7
  params.push(opts.status); // $8
  params.push(opts.q ? `%${opts.q.replace(/([%_\\])/g, '\\$1')}%` : null); // $9
  params.push(opts.limit); // $10
  params.push(opts.offset); // $11
  params.push(opts.scope || 'all'); // $12
  const orderBy = opts.sort === 'value'
    ? 'g.observable_type ASC, g.observable ASC'
    : 'g.last_seen_at DESC NULLS LAST, g.observable_type ASC, g.observable ASC';
  const { rows } = await client.query(
    `WITH ${linksCteSql()},
     grouped AS (
       SELECT i.observable_type, i.observable,
              (array_agg(i.id ORDER BY (l.origin = 'analyst') DESC, i.id ASC))[1] AS rep_id,
              bool_or(l.origin = 'analyst') AS has_analyst,
              bool_or(l.origin = 'source') AS has_source,
              ${scopeFlagsSql(DIRECT_KINDS)},
              COUNT(*) FILTER (WHERE l.origin = 'source')::int AS source_assertions,
              COUNT(DISTINCT (l.feed_key, l.evidence_ref_id)) FILTER (WHERE l.origin = 'source')::int AS source_references,
              array_remove(array_agg(DISTINCT l.association_kind), NULL) AS association_kinds,
              array_remove(array_agg(DISTINCT l.source_label), NULL) AS reported_labels,
              array_remove(array_agg(DISTINCT l.source_name), NULL) AS source_names,
              MAX(i.last_seen_at) AS last_seen_at
       FROM links l
       JOIN ioc_items i ON i.id = l.ioc_id AND i.observable_type = l.ioc_observable_type
       WHERE ($7::text[] IS NULL OR i.observable_type = ANY($7::text[]))
         AND ($9::text IS NULL OR i.observable ILIKE $9::text ESCAPE '\\')
       GROUP BY i.observable_type, i.observable
       HAVING ($8::text = 'all' OR bool_or(COALESCE(i.status, 'active') = $8::text))
          AND ${scopeHavingSql('$12', DIRECT_KINDS)}
     )
     SELECT g.*, COUNT(*) OVER()::int AS total_unique
     FROM grouped g
     ORDER BY ${orderBy}
     LIMIT $10 OFFSET $11`,
    params
  );
  return {
    rows,
    total: rows.length ? Number(rows[0].total_unique) : (opts.offset > 0 ? null : 0)
  };
}

export async function queryDiscoverySummary(client, target, { lifecycle = 'current' } = {}) {
  const params = baseParams(target, { origin: 'all', lifecycle, association: 'all' });
  const { rows } = await client.query(
    `WITH ${linksCteSql()},
     grouped AS (
       SELECT i.observable_type, i.observable,
              bool_or(l.origin = 'analyst') AS has_analyst,
              bool_or(l.origin = 'source') AS has_source,
              bool_or(l.association_kind = 'associated_via_source_pulse') AS has_pulse_context,
              bool_or(l.association_kind = ANY('{${DIRECT_KINDS.join(',')}}'::text[])) AS has_direct
       FROM links l
       JOIN ioc_items i ON i.id = l.ioc_id AND i.observable_type = l.ioc_observable_type
       GROUP BY i.observable_type, i.observable
     ),
     by_type AS (
       SELECT observable_type, COUNT(*)::int AS n FROM grouped GROUP BY observable_type
     )
     SELECT
       (SELECT COUNT(*)::int FROM grouped) AS all_unique,
       (SELECT COUNT(*)::int FROM grouped WHERE has_analyst) AS analyst_unique,
       (SELECT COUNT(*)::int FROM grouped WHERE has_source) AS source_unique,
       (SELECT COUNT(*)::int FROM grouped WHERE has_analyst AND has_source) AS both_unique,
       (SELECT COUNT(*)::int FROM grouped WHERE has_pulse_context) AS pulse_context_unique,
       (SELECT COUNT(*)::int FROM grouped WHERE has_direct) AS direct_unique,
       (SELECT COUNT(*)::int FROM links WHERE origin = 'source') AS source_assertions,
       (SELECT COUNT(DISTINCT (feed_key, evidence_ref_id))::int FROM links WHERE origin = 'source') AS source_references,
       (SELECT COUNT(DISTINCT evidence_ref_id)::int FROM links WHERE origin = 'source' AND evidence_ref_type = 'otx_pulse') AS otx_pulses,
       (SELECT COALESCE(json_object_agg(observable_type, n ORDER BY observable_type), '{}'::json) FROM by_type) AS by_type`,
    params
  );
  const r = rows[0] || {};
  return {
    lifecycle,
    all_unique: r.all_unique || 0,
    analyst_unique: r.analyst_unique || 0,
    source_unique: r.source_unique || 0,
    both_unique: r.both_unique || 0,
    pulse_context_unique: r.pulse_context_unique || 0,
    direct_unique: r.direct_unique || 0,
    // Relationship scopes over unique IOC identities. They overlap, so
    // all >= each scope and, in general, all != direct + context + analyst.
    scopes: {
      all: r.all_unique || 0,
      direct: r.direct_unique || 0,
      context: r.pulse_context_unique || 0,
      analyst: r.analyst_unique || 0
    },
    source_assertions: r.source_assertions || 0,
    source_references: r.source_references || 0,
    otx_pulses: r.otx_pulses || 0,
    by_type: r.by_type || {}
  };
}

export async function queryDiscoveryEvidence(client, target, opts, identities, { perIoc = DISCOVERY_EVIDENCE_PER_IOC } = {}) {
  if (!identities.length || opts.origin === 'analyst') return new Map();
  const params = baseParams(target, opts);
  params.push(identities.map((x) => x.observable_type)); // $7
  params.push(identities.map((x) => x.observable)); // $8
  params.push(perIoc); // $9
  const { rows } = await client.query(
    `WITH ${linksCteSql()},
     page AS (
       SELECT * FROM unnest($7::text[], $8::text[]) AS p(observable_type, observable)
     ),
     ranked AS (
       SELECT i.observable_type, i.observable, l.source_name, l.feed_key, l.evidence_ref_type,
              l.evidence_ref_id, l.evidence_title, l.evidence_url, l.association_kind,
              l.source_label, l.assertion_status, l.linked_at,
              ROW_NUMBER() OVER (
                PARTITION BY i.observable_type, i.observable
                ORDER BY (l.association_kind = ANY('{${DIRECT_KINDS.join(',')}}'::text[])) DESC,
                         l.linked_at DESC NULLS LAST, l.evidence_ref_id
              ) AS rn
       FROM links l
       JOIN ioc_items i ON i.id = l.ioc_id AND i.observable_type = l.ioc_observable_type
       JOIN page p ON p.observable_type = i.observable_type AND p.observable = i.observable
       WHERE l.origin = 'source'
     )
     SELECT * FROM ranked WHERE rn <= $9::int`,
    params
  );
  const map = new Map();
  for (const row of rows) {
    const key = `${row.observable_type}|${row.observable}`;
    if (!map.has(key)) map.set(key, []);
    map.get(key).push({
      source_name: row.source_name,
      feed_key: row.feed_key,
      evidence_ref_type: row.evidence_ref_type,
      evidence_ref_id: row.evidence_ref_id,
      evidence_title: row.evidence_title || null,
      evidence_url: row.evidence_url || null,
      association_kind: row.association_kind,
      reported_label: row.source_label,
      assertion_status: row.assertion_status
    });
  }
  return map;
}

/**
 * Associated IOC counts for a page of catalog actors (one grouped query, no
 * N+1): unique current IOC identities = analyst ∪ non-suppressed current source.
 */
export async function countAssociatedIocsForActors(client, actorIds) {
  const ids = [...new Set((actorIds || []).map(String).filter((x) => /^[0-9a-f-]{36}$/i.test(x)))];
  if (!ids.length) return new Map();
  const { rows } = await client.query(
    `WITH links AS (
       SELECT ita.threat_actor_id AS actor_id, ita.ioc_id, ita.ioc_observable_type, 'analyst'::text AS origin,
              NULL::text AS association_kind
       FROM ioc_threat_actors ita
       WHERE ita.threat_actor_id = ANY($1::uuid[])
       UNION ALL
       SELECT a.entity_id, a.ioc_id, a.ioc_observable_type, 'source'::text, a.association_kind
       FROM ioc_source_attributions a
       WHERE a.entity_kind = 'threat_actor'
         AND a.entity_id = ANY($1::uuid[])
         AND a.assertion_status = 'current'
         AND NOT EXISTS (
           SELECT 1 FROM ioc_attribution_overrides o
           WHERE o.cleared_at IS NULL AND o.action = 'suppress'
             AND o.ioc_id = a.ioc_id AND o.ioc_observable_type = a.ioc_observable_type
             AND o.entity_kind = a.entity_kind
             AND (o.feed_key IS NULL OR o.feed_key = a.feed_key)
             AND (o.evidence_ref_type IS NULL OR o.evidence_ref_type = a.evidence_ref_type)
             AND (o.evidence_ref_id IS NULL OR o.evidence_ref_id = a.evidence_ref_id)
             AND ((o.entity_id IS NOT NULL AND o.entity_id = a.entity_id)
               OR (o.source_label_normalized IS NOT NULL AND o.source_label_normalized = a.source_label_normalized))
         )
     ),
     grouped AS (
       SELECT l.actor_id, i.observable_type, i.observable,
              bool_or(l.origin = 'analyst') AS has_analyst,
              bool_or(l.origin = 'source') AS has_source,
              ${scopeFlagsSql(DIRECT_KINDS)}
       FROM links l
       JOIN ioc_items i ON i.id = l.ioc_id AND i.observable_type = l.ioc_observable_type
       GROUP BY l.actor_id, i.observable_type, i.observable
     )
     SELECT actor_id::text AS actor_id,
            COUNT(*)::int AS all_unique,
            COUNT(*) FILTER (WHERE has_analyst)::int AS analyst_unique,
            COUNT(*) FILTER (WHERE has_source)::int AS source_unique,
            COUNT(*) FILTER (WHERE has_direct)::int AS direct_unique,
            COUNT(*) FILTER (WHERE has_context)::int AS context_unique
     FROM grouped
     GROUP BY actor_id`,
    [ids]
  );
  return new Map(rows.map((r) => [r.actor_id, {
    all_unique: r.all_unique,
    analyst_unique: r.analyst_unique,
    source_unique: r.source_unique,
    direct_unique: r.direct_unique,
    context_unique: r.context_unique
  }]));
}

export async function discoverIocs(client, target, rawOptions = {}, { includeSummary = true, mapRows = null } = {}) {
  const opts = parseDiscoveryOptions(rawOptions);
  const [page, summary] = await Promise.all([
    queryDiscoveryPage(client, target, opts),
    includeSummary ? queryDiscoverySummary(client, target, { lifecycle: opts.lifecycle }) : Promise.resolve(null)
  ]);
  const [repById, evidence] = await Promise.all([
    loadRepresentativeRows(client, page.rows),
    queryDiscoveryEvidence(client, target, opts, page.rows)
  ]);
  const reps = page.rows.map((r) => repById.get(Number(r.rep_id))).filter(Boolean);
  const mapped = typeof mapRows === 'function' ? await mapRows(reps) : null;
  const mappedById = new Map((mapped || []).map((m) => [Number(m.id), m]));

  const items = page.rows.map((r) => {
    const rep = repById.get(Number(r.rep_id)) || {};
    const key = `${r.observable_type}|${r.observable}`;
    return {
      ioc: mappedById.get(Number(r.rep_id)) || null,
      id: Number(r.rep_id),
      public_id: rep.public_id || null,
      value: r.observable,
      type: r.observable_type,
      status: rep.status || null,
      confidence: rep.analyst_confidence_override || rep.confidence || null,
      last_seen_at: r.last_seen_at || null,
      attribution: attributionOrigin(r),
      relationship_scopes: relationshipScopesOf(r),
      association_kinds: r.association_kinds || [],
      reported_labels: r.reported_labels || [],
      source_names: r.source_names || [],
      source_assertions: r.source_assertions,
      source_references: r.source_references,
      evidence: evidence.get(key) || []
    };
  });

  return {
    options: opts,
    summary,
    items,
    pagination: {
      limit: opts.limit,
      offset: opts.offset,
      total: page.total,
      has_more: page.total != null ? opts.offset + items.length < page.total : false,
      next_offset: page.total != null && opts.offset + items.length < page.total ? opts.offset + opts.limit : null
    }
  };
}

export function serializeActorIdentity(actor) {
  if (!actor) return null;
  return {
    id: actor.id,
    name: actor.name,
    slug: actor.slug || null,
    aliases: actor.aliases || [],
    description: actor.description || null,
    active: actor.active !== false,
    catalog_sources: actor.catalog_sources || []
  };
}

export { DISCOVERY_DEFAULT_LIMIT, parseDiscoveryOptions };

/** Shared helpers for active vs historical IOC feed memberships and list status filters. */

export const ACTIVE_MEMBERSHIP_SQL = "m.status = 'active' AND m.purged_at IS NULL";

export function isActiveFeedMembership(m) {
  if (!m) return false;
  if (m.purged_at) return false;
  return String(m.status || 'active') === 'active';
}

export function isHistoricalFeedMembership(m) {
  if (!m) return false;
  if (m.purged_at || String(m.status || '').toLowerCase() === 'purged') return true;
  const status = String(m.status || '').toLowerCase();
  return status === 'expired' || status === 'removed';
}

/** @param {object|null|undefined} m */
export function membershipDisplayStatus(m) {
  if (!m) return 'active';
  if (m.purged_at || String(m.status || '').toLowerCase() === 'purged') return 'purged';
  return String(m.status || 'active').toLowerCase();
}

/** @param {object} m */
export function formatFeedMembershipSource(m) {
  const displayStatus = membershipDisplayStatus(m);
  const historical = !isActiveFeedMembership(m);
  return {
    id: `feed:${m.id}`,
    source_type: 'feed',
    membership_id: Number(m.id),
    name: m.feed_name || m.feed_key || 'Unknown feed',
    feed_key: m.feed_key || null,
    feed_name: m.feed_name || null,
    status: displayStatus,
    first_seen_at: m.first_seen_in_feed || null,
    last_seen_at: m.last_seen_in_feed || null,
    policy_expires_at: m.policy_expires_at || null,
    expires_at: m.expires_at || null,
    override_enabled: Boolean(m.override_enabled),
    purged_at: m.purged_at || null,
    purge_reason: m.purge_reason || null,
    actions_enabled: !historical && isActiveFeedMembership(m)
  };
}

/** @param {object} row */
export function formatManualIocSource(row) {
  const sourceName = row.source_name || row.name || 'Manual source';
  return {
    id: `manual:${row.ioc_source_id || row.ioc_item_id}`,
    source_type: 'manual',
    ioc_item_id: row.ioc_item_id != null ? Number(row.ioc_item_id) : null,
    ioc_source_id: row.ioc_source_id != null ? Number(row.ioc_source_id) : null,
    name: sourceName,
    feed_key: null,
    feed_name: null,
    status: 'active',
    first_seen_at: row.created_at || null,
    last_seen_at: row.last_seen_at || row.created_at || null,
    policy_expires_at: null,
    expires_at: row.expires_at || null,
    override_enabled: false,
    purged_at: null,
    purge_reason: null,
    actions_enabled: false
  };
}

/**
 * @param {string|undefined|null} raw
 * @returns {'active'|'expired'|'suppressed'|'disabled'|'all'}
 */
export function parseIocListStatusFilter(raw) {
  const v = String(raw ?? 'active').trim().toLowerCase();
  if (v === 'all' || v === 'historical') return 'all';
  if (v === 'expired') return 'expired';
  if (v === 'suppressed') return 'suppressed';
  if (v === 'disabled') return 'disabled';
  return 'active';
}

/**
 * @param {'active'|'expired'|'suppressed'|'disabled'|'all'} mode
 * @param {string} [alias]
 * @returns {string|null}
 */
export function iocStatusSqlClause(mode, alias = null) {
  if (mode === 'all') return null;
  const col = alias ? `${alias}.status` : 'status';
  if (mode === 'active') return `COALESCE(${col}, 'active') = 'active'`;
  if (mode === 'expired') return `COALESCE(${col}, 'active') = 'expired'`;
  if (mode === 'suppressed') return `COALESCE(${col}, 'active') = 'suppressed'`;
  if (mode === 'disabled') return `COALESCE(${col}, 'active') = 'disabled'`;
  return `COALESCE(${col}, 'active') = 'active'`;
}

function observableKey(observableType, observable) {
  return `${String(observableType || '').trim()}|${String(observable || '').trim()}`;
}

/**
 * @param {import('pg').Pool} pool
 * @param {Array<{ observable: string, observable_type: string }>} items
 */
export async function enrichItemsWithActiveSourceCounts(pool, items = []) {
  const keyed = (items || []).filter((x) => x?.observable && x?.observable_type);
  if (!keyed.length) return items;

  const observables = [...new Set(keyed.map((x) => String(x.observable)))];
  const types = [...new Set(keyed.map((x) => String(x.observable_type)))];

  const { rows: membershipRows } = await pool.query(
    `SELECT i.observable, i.observable_type, m.status, m.purged_at,
            f.name AS feed_name, f.key AS feed_key
     FROM ioc_feed_memberships m
     JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
     JOIN integration_feeds f ON f.integration_id = m.feed_id
     WHERE i.observable = ANY($1::text[])
       AND i.observable_type = ANY($2::text[])`,
    [observables, types]
  );

  const { rows: manualRows } = await pool.query(
    `SELECT observable, observable_type, source_name, ioc_source_id
     FROM ioc_items
     WHERE observable = ANY($1::text[])
       AND observable_type = ANY($2::text[])
       AND COALESCE(status, 'active') = 'active'
       AND ioc_source_id IS NOT NULL`,
    [observables, types]
  );

  const activeByKey = new Map();
  const historicalByKey = new Map();

  for (const row of membershipRows) {
    const k = observableKey(row.observable_type, row.observable);
    if (isActiveFeedMembership(row)) {
      if (!activeByKey.has(k)) activeByKey.set(k, { names: new Set(), feeds: new Set() });
      const bucket = activeByKey.get(k);
      if (row.feed_name) bucket.names.add(row.feed_name);
      if (row.feed_key) bucket.feeds.add(row.feed_key);
    } else if (isHistoricalFeedMembership(row)) {
      if (!historicalByKey.has(k)) historicalByKey.set(k, []);
      historicalByKey.get(k).push({
        feed_name: row.feed_name || row.feed_key || 'Unknown feed',
        status: membershipDisplayStatus(row),
        purge_reason: row.purge_reason || null
      });
    }
  }

  for (const row of manualRows) {
    const k = observableKey(row.observable_type, row.observable);
    if (!activeByKey.has(k)) activeByKey.set(k, { names: new Set(), feeds: new Set() });
    if (row.source_name) activeByKey.get(k).names.add(row.source_name);
  }

  return keyed.map((it) => {
    const k = observableKey(it.observable_type, it.observable);
    const active = activeByKey.get(k) || { names: new Set(), feeds: new Set() };
    const historical = historicalByKey.get(k) || [];
    const activeNames = [...active.names].sort();
    return {
      ...it,
      source_count: activeNames.length,
      source_names: activeNames,
      active_source_count: activeNames.length,
      historical_sources: historical
    };
  });
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ observable: string, observableType: string, iocItemIds?: number[] }} opts
 */
export async function fetchObservableMembershipSummary(pool, { observable, observableType, iocItemIds = [] } = {}) {
  const ids = (iocItemIds || []).filter((id) => Number.isFinite(Number(id)));
  let membershipRows;
  if (ids.length) {
    const { rows } = await pool.query(
      `SELECT m.id, m.ioc_item_id, m.status, m.purged_at, m.purge_reason,
              m.first_seen_in_feed, m.last_seen_in_feed, m.policy_expires_at, m.expires_at,
              m.override_enabled, m.explicit_confidence,
              f.key AS feed_key, f.name AS feed_name, f.default_confidence AS feed_default_confidence
       FROM ioc_feed_memberships m
       JOIN integration_feeds f ON f.integration_id = m.feed_id
       WHERE m.ioc_item_id = ANY($1::bigint[]) AND m.ioc_observable_type = $2
       ORDER BY m.last_seen_in_feed DESC NULLS LAST`,
      [ids, observableType]
    );
    membershipRows = rows;
  } else {
    const { rows } = await pool.query(
      `SELECT m.id, m.ioc_item_id, m.status, m.purged_at, m.purge_reason,
              m.first_seen_in_feed, m.last_seen_in_feed, m.policy_expires_at, m.expires_at,
              m.override_enabled, m.explicit_confidence,
              f.key AS feed_key, f.name AS feed_name, f.default_confidence AS feed_default_confidence
       FROM ioc_feed_memberships m
       JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
       JOIN integration_feeds f ON f.integration_id = m.feed_id
       WHERE i.observable = $1 AND i.observable_type = $2
       ORDER BY m.last_seen_in_feed DESC NULLS LAST`,
      [observable, observableType]
    );
    membershipRows = rows;
  }

  const activeMemberships = membershipRows.filter(isActiveFeedMembership);
  const historicalMemberships = membershipRows.filter(isHistoricalFeedMembership);

  const { rows: manualActive } = await pool.query(
    `SELECT DISTINCT ON (i.ioc_source_id)
            i.id AS ioc_item_id,
            i.ioc_source_id,
            COALESCE(s.name, i.source_name) AS source_name,
            i.created_at,
            i.last_seen_at,
            i.expires_at
     FROM ioc_items i
     LEFT JOIN ioc_sources s ON s.id = i.ioc_source_id
     WHERE i.observable = $1 AND i.observable_type = $2
       AND COALESCE(i.status, 'active') = 'active'
       AND i.ioc_source_id IS NOT NULL
     ORDER BY i.ioc_source_id, i.created_at DESC`,
    [observable, observableType]
  );

  const activeFeedSources = activeMemberships.map((m) => formatFeedMembershipSource(m));
  const activeManualSources = manualActive.map((row) => formatManualIocSource(row));
  const activeSources = [...activeManualSources, ...activeFeedSources];
  const historicalSources = historicalMemberships.map((m) => formatFeedMembershipSource(m));

  const activeSourceNames = [...new Set(activeSources.map((s) => s.name).filter(Boolean))].sort();

  return {
    membershipRows,
    activeMemberships,
    historicalMemberships,
    activeSources,
    historicalSources,
    activeSourceCount: activeSourceNames.length,
    activeSourceNames,
    historicalSourceCount: historicalSources.length
  };
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} observable
 * @param {string} observableType
 */
export async function fetchLookupTombstoneRowsForObservable(db, observable, observableType) {
  const { rows } = await db.query(
    `SELECT DISTINCT lower(observable) AS observable,
            CASE WHEN observable_type = 'hostname' THEN 'domain' ELSE observable_type END AS observable_type,
            source_name
     FROM ioc_items
     WHERE observable = $1
       AND observable_type = $2
       AND source_name IS NOT NULL
       AND source_name <> ''`,
    [observable, observableType]
  );
  return rows;
}

/**
 * SQL predicate: observable has at least one active feed membership or manual IOC source.
 * @param {string} observableExpr
 * @param {string} observableTypeExpr
 */
export function activeObservableHasActiveSourceSql(observableExpr, observableTypeExpr) {
  return `(
    EXISTS (
      SELECT 1
      FROM ioc_feed_memberships m
      INNER JOIN ioc_items ii
        ON ii.id = m.ioc_item_id AND ii.observable_type = m.ioc_observable_type
      INNER JOIN integration_feeds f ON f.integration_id = m.feed_id
      WHERE ii.observable = ${observableExpr}
        AND ii.observable_type = ${observableTypeExpr}
        AND m.status = 'active'
        AND m.purged_at IS NULL
        AND f.archived_at IS NULL
        AND COALESCE(ii.status, 'active') = 'active'
    )
    OR EXISTS (
      SELECT 1
      FROM ioc_items ii
      WHERE ii.observable = ${observableExpr}
        AND ii.observable_type = ${observableTypeExpr}
        AND COALESCE(ii.status, 'active') = 'active'
        AND ii.ioc_source_id IS NOT NULL
    )
  )`;
}

/** @param {Array<object>} items @param {string|undefined|null} statusFilter */
export function applyActiveListScope(items, statusFilter) {
  if (parseIocListStatusFilter(statusFilter) !== 'active') return items;
  return (items || []).filter((it) => Number(it.active_source_count ?? it.source_count ?? 0) > 0);
}

/** Membership-indexed active observables (avoids full ioc_items scan + correlated EXISTS). */
export function activeScopedObservablesSql() {
  return `
    SELECT DISTINCT i.observable, i.observable_type
    FROM ioc_feed_memberships m
    INNER JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
    INNER JOIN integration_feeds f ON f.integration_id = m.feed_id
    WHERE m.status = 'active'
      AND m.purged_at IS NULL
      AND f.archived_at IS NULL
      AND COALESCE(i.status, 'active') = 'active'
    UNION
    SELECT DISTINCT i.observable, i.observable_type
    FROM ioc_items i
    WHERE COALESCE(i.status, 'active') = 'active'
      AND i.ioc_source_id IS NOT NULL`;
}

function statusObservablesCte(mode) {
  if (mode === 'active') {
    return `
      WITH scoped_obs AS (
        ${activeScopedObservablesSql()}
      )`;
  }
  if (mode === 'expired') {
    return `
      WITH scoped_obs AS (
        SELECT DISTINCT observable, observable_type
        FROM ioc_items
        WHERE COALESCE(status, 'active') = 'expired'
      )`;
  }
  if (mode === 'suppressed') {
    return `
      WITH scoped_obs AS (
        SELECT DISTINCT observable, observable_type
        FROM ioc_items
        WHERE COALESCE(status, 'active') = 'suppressed'
      )`;
  }
  if (mode === 'disabled') {
    return `
      WITH scoped_obs AS (
        SELECT DISTINCT observable, observable_type
        FROM ioc_items
        WHERE COALESCE(status, 'active') = 'disabled'
      )`;
  }
  return `
    WITH scoped_obs AS (
      SELECT DISTINCT observable, observable_type
      FROM ioc_items
    )`;
}

async function fetchActiveTopSources(pool, limit = 20) {
  const { rows } = await pool.query(
    `SELECT source_name, SUM(c)::bigint AS count
     FROM (
       SELECT f.name AS source_name,
              COUNT(DISTINCT (i.observable, i.observable_type))::bigint AS c
       FROM ioc_feed_memberships m
       INNER JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
       INNER JOIN integration_feeds f ON f.integration_id = m.feed_id
       WHERE m.status = 'active'
         AND m.purged_at IS NULL
         AND f.archived_at IS NULL
         AND COALESCE(i.status, 'active') = 'active'
       GROUP BY f.name
       UNION ALL
       SELECT COALESCE(s.name, i.source_name) AS source_name,
              COUNT(DISTINCT (i.observable, i.observable_type))::bigint AS c
       FROM ioc_items i
       LEFT JOIN ioc_sources s ON s.id = i.ioc_source_id
       WHERE COALESCE(i.status, 'active') = 'active'
         AND i.ioc_source_id IS NOT NULL
       GROUP BY COALESCE(s.name, i.source_name)
     ) src
     GROUP BY source_name
     ORDER BY count DESC, source_name ASC
     LIMIT $1`,
    [limit]
  );
  return rows;
}

async function fetchItemRowTopSources(pool, statusClause, limit = 20) {
  const { rows } = await pool.query(
    `SELECT source_name, COUNT(DISTINCT (observable, observable_type))::bigint AS count
     FROM ioc_items
     WHERE ${statusClause}
       AND source_name IS NOT NULL
       AND source_name <> ''
     GROUP BY source_name
     ORDER BY count DESC, source_name ASC
     LIMIT $1`,
    [limit]
  );
  return rows;
}

/**
 * Run a query with parallel workers disabled inside a short transaction.
 * SET LOCAL requires a transaction block; without it parallel hash aggregates can exhaust /dev/shm.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} sql
 * @param {unknown[]} [params]
 */
async function queryWithoutParallelWorkers(db, sql, params = []) {
  const client = typeof db.connect === 'function' ? await db.connect() : null;
  const runner = client || db;
  const ownClient = Boolean(client);
  try {
    await runner.query('BEGIN');
    await runner.query('SET LOCAL max_parallel_workers_per_gather = 0');
    await runner.query("SET LOCAL work_mem = '4MB'");
    const result = await runner.query(sql, params);
    await runner.query('COMMIT');
    return result;
  } catch (err) {
    await runner.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    if (ownClient) client.release();
  }
}

/**
 * Cheap watermark for IOC stats cache invalidation (indexed paths only).
 * @param {import('pg').Pool} pool
 */
export async function fetchIocStatsLastUpdate(pool) {
  const { rows } = await pool.query(
    `SELECT MAX(ts) AS last_update
     FROM (
       SELECT MAX(last_seen_in_feed) AS ts
       FROM ioc_feed_memberships
       WHERE status = 'active' AND purged_at IS NULL
       UNION ALL
       SELECT MAX(created_at) AS ts
       FROM ioc_items
       WHERE ioc_source_id IS NOT NULL
     ) u`
  );
  return rows[0]?.last_update || null;
}

/**
 * Paginated active IOC browse without scanning ioc_items parent (LIMIT 2000 CTE).
 * @param {import('pg').Pool} pool
 * @param {{ limit: number, offset: number }} opts
 */
export async function fetchActiveIocListPage(pool, { limit, offset }) {
  const sql = `
    WITH feed_obs AS (
      SELECT i.observable,
             i.observable_type,
             MAX(GREATEST(COALESCE(m.last_seen_in_feed, i.created_at), i.created_at)) AS last_seen_at
      FROM ioc_feed_memberships m
      INNER JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
      INNER JOIN integration_feeds f ON f.integration_id = m.feed_id
      WHERE m.status = 'active'
        AND m.purged_at IS NULL
        AND f.archived_at IS NULL
        AND COALESCE(i.status, 'active') = 'active'
      GROUP BY i.observable, i.observable_type
    ),
    manual_obs AS (
      SELECT i.observable,
             i.observable_type,
             MAX(i.created_at) AS last_seen_at
      FROM ioc_items i
      WHERE COALESCE(i.status, 'active') = 'active'
        AND i.ioc_source_id IS NOT NULL
      GROUP BY i.observable, i.observable_type
    ),
    combined AS (
      SELECT observable, observable_type, last_seen_at FROM feed_obs
      UNION ALL
      SELECT observable, observable_type, last_seen_at FROM manual_obs
    ),
    ranked AS (
      SELECT observable, observable_type, MAX(last_seen_at) AS last_seen_at
      FROM combined
      GROUP BY observable, observable_type
    ),
    page AS (
      SELECT observable, observable_type, last_seen_at
      FROM ranked
      ORDER BY last_seen_at DESC NULLS LAST
      LIMIT $1 OFFSET $2
    )
    SELECT
      i.id,
      i.public_id,
      i.observable,
      i.observable_type,
      i.observable AS ip,
      ts.first_seen_at,
      ts.last_seen_at,
      c.asn,
      c.country_code,
      c.as_name
    FROM page pg
    JOIN LATERAL (
      SELECT MIN(ii.created_at) AS first_seen_at, MAX(ii.created_at) AS last_seen_at
      FROM ioc_items ii
      WHERE ii.observable = pg.observable
        AND ii.observable_type = pg.observable_type
        AND COALESCE(ii.status, 'active') = 'active'
    ) ts ON true
    JOIN LATERAL (
      SELECT ii.id, ii.public_id, ii.observable, ii.observable_type
      FROM ioc_items ii
      WHERE ii.observable = pg.observable
        AND ii.observable_type = pg.observable_type
        AND COALESCE(ii.status, 'active') = 'active'
      ORDER BY ii.created_at DESC
      LIMIT 1
    ) i ON true
    LEFT JOIN ioc_ip_geo_cache c
      ON c.ip = CASE WHEN i.observable_type = 'ip' THEN i.observable::inet ELSE NULL END
    ORDER BY pg.last_seen_at DESC NULLS LAST`;

  const { rows } = await queryWithoutParallelWorkers(pool, sql, [limit, offset]);
  return rows;
}

/**
 * @param {import('pg').Pool} pool
 * @param {string|undefined|null} statusFilter
 */
export async function fetchIocListStats(pool, statusFilter = 'active') {
  const mode = parseIocListStatusFilter(statusFilter);
  const cte = statusObservablesCte(mode);

  const [totalRes, byTypeRes] = await Promise.all([
    queryWithoutParallelWorkers(pool, `${cte} SELECT COUNT(*)::bigint AS count FROM scoped_obs`),
    queryWithoutParallelWorkers(pool, `${cte}
      SELECT observable_type, COUNT(*)::bigint AS count
      FROM scoped_obs
      GROUP BY observable_type
      ORDER BY count DESC`)
  ]);

  let bySource;
  if (mode === 'active') {
    bySource = await queryWithoutParallelWorkers(
      pool,
      `SELECT source_name, SUM(c)::bigint AS count
       FROM (
         SELECT f.name AS source_name,
                COUNT(DISTINCT (i.observable, i.observable_type))::bigint AS c
         FROM ioc_feed_memberships m
         INNER JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
         INNER JOIN integration_feeds f ON f.integration_id = m.feed_id
         WHERE m.status = 'active'
           AND m.purged_at IS NULL
           AND f.archived_at IS NULL
           AND COALESCE(i.status, 'active') = 'active'
         GROUP BY f.name
         UNION ALL
         SELECT COALESCE(s.name, i.source_name) AS source_name,
                COUNT(DISTINCT (i.observable, i.observable_type))::bigint AS c
         FROM ioc_items i
         LEFT JOIN ioc_sources s ON s.id = i.ioc_source_id
         WHERE COALESCE(i.status, 'active') = 'active'
           AND i.ioc_source_id IS NOT NULL
         GROUP BY COALESCE(s.name, i.source_name)
       ) src
       GROUP BY source_name
       ORDER BY count DESC, source_name ASC
       LIMIT $1`,
      [20]
    ).then((res) => res.rows);
  } else if (mode === 'all') {
    bySource = await fetchItemRowTopSources(pool, 'TRUE', 20);
  } else {
    const statusClause = iocStatusSqlClause(mode) || 'TRUE';
    bySource = await fetchItemRowTopSources(pool, statusClause, 20);
  }

  return {
    total: Number(totalRes.rows[0]?.count || 0),
    by_type: byTypeRes.rows,
    by_source: bySource
  };
}

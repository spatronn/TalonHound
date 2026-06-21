/** Shared helpers for active vs historical IOC feed memberships and list status filters. */

export const ACTIVE_MEMBERSHIP_SQL = "m.status = 'active' AND m.purged_at IS NULL";

export function isActiveFeedMembership(m) {
  if (!m) return false;
  if (m.purged_at) return false;
  return String(m.status || 'active') === 'active';
}

export function isHistoricalFeedMembership(m) {
  if (!m) return false;
  const status = String(m.status || '').toLowerCase();
  return status === 'purged' || status === 'expired' || status === 'removed' || Boolean(m.purged_at);
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
        status: row.purged_at ? 'purged' : String(row.status || 'historical')
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
  const activeFeedNames = [...new Set(activeMemberships.map((m) => m.feed_name).filter(Boolean))].sort();

  const { rows: manualActive } = await pool.query(
    `SELECT DISTINCT source_name
     FROM ioc_items
     WHERE observable = $1 AND observable_type = $2
       AND COALESCE(status, 'active') = 'active'
       AND ioc_source_id IS NOT NULL
       AND source_name IS NOT NULL`,
    [observable, observableType]
  );
  const manualNames = manualActive.map((r) => r.source_name).filter(Boolean);
  const activeSourceNames = [...new Set([...activeFeedNames, ...manualNames])].sort();

  return {
    membershipRows,
    activeMemberships,
    historicalMemberships,
    activeSourceCount: activeSourceNames.length,
    activeSourceNames,
    historicalSources: historicalMemberships.map((m) => ({
      feed_name: m.feed_name || m.feed_key || 'Unknown feed',
      status: m.purged_at ? 'purged' : String(m.status || 'historical'),
      purge_reason: m.purge_reason || null
    }))
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

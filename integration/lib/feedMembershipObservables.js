/**
 * Load durable feed membership observables for add-diff imports.
 *
 * CERT.PL / PhishTank are add-only (never remove TalonHound IOCs when the
 * upstream snapshot shrinks). Previously they duplicated the full active
 * identity set as key_hashes inside integration_source_state. Memberships in
 * ioc_feed_memberships are already the source of truth for "has this feed
 * asserted identity Y?", so checkpoint JSON only needs compact metadata.
 */

/**
 * @param {Iterable<{ observable?: string }|string>} entries
 * @param {Set<string>} existingObservables
 * @param {(entry: any) => string} [getObservable]
 * @returns {any[]}
 */
export function selectEntriesMissingMembership(
  entries,
  existingObservables,
  getObservable = (entry) => (typeof entry === 'string' ? entry : entry?.observable)
) {
  const out = [];
  for (const entry of entries || []) {
    const obs = getObservable(entry);
    if (!obs) continue;
    if (!existingObservables?.has(obs)) out.push(entry);
  }
  return out;
}

/**
 * @param {import('pg').PoolClient|import('pg').Pool} db
 * @param {string} feedId
 * @param {string} observableType
 * @returns {Promise<Set<string>>}
 */
export async function loadFeedMembershipObservableSet(db, feedId, observableType) {
  if (!feedId) return new Set();
  const type = String(observableType || '').trim();
  if (!type) return new Set();

  // Partition-friendly joins for the two add-diff feeds. Fall back to parent.
  const sql = type === 'domain'
    ? `SELECT i.observable
       FROM ioc_feed_memberships m
       JOIN ioc_domain i
         ON i.id = m.ioc_item_id
        AND i.observable_type = m.ioc_observable_type
       WHERE m.feed_id = $1::uuid
         AND m.ioc_observable_type = $2`
    : type === 'url'
      ? `SELECT i.observable
         FROM ioc_feed_memberships m
         JOIN ioc_url i
           ON i.id = m.ioc_item_id
          AND i.observable_type = m.ioc_observable_type
         WHERE m.feed_id = $1::uuid
           AND m.ioc_observable_type = $2`
      : `SELECT i.observable
         FROM ioc_feed_memberships m
         JOIN ioc_items i
           ON i.id = m.ioc_item_id
          AND i.observable_type = m.ioc_observable_type
         WHERE m.feed_id = $1::uuid
           AND m.ioc_observable_type = $2`;

  const { rows } = await db.query(sql, [feedId, type]);
  return new Set(rows.map((r) => String(r.observable)));
}

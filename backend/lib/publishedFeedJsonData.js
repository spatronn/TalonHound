// Batched metadata access for JSON Published Feeds.
//
// Given the already-selected feed items, this loads lifecycle timestamps, source
// memberships, tags, and (optionally) enrichment for ALL of them in a bounded number of
// queries per batch — never one query per IOC (no N+1). Callers process items in batches
// so IN-list sizes and memory stay bounded for very large feeds.

/** Items processed per metadata batch (bounds IN-list size + interleaves work). */
export const PUBLISHED_FEED_JSON_BATCH_SIZE = Math.max(
  Number(process.env.PUBLISHED_FEED_JSON_BATCH_SIZE || 500),
  1
);

/** Stable per-observable metadata key: lowercased type|value. */
export function metaKey(type, value) {
  return `${String(type || '').toLowerCase()}|${String(value || '').toLowerCase()}`;
}

function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

function ensureEntry(map, key) {
  let entry = map.get(key);
  if (!entry) {
    entry = {
      imported_at: null,
      first_seen_in_source: null,
      last_confirmed_in_source: null,
      sources: [],
      tags: [],
      enrichment: {}
    };
    map.set(key, entry);
  }
  return entry;
}

async function loadTimestamps(db, lowerValues, types, byKey) {
  const { rows } = await db.query(
    `SELECT lower(i.observable) AS obs, i.observable_type AS otype,
            MIN(i.created_at) AS imported_at,
            MIN(m.first_seen_in_feed) AS first_seen_in_source,
            MAX(m.last_seen_in_feed) AS last_confirmed_in_source
     FROM ioc_items i
     LEFT JOIN ioc_feed_memberships m
       ON m.ioc_item_id = i.id
      AND m.ioc_observable_type = i.observable_type
      AND m.status = 'active'
      AND m.purged_at IS NULL
     WHERE lower(i.observable) = ANY($1::text[])
       AND i.observable_type = ANY($2::text[])
     GROUP BY lower(i.observable), i.observable_type`,
    [lowerValues, types]
  );
  for (const row of rows) {
    const entry = ensureEntry(byKey, metaKey(row.otype, row.obs));
    entry.imported_at = row.imported_at;
    entry.first_seen_in_source = row.first_seen_in_source;
    entry.last_confirmed_in_source = row.last_confirmed_in_source;
  }
}

async function loadSources(db, lowerValues, types, byKey) {
  const feedRes = await db.query(
    `SELECT lower(i.observable) AS obs, i.observable_type AS otype,
            f.key AS feed_key, f.name AS feed_name,
            MIN(m.first_seen_in_feed) AS first_seen_in_source,
            MAX(m.last_seen_in_feed) AS last_confirmed_in_source
     FROM ioc_feed_memberships m
     JOIN ioc_items i ON i.id = m.ioc_item_id AND i.observable_type = m.ioc_observable_type
     JOIN integration_feeds f ON f.integration_id = m.feed_id
     WHERE lower(i.observable) = ANY($1::text[])
       AND i.observable_type = ANY($2::text[])
       AND m.status = 'active'
       AND m.purged_at IS NULL
     GROUP BY lower(i.observable), i.observable_type, f.key, f.name`,
    [lowerValues, types]
  );
  for (const row of feedRes.rows) {
    ensureEntry(byKey, metaKey(row.otype, row.obs)).sources.push({
      feed_key: row.feed_key,
      feed_name: row.feed_name,
      first_seen_in_source: row.first_seen_in_source,
      last_confirmed_in_source: row.last_confirmed_in_source
    });
  }

  // Manual IOC sources are published by name only — the internal ioc_source_id is never
  // exposed in the public contract.
  const manualRes = await db.query(
    `SELECT lower(i.observable) AS obs, i.observable_type AS otype,
            COALESCE(s.name, i.source_name) AS feed_name,
            MIN(i.created_at) AS first_seen_in_source,
            MAX(COALESCE(i.last_seen_at, i.created_at)) AS last_confirmed_in_source
     FROM ioc_items i
     LEFT JOIN ioc_sources s ON s.id = i.ioc_source_id
     WHERE lower(i.observable) = ANY($1::text[])
       AND i.observable_type = ANY($2::text[])
       AND i.ioc_source_id IS NOT NULL
       AND COALESCE(i.status, 'active') = 'active'
     GROUP BY lower(i.observable), i.observable_type, COALESCE(s.name, i.source_name)`,
    [lowerValues, types]
  );
  for (const row of manualRes.rows) {
    ensureEntry(byKey, metaKey(row.otype, row.obs)).sources.push({
      feed_key: null,
      feed_name: row.feed_name,
      first_seen_in_source: row.first_seen_in_source,
      last_confirmed_in_source: row.last_confirmed_in_source
    });
  }
}

async function loadTags(db, lowerValues, types, byKey) {
  const { rows } = await db.query(
    `SELECT lower(i.observable) AS obs, i.observable_type AS otype, tg.name AS tag_name
     FROM ioc_tags it
     JOIN tags tg ON tg.id = it.tag_id
     JOIN ioc_items i ON i.id = it.ioc_id AND i.observable_type = it.ioc_observable_type
     WHERE lower(i.observable) = ANY($1::text[])
       AND i.observable_type = ANY($2::text[])
       AND tg.enabled = TRUE`,
    [lowerValues, types]
  );
  for (const row of rows) {
    if (!row.tag_name) continue;
    ensureEntry(byKey, metaKey(row.otype, row.obs)).tags.push(row.tag_name);
  }
}

function attachEnrichmentByValue(byKey, rows, provider, valueField, itemsByLowerValue) {
  for (const row of rows) {
    const lowerVal = String(row[valueField] || '').toLowerCase();
    const items = itemsByLowerValue.get(lowerVal);
    if (!items) continue;
    for (const it of items) {
      ensureEntry(byKey, metaKey(it.observable_type, it.value)).enrichment[provider] = row;
    }
  }
}

async function loadEnrichment(db, batch, byKey) {
  // Index batch items by lowercased value so provider rows (keyed by their own value
  // column) can be mapped back to every matching item regardless of type.
  const itemsByLowerValue = new Map();
  for (const it of batch) {
    const lv = String(it.value || '').toLowerCase();
    if (!itemsByLowerValue.has(lv)) itemsByLowerValue.set(lv, []);
    itemsByLowerValue.get(lv).push(it);
  }
  const lowerValues = [...itemsByLowerValue.keys()];
  const ipValues = batch.filter((it) => it.observable_type === 'ip').map((it) => it.value);
  const domainLowerValues = batch
    .filter((it) => it.observable_type === 'domain')
    .map((it) => String(it.value).toLowerCase());

  // VirusTotal — any observable type.
  const vt = await db.query(
    `SELECT ioc_value, normalized_summary
     FROM ioc_enrichments
     WHERE provider = 'virustotal' AND status = 'success'
       AND lower(ioc_value) = ANY($1::text[])`,
    [lowerValues]
  );
  attachEnrichmentByValue(byKey, vt.rows, 'virustotal', 'ioc_value', itemsByLowerValue);

  if (ipValues.length) {
    const ipinfo = await db.query(
      `SELECT ip, country, country_code, asn, as_name
       FROM ioc_ip_enrichment
       WHERE ip = ANY($1::text[])`,
      [ipValues]
    );
    attachEnrichmentByValue(byKey, ipinfo.rows, 'ipinfo', 'ip', itemsByLowerValue);

    const abuse = await db.query(
      `SELECT ip, normalized_summary
       FROM ioc_abuseipdb_enrichment
       WHERE ip = ANY($1::text[]) AND provider_status = 'success'`,
      [ipValues]
    );
    attachEnrichmentByValue(byKey, abuse.rows, 'abuseipdb', 'ip', itemsByLowerValue);

    const spamhaus = await db.query(
      `SELECT lookup_ip, listed, list_type, matched_cidr, provider_status
       FROM ioc_spamhaus_drop_enrichment
       WHERE lookup_ip = ANY($1::text[])`,
      [ipValues]
    );
    attachEnrichmentByValue(byKey, spamhaus.rows, 'spamhaus', 'lookup_ip', itemsByLowerValue);
  }

  if (domainLowerValues.length) {
    const rdap = await db.query(
      `SELECT observable_value, registrar, registration_date, expiration_date
       FROM ioc_domain_enrichment
       WHERE lower(observable_value) = ANY($1::text[])`,
      [domainLowerValues]
    );
    attachEnrichmentByValue(byKey, rdap.rows, 'rdap', 'observable_value', itemsByLowerValue);
  }
}

/**
 * Load per-item metadata for the selected feed items in bounded batches.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {Array<{ value: string, observable_type: string }>} items
 * @param {{ includeSourceMetadata?: boolean, includeClassification?: boolean, includeEnrichment?: boolean }} flags
 * @returns {Promise<Map<string, object>>} keyed by metaKey(type, value)
 */
export async function fetchPublishedFeedItemMetadata(db, items, flags = {}) {
  const byKey = new Map();
  if (!items?.length) return byKey;

  for (const batch of chunk(items, PUBLISHED_FEED_JSON_BATCH_SIZE)) {
    const lowerValues = [...new Set(batch.map((it) => String(it.value).toLowerCase()))];
    const types = [...new Set(batch.map((it) => String(it.observable_type)))];

    // Sequential queries: a generation client holds a single connection and cannot run
    // concurrent queries.
    await loadTimestamps(db, lowerValues, types, byKey);
    if (flags.includeSourceMetadata) await loadSources(db, lowerValues, types, byKey);
    if (flags.includeClassification) await loadTags(db, lowerValues, types, byKey);
    if (flags.includeEnrichment) await loadEnrichment(db, batch, byKey);
  }

  return byKey;
}

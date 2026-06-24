import { FEED_SOURCE_RULES } from './iocExpiration.js';
import { CUSTOM_FEED_KEY_PREFIX } from './customThreatFeedUtils.js';
import { resolveIocSourceState } from './iocSourceLifecycle.js';

export const BUILTIN_PUBLISHABLE_FEED_KEYS = new Set(FEED_SOURCE_RULES.map((r) => r.key));

/** Non-IOC integration keys excluded from published feed source picker. */
export const NON_IOC_INTEGRATION_KEYS = new Set(['asn_enrichment']);

export const MANUAL_FEED_KEY_PREFIX = 'manual:';

/** @param {string} key */
export function isCustomFeedKey(key) {
  return String(key || '').trim().startsWith(CUSTOM_FEED_KEY_PREFIX);
}

/** @param {string} key */
export function isManualFeedKey(key) {
  return String(key || '').trim().startsWith(MANUAL_FEED_KEY_PREFIX);
}

/** @param {number|string} sourceId */
export function formatManualFeedKey(sourceId) {
  return `${MANUAL_FEED_KEY_PREFIX}${Number(sourceId)}`;
}

/** @param {string} key */
export function parseManualFeedKey(key) {
  if (!isManualFeedKey(key)) return null;
  const id = Number(String(key).slice(MANUAL_FEED_KEY_PREFIX.length));
  return Number.isFinite(id) && id > 0 ? id : null;
}

/**
 * SQL fragment restricting ioc_items to selected feed sources (built-in + custom + manual).
 * @param {string[]|null|undefined} feedKeys
 * @param {unknown[]} params
 */
export function buildFeedKeySourceSql(feedKeys, params) {
  if (!feedKeys?.length) return '';
  const keys = feedKeys.map((k) => String(k).trim()).filter(Boolean);
  if (!keys.length) return '';

  const parts = [];
  const customKeys = [];
  const manualIds = [];

  for (const key of keys) {
    if (isCustomFeedKey(key)) {
      customKeys.push(key);
      continue;
    }
    if (isManualFeedKey(key)) {
      const sourceId = parseManualFeedKey(key);
      if (sourceId != null) manualIds.push(sourceId);
      continue;
    }
    const rule = FEED_SOURCE_RULES.find((r) => r.key === key);
    if (!rule) continue;
    if (rule.exact) {
      params.push(rule.exact);
      parts.push(`i.source_name = $${params.length}`);
    } else if (rule.prefix) {
      params.push(`${rule.prefix}%`);
      parts.push(`i.source_name LIKE $${params.length}`);
    } else if (rule.includes) {
      for (const fragment of rule.includes) {
        params.push(`%${fragment}%`);
        parts.push(`i.source_name ILIKE $${params.length}`);
      }
    }
  }

  if (customKeys.length) {
    params.push(customKeys);
    parts.push(`EXISTS (
      SELECT 1
      FROM ioc_feed_memberships m
      JOIN integration_feeds f ON f.integration_id = m.feed_id
      WHERE m.ioc_item_id = i.id
        AND m.ioc_observable_type = i.observable_type
        AND f.key = ANY($${params.length}::text[])
        AND COALESCE(m.status, 'active') = 'active'
        AND m.purged_at IS NULL
    )`);
  }

  if (manualIds.length) {
    params.push(manualIds);
    parts.push(`i.ioc_source_id = ANY($${params.length}::bigint[])`);
  }

  if (!parts.length) return '';
  return ` AND (${parts.join(' OR ')}) `;
}

/**
 * @param {import('pg').Pool} pool
 */
export async function loadKnownPublishableFeedKeys(pool) {
  const keys = new Set(BUILTIN_PUBLISHABLE_FEED_KEYS);
  const { rows: integrationRows } = await pool.query(
    `SELECT f.key
     FROM integration_feeds f
     WHERE COALESCE(f.feed_kind, 'built_in') = 'custom'`
  );
  for (const row of integrationRows) {
    if (row?.key) keys.add(String(row.key));
  }

  const { rows: manualRows } = await pool.query(
    `SELECT id FROM ioc_sources WHERE archived_at IS NULL AND active = TRUE`
  );
  for (const row of manualRows) {
    if (row?.id != null) keys.add(formatManualFeedKey(row.id));
  }
  return keys;
}

/**
 * @param {import('pg').Pool} pool
 * @param {unknown} raw
 * @param {{ existingKeys?: string[] }} [opts]
 */
export async function normalizeIncludeFeedKeys(pool, raw, opts = {}) {
  if (raw == null) return { value: [] };
  const arr = Array.isArray(raw) ? raw : [];
  const normalized = arr.map((k) => String(k).trim()).filter(Boolean);
  if (!normalized.length) return { value: [] };

  const known = await loadKnownPublishableFeedKeys(pool);
  const existing = new Set((opts.existingKeys || []).map((k) => String(k).trim()).filter(Boolean));
  const unknown = normalized.filter((k) => !known.has(k) && !existing.has(k));
  const invalid = unknown.filter((k) =>
    !isCustomFeedKey(k)
    && !isManualFeedKey(k)
    && !BUILTIN_PUBLISHABLE_FEED_KEYS.has(k)
  );
  if (invalid.length) {
    return { error: `Unknown feed keys: ${invalid.join(', ')}` };
  }
  return { value: normalized };
}

function serializeManualSourceOption(row, { selectable = true } = {}) {
  const state = resolveIocSourceState(row);
  const active = state === 'active';
  const name = row.name || formatManualFeedKey(row.id);
  return {
    key: formatManualFeedKey(row.id),
    name,
    type: 'manual_source',
    group: 'Manual IOC Sources',
    feed_kind: 'manual',
    enabled: state !== 'archived',
    active,
    selectable: selectable && active,
    state,
    display_name: `${name} (manual)`,
    source_name: name
  };
}

/**
 * Lightweight feed list for Published Feeds source selector.
 * @param {import('pg').Pool} pool
 * @param {{ selectedKeys?: string[] }} [opts]
 */
export async function fetchPublishedFeedSourceOptions(pool, opts = {}) {
  const { rows: integrationRows } = await pool.query(
    `SELECT f.key,
            f.name,
            f.active,
            f.archived_at
     FROM integration_feeds f
     WHERE COALESCE(f.feed_kind, 'built_in') <> 'custom'
       AND f.archived_at IS NULL
     ORDER BY f.active DESC, f.name ASC`
  );

  const { rows: customRows } = await pool.query(
    `SELECT f.key,
            f.name,
            f.active AS integration_active,
            c.deactivated_at
     FROM integration_feeds f
     INNER JOIN custom_threat_feeds c ON c.feed_id = f.integration_id
     WHERE f.feed_kind = 'custom'
       AND f.archived_at IS NULL
     ORDER BY c.deactivated_at NULLS FIRST, f.active DESC, f.name ASC`
  );

  const { rows: manualRows } = await pool.query(
    `SELECT id, name, active, archived_at
     FROM ioc_sources
     WHERE archived_at IS NULL AND active = TRUE
     ORDER BY name ASC`
  );

  /** @type {Array<object>} */
  const sources = [];

  for (const row of integrationRows) {
    if (NON_IOC_INTEGRATION_KEYS.has(row.key)) continue;
    if (!BUILTIN_PUBLISHABLE_FEED_KEYS.has(row.key)) continue;
    const active = row.active !== false;
    sources.push({
      key: row.key,
      name: row.name,
      type: 'integration',
      group: 'Integration Feeds',
      feed_kind: 'built_in',
      enabled: true,
      active,
      selectable: active,
      display_name: row.name,
      source_name: row.name
    });
  }

  for (const row of customRows) {
    const active = row.integration_active !== false && row.deactivated_at == null;
    const name = row.name || row.key;
    sources.push({
      key: row.key,
      name,
      type: 'custom',
      group: 'Custom Threat Feeds',
      feed_kind: 'custom',
      enabled: row.deactivated_at == null,
      active,
      selectable: active,
      display_name: `${name} (custom)`,
      source_name: name
    });
  }

  for (const row of manualRows) {
    sources.push(serializeManualSourceOption(row));
  }

  const selectedKeys = (opts.selectedKeys || []).map((k) => String(k).trim()).filter(Boolean);
  if (!selectedKeys.length) return { sources };

  const byKey = new Map(sources.map((s) => [s.key, s]));
  const selectedManualIds = selectedKeys
    .filter(isManualFeedKey)
    .map(parseManualFeedKey)
    .filter((id) => id != null);

  if (selectedManualIds.length) {
    const missingIds = selectedManualIds.filter((id) => !byKey.has(formatManualFeedKey(id)));
    if (missingIds.length) {
      const { rows: inactiveManualRows } = await pool.query(
        `SELECT id, name, active, archived_at
         FROM ioc_sources
         WHERE id = ANY($1::bigint[])`,
        [missingIds]
      );
      for (const row of inactiveManualRows) {
        const state = resolveIocSourceState(row);
        const active = state === 'active';
        sources.push({
          ...serializeManualSourceOption(row, { selectable: false }),
          active,
          selectable: false,
          display_name: active ? `${row.name} (manual)` : `${row.name} (inactive)`,
          inactive: !active
        });
      }
    }
  }

  return { sources: mergeOrphanPublishedFeedSources(sources, selectedKeys) };
}

/**
 * Merge saved include_feed_keys missing from current options (deleted/deactivated feeds).
 * @param {Array<object>} sources
 * @param {string[]} selectedKeys
 */
export function mergeOrphanPublishedFeedSources(sources, selectedKeys = []) {
  const byKey = new Map(sources.map((s) => [s.key, s]));
  const merged = [...sources];
  for (const key of selectedKeys) {
    if (byKey.has(key)) continue;
    const custom = isCustomFeedKey(key);
    const manual = isManualFeedKey(key);
    merged.push({
      key,
      name: manual ? (parseManualFeedKey(key) ? `manual source ${parseManualFeedKey(key)}` : key) : key,
      type: manual ? 'manual_source' : custom ? 'custom' : 'integration',
      group: manual ? 'Manual IOC Sources' : custom ? 'Custom Threat Feeds' : 'Integration Feeds',
      feed_kind: manual ? 'manual' : custom ? 'custom' : 'built_in',
      enabled: false,
      active: false,
      selectable: false,
      missing: true,
      display_name: manual
        ? `${key} (missing manual source)`
        : custom
          ? `${key} (missing custom feed)`
          : `${key} (inactive)`,
      source_name: key
    });
  }
  return merged;
}

/**
 * @param {string[]|null|undefined} feedKeys
 */
export function extractManualFeedSourceIds(feedKeys) {
  return (feedKeys || [])
    .filter(isManualFeedKey)
    .map(parseManualFeedKey)
    .filter((id) => id != null);
}

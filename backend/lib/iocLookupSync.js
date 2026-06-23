import { clickhouse, query as clickhouseQuery } from './clickhouse.js';
import { normalizeObservable } from './observable-normalization.js';

/** Partition-direct sync spec — avoids parent ioc_items fan-out / CH postgresql() FDW reads. */
export const IOC_LOOKUP_SYNC_PARTITIONS = [
  { key: 'ip', table: 'ioc_ip', types: ['ip'] },
  { key: 'domain', table: 'ioc_domain', types: ['domain', 'hostname'] },
  { key: 'url', table: 'ioc_url', types: ['url'] },
  { key: 'sha256', table: 'ioc_file_hash', types: ['sha256'] }
];

const ALLOWED_TABLES = new Set(IOC_LOOKUP_SYNC_PARTITIONS.map((p) => p.table));

function confidenceToInt(v) {
  const s = String(v || '').toLowerCase();
  if (s === 'high') return 90;
  if (s === 'medium') return 60;
  if (s === 'low') return 30;
  return 50;
}

export function parseSyncCursors(lastSyncIdRaw) {
  const raw = String(lastSyncIdRaw ?? '').trim();
  if (!raw) {
    return Object.fromEntries(IOC_LOOKUP_SYNC_PARTITIONS.map((p) => [p.key, 0]));
  }
  if (raw.startsWith('{')) {
    try {
      const parsed = JSON.parse(raw);
      const out = Object.fromEntries(IOC_LOOKUP_SYNC_PARTITIONS.map((p) => [p.key, 0]));
      for (const p of IOC_LOOKUP_SYNC_PARTITIONS) {
        out[p.key] = Math.max(0, Number(parsed[p.key] || 0));
      }
      return out;
    } catch {
      // fall through to legacy numeric
    }
  }
  const legacy = Math.max(0, Number(raw) || 0);
  return Object.fromEntries(IOC_LOOKUP_SYNC_PARTITIONS.map((p) => [p.key, legacy]));
}

export function serializeSyncCursors(cursors) {
  const payload = {};
  for (const p of IOC_LOOKUP_SYNC_PARTITIONS) {
    payload[p.key] = Math.max(0, Number(cursors?.[p.key] || 0));
  }
  return JSON.stringify(payload);
}

export function hasPendingLookupChanges(partitionMaxIds, cursors) {
  return IOC_LOOKUP_SYNC_PARTITIONS.some((p) => {
    const maxId = Number(partitionMaxIds[p.key] || 0);
    const cursor = Number(cursors[p.key] || 0);
    return maxId > cursor;
  });
}

/** Cheap per-partition MAX(id) — index-friendly, no parent scan. */
export async function fetchPartitionMaxIds(pool) {
  if (!pool?.query) {
    throw new Error('fetchPartitionMaxIds requires a PostgreSQL pool');
  }

  const parts = IOC_LOOKUP_SYNC_PARTITIONS.map((p) => `
    SELECT '${p.key}' AS partition_key,
           COALESCE(MAX(id), 0)::bigint AS max_id
    FROM ${p.table}
    WHERE observable IS NOT NULL
      AND observable != ''
      AND COALESCE(status, 'active') = 'active'
  `);

  const { rows } = await pool.query(parts.join('\nUNION ALL\n'));
  const out = Object.fromEntries(IOC_LOOKUP_SYNC_PARTITIONS.map((p) => [p.key, 0]));
  for (const row of rows) {
    out[String(row.partition_key)] = Number(row.max_id || 0);
  }
  return out;
}

async function fetchPartitionDeltaRows(pool, partition, cursor, limit) {
  if (!ALLOWED_TABLES.has(partition.table)) {
    throw new Error(`Invalid partition table: ${partition.table}`);
  }

  const typeFilter = partition.types.length === 1
    ? `AND observable_type = '${partition.types[0]}'`
    : `AND observable_type IN (${partition.types.map((t) => `'${t}'`).join(', ')})`;

  const { rows } = await pool.query(
    `SELECT id,
            lower(observable) AS observable,
            observable_type,
            source_name,
            confidence,
            created_at
     FROM ${partition.table}
     WHERE observable IS NOT NULL
       AND observable != ''
       ${typeFilter}
       AND COALESCE(status, 'active') = 'active'
       AND id > $1
     ORDER BY id ASC
     LIMIT $2`,
    [cursor, limit]
  );
  return rows;
}

export async function fetchIocLookupDeltaFromPostgres(pool, cursors, batchSize, partitionMaxIds = null) {
  const remaining = Math.max(Number(batchSize || 20000), 1);
  const fetchedRows = [];
  const nextCursors = { ...cursors };
  const maxIds = partitionMaxIds || await fetchPartitionMaxIds(pool);

  for (const partition of IOC_LOOKUP_SYNC_PARTITIONS) {
    if (fetchedRows.length >= remaining) break;
    const cursor = Number(nextCursors[partition.key] || 0);
    const maxId = Number(maxIds[partition.key] || 0);
    if (maxId <= cursor) continue;

    const chunk = await fetchPartitionDeltaRows(
      pool,
      partition,
      cursor,
      remaining - fetchedRows.length
    );
    if (!chunk.length) continue;

    fetchedRows.push(...chunk);
    nextCursors[partition.key] = Number(chunk[chunk.length - 1].id);
  }

  return { rows: fetchedRows, nextCursors };
}

async function readSyncState(workerName) {
  const st = await clickhouseQuery(`
    SELECT last_sync_ts, last_sync_id, sync_cursors
    FROM ioc_lookup_sync_state
    WHERE worker_name = '${String(workerName).replace(/'/g, "''")}'
    ORDER BY updated_at DESC
    LIMIT 1
  `, { logTag: 'ioc-lookup.read-state' });
  const row = st?.[0];
  if (!row) return null;
  const cursorRaw = String(row.sync_cursors || '').trim() || String(row.last_sync_id ?? '');
  return { ...row, cursor_raw: cursorRaw };
}

async function writeSyncState(workerName, cursors, lastRow) {
  const created = lastRow?.created_at instanceof Date
    ? lastRow.created_at
    : (lastRow?.created_at ? new Date(lastRow.created_at) : new Date());
  const tsStr = Number.isNaN(created.getTime())
    ? new Date().toISOString().replace('T', ' ').replace('Z', '')
    : created.toISOString().replace('T', ' ').replace('Z', '');
  const maxId = Math.max(...Object.values(cursors).map((v) => Number(v || 0)));
  await clickhouse.insert({
    table: 'ioc_lookup_sync_state',
    values: [{
      worker_name: workerName,
      last_sync_ts: tsStr,
      last_sync_id: maxId,
      sync_cursors: serializeSyncCursors(cursors),
      updated_at: new Date().toISOString().replace('T', ' ').replace('Z', '')
    }],
    format: 'JSONEachRow'
  });
}

function aggregateLookupRows(delta) {
  const agg = new Map();
  for (const r of delta) {
    const observableType = String(r.observable_type || '').toLowerCase();
    const normalizedType = observableType === 'hostname' ? 'domain' : observableType;
    const observable = normalizedType === 'url'
      ? normalizeObservable('url', String(r.observable || ''))
      : String(r.observable || '').toLowerCase();
    const key = `${observable}|${normalizedType}`;
    const conf = confidenceToInt(r.confidence);
    const created = r.created_at instanceof Date
      ? r.created_at.toISOString()
      : String(r.created_at || '1970-01-01T00:00:00.000Z');
    const prev = agg.get(key);
    if (!prev || conf > prev.confidence || created > prev.updated_at) {
      agg.set(key, {
        observable,
        observable_type: normalizedType,
        confidence: conf,
        source_name: r.source_name || 'unknown',
        updated_at: created.replace('T', ' ').replace('Z', '')
      });
    }
  }
  return agg;
}

/**
 * Incremental IOC lookup sync: PG partition cursors + skip unchanged + direct PG reads (no CH FDW).
 */
export async function syncIocLookupFromPostgres(opts = {}) {
  const workerName = opts.workerName || 'ioc-correlation-sync-v1';
  const batchSize = Math.max(Number(opts.batchSize || 20000), 1000);
  const pgPool = opts.pgPool || opts.pool;
  const force = Boolean(opts.force);

  if (!pgPool?.query) {
    throw new Error('syncIocLookupFromPostgres requires opts.pgPool');
  }

  const state = await readSyncState(workerName);
  const cursors = parseSyncCursors(state?.cursor_raw ?? state?.last_sync_id);
  const partitionMaxIds = await fetchPartitionMaxIds(pgPool);

  if (!force && !hasPendingLookupChanges(partitionMaxIds, cursors)) {
    return {
      changed: false,
      skipped: true,
      reason: 'unchanged',
      fetched: 0,
      partition_max_ids: partitionMaxIds
    };
  }

  const { rows: delta, nextCursors } = await fetchIocLookupDeltaFromPostgres(
    pgPool,
    cursors,
    batchSize,
    partitionMaxIds
  );

  if (!delta.length) {
    await writeSyncState(workerName, partitionMaxIds, null);
    return {
      changed: false,
      skipped: true,
      reason: 'caught_up',
      fetched: 0,
      partition_max_ids: partitionMaxIds
    };
  }

  const agg = aggregateLookupRows(delta);
  await clickhouse.insert({ table: 'ioc_lookup', values: Array.from(agg.values()), format: 'JSONEachRow' });

  const mergedCursors = { ...cursors };
  for (const p of IOC_LOOKUP_SYNC_PARTITIONS) {
    mergedCursors[p.key] = Math.max(Number(mergedCursors[p.key] || 0), Number(nextCursors[p.key] || 0));
  }

  const last = delta[delta.length - 1];
  await writeSyncState(workerName, mergedCursors, last);

  return {
    changed: true,
    skipped: false,
    fetched: delta.length,
    written: agg.size,
    last_sync_id: serializeSyncCursors(mergedCursors),
    partition_max_ids: partitionMaxIds
  };
}

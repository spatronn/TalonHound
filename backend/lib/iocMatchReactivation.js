/**
 * Expired IOC correlation match: PG lookup fallback + batch reactivation before event insert.
 */

import { reactivateIocOnCorrelationMatch } from './iocExpiration.js';

function confidenceToInt(v) {
  const s = String(v || '').toLowerCase();
  if (s === 'high') return 90;
  if (s === 'medium') return 60;
  if (s === 'low') return 30;
  return 50;
}

function lookupKey(observableType, observable) {
  return `${String(observableType || '').toLowerCase()}\t${String(observable || '').toLowerCase()}`;
}

function pgTypesForLookupTuple(observable, observableType) {
  const typ = String(observableType || '').toLowerCase();
  if (typ === 'domain') return [{ observable: observable.toLowerCase(), type: 'domain' }, { observable: observable.toLowerCase(), type: 'hostname' }];
  if (typ === 'url') return [{ observable, type: 'url' }];
  if (typ === 'ip') return [{ observable, type: 'ip' }];
  if (typ === 'sha256') return [{ observable: observable.toLowerCase(), type: 'sha256' }];
  return [{ observable, type: typ }];
}

/**
 * Supplement ClickHouse lookup with Postgres rows (covers expired IOCs removed by legacy tombstones).
 */
export async function supplementLookupMapFromPostgres(client, tupleList, lookupMap) {
  if (!client || !tupleList?.length) return lookupMap;

  const missing = [];
  for (const [obs, typ] of tupleList) {
    if (!lookupMap.get(lookupKey(typ, obs))) missing.push([obs, typ]);
  }
  if (!missing.length) return lookupMap;

  const pairs = [];
  for (const [obs, typ] of missing) {
    for (const p of pgTypesForLookupTuple(obs, typ)) {
      pairs.push([p.observable, p.type]);
    }
  }

  const params = [];
  const valuesSql = pairs.map(([obs, typ]) => {
    params.push(obs, typ);
    const base = params.length - 1;
    return `(lower($${base}), lower($${base + 1}))`;
  }).join(', ');

  const { rows } = await client.query(
    `SELECT DISTINCT ON (lower(i.observable), lower(i.observable_type))
            i.observable,
            CASE WHEN i.observable_type = 'hostname' THEN 'domain' ELSE i.observable_type END AS observable_type,
            i.confidence,
            i.source_name,
            COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) AS updated_at,
            COALESCE(i.status, 'active') AS status
     FROM ioc_items i
     WHERE (lower(i.observable), lower(i.observable_type)) IN (${valuesSql})
       AND COALESCE(i.status, 'active') IN ('active', 'expired')
     ORDER BY lower(i.observable), lower(i.observable_type), i.created_at ASC`,
    params
  );

  for (const row of rows || []) {
    const typ = String(row.observable_type || '').toLowerCase();
    const obs = typ === 'url' ? String(row.observable || '') : String(row.observable || '').toLowerCase();
    const key = lookupKey(typ, obs);
    if (lookupMap.has(key)) continue;
    lookupMap.set(key, {
      observable: obs,
      observable_type: typ,
      confidence: confidenceToInt(row.confidence),
      source_name: row.source_name || 'unknown',
      updated_at: row.updated_at,
      pg_status: row.status
    });
  }

  return lookupMap;
}

function matchDedupeKey(row) {
  return [
    String(row.ioc_type || '').toLowerCase(),
    String(row.matched_ioc || '').trim().toLowerCase(),
    String(row.source_name || '').trim().toLowerCase()
  ].join('\t');
}

/**
 * Reactivate globally expired IOCs referenced by match rows (idempotent per batch key).
 */
export async function batchReactivateExpiredMatchesForRows(client, rows, {
  audit = null,
  actor = { actor_type: 'system', source: 'ioc-correlation' },
  detectionType = 'realtime'
} = {}) {
  if (!client || !rows?.length) {
    return { reactivated: 0, skipped: 0, results: [] };
  }

  const seen = new Set();
  const tasks = [];
  for (const row of rows) {
    const key = matchDedupeKey(row);
    if (!key || key.startsWith('\t') || seen.has(key)) continue;
    seen.add(key);
    tasks.push({
      observable: row.matched_ioc,
      observableType: row.ioc_type,
      sourceName: row.source_name ?? null,
      matchAt: row.event_time || new Date(),
      detectionType: row.detection_type || detectionType
    });
  }

  let reactivated = 0;
  let skipped = 0;
  const results = [];
  const reactivatedKeys = new Set();

  for (const task of tasks) {
    const res = await reactivateIocOnCorrelationMatch(client, {
      ...task,
      audit,
      actor
    });
    results.push(res);
    if (res.reactivated) {
      reactivated += 1;
      reactivatedKeys.add(matchDedupeKey({
        ioc_type: task.observableType,
        matched_ioc: task.observable,
        source_name: task.sourceName
      }));
    } else {
      skipped += 1;
    }
  }

  return { reactivated, skipped, results, reactivatedKeys };
}

export function annotateMatchRowsWithReactivation(rows, reactivatedKeys) {
  if (!reactivatedKeys?.size) return rows;

  return rows.map((row) => {
    if (!reactivatedKeys.has(matchDedupeKey(row))) return row;
    const ctx = row.match_context && typeof row.match_context === 'object'
      ? { ...row.match_context }
      : {};
    ctx.ioc_reactivated_on_match = true;
    return { ...row, match_context: ctx };
  });
}

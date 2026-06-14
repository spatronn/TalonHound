/**
 * Expired IOC correlation match: PG lookup fallback + batch reactivation before event insert.
 */

import { reactivateIocOnCorrelationMatch } from './iocExpiration.js';

const PG_SUPPLEMENT_LOOKUP_ENABLED = process.env.PG_SUPPLEMENT_LOOKUP_ENABLED !== '0'
  && process.env.PG_SUPPLEMENT_LOOKUP_ENABLED !== 'false';
/** Per supplement call (runBatch realtime path and replay path each invoke separately). Tick logs sum both, so pg_supplement_keys can reach 2× this value when replay runs in the same tick. */
const PG_SUPPLEMENT_LOOKUP_MAX_KEYS = Math.max(
  Number(process.env.PG_SUPPLEMENT_LOOKUP_MAX_KEYS || 100),
  1
);

/** SQL expression: normalized observable_type for lookup (hostname → domain). */
export const PG_LOOKUP_TYPE_SQL = `CASE WHEN i.observable_type = 'hostname' THEN 'domain' ELSE i.observable_type END`;

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

export function normalizePgLookupType(observableType) {
  const typ = String(observableType || '').toLowerCase();
  return typ === 'hostname' ? 'domain' : typ;
}

export function normalizePgLookupObservable(observable, normalizedType) {
  const raw = String(observable || '').trim();
  return normalizedType === 'url' ? raw : raw.toLowerCase();
}

function pgTypesForLookupTuple(observable, observableType) {
  const typ = String(observableType || '').toLowerCase();
  if (typ === 'domain') {
    const lv = observable.toLowerCase();
    return [{ observable: lv, type: 'domain' }, { observable: lv, type: 'hostname' }];
  }
  if (typ === 'url') return [{ observable, type: 'url' }];
  if (typ === 'ip') return [{ observable, type: 'ip' }];
  if (typ === 'sha256') return [{ observable: observable.toLowerCase(), type: 'sha256' }];
  return [{ observable, type: typ }];
}

/**
 * Select unique CH-miss tuples for PG supplement, capped by maxKeys (stable first-seen order).
 */
export function selectMissingTuplesForPgSupplement(tupleList, lookupMap, maxKeys = PG_SUPPLEMENT_LOOKUP_MAX_KEYS) {
  const seen = new Set();
  const missing = [];
  for (const [obs, typ] of tupleList) {
    if (lookupMap.get(lookupKey(typ, obs))) continue;
    const key = lookupKey(typ, obs);
    if (seen.has(key)) continue;
    seen.add(key);
    missing.push([obs, typ]);
  }
  const totalMissing = missing.length;
  if (totalMissing <= maxKeys) {
    return { selected: missing, totalMissing, skippedCount: 0 };
  }
  return {
    selected: missing.slice(0, maxKeys),
    totalMissing,
    skippedCount: totalMissing - maxKeys
  };
}

export function createPgSupplementStats() {
  return {
    pg_supplement_attempted: false,
    pg_supplement_keys: 0,
    pg_supplement_found: 0,
    pg_supplement_skipped: 0,
    skipped_pg_supplement_keys: 0,
    skip_reason: null
  };
}

/**
 * Supplement ClickHouse lookup with Postgres rows (covers expired IOCs removed from CH lookup).
 * Returns stats; mutates lookupMap in place.
 */
export async function supplementLookupMapFromPostgres(client, tupleList, lookupMap) {
  const stats = createPgSupplementStats();
  if (!client || !tupleList?.length) return stats;

  const { selected, totalMissing, skippedCount } = selectMissingTuplesForPgSupplement(
    tupleList,
    lookupMap,
    PG_SUPPLEMENT_LOOKUP_MAX_KEYS
  );

  if (!totalMissing) return stats;

  if (!PG_SUPPLEMENT_LOOKUP_ENABLED) {
    stats.pg_supplement_skipped = totalMissing;
    stats.skipped_pg_supplement_keys = totalMissing;
    stats.skip_reason = 'disabled';
    return stats;
  }

  if (skippedCount > 0) {
    stats.pg_supplement_skipped = skippedCount;
    stats.skipped_pg_supplement_keys = skippedCount;
    stats.skip_reason = 'max_keys_exceeded';
  }

  if (!selected.length) return stats;

  stats.pg_supplement_attempted = true;
  stats.pg_supplement_keys = selected.length;

  const pairKeySeen = new Set();
  const pairs = [];
  for (const [obs, typ] of selected) {
    for (const p of pgTypesForLookupTuple(obs, typ)) {
      const normType = normalizePgLookupType(p.type);
      const normObs = normalizePgLookupObservable(p.observable, normType);
      const pk = `${normType}\t${normObs}`;
      if (pairKeySeen.has(pk)) continue;
      pairKeySeen.add(pk);
      pairs.push([normObs, normType]);
    }
  }

  if (!pairs.length) return stats;

  const params = [];
  const valuesSql = pairs.map(([obs, typ]) => {
    params.push(obs, typ);
    const base = params.length - 1;
    return `($${base}, $${base + 1})`;
  }).join(', ');

  const { rows } = await client.query(
    `SELECT DISTINCT ON (lower(i.observable), ${PG_LOOKUP_TYPE_SQL})
            i.observable,
            ${PG_LOOKUP_TYPE_SQL} AS observable_type,
            i.confidence,
            i.source_name,
            COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) AS updated_at,
            COALESCE(i.status, 'active') AS status
     FROM ioc_items i
     WHERE (lower(i.observable), ${PG_LOOKUP_TYPE_SQL}) IN (${valuesSql})
       AND COALESCE(i.status, 'active') IN ('active', 'expired')
     ORDER BY lower(i.observable), ${PG_LOOKUP_TYPE_SQL}, i.created_at ASC`,
    params
  );

  stats.pg_supplement_found = (rows || []).length;

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

  return stats;
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

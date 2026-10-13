/**
 * Active IOC suppression lookup (Phase-2 workers/import).
 * Fail-open on DB errors so ingestion/correlation is not blocked.
 *
 * Exact (type, value) matching remains the base. When suppressions carry
 * file_artifact_id, fetchActiveSuppressionIndex also expands proven file-hash
 * aliases of that canonical file (see iocSuppressionFileScope.js).
 */

import {
  buildSuppressionIndexWithFileScope,
  isFileHashSuppressionType
} from './iocSuppressionFileScope.js';

export function makeSuppressionKey(iocValue, iocType) {
  const value = String(iocValue || '').trim().toLowerCase();
  const type = String(iocType || '').trim().toLowerCase();
  if (!value || !type) return '';
  return `${type}\t${value}`;
}

/**
 * @returns {{ global: boolean, sources: Set<string> }}
 */
function emptyIndexEntry() {
  return { global: false, sources: new Set() };
}

/**
 * Build lookup index from active suppression rows.
 * @param {Array<{ ioc_value?: string, ioc_type?: string, scope?: string, source_name?: string | null }>} rows
 * @returns {Map<string, { global: boolean, sources: Set<string> }>}
 */
export function buildSuppressionIndex(rows = []) {
  const index = new Map();
  for (const row of rows) {
    const key = makeSuppressionKey(row.ioc_value, row.ioc_type);
    if (!key) continue;
    const entry = index.get(key) || emptyIndexEntry();
    // Suppressions are effectively global: matching is by (value, type) only and
    // scope is ignored everywhere else (DB lookup, export, recompute). Any active
    // row — including legacy source-scoped rows — suppresses the indicator.
    entry.global = true;
    const src = String(row.source_name || '').trim().toLowerCase();
    if (src) entry.sources.add(src);
    index.set(key, entry);
  }
  return index;
}

/**
 * @param {Map<string, { global: boolean, sources: Set<string> }>} index
 */
export function isPairSuppressed(index, { iocValue, iocType, sourceName = null }) {
  const key = makeSuppressionKey(iocValue, iocType);
  if (!key) return false;
  const entry = index.get(key);
  if (!entry) return false;
  if (entry.global) return { suppressed: true, byGlobal: true };
  const src = sourceName == null ? '' : String(sourceName).trim().toLowerCase();
  if (src && entry.sources.has(src)) return { suppressed: true, byGlobal: false };
  return { suppressed: false, byGlobal: false };
}

/**
 * @param {import('pg').PoolClient | import('pg').Pool} client
 * @param {Array<{ iocValue: string, iocType: string, sourceName?: string | null }>} pairs
 * @param {{ logTag?: string }} [opts]
 * @returns {Promise<Map<string, { global: boolean, sources: Set<string> }>>}
 */
export async function fetchActiveSuppressionIndex(client, pairs = [], opts = {}) {
  const logTag = opts.logTag || 'ioc-suppression';
  const uniq = new Map();
  for (const p of pairs) {
    const v = String(p?.iocValue || '').trim();
    const t = String(p?.iocType || '').trim();
    if (!v || !t) continue;
    uniq.set(makeSuppressionKey(v, t), { iocValue: v, iocType: t });
  }
  if (!uniq.size) return new Map();

  const values = Array.from(uniq.values());
  const iocValues = values.map((x) => x.iocValue);
  const iocTypes = values.map((x) => x.iocType);
  const hasFileHashPair = values.some((x) => isFileHashSuppressionType(x.iocType));

  try {
    const q = await client.query(
      `SELECT lower(ioc_value) AS ioc_value,
              lower(ioc_type) AS ioc_type,
              scope,
              lower(source_name) AS source_name,
              file_artifact_id
       FROM ioc_suppressions
       WHERE active = TRUE
         AND deleted_at IS NULL
         AND (expires_at IS NULL OR expires_at > NOW())
         AND EXISTS (
           SELECT 1
           FROM unnest($1::text[], $2::text[]) AS u(v, t)
           WHERE lower(ioc_value) = lower(u.v)
             AND lower(ioc_type) = lower(u.t)
         )`,
      [iocValues, iocTypes]
    );
    let rows = q.rows || [];

    // File-scoped hits: active suppression whose artifact owns a requested hash.
    if (hasFileHashPair) {
      const aliasQ = await client.query(
        `SELECT lower(s.ioc_value) AS ioc_value,
                lower(s.ioc_type) AS ioc_type,
                s.scope,
                lower(s.source_name) AS source_name,
                s.file_artifact_id
         FROM ioc_suppressions s
         WHERE s.active = TRUE
           AND s.deleted_at IS NULL
           AND (s.expires_at IS NULL OR s.expires_at > NOW())
           AND s.file_artifact_id IS NOT NULL
           AND EXISTS (
             SELECT 1
             FROM unnest($1::text[], $2::text[]) AS u(v, t)
             JOIN file_artifact_hashes h
               ON h.hash_type = lower(u.t)
              AND h.normalized_hash_value = lower(u.v)
             JOIN file_artifacts fa ON fa.id = h.artifact_id
             JOIN file_artifacts sfa ON sfa.id = s.file_artifact_id
             WHERE lower(u.t) IN ('md5', 'sha1', 'sha256')
               AND COALESCE(
                     CASE
                       WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL
                         THEN fa.merged_into_artifact_id
                       ELSE fa.id
                     END,
                     fa.id
                   ) = COALESCE(
                     CASE
                       WHEN sfa.status = 'merged' AND sfa.merged_into_artifact_id IS NOT NULL
                         THEN sfa.merged_into_artifact_id
                       ELSE sfa.id
                     END,
                     sfa.id
                   )
           )`,
        [iocValues, iocTypes]
      );
      const seen = new Set(rows.map((r) => `${r.ioc_type}\t${r.ioc_value}\t${r.file_artifact_id || ''}`));
      for (const r of aliasQ.rows || []) {
        const k = `${r.ioc_type}\t${r.ioc_value}\t${r.file_artifact_id || ''}`;
        if (seen.has(k)) continue;
        seen.add(k);
        rows.push(r);
      }
    }

    return buildSuppressionIndexWithFileScope(client, rows, { buildSuppressionIndex, makeSuppressionKey });
  } catch (err) {
    // Older DBs without file_artifact_id: retry exact-only.
    if (err?.code === '42703' || String(err?.message || '').includes('file_artifact_id')) {
      try {
        const q = await client.query(
          `SELECT lower(ioc_value) AS ioc_value,
                  lower(ioc_type) AS ioc_type,
                  scope,
                  lower(source_name) AS source_name
           FROM ioc_suppressions
           WHERE active = TRUE
             AND deleted_at IS NULL
             AND (expires_at IS NULL OR expires_at > NOW())
             AND EXISTS (
               SELECT 1
               FROM unnest($1::text[], $2::text[]) AS u(v, t)
               WHERE lower(ioc_value) = lower(u.v)
                 AND lower(ioc_type) = lower(u.t)
             )`,
          [iocValues, iocTypes]
        );
        return buildSuppressionIndex(q.rows || []);
      } catch (err2) {
        console.error(`[${logTag}] suppression lookup failed (fail-open):`, err2?.message || err2);
        return new Map();
      }
    }
    console.error(`[${logTag}] suppression lookup failed (fail-open):`, err?.message || err);
    return new Map();
  }
}

/**
 * @param {import('pg').PoolClient | import('pg').Pool} client
 * @param {{ iocValue: string, iocType: string, sourceName?: string | null }} params
 */
export async function isIocSuppressed(client, { iocValue, iocType, sourceName = null }) {
  const index = await fetchActiveSuppressionIndex(client, [{ iocValue, iocType, sourceName }], {
    logTag: 'ioc-suppression'
  });
  const hit = isPairSuppressed(index, { iocValue, iocType, sourceName });
  return Boolean(hit?.suppressed);
}

export function createSuppressionStats() {
  return {
    suppressed_count: 0,
    suppressed_by_global_count: 0,
    skipped_suppressed_iocs: 0,
    noteSuppressionSkip({ byGlobal = true } = {}) {
      this.suppressed_count += 1;
      this.skipped_suppressed_iocs += 1;
      if (byGlobal) this.suppressed_by_global_count += 1;
    },
    merge(other) {
      if (!other) return this;
      this.suppressed_count += Number(other.suppressed_count || 0);
      this.suppressed_by_global_count += Number(other.suppressed_by_global_count || 0);
      this.skipped_suppressed_iocs += Number(other.skipped_suppressed_iocs || 0);
      return this;
    },
    toJSON() {
      return {
        suppressed_count: this.suppressed_count,
        suppressed_by_global_count: this.suppressed_by_global_count,
        skipped_suppressed_iocs: this.skipped_suppressed_iocs
      };
    }
  };
}

/**
 * Filter match/import rows using a preloaded suppression index.
 * @returns {{ kept: Array, stats: ReturnType<typeof createSuppressionStats> }}
 */
export function filterSuppressedPairs(index, items, pickPair) {
  const stats = createSuppressionStats();
  if (!items?.length || !index?.size) {
    return { kept: items || [], stats };
  }
  const kept = [];
  for (const item of items) {
    const pair = pickPair(item);
    const hit = isPairSuppressed(index, pair);
    if (hit?.suppressed) {
      stats.noteSuppressionSkip({ byGlobal: hit.byGlobal });
      continue;
    }
    kept.push(item);
  }
  return { kept, stats };
}

export const RETRO_CURSOR_LAG_WARNING_SECONDS = Math.max(
  Number(process.env.RETRO_CURSOR_LAG_WARNING_SECONDS || 900),
  60
);
export const RETRO_RUN_STALE_SECONDS = Math.max(
  Number(process.env.RETRO_RUN_STALE_SECONDS || 1800),
  60
);
export const PG_CH_SYNC_LAG_WARNING_SECONDS = Math.max(
  Number(process.env.PG_CH_SYNC_LAG_WARNING_SECONDS || 900),
  60
);

export const RETRO_CURSOR_SOURCE = 'clickhouse:ioc_retro_state.last_processed_ts';
export const RETRO_CURSOR_SEMANTICS = 'Newest IOC lookup updated_at successfully covered by retro scan';

export function safeTs(v) {
  return String(v || '1970-01-01 00:00:00.000').replace(/'/g, "''");
}

export function safeHash(v) {
  const n = String(v == null ? '0' : v).replace(/[^0-9]/g, '');
  return n || '0';
}

/** Worker-aligned pending predicate (ioc_lookup_by_updated + confidence > 0). */
export function retroPendingWhereSql(cursorTs, cursorHash) {
  return `
    confidence > 0
    AND (
      updated_at > toDateTime64('${safeTs(cursorTs)}', 3)
      OR (
        updated_at = toDateTime64('${safeTs(cursorTs)}', 3)
        AND cityHash64(concat(observable, '|', observable_type, '|', source_name))
            > toUInt64('${safeHash(cursorHash)}')
      )
    )
  `;
}

export function retroPendingCountQuery(cursorTs, cursorHash) {
  return `
    SELECT
      count() AS pending,
      min(updated_at) AS pending_min_ts,
      max(updated_at) AS pending_max_ts
    FROM default.ioc_lookup_by_updated
    WHERE ${retroPendingWhereSql(cursorTs, cursorHash)}
  `;
}

export function retroScannedBetweenQuery(prevCursorTs, prevCursorHash, latestCursorTs, latestCursorHash) {
  return `
    SELECT count() AS scanned
    FROM default.ioc_lookup_by_updated
    WHERE confidence > 0
      AND (
        updated_at > toDateTime64('${safeTs(prevCursorTs)}', 3)
        OR (
          updated_at = toDateTime64('${safeTs(prevCursorTs)}', 3)
          AND cityHash64(concat(observable, '|', observable_type, '|', source_name))
              > toUInt64('${safeHash(prevCursorHash)}')
        )
      )
      AND (
        updated_at < toDateTime64('${safeTs(latestCursorTs)}', 3)
        OR (
          updated_at = toDateTime64('${safeTs(latestCursorTs)}', 3)
          AND cityHash64(concat(observable, '|', observable_type, '|', source_name))
              <= toUInt64('${safeHash(latestCursorHash)}')
        )
      )
  `;
}

export function secondsBetween(laterMs, earlierMs) {
  const a = Number(laterMs);
  const b = Number(earlierMs);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return Math.max(0, Math.round((a - b) / 1000));
}

export function parseChDateTimeMs(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  if (Number.isFinite(n) && n > 0) return n;
  const raw = String(value).trim();
  if (!raw) return null;
  const normalized = raw.includes(' ') ? raw.replace(' ', 'T') : raw;
  const hasTz = /([zZ]|[+\-]\d{2}:?\d{2})$/.test(normalized);
  const ms = Date.parse(hasTz ? normalized : `${normalized}Z`);
  return Number.isFinite(ms) ? ms : null;
}

export function computeRetroStateHealth({
  chOk = true,
  pgOk = true,
  cursorTs = null,
  chMaxLookupUpdatedAtMs = null,
  chPendingIocCount = 0,
  chCursorLagSeconds = null,
  pgUnsyncedIocCount = 0,
  pgToChSyncLagSeconds = null,
  lastRunAtMs = null,
  chunkActive = 0,
  nowMs = Date.now()
} = {}) {
  if (!chOk || !pgOk) return 'ERROR';
  if (!cursorTs && chMaxLookupUpdatedAtMs != null && chMaxLookupUpdatedAtMs > 0) return 'ERROR';

  const runAgeSeconds = lastRunAtMs != null
    ? Math.max(0, Math.round((nowMs - lastRunAtMs) / 1000))
    : null;

  if (runAgeSeconds != null && runAgeSeconds > RETRO_RUN_STALE_SECONDS) {
    return 'STALE';
  }

  if (chPendingIocCount > 0) {
    if (runAgeSeconds != null && runAgeSeconds > RETRO_RUN_STALE_SECONDS) return 'STALE';
    return 'WARNING';
  }

  if (
    pgUnsyncedIocCount > 0
    && chPendingIocCount === 0
  ) {
    return 'WARNING';
  }

  if (
    chCursorLagSeconds != null
    && chCursorLagSeconds > RETRO_CURSOR_LAG_WARNING_SECONDS
  ) {
    return 'WARNING';
  }

  if (
    pgToChSyncLagSeconds != null
    && pgToChSyncLagSeconds > PG_CH_SYNC_LAG_WARNING_SECONDS
  ) {
    return 'WARNING';
  }

  if (Number(chunkActive) === 1) {
    return 'OK';
  }

  return 'OK';
}

export function healthPresentation(stateHealth) {
  const key = String(stateHealth || 'ERROR').toUpperCase();
  const map = {
    OK: { label: 'OK', color: '#22c55e' },
    WARNING: { label: 'Sync Lag Warning', color: '#fbbf24' },
    STALE: { label: 'Stale', color: '#fb923c' },
    ERROR: { label: 'Error', color: '#f87171' }
  };
  return map[key] || map.ERROR;
}

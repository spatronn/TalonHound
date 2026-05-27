function readPositiveMinutes(name, fallback, min = 1) {
  const n = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(n) || n < min) return fallback;
  return Math.floor(n);
}

function readPositiveSeconds(name, fallback, min = 60) {
  const n = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(n) || n < min) return fallback;
  return Math.floor(n);
}

/** Expected retro worker cadence (default hourly). */
export const RETRO_RUN_INTERVAL_MINUTES = readPositiveMinutes('RETRO_RUN_INTERVAL_MINUTES', 60);
export const RETRO_RUN_GRACE_MINUTES = Math.max(readPositiveMinutes('RETRO_RUN_GRACE_MINUTES', 5, 0), 0);
export const RETRO_RUN_STALE_MINUTES = readPositiveMinutes('RETRO_RUN_STALE_MINUTES', 90);

export const RETRO_RUN_INTERVAL_SECONDS = RETRO_RUN_INTERVAL_MINUTES * 60;
export const RETRO_RUN_GRACE_SECONDS = RETRO_RUN_GRACE_MINUTES * 60;
/** last_run_age above this → worker Warning (interval + grace, default 65m). */
export const RETRO_RUN_WARNING_SECONDS = RETRO_RUN_INTERVAL_SECONDS + RETRO_RUN_GRACE_SECONDS;
/** last_run_age above this → worker Stale (default 90m). */
export const RETRO_RUN_STALE_SECONDS = RETRO_RUN_STALE_MINUTES * 60;

export const RETRO_CURSOR_LAG_WARNING_SECONDS = readPositiveSeconds(
  'RETRO_CURSOR_LAG_WARNING_SECONDS',
  RETRO_RUN_WARNING_SECONDS
);
export const RETRO_CURSOR_LAG_STALE_SECONDS = readPositiveSeconds(
  'RETRO_CURSOR_LAG_STALE_SECONDS',
  RETRO_RUN_STALE_SECONDS
);

export const PG_CH_SYNC_LAG_WARNING_SECONDS = readPositiveSeconds(
  'PG_CH_SYNC_LAG_WARNING_SECONDS',
  RETRO_RUN_WARNING_SECONDS
);
export const PG_CH_SYNC_LAG_STALE_SECONDS = readPositiveSeconds(
  'PG_CH_SYNC_LAG_STALE_SECONDS',
  RETRO_RUN_STALE_SECONDS
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

function classifyLagSeconds(seconds, { warningAfter, staleAfter }) {
  if (seconds == null || !Number.isFinite(seconds)) return 'OK';
  if (seconds > staleAfter) return 'STALE';
  if (seconds > warningAfter) return 'WARNING';
  return 'OK';
}

function maxHealth(...levels) {
  const order = { OK: 0, WARNING: 1, STALE: 2, ERROR: 3 };
  let worst = 'OK';
  for (const level of levels) {
    const key = String(level || 'OK').toUpperCase();
    if ((order[key] ?? 3) > (order[worst] ?? 0)) worst = key;
  }
  return worst;
}

/**
 * Retro worker cadence health — based on last successful state write age only.
 */
export function computeRetroWorkerHealth({
  lastRunAgeSeconds = null
} = {}) {
  if (lastRunAgeSeconds == null) return 'WARNING';
  return classifyLagSeconds(lastRunAgeSeconds, {
    warningAfter: RETRO_RUN_WARNING_SECONDS,
    staleAfter: RETRO_RUN_STALE_SECONDS
  });
}

/**
 * Retro cursor / CH backlog health — independent from PG→CH sync lag.
 */
export function computeRetroCursorHealth({
  chPendingIocCount = 0,
  chCursorLagSeconds = null,
  lastRunAgeSeconds = null
} = {}) {
  const pending = Number(chPendingIocCount || 0);
  const lagHealth = classifyLagSeconds(chCursorLagSeconds, {
    warningAfter: RETRO_CURSOR_LAG_WARNING_SECONDS,
    staleAfter: RETRO_CURSOR_LAG_STALE_SECONDS
  });

  if (pending === 0 && lagHealth === 'OK') return 'OK';

  const runHealth = lastRunAgeSeconds == null
    ? 'WARNING'
    : classifyLagSeconds(lastRunAgeSeconds, {
      warningAfter: RETRO_RUN_WARNING_SECONDS,
      staleAfter: RETRO_RUN_STALE_SECONDS
    });

  if (pending > 0) {
    if (runHealth === 'STALE') return 'STALE';
    if (runHealth === 'WARNING' || lagHealth === 'WARNING') return 'WARNING';
    if (lagHealth === 'STALE') return 'STALE';
    return 'WARNING';
  }

  return lagHealth;
}

/**
 * PostgreSQL → ClickHouse correlation sync health — does not mark retro worker stale.
 */
export function computeCorrelationSyncHealth({
  pgUnsyncedIocCount = 0,
  pgToChSyncLagSeconds = null
} = {}) {
  const unsynced = Number(pgUnsyncedIocCount || 0);
  if (unsynced === 0) return 'OK';
  return classifyLagSeconds(pgToChSyncLagSeconds, {
    warningAfter: PG_CH_SYNC_LAG_WARNING_SECONDS,
    staleAfter: PG_CH_SYNC_LAG_STALE_SECONDS
  });
}

/**
 * Overall retro panel health for UI header badge.
 */
export function computeRetroOverallHealth({
  chOk = true,
  pgOk = true,
  retroWorkerHealth = 'OK',
  retroCursorHealth = 'OK',
  correlationSyncHealth = 'OK'
} = {}) {
  if (!chOk || !pgOk) return 'ERROR';
  return maxHealth(retroWorkerHealth, retroCursorHealth, correlationSyncHealth);
}

export function buildRetroHealthPayload(input = {}) {
  const {
    chOk = true,
    pgOk = true,
    cursorTs = null,
    chMaxLookupUpdatedAtMs = null,
    chPendingIocCount = 0,
    chCursorLagSeconds = null,
    pgUnsyncedIocCount = 0,
    pgToChSyncLagSeconds = null,
    lastRunAtMs = null,
    nowMs = Date.now()
  } = input;

  if (!chOk || !pgOk) {
    return {
      retro_worker_health: 'ERROR',
      retro_cursor_health: 'ERROR',
      correlation_sync_health: 'ERROR',
      overall_health: 'ERROR',
      last_run_age_seconds: null
    };
  }

  if (!cursorTs && chMaxLookupUpdatedAtMs != null && chMaxLookupUpdatedAtMs > 0) {
    return {
      retro_worker_health: 'ERROR',
      retro_cursor_health: 'ERROR',
      correlation_sync_health: 'ERROR',
      overall_health: 'ERROR',
      last_run_age_seconds: null
    };
  }

  const lastRunAgeSeconds = lastRunAtMs != null
    ? Math.max(0, Math.round((nowMs - lastRunAtMs) / 1000))
    : null;

  const retroWorkerHealth = computeRetroWorkerHealth({ lastRunAgeSeconds });
  const retroCursorHealth = computeRetroCursorHealth({
    chPendingIocCount,
    chCursorLagSeconds,
    lastRunAgeSeconds
  });
  const correlationSyncHealth = computeCorrelationSyncHealth({
    pgUnsyncedIocCount,
    pgToChSyncLagSeconds
  });
  const overallHealth = computeRetroOverallHealth({
    chOk,
    pgOk,
    retroWorkerHealth,
    retroCursorHealth,
    correlationSyncHealth
  });

  return {
    last_run_age_seconds: lastRunAgeSeconds,
    expected_interval_seconds: RETRO_RUN_INTERVAL_SECONDS,
    grace_seconds: RETRO_RUN_GRACE_SECONDS,
    stale_after_seconds: RETRO_RUN_STALE_SECONDS,
    retro_worker_health: retroWorkerHealth,
    retro_cursor_health: retroCursorHealth,
    correlation_sync_health: correlationSyncHealth,
    overall_health: overallHealth
  };
}

/** @deprecated Use buildRetroHealthPayload / overall_health. Kept for backward compatibility. */
export function computeRetroStateHealth(input = {}) {
  return buildRetroHealthPayload(input).overall_health;
}

export function healthPresentation(stateHealth, { variant = 'overall' } = {}) {
  const key = String(stateHealth || 'ERROR').toUpperCase();
  const labels = {
    overall: {
      OK: 'OK',
      WARNING: 'Warning',
      STALE: 'Stale',
      ERROR: 'Error'
    },
    worker: {
      OK: 'OK',
      WARNING: 'Run Delayed',
      STALE: 'Stale',
      ERROR: 'Error'
    },
    cursor: {
      OK: 'OK',
      WARNING: 'Backlog / Lag',
      STALE: 'Stale',
      ERROR: 'Error'
    },
    sync: {
      OK: 'OK',
      WARNING: 'Sync Lag',
      STALE: 'Sync Stale',
      ERROR: 'Error'
    }
  };
  const labelMap = labels[variant] || labels.overall;
  const colors = {
    OK: '#22c55e',
    WARNING: '#fbbf24',
    STALE: '#fb923c',
    ERROR: '#f87171'
  };
  return {
    label: labelMap[key] || labelMap.ERROR,
    color: colors[key] || colors.ERROR
  };
}

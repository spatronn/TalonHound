import {
  createUsomApiClient,
  createUsomRunDetails
} from '../lib/usomOfficialApi.js';
import {
  buildUsomCanonicalSnapshotHash,
  normalizeUsomModel,
  USOM_SUPPORTED_API_TYPES
} from '../lib/usomNormalizer.js';

const mode = process.argv.includes('--full')
  ? 'full_reconciliation'
  : process.argv.includes('--incremental')
    ? 'incremental'
    : 'sample';
const runStartedAt = new Date();
const client = createUsomApiClient({
  baseUrl: process.env.USOM_API_BASE_URL,
  perPage: mode === 'sample' ? 5 : process.env.USOM_API_PER_PAGE,
  timeoutMs: process.env.USOM_API_TIMEOUT_MS,
  maxRetries: process.env.USOM_API_MAX_RETRIES,
  requestDelayMs: process.env.USOM_API_REQUEST_DELAY_MS,
  cursorOverlapHours: process.env.USOM_INCREMENTAL_OVERLAP_HOURS
    || process.env.USOM_CURSOR_OVERLAP_HOURS,
  incrementalMaxRecords: process.env.USOM_INCREMENTAL_MAX_RECORDS,
  lookupCacheTtlHours: process.env.USOM_LOOKUP_CACHE_TTL_HOURS
});
const stats = createUsomRunDetails();

if (mode === 'sample') {
  const result = { mode, types: {}, lookups: {} };
  for (const type of USOM_SUPPORTED_API_TYPES) {
    const page = await client.requestJson('/address/index', {
      type,
      page: 1,
      'per-page': 5
    }, stats);
    result.types[type] = {
      total: page.totalCount,
      page: page.page,
      pageCount: page.pageCount,
      sampleCount: page.models.length,
      valid: page.models.filter((row) => normalizeUsomModel(row, type).ok).length
    };
  }
  for (const [name, pathname] of [
    ['descriptions', '/address-description/index'],
    ['sources', '/address-source/index'],
    ['connectionTypes', '/address-connection-type/index']
  ]) {
    try {
      const page = await client.requestJson(pathname, { page: 1, 'per-page': 5 }, stats);
      result.lookups[name] = { ok: true, total: page.totalCount, sampleCount: page.models.length };
    } catch (err) {
      result.lookups[name] = { ok: false, reason: String(err?.code || err?.message || 'unknown') };
    }
  }
  result.requests = stats.request_count;
  console.log(JSON.stringify(result, null, 2));
} else {
  let normalizedCount = 0;
  const identities = [];
  const startedAt = Date.now();
  const cursorArg = process.argv.find((arg) => arg.startsWith('--cursor='));
  const cursorTimestamp = cursorArg?.slice('--cursor='.length)
    || process.env.USOM_DRY_RUN_CURSOR
    || runStartedAt.toISOString();
  if (mode === 'incremental' && Number.isNaN(new Date(cursorTimestamp).getTime())) {
    throw new TypeError('USOM dry-run cursor must be a valid timestamp');
  }
  let cursors = {};
  if (mode === 'incremental') {
    const configuredCursors = process.env.USOM_DRY_RUN_CURSORS_JSON
      ? JSON.parse(process.env.USOM_DRY_RUN_CURSORS_JSON)
      : null;
    cursors = Object.fromEntries(USOM_SUPPORTED_API_TYPES.map((type) => {
      const configured = configuredCursors?.[type];
      const timestamp = configured?.timestamp || cursorTimestamp;
      if (Number.isNaN(new Date(timestamp).getTime())) {
        throw new TypeError(`USOM dry-run ${type} cursor must be a valid timestamp`);
      }
      return [
        type,
        {
          timestamp: new Date(timestamp).toISOString(),
          providerId: String(configured?.providerId ?? '0')
        }
      ];
    }));
  }
  const collection = await client.collect({
    stats,
    mode,
    cursors,
    runStartedAt,
    onEntries: async (entries) => {
      normalizedCount += entries.length;
      for (const entry of entries) identities.push(`${entry.observableType}|${entry.observable}`);
    }
  });
  stats.duration_ms = Date.now() - startedAt;
  console.log(JSON.stringify({
    mode: 'dry_run',
    strategy: mode,
    production_writes: false,
    normalized_count: normalizedCount,
    snapshot_hash: mode === 'full_reconciliation'
      ? buildUsomCanonicalSnapshotHash(identities)
      : null,
    cursor_before: cursors,
    cursor_after: { ...cursors, ...collection.highwaters },
    query_windows: collection.queryWindows,
    pagination_stable: collection.paginationStable !== false,
    reconciliation_would_apply: mode !== 'full_reconciliation'
      || collection.paginationStable !== false,
    stats
  }, null, 2));
}

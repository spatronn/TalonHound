import {
  compareUsomHighwaters,
  highwaterFromModel,
  normalizeUsomModel,
  parseProviderDate,
  sanitizeUsomLogValue,
  USOM_SUPPORTED_API_TYPES
} from './usomNormalizer.js';
import { throwIfAborted } from './job-cancellation.js';

export const USOM_API_BASE_URL_DEFAULT = 'https://siberguvenlik.gov.tr/api';
export const USOM_API_PER_PAGE_DEFAULT = 5000;
export const USOM_API_TIMEOUT_MS_DEFAULT = 30_000;
export const USOM_API_MAX_RETRIES_DEFAULT = 5;
export const USOM_API_REQUEST_DELAY_MS_DEFAULT = 250;
export const USOM_CURSOR_OVERLAP_HOURS_DEFAULT = 24;
export const USOM_LOOKUP_CACHE_TTL_HOURS_DEFAULT = 24;
export const USOM_INCREMENTAL_MAX_RECORDS_DEFAULT = 100_000;
export const USOM_RUN_MODES = Object.freeze(['incremental', 'full_reconciliation', 'dry_run']);

const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);
const LOOKUP_DEFINITIONS = Object.freeze([
  ['descriptions', '/address-description/index'],
  ['sources', '/address-source/index'],
  ['connectionTypes', '/address-connection-type/index']
]);

function clampInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

export function resolveUsomApiConfig(input = {}) {
  const rawBaseUrl = String(input.baseUrl || USOM_API_BASE_URL_DEFAULT).trim().replace(/\/+$/, '');
  let parsedBaseUrl;
  try {
    parsedBaseUrl = new URL(rawBaseUrl);
  } catch {
    throw new TypeError('USOM_API_BASE_URL must be a valid URL');
  }
  if (
    parsedBaseUrl.username
    || parsedBaseUrl.password
    || parsedBaseUrl.search
    || parsedBaseUrl.hash
    || (
      !input.allowNonOfficialBaseUrl
      && (parsedBaseUrl.protocol !== 'https:' || parsedBaseUrl.hostname !== 'siberguvenlik.gov.tr')
    )
  ) {
    throw new TypeError('USOM_API_BASE_URL must use the official https://siberguvenlik.gov.tr API');
  }
  return {
    baseUrl: rawBaseUrl,
    perPage: clampInt(input.perPage, USOM_API_PER_PAGE_DEFAULT, 1, 5000),
    timeoutMs: clampInt(input.timeoutMs, USOM_API_TIMEOUT_MS_DEFAULT, 1000, 120_000),
    maxRetries: clampInt(input.maxRetries, USOM_API_MAX_RETRIES_DEFAULT, 0, 10),
    requestDelayMs: clampInt(input.requestDelayMs, USOM_API_REQUEST_DELAY_MS_DEFAULT, 0, 10_000),
    cursorOverlapHours: clampInt(
      input.cursorOverlapHours,
      USOM_CURSOR_OVERLAP_HOURS_DEFAULT,
      1,
      168
    ),
    lookupCacheTtlHours: clampInt(
      input.lookupCacheTtlHours,
      USOM_LOOKUP_CACHE_TTL_HOURS_DEFAULT,
      1,
      168
    ),
    incrementalMaxRecords: clampInt(
      input.incrementalMaxRecords,
      USOM_INCREMENTAL_MAX_RECORDS_DEFAULT,
      1_000,
      5_000_000
    )
  };
}

export function createUsomRunDetails() {
  return {
    api_total_domain: 0,
    api_total_url: 0,
    api_total_ip: 0,
    api_total_ip6: 0,
    api_total_ip6net: 0,
    pages_domain: 0,
    pages_url: 0,
    pages_ip: 0,
    pages_ip6: 0,
    pages_ip6net: 0,
    pages_fetched: 0,
    normalized: 0,
    api_filtered_total: 0,
    skipped_invalid: 0,
    skipped_unsupported_ip_network: 0,
    lookup_refresh_success: 0,
    lookup_refresh_failed: 0,
    lookup_cache_fresh: 0,
    lookup_cache_not_modified: 0,
    lookup_cache_stale_fallback: 0,
    request_count: 0,
    retry_count: 0,
    rate_limit_count: 0,
    duration_ms: 0
  };
}

function parseRetryAfter(value, nowMs = Date.now()) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  if (/^\d+(?:\.\d+)?$/.test(raw)) return Math.max(0, Math.ceil(Number(raw) * 1000));
  const dateMs = Date.parse(raw);
  if (!Number.isFinite(dateMs)) return null;
  return Math.max(0, dateMs - nowMs);
}

function defaultSleep(ms, signal) {
  if (!ms) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const onDone = () => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    };
    const timer = setTimeout(onDone, ms);
    if (!signal) return;
    function onAbort() {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      reject(signal.reason instanceof Error ? signal.reason : new Error('USOM request aborted'));
    }
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

function retryDelayMs(attempt, retryAfter, randomFn) {
  if (retryAfter != null) return Math.min(retryAfter, 120_000);
  const exponential = Math.min(500 * (2 ** attempt), 30_000);
  return Math.floor(exponential + exponential * 0.25 * randomFn());
}

function isRetryableNetworkError(err) {
  const code = String(err?.code || err?.cause?.code || '').toUpperCase();
  return err?.name === 'AbortError'
    || err?.name === 'TimeoutError'
    || ['ETIMEDOUT', 'ECONNRESET', 'EAI_AGAIN', 'ENETUNREACH', 'ECONNREFUSED'].includes(code);
}

export class UsomApiError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'UsomApiError';
    Object.assign(this, details);
  }
}

function validatePagePayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new UsomApiError('USOM API response must be an object', { code: 'invalid_schema' });
  }
  if (!Array.isArray(payload.models)) {
    throw new UsomApiError('USOM API response is missing models', { code: 'invalid_schema' });
  }
  for (const key of ['totalCount', 'count', 'page', 'pageCount']) {
    if (!Number.isInteger(payload[key]) || payload[key] < 0) {
      throw new UsomApiError(`USOM API response has invalid ${key}`, { code: 'invalid_schema' });
    }
  }
  if (Number(payload.count) !== payload.models.length) {
    throw new UsomApiError('USOM API response count does not match models length', {
      code: 'invalid_schema'
    });
  }
  return payload;
}

export function createUsomApiClient(options = {}) {
  const config = resolveUsomApiConfig(options);
  const fetchFn = options.fetchFn || globalThis.fetch;
  const sleepFn = options.sleepFn || defaultSleep;
  const randomFn = options.randomFn || Math.random;
  const logger = options.logger || console;
  if (typeof fetchFn !== 'function') throw new TypeError('fetchFn is required');

  async function requestJson(pathname, query, stats, signal, requestOptions = {}) {
    const url = new URL(`${config.baseUrl}${pathname}`);
    for (const [key, value] of Object.entries(query || {})) {
      if (value !== undefined && value !== null && value !== '') url.searchParams.set(key, String(value));
    }

    for (let attempt = 0; attempt <= config.maxRetries; attempt += 1) {
      throwIfAborted(signal);
      stats.request_count += 1;
      const controller = new AbortController();
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, config.timeoutMs);
      const abortParent = () => controller.abort(signal?.reason);
      signal?.addEventListener('abort', abortParent, { once: true });

      try {
        const response = await fetchFn(url, {
          method: 'GET',
          headers: {
            Accept: 'application/json',
            'User-Agent': 'TalonHound/1.0',
            ...(requestOptions.headers || {})
          },
          signal: controller.signal
        });
        if (response.status === 304 && requestOptions.allowNotModified) {
          return {
            notModified: true,
            lastModified: response.headers?.get?.('last-modified') || null
          };
        }
        if (!response.ok) {
          const retryable = RETRYABLE_STATUS.has(response.status);
          if (response.status === 429) stats.rate_limit_count += 1;
          if (!retryable || attempt >= config.maxRetries) {
            throw new UsomApiError(`USOM API request failed with HTTP ${response.status}`, {
              code: 'http_error',
              statusCode: response.status,
              retryable
            });
          }
          stats.retry_count += 1;
          const retryAfter = parseRetryAfter(response.headers?.get?.('retry-after'));
          await sleepFn(retryDelayMs(attempt, retryAfter, randomFn), signal);
          continue;
        }

        let payload;
        try {
          payload = await response.json();
        } catch {
          throw new UsomApiError('USOM API returned malformed JSON', { code: 'malformed_json' });
        }
        const validated = validatePagePayload(payload);
        Object.defineProperty(validated, 'providerLastModified', {
          value: response.headers?.get?.('last-modified') || null,
          enumerable: false
        });
        return validated;
      } catch (err) {
        if (signal?.aborted) {
          throwIfAborted(signal);
        }
        if (err instanceof UsomApiError) {
          err.pathname ??= pathname;
          err.apiType ??= query?.type || null;
          err.requestPage ??= query?.page || null;
          const retryablePayloadError = ['invalid_schema', 'malformed_json'].includes(err.code);
          if (!retryablePayloadError || attempt >= config.maxRetries) throw err;
          stats.retry_count += 1;
          logger.warn?.(
            `[usom-api] retry attempt=${attempt + 1} reason=${err.code}`
            + ` type=${sanitizeUsomLogValue(err.apiType || '-')}`
            + ` page=${sanitizeUsomLogValue(err.requestPage || '-')}`
          );
          await sleepFn(retryDelayMs(attempt, null, randomFn), signal);
          continue;
        }
        const networkError = timedOut
          ? Object.assign(new Error('USOM API request timed out'), { name: 'TimeoutError', code: 'ETIMEDOUT' })
          : err;
        if (!isRetryableNetworkError(networkError) || attempt >= config.maxRetries) {
          throw new UsomApiError(sanitizeUsomLogValue(networkError?.message || 'USOM API network error'), {
            code: timedOut ? 'timeout' : 'network_error',
            retryable: isRetryableNetworkError(networkError),
            cause: networkError
          });
        }
        stats.retry_count += 1;
        logger.warn?.(`[usom-api] retry attempt=${attempt + 1} reason=${timedOut ? 'timeout' : 'network'}`);
        await sleepFn(retryDelayMs(attempt, null, randomFn), signal);
      } finally {
        clearTimeout(timer);
        signal?.removeEventListener('abort', abortParent);
      }
    }
    throw new UsomApiError('USOM API retry budget exhausted', { code: 'retry_exhausted' });
  }

  async function walkPages(pathname, query, stats, signal, onPage, walkOptions = {}) {
    let requestPage = 1;
    let expectedPageCount = null;
    let expectedTotal = null;
    let latestTotal = null;
    let paginationStable = true;
    let rawCount = 0;
    const seenResponsePages = new Set();

    while (expectedPageCount == null || requestPage <= expectedPageCount) {
      const payload = await requestJson(pathname, {
        ...query,
        page: requestPage,
        'per-page': config.perPage
      }, stats, signal, requestPage === 1 ? {
        headers: walkOptions.headers,
        allowNotModified: walkOptions.allowNotModified
      } : {});
      if (payload.notModified) {
        return {
          notModified: true,
          lastModified: payload.lastModified || null,
          totalCount: 0,
          pages: 0,
          rawCount: 0
        };
      }
      if (requestPage === 1) walkOptions.onResponseMetadata?.({
        lastModified: payload.providerLastModified || null
      });
      const responsePage = Number(payload.page);
      if (seenResponsePages.has(responsePage)) {
        throw new UsomApiError('USOM API repeated a pagination page', { code: 'pagination_stalled' });
      }
      seenResponsePages.add(responsePage);
      if (responsePage !== requestPage - 1) {
        throw new UsomApiError(`USOM API page progress mismatch: request=${requestPage}, response=${responsePage}`, {
          code: 'pagination_mismatch'
        });
      }

      const pageCount = Number(payload.pageCount);
      const totalCount = Number(payload.totalCount);
      if (expectedPageCount == null) {
        expectedPageCount = pageCount;
        expectedTotal = totalCount;
        latestTotal = totalCount;
      } else if (pageCount !== expectedPageCount || totalCount !== expectedTotal) {
        if (!walkOptions.allowPaginationChanges) {
          throw new UsomApiError('USOM API pagination totals changed during the run', {
            code: 'pagination_changed'
          });
        }
        paginationStable = false;
        expectedPageCount = Math.max(expectedPageCount, pageCount);
        latestTotal = totalCount;
      }
      if (!payload.models.length && totalCount > rawCount) {
        if (!walkOptions.allowPaginationChanges) {
          throw new UsomApiError('USOM API returned an empty page before pagination completed', {
            code: 'pagination_incomplete'
          });
        }
        paginationStable = false;
        break;
      }

      rawCount += payload.models.length;
      await onPage(payload.models, {
        requestPage,
        responsePage,
        pageCount,
        totalCount
      });
      if (pageCount === 0 || requestPage >= expectedPageCount) break;
      requestPage += 1;
      await sleepFn(config.requestDelayMs, signal);
    }

    if (rawCount !== expectedTotal) {
      if (!walkOptions.allowPaginationChanges) {
        throw new UsomApiError(`USOM API total mismatch: expected=${expectedTotal}, received=${rawCount}`, {
          code: 'total_mismatch'
        });
      }
      paginationStable = false;
    }
    return {
      totalCount: latestTotal ?? expectedTotal ?? 0,
      initialTotalCount: expectedTotal || 0,
      pages: seenResponsePages.size,
      rawCount,
      paginationStable
    };
  }

  async function refreshLookups(stats, signal, {
    lookupCache = {},
    persistLookup = null,
    now = new Date()
  } = {}) {
    const lookups = {
      descriptions: new Map(),
      sources: new Map(),
      connectionTypes: new Map()
    };
    for (const [group, pathname] of LOOKUP_DEFINITIONS) {
      const cached = lookupCache?.[group] || null;
      const cachedMap = cached?.values instanceof Map
        ? cached.values
        : new Map((cached?.rows || []).map((row) => [String(row?.id ?? '').trim(), row]).filter(([id]) => id));
      const cacheAgeMs = cached?.updatedAt ? now.getTime() - new Date(cached.updatedAt).getTime() : Infinity;
      if (cachedMap.size && cacheAgeMs >= 0 && cacheAgeMs < config.lookupCacheTtlHours * 3_600_000) {
        lookups[group] = cachedMap;
        stats.lookup_cache_fresh += 1;
        continue;
      }

      const refreshedRows = [];
      let responseLastModified = null;
      try {
        const result = await walkPages(pathname, {}, stats, signal, async (models) => {
          for (const row of models) {
            const id = String(row?.id ?? '').trim();
            if (id) {
              lookups[group].set(id, row);
              refreshedRows.push(row);
            }
          }
        }, {
          headers: cached?.lastModified ? { 'If-Modified-Since': cached.lastModified } : undefined,
          allowNotModified: Boolean(cached?.lastModified),
          onResponseMetadata: (metadata) => {
            responseLastModified = metadata.lastModified;
          }
        });
        if (result.notModified) {
          lookups[group] = cachedMap;
          stats.lookup_cache_not_modified += 1;
          await persistLookup?.(group, {
            rows: cached?.rows || [...cachedMap.values()],
            lastModified: result.lastModified || cached?.lastModified || null,
            checkedAt: now
          });
        } else {
          await persistLookup?.(group, {
            rows: refreshedRows,
            lastModified: responseLastModified,
            checkedAt: now
          });
        }
        stats.lookup_refresh_success += 1;
      } catch (err) {
        stats.lookup_refresh_failed += 1;
        if (cachedMap.size) {
          lookups[group] = cachedMap;
          stats.lookup_cache_stale_fallback += 1;
        }
        logger.warn?.(`[usom-api] lookup_failed group=${group} reason=${sanitizeUsomLogValue(err?.message)}`);
      }
      await sleepFn(config.requestDelayMs, signal);
    }
    return lookups;
  }

  async function collect({
    signal,
    onEntries = async () => {},
    types = USOM_SUPPORTED_API_TYPES,
    stats = createUsomRunDetails(),
    mode = 'full_reconciliation',
    cursors = {},
    runStartedAt = new Date(),
    lookupCache = {},
    persistLookup = null
  } = {}) {
    if (!USOM_RUN_MODES.includes(mode)) {
      throw new UsomApiError(`Unsupported USOM run mode: ${sanitizeUsomLogValue(mode)}`, {
        code: 'unsupported_run_mode'
      });
    }
    const startedAt = Date.now();
    const fixedUpperBound = new Date(runStartedAt);
    if (Number.isNaN(fixedUpperBound.getTime())) {
      throw new UsomApiError('USOM run start must be a valid date', { code: 'invalid_run_start' });
    }
    const lookups = await refreshLookups(stats, signal, {
      lookupCache,
      persistLookup,
      now: fixedUpperBound
    });
    const highwaters = {};
    const queryWindows = {};
    let paginationStable = true;

    for (const apiType of types) {
      if (!USOM_SUPPORTED_API_TYPES.includes(apiType)) {
        throw new UsomApiError(`Unsupported configured USOM type: ${sanitizeUsomLogValue(apiType)}`, {
          code: 'unsupported_configured_type'
        });
      }
      const cursor = cursors?.[apiType] || null;
      const cursorTime = cursor?.timestamp ? new Date(cursor.timestamp).getTime() : null;
      if (cursor?.timestamp && !Number.isFinite(cursorTime)) {
        throw new UsomApiError(`USOM ${apiType} cursor is invalid`, {
          code: 'invalid_cursor',
          apiType
        });
      }
      if (cursorTime != null && cursorTime > fixedUpperBound.getTime()) {
        throw new UsomApiError(`USOM ${apiType} cursor is in the future`, {
          code: 'future_cursor',
          apiType
        });
      }
      const lowerBound = mode === 'incremental' && cursorTime != null
        ? new Date(cursorTime - config.cursorOverlapHours * 3_600_000)
        : null;
      const query = {
        type: apiType,
        date_gte: lowerBound?.toISOString(),
        date_lte: fixedUpperBound.toISOString()
      };
      queryWindows[apiType] = {
        date_gte: query.date_gte || null,
        date_lte: query.date_lte
      };
      let typeHighwater = null;
      const pageResult = await walkPages('/address/index', query, stats, signal, async (models, page) => {
        if (
          mode === 'incremental'
          && page.requestPage === 1
          && page.totalCount > config.incrementalMaxRecords
        ) {
          throw new UsomApiError(
            `USOM incremental ${apiType} result exceeded safety limit`,
            {
              code: 'filter_ignored',
              apiType,
              totalCount: page.totalCount,
              incrementalMaxRecords: config.incrementalMaxRecords
            }
          );
        }
        const entries = [];
        for (const model of models) {
          const modelType = String(model?.type || '').trim().toLowerCase();
          if (modelType !== apiType) {
            throw new UsomApiError(`USOM API ignored type filter for ${apiType}`, {
              code: 'filter_ignored',
              apiType
            });
          }
          const providerDate = parseProviderDate(model?.date);
          if (mode === 'incremental' && !providerDate.valid) {
            throw new UsomApiError(`USOM incremental ${apiType} model has invalid date`, {
              code: 'invalid_incremental_date',
              apiType
            });
          }
          if (providerDate.valid) {
            const modelTime = new Date(providerDate.utc).getTime();
            if (
              modelTime > fixedUpperBound.getTime()
              || (lowerBound && modelTime < lowerBound.getTime())
            ) {
              throw new UsomApiError(`USOM API ignored date bounds for ${apiType}`, {
                code: 'filter_ignored',
                apiType
              });
            }
          }
          const modelHighwater = highwaterFromModel(model);
          if (mode === 'incremental' && !modelHighwater) {
            throw new UsomApiError(`USOM incremental ${apiType} model is missing cursor fields`, {
              code: 'invalid_incremental_highwater',
              apiType
            });
          }
          if (modelHighwater && compareUsomHighwaters(modelHighwater, typeHighwater) > 0) {
            typeHighwater = modelHighwater;
          }
          const normalized = normalizeUsomModel(model, apiType, lookups);
          if (!normalized.ok) {
            if (normalized.reason === 'unsupported_ip_network') stats.skipped_unsupported_ip_network += 1;
            else stats.skipped_invalid += 1;
            continue;
          }
          entries.push(normalized.entry);
        }
        stats.normalized += entries.length;
        await onEntries(entries, { apiType, ...page });
      }, {
        allowPaginationChanges: mode === 'full_reconciliation'
      });
      if (pageResult.paginationStable === false) paginationStable = false;
      stats[`api_total_${apiType}`] = pageResult.totalCount;
      stats[`pages_${apiType}`] = pageResult.pages;
      if (pageResult.rawCount > 0 && typeHighwater) {
        if (
          mode === 'full_reconciliation'
          || !cursor
          || compareUsomHighwaters(typeHighwater, cursor) > 0
        ) {
          highwaters[apiType] = typeHighwater;
        }
      }
      await sleepFn(config.requestDelayMs, signal);
    }
    stats.pages_fetched = types.reduce(
      (sum, type) => sum + Number(stats[`pages_${type}`] || 0),
      0
    );
    stats.api_filtered_total = mode === 'incremental'
      ? types.reduce((sum, type) => sum + Number(stats[`api_total_${type}`] || 0), 0)
      : 0;
    stats.duration_ms = Date.now() - startedAt;
    return {
      stats,
      lookups,
      highwaters,
      queryWindows,
      paginationStable,
      runStartedAt: fixedUpperBound.toISOString()
    };
  }

  return { config, requestJson, walkPages, refreshLookups, collect };
}

import {
  FILESCAN_PROVIDER,
  FILESCAN_API_BASE,
  FILESCAN_SEARCH_PATH,
  maskApiKey,
  normalizeFilescanResponse,
  filescanHttpError,
  normalizeFilescanCacheKey
} from '../lib/filescanEnrichment.js';

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_TTL_HOURS = 24;
const DEFAULT_RATE_LIMIT_PER_MINUTE = 10;
const FORCE_COOLDOWN_MS = 5 * 60 * 1000;
// Known SHA256 used for connection test (EICAR standard test file)
const TEST_IOC_VALUE = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
const TEST_IOC_TYPE = 'hash';

export { maskApiKey, FILESCAN_PROVIDER };

export async function getFilescanConfig(pool) {
  const envKey = String(process.env.FILESCAN_API_KEY || '').trim();
  const { rows } = await pool.query(
    `SELECT provider, enabled, api_key, ttl_hours, timeout_ms, config,
            last_test_at, last_success_at, last_error_at, last_error_message
     FROM threat_intel_provider_configs WHERE provider = $1 LIMIT 1`,
    [FILESCAN_PROVIDER]
  );
  const row = rows[0] || null;
  const dbKey = String(row?.api_key || '').trim();
  const apiKey = dbKey || envKey;

  const cfg = row?.config && typeof row.config === 'object' ? row.config : {};
  const rateLimitPerMinute = Math.max(1, Number(cfg.rate_limit_per_minute ?? DEFAULT_RATE_LIMIT_PER_MINUTE));

  const ttlHours = Math.max(1, Number(row?.ttl_hours || process.env.FILESCAN_CACHE_TTL_HOURS || DEFAULT_TTL_HOURS));
  const timeoutMs = Math.max(3000, Number(row?.timeout_ms || process.env.FILESCAN_TIMEOUT_MS || DEFAULT_TIMEOUT_MS));

  return {
    provider_key: FILESCAN_PROVIDER,
    display_name: 'Filescan.io',
    enabled: row?.enabled === true,
    // API key is optional — provider can work without one (lower rate limits)
    configured: true,
    apiKey: apiKey || null,
    api_key_masked: maskApiKey(apiKey),
    api_key_set: Boolean(apiKey),
    source: dbKey ? 'db' : (envKey ? 'env' : 'none'),
    cache_ttl_hours: ttlHours,
    timeout_ms: timeoutMs,
    rate_limit_per_minute: rateLimitPerMinute,
    last_test_at: row?.last_test_at || null,
    last_success_at: row?.last_success_at || null,
    last_error_at: row?.last_error_at || null,
    last_error_message: row?.last_error_message || null
  };
}

export function isCacheFresh(row, config, { force = false } = {}) {
  if (!row?.last_enriched_at) return false;
  const at = Date.parse(row.last_enriched_at);
  if (!Number.isFinite(at)) return false;
  const ttlMs = Math.max(1, Number(config?.cache_ttl_hours || DEFAULT_TTL_HOURS)) * 60 * 60 * 1000;
  const ageMs = Date.now() - at;

  if (row.provider_status === 'failed' || row.provider_status === 'rate_limited') {
    return ageMs < 60 * 60 * 1000; // 1-hour cooldown for failures
  }

  if (force) {
    const summary = row.normalized_summary && typeof row.normalized_summary === 'object'
      ? row.normalized_summary : {};
    const lastForce = summary.last_force_refresh_at ? Date.parse(summary.last_force_refresh_at) : NaN;
    if (Number.isFinite(lastForce) && (Date.now() - lastForce) < FORCE_COOLDOWN_MS) {
      return true; // within cooldown window, treat as fresh
    }
    return false;
  }

  return row.provider_status === 'success' && ageMs < ttlMs;
}

export async function getEnrichmentByIoc(pool, iocType, iocValue) {
  const cacheKey = normalizeFilescanCacheKey(iocType, iocValue);
  const { rows } = await pool.query(
    `SELECT * FROM ioc_filescan_enrichment WHERE cache_key = $1 LIMIT 1`,
    [cacheKey]
  );
  return rows[0] || null;
}

export async function upsertFilescanEnrichment(pool, record) {
  const now = new Date().toISOString();
  const cacheKey = normalizeFilescanCacheKey(record.ioc_type, record.ioc_value);
  const summary = { ...(record.normalized_summary || {}), provider_status: record.provider_status };

  const { rows } = await pool.query(
    `INSERT INTO ioc_filescan_enrichment (
      cache_key, ioc_type, ioc_value,
      provider_status, normalized_summary, raw_json,
      error_message, last_enriched_at, updated_at
    ) VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8::timestamptz, NOW())
    ON CONFLICT (cache_key) DO UPDATE SET
      provider_status    = EXCLUDED.provider_status,
      normalized_summary = EXCLUDED.normalized_summary,
      raw_json           = EXCLUDED.raw_json,
      error_message      = EXCLUDED.error_message,
      last_enriched_at   = EXCLUDED.last_enriched_at,
      updated_at         = NOW()
    RETURNING *`,
    [
      cacheKey,
      record.ioc_type,
      record.ioc_value,
      record.provider_status,
      JSON.stringify(summary),
      record.raw_json ? JSON.stringify(record.raw_json) : null,
      record.error_message || null,
      now
    ]
  );
  return rows[0];
}

export function rowToApiPayload(row, { cached = false, iocType = null, iocValue = null, providerStatus = null } = {}) {
  if (providerStatus && !row) {
    return {
      enriched: false,
      cached: false,
      ioc_type: iocType,
      ioc_value: iocValue,
      provider: FILESCAN_PROVIDER,
      provider_status: providerStatus
    };
  }
  if (!row) {
    return { enriched: false, cached: false, ioc_type: iocType, ioc_value: iocValue, provider: FILESCAN_PROVIDER };
  }
  const summary = row.normalized_summary && typeof row.normalized_summary === 'object'
    ? row.normalized_summary : {};
  const status = row.provider_status || summary.provider_status || 'unknown';
  return {
    enriched: status === 'success',
    cached,
    ioc_type: row.ioc_type || iocType,
    ioc_value: row.ioc_value || iocValue,
    provider: FILESCAN_PROVIDER,
    provider_status: status,
    ...summary,
    error_message: row.error_message || null,
    last_enriched_at: row.last_enriched_at || summary.fetched_at || null
  };
}

/**
 * @param {string} iocValue
 * @param {{ apiKey: string|null, timeout_ms: number }} config
 * @param {{ fetchImpl?: typeof fetch }} [options]
 */
export async function fetchFilescanSearch(iocValue, config, options = {}) {
  const fetchImpl = options.fetchImpl || fetch;
  const params = new URLSearchParams({ query: String(iocValue).trim() });
  const url = `${FILESCAN_API_BASE}${FILESCAN_SEARCH_PATH}?${params.toString()}`;

  const headers = { Accept: 'application/json' };
  if (config.apiKey) {
    headers['X-Api-Key'] = config.apiKey;
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), config.timeout_ms);
  try {
    const res = await fetchImpl(url, { signal: ctrl.signal, headers });
    if (!res.ok) {
      const mapped = filescanHttpError(res.status);
      const err = new Error(mapped.message);
      err.code = mapped.code;
      err.provider_status = mapped.provider_status;
      err.status = res.status;
      if (res.status === 429) {
        const retryAfter = res.headers.get('retry-after');
        if (retryAfter) err.retryAfter = retryAfter;
      }
      throw err;
    }
    const raw = await res.json();
    return raw;
  } catch (err) {
    if (err?.name === 'AbortError') {
      const timeoutErr = new Error('Filescan.io lookup timed out');
      timeoutErr.code = 'timeout';
      timeoutErr.provider_status = 'failed';
      throw timeoutErr;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Supported IOC types for Filescan.io direct lookup.
 * @param {string} iocType
 */
export function isFilescanSupportedType(iocType) {
  const t = String(iocType || '').trim().toLowerCase();
  // Filescan enrichment is scoped to file hashes only.
  // URL/domain/IP lookup returns little signal and adds UI noise.
  return new Set(['file_hash', 'hash', 'md5', 'sha1', 'sha256']).has(t);
}

/**
 * @param {import('pg').Pool} pool
 * @param {string} iocType
 * @param {string} iocValue
 * @param {{ force?: boolean, fetchImpl?: typeof fetch }} [options]
 */
export async function enrichIocWithFilescan(pool, iocType, iocValue, options = {}) {
  const rawType = String(iocType || '').trim();
  const rawValue = String(iocValue || '').trim();

  if (!rawType || !rawValue) {
    const err = new Error('IOC type and value are required');
    err.code = 'invalid_input';
    err.provider_status = 'invalid_input';
    throw err;
  }

  if (!isFilescanSupportedType(rawType)) {
    return {
      row: null,
      cached: false,
      skipped: true,
      provider_status: 'unsupported_type',
      ioc_type: rawType,
      ioc_value: rawValue
    };
  }

  const config = await getFilescanConfig(pool);
  if (!config.enabled) {
    return {
      row: null,
      cached: false,
      skipped: true,
      provider_status: 'disabled',
      ioc_type: rawType,
      ioc_value: rawValue
    };
  }

  const force = options.force === true;
  const existing = await getEnrichmentByIoc(pool, rawType, rawValue);
  if (existing && isCacheFresh(existing, config, { force })) {
    return { row: existing, cached: true, skipped: false, provider_status: existing.provider_status, ioc_type: rawType, ioc_value: rawValue };
  }

  try {
    const raw = await fetchFilescanSearch(rawValue, {
      apiKey: config.apiKey,
      timeout_ms: config.timeout_ms
    }, { fetchImpl: options.fetchImpl });

    const fetchedAt = new Date().toISOString();
    const normalized = normalizeFilescanResponse(raw, { iocType: rawType, iocValue: rawValue, fetchedAt });
    if (force) {
      normalized.last_force_refresh_at = fetchedAt;
    }

    const row = await upsertFilescanEnrichment(pool, {
      ioc_type: rawType,
      ioc_value: rawValue,
      provider_status: 'success',
      normalized_summary: normalized,
      raw_json: raw,
      error_message: null
    });
    return { row, cached: false, skipped: false, provider_status: 'success', ioc_type: rawType, ioc_value: rawValue };
  } catch (err) {
    const providerStatus = err.provider_status || (err.code === 'auth' ? 'auth_error' : 'failed');
    let errorMessage = String(err?.message || 'Filescan.io lookup failed').slice(0, 2000);
    if (err.retryAfter) errorMessage += ` (Retry-After: ${err.retryAfter})`;

    const failedSummary = {
      ioc_type: rawType,
      ioc_value: rawValue,
      fetched_at: new Date().toISOString(),
      provider_status: providerStatus,
      found: false,
      verdict: 'unknown'
    };

    const row = await upsertFilescanEnrichment(pool, {
      ioc_type: rawType,
      ioc_value: rawValue,
      provider_status: providerStatus,
      normalized_summary: failedSummary,
      raw_json: null,
      error_message: errorMessage
    });

    if (err.code === 'auth' || err.code === 'rate_limit') {
      const rethrow = new Error(errorMessage);
      rethrow.code = err.code;
      rethrow.provider_status = providerStatus;
      rethrow.row = row;
      if (err.retryAfter) rethrow.retryAfter = err.retryAfter;
      throw rethrow;
    }

    return { row, cached: false, skipped: false, provider_status: providerStatus, ioc_type: rawType, ioc_value: rawValue, error: err };
  }
}

export async function testFilescanConnection(pool, options = {}) {
  const config = await getFilescanConfig(pool);
  if (!config.enabled) {
    const err = new Error('Filescan.io provider is disabled');
    err.code = 'disabled';
    throw err;
  }

  const raw = await fetchFilescanSearch(TEST_IOC_VALUE, {
    apiKey: config.apiKey,
    timeout_ms: config.timeout_ms
  }, { fetchImpl: options.fetchImpl });

  const normalized = normalizeFilescanResponse(raw, { iocType: TEST_IOC_TYPE, iocValue: TEST_IOC_VALUE });
  return { ioc_value: TEST_IOC_VALUE, ioc_type: TEST_IOC_TYPE, ...normalized };
}

export { TEST_IOC_VALUE, TEST_IOC_TYPE };

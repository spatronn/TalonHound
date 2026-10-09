import { validatePublicIp, isValidIpAddress } from '../lib/publicIp.js';
import {
  URLSCAN_PROVIDER,
  URLSCAN_DISPLAY_NAME,
  URLSCAN_API_ORIGIN,
  URLSCAN_ASSESSMENT,
  URLSCAN_RESULT_UUID_RE,
  maskApiKey,
  buildUrlscanSearchQuery,
  clampSearchSize,
  clampDetailLimit,
  clampLookbackDays,
  urlscanAllowlistedFetch,
  normalizeSearchHit,
  selectDetailCandidates,
  normalizeResultDetail,
  buildUrlscanNormalizedSummary,
  deriveEvidenceAssessment,
  storeStatusForAssessment,
  buildCompactRawResponse,
  isSupportedUrlscanIocType,
  assessUrlPrivacyForLookup,
  DEFAULT_SEARCH_SIZE,
  DEFAULT_DETAIL_LIMIT,
  DEFAULT_LOOKBACK_DAYS
} from '../lib/urlscanEnrichment.js';

const DEFAULT_TIMEOUT_MS = 12000;
const DEFAULT_TTL_HOURS = 24;
const NO_RESULT_TTL_HOURS = 6;
const FORCE_COOLDOWN_MS = 5 * 60 * 1000;
const MAX_RETRIES = 2;

export { URLSCAN_PROVIDER, URLSCAN_DISPLAY_NAME, maskApiKey };

function parseProviderConfig(row) {
  const cfg = row?.config && typeof row.config === 'object' ? row.config : {};
  return {
    lookback_days: clampLookbackDays(cfg.lookback_days ?? DEFAULT_LOOKBACK_DAYS),
    search_size: clampSearchSize(cfg.search_size ?? DEFAULT_SEARCH_SIZE),
    detail_limit: clampDetailLimit(cfg.detail_limit ?? DEFAULT_DETAIL_LIMIT),
    no_result_ttl_hours: Math.min(48, Math.max(1, Number(cfg.no_result_ttl_hours ?? NO_RESULT_TTL_HOURS)))
  };
}

export async function getUrlscanConfig(pool) {
  const envKey = String(process.env.URLSCAN_API_KEY || '').trim();
  const { rows } = await pool.query(
    `SELECT provider, enabled, api_key, ttl_hours, timeout_ms, config,
            last_test_at, last_success_at, last_error_at, last_error_message
     FROM threat_intel_provider_configs WHERE provider = $1 LIMIT 1`,
    [URLSCAN_PROVIDER]
  );
  const row = rows[0] || null;
  const dbKey = String(row?.api_key || '').trim();
  const apiKey = dbKey || envKey;
  const extras = parseProviderConfig(row);
  const ttlHours = Math.max(1, Number(row?.ttl_hours || process.env.URLSCAN_CACHE_TTL_HOURS || DEFAULT_TTL_HOURS));
  const timeoutMs = Math.max(
    3000,
    Number(row?.timeout_ms || process.env.URLSCAN_TIMEOUT_MS || DEFAULT_TIMEOUT_MS)
  );

  return {
    provider_key: URLSCAN_PROVIDER,
    display_name: URLSCAN_DISPLAY_NAME,
    // Disabled until explicitly enabled (same posture as AbuseIPDB).
    enabled: row?.enabled === true,
    configured: Boolean(apiKey),
    apiKey,
    api_key_masked: maskApiKey(apiKey),
    source: dbKey ? 'db' : (envKey ? 'env' : 'none'),
    cache_ttl_hours: ttlHours,
    timeout_ms: timeoutMs,
    ...extras,
    last_test_at: row?.last_test_at || null,
    last_success_at: row?.last_success_at || null,
    last_error_at: row?.last_error_at || null,
    last_error_message: row?.last_error_message || null
  };
}

export function isCacheFresh(row, config, { force = false } = {}) {
  if (!row?.fetched_at) return false;
  const at = Date.parse(row.fetched_at);
  if (!Number.isFinite(at)) return false;
  const ageMs = Date.now() - at;
  const successTtlMs = Math.max(1, Number(config?.cache_ttl_hours || DEFAULT_TTL_HOURS)) * 3600 * 1000;
  const noResultTtlMs = Math.max(1, Number(config?.no_result_ttl_hours || NO_RESULT_TTL_HOURS)) * 3600 * 1000;

  if (row.status === 'rate_limited' || row.status === 'error') {
    return ageMs < 60 * 60 * 1000;
  }

  if (force) {
    const summary = row.normalized_summary && typeof row.normalized_summary === 'object'
      ? row.normalized_summary
      : {};
    const lastForce = summary.last_force_refresh_at ? Date.parse(summary.last_force_refresh_at) : NaN;
    if (Number.isFinite(lastForce) && (Date.now() - lastForce) < FORCE_COOLDOWN_MS) {
      return true;
    }
    return false;
  }

  if (row.status === 'not_found' || row.status === 'skipped') {
    return ageMs < noResultTtlMs;
  }

  if (row.status === 'success') {
    if (row.expires_at) {
      const exp = Date.parse(row.expires_at);
      if (Number.isFinite(exp)) return exp > Date.now();
    }
    return ageMs < successTtlMs;
  }

  return false;
}

export async function getUrlscanEnrichmentByIoc(pool, iocId) {
  const id = Number(iocId);
  if (!Number.isFinite(id) || id <= 0) return null;
  const { rows } = await pool.query(
    `SELECT * FROM ioc_enrichments
     WHERE ioc_id = $1 AND provider = $2
     ORDER BY fetched_at DESC NULLS LAST
     LIMIT 1`,
    [id, URLSCAN_PROVIDER]
  );
  return rows[0] || null;
}

export async function getUrlscanEnrichmentByValue(pool, iocValue, iocType) {
  const { rows } = await pool.query(
    `SELECT * FROM ioc_enrichments
     WHERE provider = $1 AND ioc_value = $2 AND ioc_type = $3
     LIMIT 1`,
    [URLSCAN_PROVIDER, iocValue, iocType]
  );
  return rows[0] || null;
}

export async function upsertUrlscanEnrichment(pool, record) {
  const fetchedAt = record.fetched_at || new Date().toISOString();
  const expiresAt = record.expires_at || null;
  const { rows } = await pool.query(
    `INSERT INTO ioc_enrichments (
      ioc_id, ioc_value, ioc_type, provider, status,
      normalized_summary, raw_response, error_message,
      fetched_at, expires_at, updated_at
    ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9::timestamptz,$10::timestamptz,NOW())
    ON CONFLICT (provider, ioc_value, ioc_type) DO UPDATE SET
      ioc_id = EXCLUDED.ioc_id,
      status = EXCLUDED.status,
      normalized_summary = EXCLUDED.normalized_summary,
      raw_response = EXCLUDED.raw_response,
      error_message = EXCLUDED.error_message,
      fetched_at = EXCLUDED.fetched_at,
      expires_at = EXCLUDED.expires_at,
      updated_at = NOW()
    RETURNING *`,
    [
      record.ioc_id,
      record.ioc_value,
      record.ioc_type,
      URLSCAN_PROVIDER,
      record.status,
      record.normalized_summary ? JSON.stringify(record.normalized_summary) : null,
      record.raw_response ? JSON.stringify(record.raw_response) : null,
      record.error_message || null,
      fetchedAt,
      expiresAt
    ]
  );
  return rows[0];
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoffMs(attempt, retryAfter) {
  const parsed = Number(retryAfter);
  if (Number.isFinite(parsed) && parsed > 0) {
    return Math.min(60_000, Math.max(500, parsed * 1000));
  }
  const base = Math.min(30_000, 500 * (2 ** attempt));
  const jitter = Math.floor(Math.random() * 250);
  return base + jitter;
}

async function fetchWithRetry(url, options, { retries = MAX_RETRIES } = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      return await urlscanAllowlistedFetch(url, options);
    } catch (err) {
      lastErr = err;
      const retryable = err?.code === 'rate_limit'
        || err?.code === 'provider_error'
        || err?.code === 'timeout';
      if (!retryable || attempt >= retries) throw err;
      await sleep(backoffMs(attempt, err.retryAfter));
    }
  }
  throw lastErr;
}

export async function searchUrlscan(query, config, options = {}) {
  const size = clampSearchSize(options.size ?? config.search_size);
  const params = new URLSearchParams({
    q: query,
    size: String(size)
  });
  const url = `${URLSCAN_API_ORIGIN}/api/v1/search?${params.toString()}`;
  const result = await fetchWithRetry(url, {
    apiKey: config.apiKey,
    timeoutMs: config.timeout_ms,
    fetchImpl: options.fetchImpl
  });
  const json = result.json || {};
  const results = Array.isArray(json.results) ? json.results : [];
  return {
    results,
    total: json.total,
    took: json.took,
    has_more: json.has_more === true,
    search_date_limit_days: json.search_date_limit_days ?? null,
    rateHeaders: result.rateHeaders
  };
}

export async function fetchUrlscanResult(scanId, config, options = {}) {
  const id = String(scanId || '').toLowerCase();
  if (!URLSCAN_RESULT_UUID_RE.test(id)) {
    const err = new Error('Invalid urlscan scan id');
    err.code = 'invalid_scan_id';
    err.provider_status = 'failed';
    throw err;
  }
  const url = `${URLSCAN_API_ORIGIN}/api/v1/result/${id}/`;
  const result = await fetchWithRetry(url, {
    apiKey: config.apiKey,
    timeoutMs: config.timeout_ms,
    fetchImpl: options.fetchImpl
  }, { retries: 1 });
  return normalizeResultDetail(result.json, id);
}

export async function fetchUrlscanQuotas(config, options = {}) {
  const url = `${URLSCAN_API_ORIGIN}/api/v1/quotas`;
  const result = await urlscanAllowlistedFetch(url, {
    apiKey: config.apiKey,
    timeoutMs: config.timeout_ms,
    fetchImpl: options.fetchImpl
  });
  const limits = result.json?.limits && typeof result.json.limits === 'object'
    ? result.json.limits
    : {};
  const search = limits.search && typeof limits.search === 'object' ? limits.search : null;
  return {
    scope: result.json?.scope || null,
    search: search ? {
      minute: search.minute ?? null,
      hour: search.hour ?? null,
      day: search.day ?? null
    } : null,
    maxSearchRangeMonths: limits.maxSearchRangeMonths ?? null,
    maxSearchResults: limits.maxSearchResults ?? null
  };
}

function rowToExpires(config, status, fetchedAt) {
  const base = fetchedAt ? new Date(fetchedAt) : new Date();
  const hours = status === 'not_found' || status === 'skipped'
    ? Number(config.no_result_ttl_hours || NO_RESULT_TTL_HOURS)
    : Number(config.cache_ttl_hours || DEFAULT_TTL_HOURS);
  return new Date(base.getTime() + hours * 3600 * 1000).toISOString();
}

export function rowToApiPayload(row, {
  cached = false,
  iocId = null,
  providerStatus = null,
  message = null
} = {}) {
  if (providerStatus && !row) {
    return {
      provider: URLSCAN_PROVIDER,
      status: providerStatus,
      provider_status: providerStatus,
      enriched: false,
      cached: false,
      ioc_id: iocId,
      message: message || null,
      summary: null
    };
  }
  if (!row) {
    return {
      provider: URLSCAN_PROVIDER,
      status: 'not_found',
      provider_status: 'not_run',
      enriched: false,
      cached: false,
      ioc_id: iocId,
      message: message || 'urlscan enrichment has not been run yet.',
      summary: null
    };
  }
  const summary = row.normalized_summary && typeof row.normalized_summary === 'object'
    ? row.normalized_summary
    : null;
  const assessment = summary?.evidence_assessment || null;
  return {
    provider: URLSCAN_PROVIDER,
    status: row.status,
    provider_status: row.status,
    evidence_assessment: assessment,
    evidence_assessment_label: summary?.evidence_assessment_label || null,
    enriched: row.status === 'success' || row.status === 'not_found' || row.status === 'skipped',
    cached,
    ioc_id: row.ioc_id || iocId,
    ioc_value: row.ioc_value,
    ioc_type: row.ioc_type,
    summary,
    error_message: row.error_message || null,
    message: row.error_message || message || null,
    fetched_at: row.fetched_at || null,
    expires_at: row.expires_at || null,
    is_authoritative_verdict: false,
    score_is_not_confidence: true
  };
}

/**
 * Passive-only enrichment for one IOC. Never submits URLs for scanning.
 */
export async function enrichIocWithUrlscan(pool, {
  iocId,
  iocValue,
  iocType,
  force = false,
  fetchImpl
} = {}) {
  const category = isSupportedUrlscanIocType(iocType);
  if (!category) {
    return {
      skipped: true,
      provider_status: 'unsupported',
      assessment: URLSCAN_ASSESSMENT.UNSUPPORTED,
      row: null
    };
  }

  if (category === 'ip') {
    if (!isValidIpAddress(iocValue)) {
      const err = new Error('Invalid IP address');
      err.code = 'invalid_ip';
      err.provider_status = 'unsupported';
      throw err;
    }
    if (!validatePublicIp(iocValue)) {
      return {
        skipped: true,
        provider_status: 'unsupported_private_ip',
        assessment: URLSCAN_ASSESSMENT.UNSUPPORTED,
        row: null
      };
    }
  }

  const config = await getUrlscanConfig(pool);
  if (!config.enabled) {
    return {
      skipped: true,
      provider_status: 'disabled',
      assessment: URLSCAN_ASSESSMENT.DISABLED,
      row: null
    };
  }
  if (!config.configured || !config.apiKey) {
    return {
      skipped: true,
      provider_status: 'not_configured',
      assessment: URLSCAN_ASSESSMENT.NOT_CONFIGURED,
      row: null
    };
  }

  if (category === 'url') {
    const privacy = assessUrlPrivacyForLookup(iocValue);
    if (!privacy.ok && privacy.reason !== 'empty' && privacy.reason !== 'invalid_url') {
      const fetchedAt = new Date().toISOString();
      const summary = buildUrlscanNormalizedSummary({
        category,
        observable: iocValue,
        searchMeta: {},
        hits: [],
        details: [],
        fetchedAt,
        assessment: URLSCAN_ASSESSMENT.PRIVACY_RESTRICTED,
        lookbackDays: config.lookback_days,
        searchSize: config.search_size
      });
      summary.privacy_reason = privacy.reason;
      const row = await upsertUrlscanEnrichment(pool, {
        ioc_id: iocId,
        ioc_value: iocValue,
        ioc_type: category,
        status: 'skipped',
        normalized_summary: summary,
        raw_response: null,
        error_message: privacy.message,
        fetched_at: fetchedAt,
        expires_at: rowToExpires(config, 'skipped', fetchedAt)
      });
      return {
        skipped: true,
        cached: false,
        provider_status: 'skipped',
        assessment: URLSCAN_ASSESSMENT.PRIVACY_RESTRICTED,
        row
      };
    }
  }

  const existing = await getUrlscanEnrichmentByValue(pool, iocValue, category)
    || (iocId ? await getUrlscanEnrichmentByIoc(pool, iocId) : null);

  if (existing && isCacheFresh(existing, config, { force })) {
    return {
      skipped: false,
      cached: true,
      provider_status: existing.status,
      assessment: existing.normalized_summary?.evidence_assessment || null,
      row: existing
    };
  }

  const built = buildUrlscanSearchQuery(category, iocValue, { lookbackDays: config.lookback_days });
  if (!built.ok) {
    if (built.reason === 'privacy_restricted') {
      const fetchedAt = new Date().toISOString();
      const summary = buildUrlscanNormalizedSummary({
        category,
        observable: iocValue,
        searchMeta: {},
        hits: [],
        details: [],
        fetchedAt,
        assessment: URLSCAN_ASSESSMENT.PRIVACY_RESTRICTED,
        lookbackDays: config.lookback_days,
        searchSize: config.search_size
      });
      summary.privacy_reason = built.privacy_reason;
      const row = await upsertUrlscanEnrichment(pool, {
        ioc_id: iocId,
        ioc_value: iocValue,
        ioc_type: category,
        status: 'skipped',
        normalized_summary: summary,
        raw_response: null,
        error_message: built.message,
        fetched_at: fetchedAt,
        expires_at: rowToExpires(config, 'skipped', fetchedAt)
      });
      return {
        skipped: true,
        cached: false,
        provider_status: 'skipped',
        assessment: URLSCAN_ASSESSMENT.PRIVACY_RESTRICTED,
        row
      };
    }
    const err = new Error(built.message || `Unsupported urlscan lookup (${built.reason})`);
    err.code = built.reason || 'unsupported';
    err.provider_status = 'unsupported';
    throw err;
  }

  let search;
  try {
    search = await searchUrlscan(built.query, config, {
      size: config.search_size,
      fetchImpl
    });
  } catch (err) {
    const fetchedAt = new Date().toISOString();
    const status = err.provider_status === 'rate_limited' ? 'rate_limited' : 'error';
    const assessment = err.provider_status === 'rate_limited'
      ? URLSCAN_ASSESSMENT.RATE_LIMITED
      : URLSCAN_ASSESSMENT.ERROR;
    const summary = buildUrlscanNormalizedSummary({
      category,
      observable: iocValue,
      searchMeta: {},
      hits: [],
      details: [],
      fetchedAt,
      assessment,
      lookbackDays: config.lookback_days,
      searchSize: config.search_size
    });
    const row = await upsertUrlscanEnrichment(pool, {
      ioc_id: iocId,
      ioc_value: iocValue,
      ioc_type: category,
      status,
      normalized_summary: summary,
      raw_response: null,
      error_message: err.message,
      fetched_at: fetchedAt,
      expires_at: rowToExpires(config, status, fetchedAt)
    });
    return {
      skipped: false,
      cached: false,
      provider_status: status,
      assessment,
      row,
      error: err
    };
  }

  const hits = [];
  for (const hit of search.results) {
    const n = normalizeSearchHit(hit, category, iocValue);
    if (n) hits.push(n);
  }

  const detailIds = selectDetailCandidates(hits, config.detail_limit);
  const details = [];
  for (const scanId of detailIds) {
    try {
      const detail = await fetchUrlscanResult(scanId, config, { fetchImpl });
      if (detail) details.push(detail);
      // Merge verdict from detail into matching hit when search lacked it
      if (detail) {
        const hit = hits.find((h) => h.scan_id === detail.scan_id);
        if (hit) {
          if (hit.malicious == null && detail.overall_malicious != null) {
            hit.malicious = detail.overall_malicious === true;
          }
          if (hit.urlscan_score == null && detail.urlscan_score != null) {
            hit.urlscan_score = detail.urlscan_score;
          }
          if (!hit.categories?.length && detail.categories?.length) {
            hit.categories = detail.categories;
          }
        }
      }
    } catch (err) {
      // Detail failures are non-fatal; keep search evidence.
      if (err?.code === 'rate_limit') {
        // Stop further detail fetches on rate limit.
        break;
      }
    }
  }

  const assessment = deriveEvidenceAssessment(category, hits);
  const fetchedAt = new Date().toISOString();
  let summary = buildUrlscanNormalizedSummary({
    category,
    observable: iocValue,
    searchMeta: search,
    hits,
    details,
    fetchedAt,
    assessment,
    lookbackDays: config.lookback_days,
    searchSize: config.search_size
  });
  if (force) {
    summary = { ...summary, last_force_refresh_at: fetchedAt };
  }

  const status = storeStatusForAssessment(assessment);
  const row = await upsertUrlscanEnrichment(pool, {
    ioc_id: iocId,
    ioc_value: iocValue,
    ioc_type: category,
    status,
    normalized_summary: summary,
    raw_response: buildCompactRawResponse({
      searchMeta: search,
      scanIds: hits.map((h) => h.scan_id),
      detailIds
    }),
    error_message: null,
    fetched_at: fetchedAt,
    expires_at: rowToExpires(config, status, fetchedAt)
  });

  // Mark provider last_success on usable lookups (including no_results).
  await pool.query(
    `UPDATE threat_intel_provider_configs
     SET last_success_at = NOW(), last_error_at = NULL, last_error_message = NULL, updated_at = NOW()
     WHERE provider = $1`,
    [URLSCAN_PROVIDER]
  ).catch(() => {});

  return {
    skipped: false,
    cached: false,
    provider_status: status,
    assessment,
    row
  };
}

/**
 * Connection test: GET /api/v1/quotas (read-only). Never submits a scan.
 */
export async function testUrlscanConnection(pool, { fetchImpl } = {}) {
  const config = await getUrlscanConfig(pool);
  if (!config.configured || !config.apiKey) {
    const err = new Error('urlscan.io API key is not configured');
    err.code = 'not_configured';
    throw err;
  }
  if (!config.enabled) {
    const err = new Error('urlscan.io provider is disabled');
    err.code = 'disabled';
    throw err;
  }

  const quotas = await fetchUrlscanQuotas(config, { fetchImpl });

  // Light search against a reserved domain to prove Search API access (read-only).
  const built = buildUrlscanSearchQuery('domain', 'example.com', { lookbackDays: 7 });
  const search = await searchUrlscan(built.query, config, { size: 1, fetchImpl });

  await pool.query(
    `UPDATE threat_intel_provider_configs
     SET last_test_at = NOW(), last_success_at = NOW(), last_error_at = NULL, last_error_message = NULL, updated_at = NOW()
     WHERE provider = $1`,
    [URLSCAN_PROVIDER]
  ).catch(() => {});

  return {
    ok: true,
    quotas,
    search_total: search.total ?? null,
    probe_query: 'domain:example.com (bounded)'
  };
}

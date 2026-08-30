import { validatePublicIp, isValidIpAddress } from '../lib/publicIp.js';
import {
  ABUSEIPDB_PROVIDER,
  ABUSEIPDB_API_BASE,
  maskApiKey,
  normalizeAbuseIpdbResponse,
  abuseIpdbHttpError
} from '../lib/abuseipdbEnrichment.js';

const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_TTL_HOURS = 24;
const DEFAULT_MAX_AGE_DAYS = 90;
const FORCE_COOLDOWN_MS = 5 * 60 * 1000;
const TEST_IP = '8.8.8.8';

function parseConfig(row) {
  const cfg = row?.config && typeof row.config === 'object' ? row.config : {};
  const maxAgeDays = Math.min(
    365,
    Math.max(1, Number(cfg.max_age_days ?? DEFAULT_MAX_AGE_DAYS))
  );
  const verbose = cfg.verbose === true;
  return { maxAgeDays, verbose };
}

export async function getAbuseIpdbConfig(pool) {
  const envKey = String(process.env.ABUSEIPDB_API_KEY || '').trim();
  const { rows } = await pool.query(
    `SELECT provider, enabled, api_key, ttl_hours, timeout_ms, config,
            last_test_at, last_success_at, last_error_at, last_error_message
     FROM threat_intel_provider_configs WHERE provider = $1 LIMIT 1`,
    [ABUSEIPDB_PROVIDER]
  );
  const row = rows[0] || null;
  const dbKey = String(row?.api_key || '').trim();
  const apiKey = dbKey || envKey;
  const { maxAgeDays, verbose } = parseConfig(row);
  const ttlHours = Math.max(1, Number(row?.ttl_hours || process.env.ABUSEIPDB_CACHE_TTL_HOURS || DEFAULT_TTL_HOURS));
  const timeoutMs = Math.max(
    3000,
    Number(row?.timeout_ms || process.env.ABUSEIPDB_TIMEOUT_MS || DEFAULT_TIMEOUT_MS)
  );

  return {
    provider_key: ABUSEIPDB_PROVIDER,
    display_name: 'AbuseIPDB',
    enabled: row?.enabled === true,
    configured: Boolean(apiKey),
    apiKey,
    api_key_masked: maskApiKey(apiKey),
    source: dbKey ? 'db' : (envKey ? 'env' : 'none'),
    cache_ttl_hours: ttlHours,
    timeout_ms: timeoutMs,
    max_age_days: maxAgeDays,
    verbose,
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

  if (row.max_age_days !== config.max_age_days || row.verbose_enabled !== config.verbose) {
    return false;
  }

  if (row.provider_status === 'failed' || row.provider_status === 'rate_limited') {
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

  return row.provider_status === 'success' && ageMs < ttlMs;
}

export async function getEnrichmentByIp(pool, ip) {
  const { rows } = await pool.query(
    `SELECT * FROM ioc_abuseipdb_enrichment WHERE ip = $1 LIMIT 1`,
    [ip]
  );
  return rows[0] || null;
}

function summaryFromRow(row) {
  if (!row) return null;
  const s = row.normalized_summary && typeof row.normalized_summary === 'object'
    ? row.normalized_summary
    : {};
  return s;
}

export function rowToApiPayload(row, {
  cached = false,
  enriched = true,
  ip = null,
  providerStatus = null
} = {}) {
  if (providerStatus && !row) {
    return {
      enriched: false,
      cached: false,
      ip,
      provider: ABUSEIPDB_PROVIDER,
      provider_status: providerStatus
    };
  }
  if (!row) {
    return { enriched: false, cached: false, ip, provider: ABUSEIPDB_PROVIDER };
  }
  const summary = summaryFromRow(row) || {};
  const status = row.provider_status || summary.provider_status || 'unknown';
  return {
    enriched: enriched && status === 'success',
    cached,
    ip: row.ip || ip,
    provider: ABUSEIPDB_PROVIDER,
    provider_status: status,
    ...summary,
    error_message: row.error_message || null,
    last_enriched_at: row.last_enriched_at || summary.fetched_at || null
  };
}

export async function upsertAbuseIpdbEnrichment(pool, record) {
  const now = new Date().toISOString();
  const summary = { ...(record.normalized_summary || {}), provider_status: record.provider_status };
  const { rows } = await pool.query(
    `INSERT INTO ioc_abuseipdb_enrichment (
      ip, provider_status, max_age_days, verbose_enabled, normalized_summary, raw_json, error_message, last_enriched_at, updated_at
    ) VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8::timestamptz,NOW())
    ON CONFLICT (ip) DO UPDATE SET
      provider_status = EXCLUDED.provider_status,
      max_age_days = EXCLUDED.max_age_days,
      verbose_enabled = EXCLUDED.verbose_enabled,
      normalized_summary = EXCLUDED.normalized_summary,
      raw_json = EXCLUDED.raw_json,
      error_message = EXCLUDED.error_message,
      last_enriched_at = EXCLUDED.last_enriched_at,
      updated_at = NOW()
    RETURNING *`,
    [
      record.ip,
      record.provider_status,
      record.max_age_days,
      record.verbose,
      JSON.stringify(summary),
      record.raw_json ? JSON.stringify(record.raw_json) : null,
      record.error_message,
      now
    ]
  );
  return rows[0];
}

/**
 * @param {string} ip
 * @param {{ apiKey: string, timeout_ms: number, max_age_days: number, verbose: boolean }} config
 * @param {{ fetchImpl?: typeof fetch }} [options]
 */
export async function fetchAbuseIpdbCheck(ip, config, options = {}) {
  const fetchImpl = options.fetchImpl || fetch;
  const params = new URLSearchParams({
    ipAddress: ip,
    maxAgeInDays: String(config.max_age_days),
    verbose: config.verbose ? 'true' : 'false'
  });
  const url = `${ABUSEIPDB_API_BASE}/check?${params.toString()}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), config.timeout_ms);
  try {
    const res = await fetchImpl(url, {
      signal: ctrl.signal,
      headers: {
        Key: config.apiKey,
        Accept: 'application/json'
      }
    });
    if (!res.ok) {
      const mapped = abuseIpdbHttpError(res.status);
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
    if (!raw?.data) {
      const err = new Error('AbuseIPDB returned empty response');
      err.code = 'unavailable';
      err.provider_status = 'failed';
      throw err;
    }
    return raw;
  } catch (err) {
    if (err?.name === 'AbortError') {
      const timeoutErr = new Error('AbuseIPDB lookup timed out');
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
 * @param {import('pg').Pool} pool
 * @param {string} ip
 * @param {{ force?: boolean, fetchImpl?: typeof fetch }} [options]
 */
export async function enrichIpWithAbuseIpdb(pool, ip, options = {}) {
  const rawInput = String(ip || '').trim();
  if (!rawInput || !isValidIpAddress(rawInput)) {
    const err = new Error('Invalid IP address');
    err.code = 'invalid_ip';
    err.provider_status = 'invalid_ip';
    throw err;
  }

  const publicIp = validatePublicIp(rawInput);
  if (!publicIp) {
    return {
      row: null,
      cached: false,
      skipped: true,
      provider_status: 'unsupported_private_ip',
      ip: rawInput.split('/')[0].trim()
    };
  }

  const config = await getAbuseIpdbConfig(pool);
  if (!config.configured) {
    return {
      row: null,
      cached: false,
      skipped: true,
      provider_status: 'not_configured',
      ip: publicIp
    };
  }
  if (!config.enabled) {
    return {
      row: null,
      cached: false,
      skipped: true,
      provider_status: 'disabled',
      ip: publicIp
    };
  }

  const force = options.force === true;
  const existing = await getEnrichmentByIp(pool, publicIp);
  if (existing && isCacheFresh(existing, config, { force })) {
    return { row: existing, cached: true, skipped: false, provider_status: existing.provider_status, ip: publicIp };
  }

  try {
    const raw = await fetchAbuseIpdbCheck(publicIp, {
      apiKey: config.apiKey,
      timeout_ms: config.timeout_ms,
      max_age_days: config.max_age_days,
      verbose: config.verbose
    }, { fetchImpl: options.fetchImpl });

    const fetchedAt = new Date().toISOString();
    const normalized = normalizeAbuseIpdbResponse(raw, {
      ip: publicIp,
      maxAgeInDays: config.max_age_days,
      verbose: config.verbose,
      fetchedAt
    });
    if (force) {
      normalized.last_force_refresh_at = fetchedAt;
    }

    const row = await upsertAbuseIpdbEnrichment(pool, {
      ip: publicIp,
      provider_status: 'success',
      max_age_days: config.max_age_days,
      verbose: config.verbose,
      normalized_summary: normalized,
      raw_json: raw,
      error_message: null
    });
    return { row, cached: false, skipped: false, provider_status: 'success', ip: publicIp };
  } catch (err) {
    const providerStatus = err.provider_status || (err.code === 'auth' ? 'auth_error' : 'failed');
    let errorMessage = String(err?.message || 'AbuseIPDB lookup failed').slice(0, 2000);
    if (err.retryAfter) errorMessage += ` (Retry-After: ${err.retryAfter})`;

    const failedSummary = {
      ipAddress: publicIp,
      fetched_at: new Date().toISOString(),
      provider_status: providerStatus,
      abuseConfidenceScore: null,
      risk_label: 'unknown'
    };

    const row = await upsertAbuseIpdbEnrichment(pool, {
      ip: publicIp,
      provider_status: providerStatus,
      max_age_days: config.max_age_days,
      verbose: config.verbose,
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

    return { row, cached: false, skipped: false, provider_status: providerStatus, ip: publicIp, error: err };
  }
}

export async function testAbuseIpdbConnection(pool, testIp = TEST_IP, options = {}) {
  const config = await getAbuseIpdbConfig(pool);
  if (!config.configured) {
    const err = new Error('AbuseIPDB API key is not configured');
    err.code = 'not_configured';
    throw err;
  }
  if (!config.enabled) {
    const err = new Error('AbuseIPDB provider is disabled');
    err.code = 'disabled';
    throw err;
  }

  const ipInput = String(testIp || TEST_IP).trim();
  if (!isValidIpAddress(ipInput)) {
    const err = new Error('Invalid IP address for test');
    err.code = 'invalid_ip';
    throw err;
  }
  const publicIp = validatePublicIp(ipInput);
  if (!publicIp) {
    const err = new Error('Private or reserved IP — external lookup not supported for test');
    err.code = 'unsupported_private_ip';
    throw err;
  }

  const raw = await fetchAbuseIpdbCheck(publicIp, {
    apiKey: config.apiKey,
    timeout_ms: config.timeout_ms,
    max_age_days: config.max_age_days,
    verbose: false
  }, { fetchImpl: options.fetchImpl });

  const normalized = normalizeAbuseIpdbResponse(raw, {
    ip: publicIp,
    maxAgeInDays: config.max_age_days,
    verbose: false
  });
  return { ip: publicIp, ...normalized };
}

export { maskApiKey, ABUSEIPDB_PROVIDER, TEST_IP };

import { validatePublicIp } from '../lib/publicIp.js';

const IPINFO_PROVIDER = 'ipinfo_lite';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const FORCE_COOLDOWN_MS = 5 * 60 * 1000;
const MAX_CONCURRENCY = Math.min(Math.max(Number(process.env.IPINFO_LITE_MAX_CONCURRENCY || 3), 1), 5);
const DEFAULT_BASE_URL = 'https://api.ipinfo.io/lite';
const DEFAULT_TIMEOUT_SEC = 6;

let activeLookups = 0;
const waiters = [];

function acquireSlot() {
  if (activeLookups < MAX_CONCURRENCY) {
    activeLookups += 1;
    return Promise.resolve();
  }
  return new Promise((resolve) => waiters.push(resolve));
}

function releaseSlot() {
  activeLookups = Math.max(0, activeLookups - 1);
  const next = waiters.shift();
  if (next) {
    activeLookups += 1;
    next();
  }
}

export function maskToken(token) {
  const s = String(token || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  return `${s.slice(0, 4)}${'*'.repeat(Math.max(8, s.length - 4))}`;
}

function parseConfig(row) {
  const cfg = row?.config && typeof row.config === 'object' ? row.config : {};
  const baseUrl = String(cfg.base_url || process.env.IPINFO_LITE_BASE_URL || DEFAULT_BASE_URL).replace(/\/$/, '');
  const timeoutSeconds = Math.min(Math.max(Number(cfg.timeout_seconds || (row?.timeout_ms ? row.timeout_ms / 1000 : DEFAULT_TIMEOUT_SEC)), 3), 30);
  return { baseUrl, timeoutSeconds, usageNote: cfg.usage_note || null };
}

export async function getIpinfoLiteConfig(pool) {
  const envToken = String(process.env.IPINFO_LITE_TOKEN || '').trim();
  const { rows } = await pool.query(
    `SELECT provider, enabled, api_key, timeout_ms, config, last_test_at, last_success_at, last_error_at, last_error_message
     FROM threat_intel_provider_configs WHERE provider = $1 LIMIT 1`,
    [IPINFO_PROVIDER]
  );
  const row = rows[0] || null;
  const dbToken = String(row?.api_key || '').trim();
  const token = dbToken || envToken;
  const { baseUrl, timeoutSeconds, usageNote } = parseConfig(row);
  return {
    provider_key: IPINFO_PROVIDER,
    display_name: 'IPinfo Lite',
    enabled: row?.enabled !== false,
    configured: Boolean(token),
    token,
    token_masked: maskToken(token),
    source: dbToken ? 'db' : (envToken ? 'env' : 'none'),
    base_url: baseUrl,
    timeout_seconds: timeoutSeconds,
    timeout_ms: timeoutSeconds * 1000,
    usage_note: usageNote,
    last_test_at: row?.last_test_at || null,
    last_success_at: row?.last_success_at || null,
    last_error_at: row?.last_error_at || null,
    last_error_message: row?.last_error_message || null
  };
}

function buildDerivedSignals(record) {
  return {
    ipinfo_available: record.provider_status === 'success',
    asn_available: Boolean(record.asn),
    country_available: Boolean(record.country_code || record.country),
    continent_available: Boolean(record.continent_code || record.continent)
  };
}

function parseIpinfoResponse(raw, ip) {
  const asnRaw = String(raw?.asn || '').trim();
  const asn = asnRaw ? (asnRaw.toUpperCase().startsWith('AS') ? asnRaw.toUpperCase() : `AS${asnRaw}`) : null;
  return {
    ip: String(raw?.ip || ip),
    provider: IPINFO_PROVIDER,
    provider_status: 'success',
    asn,
    as_name: raw?.as_name ? String(raw.as_name).trim() : null,
    as_domain: raw?.as_domain ? String(raw.as_domain).trim() : null,
    country_code: raw?.country_code ? String(raw.country_code).trim().toUpperCase() : null,
    country: raw?.country ? String(raw.country).trim() : null,
    continent_code: raw?.continent_code ? String(raw.continent_code).trim().toUpperCase() : null,
    continent: raw?.continent ? String(raw.continent).trim() : null,
    derived_signals: {},
    raw_json: raw,
    error_message: null
  };
}

export function rowToApiPayload(row, { cached = false, enriched = true } = {}) {
  if (!row) {
    return { enriched: false, cached: false, ip: null, provider: IPINFO_PROVIDER };
  }
  const signals = row.derived_signals && typeof row.derived_signals === 'object'
    ? row.derived_signals
    : buildDerivedSignals(row);
  return {
    enriched: enriched && row.provider_status === 'success',
    cached,
    ip: row.ip,
    provider: row.provider || IPINFO_PROVIDER,
    provider_status: row.provider_status,
    asn: row.asn,
    as_name: row.as_name,
    as_domain: row.as_domain,
    country_code: row.country_code,
    country: row.country,
    continent_code: row.continent_code,
    continent: row.continent,
    derived_signals: signals,
    error_message: row.error_message,
    last_enriched_at: row.last_enriched_at
  };
}

export function isCacheFresh(row, { force = false } = {}) {
  if (!row?.last_enriched_at) return false;
  const at = Date.parse(row.last_enriched_at);
  if (!Number.isFinite(at)) return false;
  const ageMs = Date.now() - at;

  if (row.provider_status === 'failed') {
    // Don't cache transient failures — each manual retry should hit the API.
    return false;
  }

  if (force) {
    const signals = row.derived_signals || {};
    const lastForce = signals.last_force_refresh_at ? Date.parse(signals.last_force_refresh_at) : NaN;
    if (Number.isFinite(lastForce) && (Date.now() - lastForce) < FORCE_COOLDOWN_MS) {
      return true;
    }
    return false;
  }

  return row.provider_status === 'success' && ageMs < CACHE_TTL_MS;
}

export async function getEnrichmentByIp(pool, ip) {
  const { rows } = await pool.query(`SELECT * FROM ioc_ip_enrichment WHERE ip = $1 LIMIT 1`, [ip]);
  return rows[0] || null;
}

export async function upsertIpEnrichment(pool, record) {
  const signals = buildDerivedSignals(record);
  const now = new Date().toISOString();
  const { rows } = await pool.query(
    `INSERT INTO ioc_ip_enrichment (
      ip, provider, provider_status, asn, as_name, as_domain,
      country_code, country, continent_code, continent,
      derived_signals, raw_json, error_message, last_enriched_at, updated_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14::timestamptz,NOW())
    ON CONFLICT (ip) DO UPDATE SET
      provider = EXCLUDED.provider,
      provider_status = EXCLUDED.provider_status,
      asn = EXCLUDED.asn,
      as_name = EXCLUDED.as_name,
      as_domain = EXCLUDED.as_domain,
      country_code = EXCLUDED.country_code,
      country = EXCLUDED.country,
      continent_code = EXCLUDED.continent_code,
      continent = EXCLUDED.continent,
      derived_signals = EXCLUDED.derived_signals,
      raw_json = EXCLUDED.raw_json,
      error_message = EXCLUDED.error_message,
      last_enriched_at = EXCLUDED.last_enriched_at,
      updated_at = NOW()
    RETURNING *`,
    [
      record.ip,
      record.provider || IPINFO_PROVIDER,
      record.provider_status,
      record.asn,
      record.as_name,
      record.as_domain,
      record.country_code,
      record.country,
      record.continent_code,
      record.continent,
      JSON.stringify({ ...signals, ...(record.derived_signals || {}) }),
      record.raw_json ? JSON.stringify(record.raw_json) : null,
      record.error_message,
      now
    ]
  );
  return rows[0];
}

async function fetchIpinfoLite(ip, config) {
  const url = `${config.base_url}/${encodeURIComponent(ip)}?token=${encodeURIComponent(config.token)}`;
  await acquireSlot();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), config.timeout_ms);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { Accept: 'application/json' } });
    if (res.status === 401 || res.status === 403) {
      const err = new Error('Invalid IPinfo Lite token / unauthorized');
      err.code = 'auth';
      err.status = res.status;
      throw err;
    }
    if (res.status === 429) {
      const err = new Error('IPinfo Lite rate limited');
      err.code = 'rate_limit';
      err.status = 429;
      const retryAfter = res.headers.get('retry-after');
      if (retryAfter) err.retryAfter = retryAfter;
      throw err;
    }
    if (res.status === 404) {
      const err = new Error('IPinfo Lite data not available for this IP');
      err.code = 'unavailable';
      err.status = 404;
      throw err;
    }
    if (!res.ok) {
      const err = new Error(`IPinfo Lite lookup failed (${res.status})`);
      err.code = 'http_error';
      err.status = res.status;
      throw err;
    }
    const raw = await res.json();
    if (!raw || !raw.ip) {
      const err = new Error('IPinfo Lite returned empty response');
      err.code = 'unavailable';
      throw err;
    }
    return raw;
  } finally {
    clearTimeout(timer);
    releaseSlot();
  }
}

export async function enrichIpWithIpinfoLite(pool, ip, options = {}) {
  const normalized = validatePublicIp(ip);
  if (!normalized) {
    return {
      row: await upsertIpEnrichment(pool, {
        ip: String(ip || '').trim(),
        provider: IPINFO_PROVIDER,
        provider_status: 'skipped',
        asn: null,
        as_name: null,
        as_domain: null,
        country_code: null,
        country: null,
        continent_code: null,
        continent: null,
        derived_signals: { skipped: true, reason: 'private_or_reserved' },
        raw_json: null,
        error_message: 'Private or reserved IP — external lookup skipped'
      }),
      cached: false,
      skipped: true,
      configured: true
    };
  }

  const config = await getIpinfoLiteConfig(pool);
  if (!config.configured || !config.enabled) {
    const err = new Error('IPinfo Lite provider is not configured');
    err.code = 'not_configured';
    throw err;
  }

  const force = options.force === true;
  const existing = await getEnrichmentByIp(pool, normalized);
  if (existing && isCacheFresh(existing, { force })) {
    return { row: existing, cached: true, skipped: false, configured: true };
  }

  try {
    const raw = await fetchIpinfoLite(normalized, config);
    const parsed = parseIpinfoResponse(raw, normalized);
    parsed.derived_signals = buildDerivedSignals(parsed);
    if (force) {
      parsed.derived_signals.last_force_refresh_at = new Date().toISOString();
    }
    const row = await upsertIpEnrichment(pool, parsed);
    return { row, cached: false, skipped: false, configured: true };
  } catch (err) {
    const status = err.code === 'unavailable' ? 'unavailable' : 'failed';
    let errorMessage = String(err?.message || 'IPinfo Lite lookup failed').slice(0, 2000);
    if (err.retryAfter) errorMessage += ` (Retry-After: ${err.retryAfter})`;

    const failed = {
      ip: normalized,
      provider: IPINFO_PROVIDER,
      provider_status: status,
      asn: null,
      as_name: null,
      as_domain: null,
      country_code: null,
      country: null,
      continent_code: null,
      continent: null,
      derived_signals: buildDerivedSignals({ provider_status: status }),
      raw_json: null,
      error_message: errorMessage
    };
    const row = await upsertIpEnrichment(pool, failed);
    if (err.code === 'not_configured') throw err;
    if (err.code === 'auth') {
      const authErr = new Error(errorMessage);
      authErr.code = 'auth';
      throw authErr;
    }
    if (err.code === 'rate_limit') {
      const rlErr = new Error(errorMessage);
      rlErr.code = 'rate_limit';
      rlErr.retryAfter = err.retryAfter;
      throw rlErr;
    }
    return { row, cached: false, skipped: false, configured: true, error: err };
  }
}

/** Geo summary for IOC details URL/IP Information table */
export function enrichmentToGeoSummary(row, fallbackIp = null) {
  if (!row || row.provider_status !== 'success') {
    return { ip: fallbackIp, asn: null, country_code: null, as_name: null, country: null };
  }
  return {
    ip: row.ip || fallbackIp,
    asn: row.asn ?? null,
    country_code: row.country_code || null,
    as_name: row.as_name || null,
    country: row.country || null
  };
}

export async function lookupGeoFromIpEnrichment(pool, ip) {
  if (!ip) return { ip: null, asn: null, country_code: null, as_name: null, country: null };
  const row = await getEnrichmentByIp(pool, ip);
  return enrichmentToGeoSummary(row, ip);
}

export async function testIpinfoLiteConnection(pool) {
  const config = await getIpinfoLiteConfig(pool);
  if (!config.configured) {
    const err = new Error('IPinfo Lite token is not configured');
    err.code = 'not_configured';
    throw err;
  }
  const result = await enrichIpWithIpinfoLite(pool, '8.8.8.8', { force: true });
  if (result.row?.provider_status !== 'success') {
    throw new Error(result.row?.error_message || 'IPinfo Lite test failed');
  }
  return result.row;
}

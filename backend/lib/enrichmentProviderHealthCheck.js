// Canonical active-probe provider health.
//
// One connection-test implementation per provider, shared by the manual "Test
// Connection" admin actions and the scheduled 24h health probe. Results persist
// in enrichment_provider_health (see migration 165) — the single source of truth
// for provider health. Health is never derived from enrichment usage here:
// an idle-but-working provider stays Healthy, and Unknown means only that no
// health check has ever produced evidence.
//
// Provider health modes:
//   active_probe        virustotal, ipinfo_lite, abuseipdb, rdap  (explicit connection test)
//   scheduled_operation spamhaus_drop                             (dataset sync is the evidence)

// Provider services and the registry are imported lazily inside the probe paths
// (dynamic import) rather than at module load. This keeps the broadly-imported
// health resolver lightweight and defers loading the RDAP/tldts stack until an
// actual probe runs.

export const PROVIDER_HEALTH_MODE = Object.freeze({
  virustotal: 'active_probe',
  ipinfo_lite: 'active_probe',
  abuseipdb: 'active_probe',
  rdap: 'active_probe',
  spamhaus_drop: 'scheduled_operation'
});

/** Providers that support an active connection test / scheduled probe. */
export const ACTIVE_PROBE_PROVIDERS = Object.freeze(
  Object.entries(PROVIDER_HEALTH_MODE)
    .filter(([, mode]) => mode === 'active_probe')
    .map(([key]) => key)
);

// A single transient network/HTTP failure should degrade, not condemn. Only a
// run of consecutive failures (initial probe + the two scheduled retries) marks
// a provider Unhealthy. Auth failures short-circuit to Unhealthy immediately.
export const HEALTH_FAILURE_THRESHOLD = 3;

// Standards-reserved domain used for the RDAP connection probe. example.com is
// guaranteed to resolve in RDAP and is safe to query repeatedly.
export const RDAP_HEALTH_PROBE_DOMAIN = 'example.com';

const DEFAULT_STALE_MS = 36 * 60 * 60 * 1000; // 24h cadence + tolerance

/**
 * Stale threshold for a nominal 24h probe cadence. A late scheduler tick must
 * not flip a provider that has real historical evidence; only a genuinely
 * overdue checker downgrades Healthy -> Degraded (never to Unknown).
 */
export function healthStaleThresholdMs() {
  const configured = Number(process.env.ENRICHMENT_HEALTH_STALE_MS);
  return Number.isFinite(configured) && configured >= 60 * 60 * 1000
    ? configured
    : DEFAULT_STALE_MS;
}

/** Delays (ms) for scheduled transient-failure retries: ~5m then ~30m. */
export function healthRetryDelaysMs() {
  return [5 * 60 * 1000, 30 * 60 * 1000];
}

/**
 * Classify a probe error into a sanitized category + human-readable evidence.
 * Never surfaces secrets or raw provider bodies — messages are fixed strings
 * keyed on the error code, not the provider's response text.
 */
export function classifyProbeError(err) {
  const code = String(err?.code || '').toLowerCase();
  if (code === 'not_configured') {
    return { category: 'not_configured', evidence: 'Provider is not configured' };
  }
  if (code === 'auth') {
    return { category: 'auth', evidence: 'Authentication failed (invalid or revoked credentials)' };
  }
  if (code === 'rate_limit') {
    return { category: 'rate_limit', evidence: 'Provider rate limit reached' };
  }
  if (code === 'timeout') {
    return { category: 'timeout', evidence: 'Connection test timed out' };
  }
  if (code === 'http' || code === 'http_error' || code === 'not_found') {
    return { category: 'http', evidence: 'Provider returned an unexpected response' };
  }
  return { category: 'network', evidence: 'Network or provider error during connection test' };
}

/**
 * Map a failure category + running failure count to a canonical status.
 * Auth is authoritative (Unhealthy now). Rate limit stays Degraded (connectivity
 * and credentials are fine). Transient network/timeout/http degrade first and
 * only escalate to Unhealthy once consecutive failures reach the threshold.
 */
export function statusForFailure(category, consecutiveFailures) {
  if (category === 'auth') return 'unhealthy';
  if (category === 'rate_limit') return 'degraded';
  return consecutiveFailures >= HEALTH_FAILURE_THRESHOLD ? 'unhealthy' : 'degraded';
}

// --- Per-provider canonical probes. Each returns a `detail` object on success
// and throws an Error carrying a `.code` on failure. -------------------------

async function probeVirustotal(pool) {
  const { rows } = await pool.query(
    'SELECT api_key, timeout_ms FROM threat_intel_provider_configs WHERE provider = $1 LIMIT 1',
    ['virustotal']
  );
  const row = rows[0] || null;
  const apiKey = String(row?.api_key || '').trim() || String(process.env.VIRUSTOTAL_API_KEY || '').trim();
  if (!apiKey) {
    const err = new Error('VirusTotal API key is not configured');
    err.code = 'not_configured';
    throw err;
  }
  const timeoutMs = Math.max(3000, Number(row?.timeout_ms || process.env.VIRUSTOTAL_TIMEOUT_MS || 12000));
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res;
  try {
    res = await fetch('https://www.virustotal.com/api/v3/domains/example.com', {
      headers: { 'x-apikey': apiKey },
      signal: ctrl.signal
    });
  } catch (err) {
    if (String(err?.name) === 'AbortError') {
      const t = new Error('VirusTotal connection test timed out');
      t.code = 'timeout';
      throw t;
    }
    const n = new Error('VirusTotal connection test failed');
    n.code = 'network';
    throw n;
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 429) {
    const err = new Error('VirusTotal rate limit reached');
    err.code = 'rate_limit';
    throw err;
  }
  if (res.status === 401 || res.status === 403) {
    const err = new Error('Invalid VirusTotal API key');
    err.code = 'auth';
    throw err;
  }
  if (!res.ok) {
    const err = new Error('VirusTotal connection test failed');
    err.code = 'http';
    throw err;
  }
  return { domain: 'example.com' };
}

async function probeIpinfoLite(pool) {
  const { testIpinfoLiteConnection } = await import('../services/ipinfoLiteService.js');
  const row = await testIpinfoLiteConnection(pool);
  return { asn: row?.asn || null, as_name: row?.as_name || null, country_code: row?.country_code || null };
}

async function probeAbuseIpdb(pool) {
  const { testAbuseIpdbConnection } = await import('../services/abuseipdbService.js');
  const result = await testAbuseIpdbConnection(pool);
  return {
    ip: result?.ip || null,
    abuse_confidence_score: result?.abuseConfidenceScore ?? null,
    country_code: result?.countryCode || null
  };
}

/**
 * RDAP health probe. Exercises the real lookup path (bootstrap resolution, DNS,
 * TLS, HTTP, redirects, timeout, RDAP JSON parsing) against a standards-reserved
 * domain WITHOUT touching the ioc_domain_enrichment cache — a true uncached
 * network request, so a cached lookup can never fake a healthy probe.
 * @param {(domain: string) => Promise<object>} [fetchFn] override for tests
 */
export async function testRdapConnection(pool, { fetchFn = null } = {}) {
  const { fetchRdapDomain, parseRdapDomainResponse } = await import('../services/rdapEnrichmentService.js');
  const doFetch = fetchFn || fetchRdapDomain;
  const raw = await doFetch(RDAP_HEALTH_PROBE_DOMAIN);
  const parsed = parseRdapDomainResponse(raw, RDAP_HEALTH_PROBE_DOMAIN);
  if (!parsed || parsed.rdap_status !== 'success') {
    const err = new Error('RDAP response did not parse as a valid domain record');
    err.code = 'http';
    throw err;
  }
  return { domain: RDAP_HEALTH_PROBE_DOMAIN, registrar: parsed.registrar || null };
}

async function probeRdap(pool) {
  return testRdapConnection(pool);
}

const PROBES = Object.freeze({
  virustotal: probeVirustotal,
  ipinfo_lite: probeIpinfoLite,
  abuseipdb: probeAbuseIpdb,
  rdap: probeRdap
});

// --- Persistence -----------------------------------------------------------

async function readHealthRow(pool, provider) {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM enrichment_provider_health WHERE provider = $1 LIMIT 1',
      [provider]
    );
    return rows[0] || null;
  } catch {
    return null;
  }
}

export async function readProviderHealthRows(pool) {
  const map = new Map();
  try {
    const { rows } = await pool.query('SELECT * FROM enrichment_provider_health');
    for (const row of rows) map.set(row.provider, row);
  } catch {
    /* table missing (pre-migration) -> empty map, providers resolve to Unknown */
  }
  return map;
}

/**
 * Persist a health-check result and return the stored canonical status. Success
 * resets consecutive failures; failure escalates per statusForFailure.
 */
export async function recordHealthProbeResult(pool, {
  provider,
  source = 'scheduled',
  outcome,
  category = null,
  evidence = null
} = {}) {
  const key = String(provider || '').trim();
  if (!pool || !key || !['success', 'failure'].includes(outcome)) return null;

  if (outcome === 'success') {
    const message = evidence
      || (source === 'manual' ? 'Manual connection test succeeded' : 'Scheduled connection test succeeded');
    await pool.query(
      `INSERT INTO enrichment_provider_health
         (provider, status, last_check_at, last_success_at, check_source, error_category, evidence, consecutive_failures, updated_at)
       VALUES ($1, 'healthy', NOW(), NOW(), $2, NULL, $3, 0, NOW())
       ON CONFLICT (provider) DO UPDATE SET
         status = 'healthy',
         last_check_at = NOW(),
         last_success_at = NOW(),
         check_source = $2,
         error_category = NULL,
         evidence = $3,
         consecutive_failures = 0,
         updated_at = NOW()`,
      [key, source, message.slice(0, 500)]
    );
    return { provider: key, status: 'healthy', evidence: message };
  }

  const existing = await readHealthRow(pool, key);
  const prior = Number(existing?.consecutive_failures || 0);
  // Rate limiting is not a hard failure; it does not accrue toward Unhealthy.
  const nextConsecutive = category === 'rate_limit' ? prior : prior + 1;
  const status = statusForFailure(category, nextConsecutive);
  const message = (evidence || 'Connection test failed').slice(0, 500);

  await pool.query(
    `INSERT INTO enrichment_provider_health
       (provider, status, last_check_at, last_failure_at, check_source, error_category, evidence, consecutive_failures, updated_at)
     VALUES ($1, $2, NOW(), NOW(), $3, $4, $5, $6, NOW())
     ON CONFLICT (provider) DO UPDATE SET
       status = $2,
       last_check_at = NOW(),
       last_failure_at = NOW(),
       check_source = $3,
       error_category = $4,
       evidence = $5,
       consecutive_failures = $6,
       updated_at = NOW()`,
    [key, status, source, category, message, nextConsecutive]
  );
  return { provider: key, status, category, evidence: message, consecutive_failures: nextConsecutive };
}

// --- Probe orchestration ---------------------------------------------------

/**
 * Run one provider's canonical connection test and persist the result. Shared by
 * the manual admin route and the scheduled probe job.
 *
 * @returns {Promise<{provider, ran, skipped?, reason?, ok?, status, category?, evidence?, detail?}>}
 */
export async function runProviderHealthProbe(pool, provider, { source = 'scheduled' } = {}) {
  const key = String(provider || '').trim();
  const probe = PROBES[key];
  if (!probe) {
    return { provider: key, ran: false, skipped: true, reason: 'unsupported_provider' };
  }

  // Respect enabled/configured state: never probe a disabled provider or one
  // missing required credentials (no meaningless external calls). Such providers
  // simply stay at their prior/Unknown health.
  const { getEnrichmentProvider } = await import('./enrichmentProviderRegistry.js');
  const entry = getEnrichmentProvider(key);
  if (entry) {
    let state = null;
    try {
      state = await entry.loadState(pool);
    } catch {
      state = null;
    }
    if (state && state.enabled === false) {
      return { provider: key, ran: false, skipped: true, reason: 'disabled' };
    }
    if (state && state.configured === false) {
      return { provider: key, ran: false, skipped: true, reason: 'not_configured' };
    }
  }

  try {
    const detail = await probe(pool);
    const evidence = source === 'manual'
      ? 'Manual connection test succeeded'
      : 'Scheduled connection test succeeded';
    await recordHealthProbeResult(pool, { provider: key, source, outcome: 'success', evidence });
    return { provider: key, ran: true, ok: true, status: 'healthy', evidence, detail };
  } catch (err) {
    const { category, evidence } = classifyProbeError(err);
    if (category === 'not_configured') {
      return { provider: key, ran: false, skipped: true, reason: 'not_configured' };
    }
    const recorded = await recordHealthProbeResult(pool, {
      provider: key, source, outcome: 'failure', category, evidence
    });
    return {
      provider: key,
      ran: true,
      ok: false,
      status: recorded?.status || statusForFailure(category, 1),
      category,
      evidence,
      error: err
    };
  }
}

// --- Canonical resolution (used by both admin + system health endpoints) ---

const STATUS_REASON = Object.freeze({
  healthy: 'health_check_passed',
  degraded: 'health_check_degraded',
  unhealthy: 'health_check_failed',
  unknown: 'never_checked'
});

/**
 * Resolve canonical health for an active-probe provider from its stored row.
 * Unknown means only "never checked". An overdue checker with prior Healthy
 * evidence degrades (never reverts to Unknown just because evidence aged).
 */
export function resolveActiveProbeHealth(row, options = {}) {
  const nowMs = options.now instanceof Date ? options.now.getTime()
    : Number.isFinite(options.now) ? options.now : Date.now();
  const staleMs = Number(options.staleMs || healthStaleThresholdMs());

  if (!row || !row.last_check_at) {
    return {
      status: 'unknown',
      reason: 'never_checked',
      evidence: 'No health check has been performed yet',
      last_success_at: row?.last_success_at || null,
      last_failure_at: row?.last_failure_at || null,
      last_checked_at: row?.last_check_at || null,
      source: row?.check_source || null,
      error_category: row?.error_category || null
    };
  }

  let status = String(row.status || 'unknown').toLowerCase();
  let reason = STATUS_REASON[status] || 'health_check';
  let evidence = row.evidence || null;

  const checkedMs = Date.parse(row.last_check_at);
  const overdue = Number.isFinite(checkedMs) && (nowMs - checkedMs) > staleMs;
  if (overdue && status === 'healthy') {
    status = 'degraded';
    reason = 'overdue';
    evidence = 'Scheduled health check is overdue';
  }

  return {
    status,
    reason,
    evidence,
    last_success_at: row.last_success_at || null,
    last_failure_at: row.last_failure_at || null,
    last_checked_at: row.last_check_at || null,
    source: row.check_source || null,
    error_category: row.error_category || null
  };
}

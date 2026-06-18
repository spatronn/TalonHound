export const ABUSEIPDB_PROVIDER = 'abuseipdb';
export const ABUSEIPDB_API_BASE = 'https://api.abuseipdb.com/api/v2';

export function maskApiKey(key) {
  const s = String(key || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  return `${s.slice(0, 4)}${'*'.repeat(Math.max(8, s.length - 4))}`;
}

/**
 * @param {number|null|undefined} score
 * @returns {'clean'|'low'|'suspicious'|'high'|'unknown'}
 */
export function abuseScoreRiskLabel(score) {
  if (score === null || score === undefined || !Number.isFinite(Number(score))) return 'unknown';
  const n = Math.round(Number(score));
  if (n <= 0) return 'clean';
  if (n <= 24) return 'low';
  if (n <= 74) return 'suspicious';
  return 'high';
}

/** @param {'clean'|'low'|'suspicious'|'high'|'unknown'} label */
export function abuseScoreRiskLabelDisplay(label) {
  const map = {
    clean: 'Clean / No reports',
    low: 'Low',
    suspicious: 'Suspicious',
    high: 'High',
    unknown: 'Unknown'
  };
  return map[label] || 'Unknown';
}

/**
 * @param {unknown} rawBody
 * @param {{ ip: string, maxAgeInDays: number, verbose: boolean, fetchedAt?: string }} ctx
 */
export function normalizeAbuseIpdbResponse(rawBody, ctx) {
  const data = rawBody?.data && typeof rawBody.data === 'object' ? rawBody.data : {};
  const ipAddress = String(data.ipAddress || ctx.ip).trim();
  const score = Number.isFinite(Number(data.abuseConfidenceScore))
    ? Math.min(100, Math.max(0, Math.round(Number(data.abuseConfidenceScore))))
    : 0;
  const hostnames = Array.isArray(data.hostnames)
    ? data.hostnames.map((h) => String(h).trim()).filter(Boolean)
    : [];

  const recentReportsSummary = ctx.verbose && Array.isArray(data.reports)
    ? data.reports.slice(0, 10).map((r) => ({
        reportedAt: r?.reportedAt || null,
        comment: r?.comment ? String(r.comment).slice(0, 240) : null,
        categories: Array.isArray(r?.categories)
          ? r.categories.map((c) => Number(c)).filter((c) => Number.isFinite(c))
          : []
      }))
    : null;

  const fetchedAt = ctx.fetchedAt || new Date().toISOString();

  return {
    ipAddress,
    isPublic: data.isPublic !== false,
    ipVersion: Number.isFinite(Number(data.ipVersion)) ? Number(data.ipVersion) : null,
    abuseConfidenceScore: score,
    risk_label: abuseScoreRiskLabel(score),
    countryCode: data.countryCode ? String(data.countryCode).trim().toUpperCase() : null,
    usageType: data.usageType ? String(data.usageType).trim() : null,
    isp: data.isp ? String(data.isp).trim() : null,
    domain: data.domain ? String(data.domain).trim() : null,
    hostnames,
    totalReports: Number.isFinite(Number(data.totalReports)) ? Number(data.totalReports) : 0,
    numDistinctUsers: Number.isFinite(Number(data.numDistinctUsers)) ? Number(data.numDistinctUsers) : 0,
    lastReportedAt: data.lastReportedAt ? String(data.lastReportedAt) : null,
    maxAgeInDays: ctx.maxAgeInDays,
    recent_reports_summary: recentReportsSummary,
    fetched_at: fetchedAt,
    provider_status: 'success'
  };
}

/**
 * Map HTTP status to normalized provider_status + user message.
 * @param {number} status
 */
export function abuseIpdbHttpError(status) {
  const code = Number(status);
  if (code === 401 || code === 403) {
    return { provider_status: 'auth_error', code: 'auth', message: 'Invalid AbuseIPDB API key or unauthorized' };
  }
  if (code === 429) {
    return { provider_status: 'rate_limited', code: 'rate_limit', message: 'AbuseIPDB rate limit reached. Try again later.' };
  }
  if (code >= 500) {
    return { provider_status: 'provider_error', code: 'provider_error', message: 'AbuseIPDB service error. Try again later.' };
  }
  return { provider_status: 'failed', code: 'http_error', message: `AbuseIPDB lookup failed (${code})` };
}

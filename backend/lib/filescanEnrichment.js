export const FILESCAN_PROVIDER = 'filescan';
export const FILESCAN_API_BASE = 'https://www.filescan.io/api';
export const FILESCAN_SEARCH_PATH = '/reports/search';

export function maskApiKey(key) {
  const s = String(key || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  return `${s.slice(0, 4)}${'*'.repeat(Math.max(8, s.length - 4))}`;
}

/**
 * Derive an overall verdict from an array of per-item verdicts.
 * Precedence: malicious > suspicious > benign > no_threat > unknown
 * @param {string[]} verdicts
 * @returns {'malicious'|'suspicious'|'benign'|'no_threat'|'unknown'}
 */
export function aggregateVerdict(verdicts) {
  const all = (verdicts || []).map((v) => String(v || '').toLowerCase());
  if (all.includes('malicious')) return 'malicious';
  if (all.includes('suspicious')) return 'suspicious';
  if (all.includes('benign')) return 'benign';
  if (all.includes('no_threat')) return 'no_threat';
  return 'unknown';
}

/**
 * @param {'malicious'|'suspicious'|'benign'|'no_threat'|'unknown'} verdict
 * @returns {'high'|'medium'|'low'|null}
 */
export function verdictToConfidenceHint(verdict) {
  if (verdict === 'malicious') return 'high';
  if (verdict === 'suspicious') return 'medium';
  if (verdict === 'benign' || verdict === 'no_threat') return 'low';
  return null;
}

/**
 * Normalize a raw Filescan.io search response into the canonical enrichment model.
 * @param {unknown} rawBody
 * @param {{ iocType: string, iocValue: string, fetchedAt?: string }} ctx
 */
export function normalizeFilescanResponse(rawBody, ctx) {
  const items = Array.isArray(rawBody?.items) ? rawBody.items : [];
  const fetchedAt = ctx.fetchedAt || new Date().toISOString();

  const verdicts = items.map((item) => String(item?.verdict || 'unknown').toLowerCase());
  const verdict = aggregateVerdict(verdicts);

  const reports = items.slice(0, 20).map((item) => {
    const flowId = item?.scan_init?.id || item?.id || null;
    const fileHash = item?.file?.sha256 || null;
    const fileLink = item?.file?.link || null;
    const reportLink = flowId
      ? `https://www.filescan.io/reports/${encodeURIComponent(String(flowId))}`
      : null;
    return {
      report_id: item?.id ? String(item.id) : null,
      flow_id: flowId ? String(flowId) : null,
      verdict: String(item?.verdict || 'unknown').toLowerCase(),
      report_date: item?.date || null,
      file_name: item?.file?.name || null,
      file_hash: fileHash,
      file_link: fileLink,
      link: reportLink
    };
  });

  // Collect unique tag names across all items
  const tagSet = new Set();
  const threatIndicators = [];
  for (const item of items) {
    if (!Array.isArray(item?.tags)) continue;
    for (const t of item.tags) {
      const name = t?.tag?.name;
      if (name && typeof name === 'string') {
        tagSet.add(name.trim());
        if (t.isRootTag || t.isMalwareFamilyTag) {
          if (!threatIndicators.find((x) => x.name === name.trim())) {
            threatIndicators.push({
              name: name.trim(),
              source: t.source || null,
              is_malware_family: Boolean(t.isMalwareFamilyTag)
            });
          }
        }
      }
    }
  }

  return {
    provider: FILESCAN_PROVIDER,
    found: items.length > 0,
    verdict,
    confidence_hint: verdictToConfidenceHint(verdict),
    report_count: items.length,
    reports,
    tags: Array.from(tagSet).slice(0, 30),
    threat_indicators: threatIndicators.slice(0, 20),
    source_references: [],
    ioc_type: ctx.iocType,
    ioc_value: ctx.iocValue,
    fetched_at: fetchedAt,
    provider_status: 'success',
    raw_summary: {
      count: rawBody?.count ?? items.length,
      method: rawBody?.method || null
    }
  };
}

/**
 * Map HTTP status to normalized provider_status + user message.
 * @param {number} status
 */
export function filescanHttpError(status) {
  const code = Number(status);
  if (code === 401 || code === 403) {
    return { provider_status: 'auth_error', code: 'auth', message: 'Invalid or unauthorized Filescan.io API key' };
  }
  if (code === 429) {
    return { provider_status: 'rate_limited', code: 'rate_limit', message: 'Filescan.io rate limit reached. Try again later.' };
  }
  if (code >= 500) {
    return { provider_status: 'provider_error', code: 'provider_error', message: 'Filescan.io service error. Try again later.' };
  }
  return { provider_status: 'failed', code: 'http_error', message: `Filescan.io lookup failed (${code})` };
}

/**
 * Normalize an IOC value for cache key purposes.
 * @param {string} iocType
 * @param {string} iocValue
 */
export function normalizeFilescanCacheKey(iocType, iocValue) {
  const t = String(iocType || '').trim().toLowerCase();
  const v = String(iocValue || '').trim().toLowerCase();
  return `${t}:${v}`;
}

const RESULT_STATES = new Set(['cached', 'enriched', 'not_found', 'provider_error', 'invalid_ip']);

export function indexAssociatedIpResults(results) {
  const indexed = {};
  for (const result of Array.isArray(results) ? results : []) {
    const key = String(result?.normalized_ip || result?.requested_ip || '').trim().toLowerCase();
    if (key) indexed[key] = result;
  }
  return indexed;
}

export function compactAssociatedIpViewModel(result, fallbackIp) {
  const data = result?.data && typeof result.data === 'object' ? result.data : null;
  const state = RESULT_STATES.has(result?.state) ? result.state : 'not_found';
  const country = data?.country || null;
  const continent = data?.continent || null;
  return {
    state,
    hasData: data?.provider_status === 'success' || data?.enriched === true,
    ip: data?.normalized_ip || data?.ip || result?.normalized_ip || fallbackIp || null,
    asName: data?.as_name || null,
    asn: data?.asn || null,
    asDomain: data?.as_domain || null,
    location: [country, continent].filter(Boolean).join(' · ') || null,
    provider: 'IPinfo Lite',
    lastChecked: data?.last_enriched_at || null,
    error: result?.error || data?.error_message || null
  };
}

export function isAssociatedIpEnrichmentCandidate(result) {
  const state = result?.state;
  return state === 'not_found' || state === 'provider_error';
}

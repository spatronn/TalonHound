import { isProviderApplicable } from './iocProviderApplicability.js';

function providerCoverageStatus(snapshot) {
  const status = String(snapshot?.status || 'not_run').toLowerCase();
  if (['success', 'available', 'enriched', 'vt_not_indexed', 'listed', 'not_listed'].includes(status)) {
    if (snapshot?.found === false) return 'not_found';
    if (snapshot?.scan_state === 'success_partial') return 'partial';
    return 'available';
  }
  if (status === 'not_found') return 'not_found';
  if (status === 'no_data') return 'not_found';
  if (status === 'completed') return snapshot?.known === false ? 'not_found' : 'available';
  if (status === 'disabled') return 'disabled';
  if (['not_configured', 'api_key_missing'].includes(status)) return 'not_configured';
  if (['dataset_not_synced', 'suspicious', 'stale'].includes(status)) return 'not_configured';
  if (['error', 'failed'].includes(status)) return 'error';
  return 'not_run';
}

export function computeOverallSignal({ vt, abuseipdb }) {
  const vtMal = Number(vt?.malicious ?? vt?.stats?.malicious ?? 0);
  const vtSusp = Number(vt?.suspicious ?? vt?.stats?.suspicious ?? 0);
  const vtDetected = Number(vt?.detected ?? vt?.detection_ratio?.detected ?? 0);
  const abuseScore = abuseipdb?.score != null ? Number(abuseipdb.score) : null;

  const hasVt = vt && vt.status === 'success';
  const hasAbuse = abuseipdb && abuseipdb.status === 'success';

  if (!hasVt && !hasAbuse) return { label: 'Unknown', tone: 'muted' };

  if ((hasVt && vtMal >= 5) || (hasAbuse && abuseScore >= 75)) {
    return { label: 'Malicious signal', tone: 'bad' };
  }
  if (
    (hasVt && (vtMal > 0 || vtSusp > 0 || vtDetected > 0)) ||
    (hasAbuse && abuseScore >= 25)
  ) {
    return { label: 'Suspicious', tone: 'warn' };
  }
  if (hasVt || hasAbuse) return { label: 'Clean / No reports', tone: 'good' };
  return { label: 'Unknown', tone: 'muted' };
}

export function computeReputationSummary({ vt, abuseipdb }) {
  const parts = [];
  if (vt?.status === 'success') {
    const detected = Number(vt.detected ?? vt.detection_ratio?.detected ?? 0);
    const total = Number(vt.total ?? vt.detection_ratio?.total ?? 0);
    if (total > 0) parts.push({ label: 'VT', value: `${detected} / ${total}` });
  }
  if (abuseipdb?.status === 'success' && abuseipdb.score != null) {
    parts.push({ label: 'AbuseIPDB', value: `${Number(abuseipdb.score)} / 100` });
  }
  return parts.slice(0, 3);
}

export function computeInfrastructureSummary({ ipinfo, abuseipdb, rdap }) {
  const parts = [];
  if (ipinfo?.status === 'success') {
    const asn = ipinfo.asn || ipinfo.as_number;
    const country = ipinfo.country || ipinfo.country_code;
    const provider = ipinfo.provider || ipinfo.org || ipinfo.as_name;
    if (asn) parts.push(`ASN ${asn}`);
    if (country) parts.push(String(country));
    if (provider) parts.push(String(provider));
  } else if (abuseipdb?.status === 'success') {
    if (abuseipdb.country) parts.push(String(abuseipdb.country));
    if (abuseipdb.isp) parts.push(String(abuseipdb.isp));
    if (abuseipdb.usage_type) parts.push(String(abuseipdb.usage_type));
  }
  if (rdap?.status === 'success') {
    if (rdap.registrar) parts.push(String(rdap.registrar));
    if (rdap.root_domain) parts.push(String(rdap.root_domain));
    if (rdap.created) parts.push(`Created ${rdap.created}`);
  }
  if (!parts.length) return 'Not enriched yet';
  return parts.slice(0, 4).join(' · ');
}

export function computeProviderCoverage(snapshots, { iocType, rdapEligible = false, providerKeys } = {}) {
  const providers = [
    { key: 'virustotal', label: 'VT' },
    { key: 'ipinfo', label: 'IPinfo' },
    { key: 'abuseipdb', label: 'AbuseIPDB' },
    { key: 'rdap', label: 'RDAP' },
    { key: 'spamhaus_drop', label: 'Spamhaus' },
    { key: 'dnsmania', label: 'DNSMania' }
  ];
  let applicable;
  if (Array.isArray(providerKeys) && providerKeys.length) {
    applicable = providers.filter((p) => providerKeys.includes(p.key));
  } else if (iocType) {
    applicable = providers.filter((p) => isProviderApplicable(p.key, iocType, { rdapEligible }));
  } else {
    applicable = providers;
  }
  return applicable.map((p) => {
    const snap = snapshots?.[p.key];
    const state = providerCoverageStatus(snap);
    return {
      ...p,
      state,
      detail: p.key === 'dnsmania' ? dnsmaniaCoverageDetail(snap, state) : null
    };
  });
}

/** Frontend-only coverage caption for DNSMania snapshots (no risk/signal impact). */
export function dnsmaniaCoverageDetail(snapshot, state) {
  if (!snapshot || String(snapshot?.status || '') === 'not_run' || state === 'not_run') return 'Not run';
  const status = String(snapshot.status || '').toLowerCase();
  if (status === 'disabled' || state === 'disabled') return 'Disabled';
  if (status === 'failed' || state === 'error') return 'Error';
  if (status === 'no_data' || (status === 'completed' && snapshot.known === false) || state === 'not_found') {
    return 'No data';
  }
  if (status === 'completed' || state === 'available') {
    if (snapshot.nxdomain_observed === true) return 'NXDOMAIN observed';
    const n = Number(snapshot.relation_count);
    if (Number.isFinite(n) && n > 0) return `${n} relation${n === 1 ? '' : 's'}`;
    return 'Found';
  }
  return providerStateLabel(state);
}

export function computeLayeredProviderCoverage({
  directSnapshots = {},
  derivedSnapshots = {},
  iocType,
  rdapEligible = false,
  derivedContext = null
}) {
  const direct = computeProviderCoverage(directSnapshots, { iocType, rdapEligible });
  if (!derivedContext?.providers?.length) {
    return { direct, derived: null, derivedHost: null };
  }
  const derived = computeProviderCoverage(derivedSnapshots, {
    providerKeys: derivedContext.providers
  });
  return {
    direct,
    derived,
    derivedHost: derivedContext.host
  };
}

export function computeAnalystRefsSummary(summary) {
  const total = Number(summary?.total_count || 0);
  const malicious = Number(summary?.supports_malicious_count || 0);
  if (!total) return '0 refs';
  if (malicious > 0) return `${total} refs / ${malicious} supports malicious`;
  return `${total} ref${total === 1 ? '' : 's'}`;
}

export function signalToneStyle(tone) {
  if (tone === 'bad') return { border: '#7f1d1d', bg: 'rgba(220,38,38,0.14)', color: '#fca5a5' };
  if (tone === 'warn') return { border: '#92400e', bg: 'rgba(217,119,6,0.14)', color: '#fcd34d' };
  if (tone === 'good') return { border: '#166534', bg: 'rgba(22,163,74,0.14)', color: '#86efac' };
  return { border: '#475569', bg: 'rgba(71,85,105,0.18)', color: '#94a3b8' };
}

export function providerStateLabel(state) {
  if (state === 'available') return 'Available';
  if (state === 'partial') return 'Partial';
  if (state === 'not_found') return 'Not found';
  if (state === 'disabled') return 'Disabled';
  if (state === 'not_configured') return 'Not configured';
  if (state === 'error') return 'Error';
  return 'Not run';
}

export function providerStateStyle(state) {
  if (state === 'available') return { dot: '#22c55e', color: '#86efac' };
  if (state === 'partial') return { dot: '#f59e0b', color: '#fbbf24' };
  if (state === 'not_found') return { dot: '#64748b', color: '#94a3b8' };
  if (state === 'error') return { dot: '#ef4444', color: '#fca5a5' };
  if (state === 'disabled' || state === 'not_configured') return { dot: '#f59e0b', color: '#fcd34d' };
  return { dot: '#64748b', color: '#94a3b8' };
}

import { isProviderApplicable } from './iocProviderApplicability.js';

function providerCoverageStatus(snapshot) {
  const status = String(snapshot?.status || 'not_run').toLowerCase();
  if (['success', 'available', 'enriched', 'vt_not_indexed'].includes(status)) return 'available';
  if (['not_configured', 'api_key_missing', 'disabled'].includes(status)) return status === 'disabled' ? 'disabled' : 'not_configured';
  if (['error', 'failed'].includes(status)) return 'error';
  if (['not_found', 'loading', 'private_ip'].includes(status)) return status === 'loading' ? 'not_run' : 'not_run';
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
  if ((hasVt && (vtMal > 0 || vtSusp > 0 || vtDetected > 0)) || (hasAbuse && abuseScore >= 25)) {
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
  return parts.slice(0, 2);
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
    { key: 'rdap', label: 'RDAP' }
  ];
  let applicable;
  if (Array.isArray(providerKeys) && providerKeys.length) {
    applicable = providers.filter((p) => providerKeys.includes(p.key));
  } else if (iocType) {
    applicable = providers.filter((p) => isProviderApplicable(p.key, iocType, { rdapEligible }));
  } else {
    applicable = providers;
  }
  return applicable.map((p) => ({
    ...p,
    state: providerCoverageStatus(snapshots?.[p.key])
  }));
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
  if (state === 'disabled') return 'Disabled';
  if (state === 'not_configured') return 'Not configured';
  if (state === 'error') return 'Error';
  return 'Not run';
}

export function providerStateStyle(state) {
  if (state === 'available') return { dot: '#22c55e', color: '#86efac' };
  if (state === 'error') return { dot: '#ef4444', color: '#fca5a5' };
  if (state === 'disabled' || state === 'not_configured') return { dot: '#f59e0b', color: '#fcd34d' };
  return { dot: '#64748b', color: '#94a3b8' };
}

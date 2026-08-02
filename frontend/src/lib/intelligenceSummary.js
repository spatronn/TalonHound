import { isProviderApplicable } from './iocProviderApplicability.js';

/**
 * True when a provider snapshot carries a previously fetched result, regardless
 * of the provider's current enabled state. Used to distinguish a disabled
 * provider that still has a viewable historical result from one with nothing.
 */
export function snapshotHasResult(snapshot) {
  if (!snapshot) return false;
  if (snapshot.hasResult === true || snapshot.historical === true) return true;
  if (snapshot.data != null) return true;
  if (snapshot.summary != null) return true;
  if (snapshot.found === true) return true;
  if (snapshot.listed != null) return true;
  if (snapshot.fetched_at || snapshot.last_analysis_at || snapshot.last_enriched_at) return true;
  return false;
}

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
  // Disabled provider: keep historical results distinguishable from an empty one.
  if (status === 'disabled') return snapshotHasResult(snapshot) ? 'historical_disabled' : 'disabled';
  if (['not_configured', 'api_key_missing'].includes(status)) return 'not_configured';
  if (['dataset_not_synced', 'suspicious', 'stale'].includes(status)) return 'not_configured';
  if (['error', 'failed'].includes(status)) return 'error';
  return 'not_run';
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
  if (state === 'historical_disabled') return 'Historical · Disabled';
  if (status === 'disabled' || status === 'not_configured' || state === 'disabled' || state === 'not_configured') {
    return 'Disabled';
  }
  if (status === 'failed' || state === 'error') return 'Failed';
  if (status === 'no_data' || (status === 'completed' && snapshot.known === false) || state === 'not_found') {
    return 'No data';
  }
  if (status === 'completed' || state === 'available') {
    // Prefer Found over Available — DNS history present is not a reputation verdict.
    return 'Found';
  }
  return 'Not run';
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

export function providerStateLabel(state) {
  if (state === 'available') return 'Available';
  if (state === 'partial') return 'Partial';
  if (state === 'not_found') return 'Not found';
  if (state === 'historical_disabled') return 'Historical · Disabled';
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
  // Historical result under a now-disabled provider: present but muted, not dominant.
  if (state === 'historical_disabled') return { dot: '#f59e0b', color: '#cbd5e1' };
  if (state === 'disabled' || state === 'not_configured') return { dot: '#f59e0b', color: '#fcd34d' };
  return { dot: '#64748b', color: '#94a3b8' };
}

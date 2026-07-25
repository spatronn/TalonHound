export const PROVIDER_META = {
  virustotal: {
    key: 'virustotal',
    name: 'VirusTotal',
    shortDescription: 'File, URL and domain reputation lookup.',
    longDescription: 'File, URL and domain reputation lookup using VirusTotal API.',
    editable: true
  },
  ipinfo_lite: {
    key: 'ipinfo_lite',
    name: 'IPinfo Lite',
    shortDescription: 'On-demand IP enrichment (ASN, country, continent).',
    longDescription: 'On-demand IP enrichment (ASN, country, continent). No bulk feed.',
    editable: true
  },
  abuseipdb: {
    key: 'abuseipdb',
    name: 'AbuseIPDB',
    shortDescription: 'Public IP reputation checks (check endpoint only).',
    longDescription: 'Read-only public IP reputation checks using AbuseIPDB check endpoint.',
    editable: true
  },
  rdap: {
    key: 'rdap',
    name: 'RDAP / WHOIS',
    shortDescription: 'Domain registration data via public RDAP.',
    longDescription: 'Public RDAP domain registration lookups for domain and URL IOCs. No API key required.',
    editable: false
  },
  dnsmania: {
    key: 'dnsmania',
    name: 'DNSMania',
    shortDescription: 'Passive DNS history from DNSMania (DNSTAP).',
    longDescription: 'Passive DNS history from DNSMania (DNSTAP). Manual on-demand enrichment from IOC Details > Intelligence.',
    editable: false
  },
  spamhaus_drop: {
    key: 'spamhaus_drop',
    name: 'Spamhaus DROP',
    shortDescription: 'Periodic CIDR blocklist dataset sync.',
    longDescription: 'Periodic CIDR blocklist dataset sync. Local lookup only — no per-IP external calls.',
    editable: true
  }
};

export const PROVIDER_ORDER = [
  'virustotal',
  'ipinfo_lite',
  'abuseipdb',
  'rdap',
  'dnsmania',
  'spamhaus_drop'
];

export function getProviderMeta(providerKey) {
  return PROVIDER_META[providerKey] || {
    key: providerKey,
    name: providerKey,
    shortDescription: '',
    longDescription: '',
    editable: false
  };
}

export function resolveProviderStatus(row) {
  if (!row) return 'not_configured';
  const raw = String(row.status || '').toLowerCase();
  if (row.enabled === false || raw === 'disabled') return 'disabled';
  if (raw === 'healthy') return 'healthy';
  if (raw === 'error') return 'error';
  if (raw === 'rate_limited') return 'rate_limited';
  if (raw === 'configured') return 'configured';
  if (raw === 'never_synced') return 'never_synced';
  if (raw === 'running') return 'running';
  if (raw === 'built-in' || (row.provider === 'rdap' && row.enabled !== false)) return 'healthy';
  return raw || 'not_configured';
}

import React from 'react';
import abuseipdbLogo from '../../assets/provider-logos/abuseipdb.png';
import virustotalLogo from '../../assets/provider-logos/virustotal.svg';
import ipinfoLogo from '../../assets/provider-logos/ipinfo.svg';
import rdapLogo from '../../assets/provider-logos/rdap.svg';
import dnsmaniaLogo from '../../assets/provider-logos/dnsmania.svg';
import spamhausLogo from '../../assets/provider-logos/spamhaus.svg';

const LOGO_BY_KEY = {
  virustotal: virustotalLogo,
  ipinfo_lite: ipinfoLogo,
  abuseipdb: abuseipdbLogo,
  rdap: rdapLogo,
  dnsmania: dnsmaniaLogo,
  spamhaus_drop: spamhausLogo
};

export default function ProviderLogo({ providerKey, name, size = 36 }) {
  const src = LOGO_BY_KEY[providerKey];
  const label = name || providerKey || 'Provider';

  if (!src) {
    const initial = String(label).charAt(0).toUpperCase() || '?';
    return (
      <span
        className="ep-logo ep-logo--fallback"
        style={{ width: size, height: size, fontSize: Math.round(size * 0.42) }}
        aria-hidden="true"
      >
        {initial}
      </span>
    );
  }

  return (
    <span className="ep-logo" style={{ width: size, height: size }}>
      <img src={src} alt="" width={size} height={size} />
      <span className="sr-only">{label}</span>
    </span>
  );
}

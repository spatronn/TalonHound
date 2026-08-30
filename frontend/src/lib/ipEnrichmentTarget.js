const IP_ENRICH_IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export function ipEnrichStripHostPort(host) {
  let h = String(host || '').trim().toLowerCase();
  h = h.replace(/\.$/, '').replace(/^\[/, '').replace(/\]$/, '');
  const portIdx = h.indexOf(':');
  if (portIdx > 0 && /^\d+$/.test(h.slice(portIdx + 1))) h = h.slice(0, portIdx);
  return h;
}

export function ipEnrichIsPrivateIpv4(host) {
  const parts = String(host || '').split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n))) return true;
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a >= 224) return true;
  return false;
}

function isIpLiteralHost(host) {
  return IP_ENRICH_IPV4_RE.test(host) || host.includes(':');
}

/**
 * Extract IP literal from IP or URL IOC values for enrichment providers.
 * @returns {{ ip: string|null, observable: string|null, isIpLiteral: boolean, privateIp: boolean }}
 */
export function parseIpEnrichmentTarget(iocValue, iocType) {
  const raw = String(iocValue || '').trim();
  const type = String(iocType || '').toLowerCase();
  if (!raw) return { ip: null, observable: null, isIpLiteral: false, privateIp: false };
  if (type === 'domain' || type === 'hash' || type === 'file_hash' || type === 'email') {
    return { ip: null, observable: raw, isIpLiteral: false, privateIp: false };
  }

  let ip = null;
  if (type === 'ip') {
    ip = ipEnrichStripHostPort(raw.split('/')[0]);
  } else if (type === 'url') {
    try {
      const u = new URL(raw);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return { ip: null, observable: raw, isIpLiteral: false, privateIp: false };
      }
      ip = ipEnrichStripHostPort(u.hostname);
    } catch {
      return { ip: null, observable: raw, isIpLiteral: false, privateIp: false };
    }
  } else {
    return { ip: null, observable: raw, isIpLiteral: false, privateIp: false };
  }

  if (!ip || !isIpLiteralHost(ip)) {
    return { ip: null, observable: raw, isIpLiteral: false, privateIp: false };
  }

  const privateIp = IP_ENRICH_IPV4_RE.test(ip) && ipEnrichIsPrivateIpv4(ip);
  return { ip, observable: raw, isIpLiteral: true, privateIp };
}

/** IPinfo Lite: public IP literals only (IP IOC or URL-with-IP host). */
export function getIpEnrichmentEligibility(iocValue, iocType) {
  const parsed = parseIpEnrichmentTarget(iocValue, iocType);
  if (!parsed.ip || parsed.privateIp) {
    return { eligible: false, ip: parsed.ip, observable: parsed.observable };
  }
  return { eligible: true, ip: parsed.ip, observable: parsed.observable };
}

/** AbuseIPDB: IP literals including private/reserved (UI shows unsupported message). */
export function getAbuseIpdbEligibility(iocValue, iocType) {
  const parsed = parseIpEnrichmentTarget(iocValue, iocType);
  if (!parsed.ip) {
    return { eligible: false, ip: null, privateIp: false, observable: parsed.observable };
  }
  return {
    eligible: true,
    ip: parsed.ip,
    privateIp: parsed.privateIp,
    observable: parsed.observable
  };
}

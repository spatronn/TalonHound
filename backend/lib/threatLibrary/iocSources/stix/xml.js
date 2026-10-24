/**
 * STIX 1.x / CybOX semantic extraction for linked IOC Sources.
 * Only values inside Indicator (or explicitly indicator-linked) Observables
 * become Indicators. Email From/To addresses do not promote provider domains.
 */

import { normalizeObservable } from '../../../observable-normalization.js';
import { createStixEvidence, EVIDENCE_MEMBERSHIP, summarizeEvidence } from './evidence.js';

/**
 * @param {string} text
 */
export function looksLikeStixXml(text) {
  const s = String(text || '').slice(0, 8000);
  return /<(?:[\w.-]+:)?STIX_Package\b/i.test(s) || /xmlns:stix=/i.test(s) || /stix\.mitre\.org\/stix-1/i.test(s);
}

function decodeXmlEntities(s) {
  return String(s || '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
    .replace(/&amp;/g, '&');
}

function localName(tag) {
  const t = String(tag || '');
  const i = t.indexOf(':');
  return (i >= 0 ? t.slice(i + 1) : t).toLowerCase();
}

/**
 * Split STIX package into Indicator element bodies.
 * CISA STIX 1.x packages use non-nested `<stix:Indicator>...</stix:Indicator>`.
 * @param {string} xml
 * @returns {Array<{ id: string|null, xml: string }>}
 */
export function extractIndicatorElements(xml) {
  const src = String(xml || '');
  const out = [];
  const re = /<((?:[\w.-]+:)?Indicator)\b([^>]*)>([\s\S]*?)<\/(?:[\w.-]+:)?Indicator\s*>/gi;
  let m;
  while ((m = re.exec(src)) !== null) {
    if (localName(m[1]) !== 'indicator') continue;
    const attrs = m[2] || '';
    const idM = /\bid\s*=\s*"([^"]+)"/i.exec(attrs);
    out.push({ id: idM ? idM[1] : null, xml: m[0] });
  }
  return out;
}

function firstTagText(block, local) {
  const re = new RegExp(`<(?:[\\w.-]+:)?${local}(?:\\s[^>]*)?>([^<]*)</(?:[\\w.-]+:)?${local}\\s*>`, 'i');
  const m = re.exec(block);
  return m ? decodeXmlEntities(m[1]).trim() : null;
}

/**
 * Extract typed observables from a CybOX Observable / Properties fragment.
 * Never promotes email-provider domains from Address category="e-mail".
 * @param {string} fragment
 * @param {{ indicatorId?: string|null, indicatorType?: string|null }} ctx
 */
export function extractObservablesFromCybox(fragment, ctx = {}) {
  /** @type {Array<{ type: string, value: string, role: string, membership: string, diagnostics: string[], locator: string }>} */
  const out = [];
  const xml = String(fragment || '');

  // File hashes
  const hashRe =
    /<(?:[\w.-]+:)?Type(?:\s[^>]*)?>(MD5|SHA1|SHA-1|SHA256|SHA-256)<\/(?:[\w.-]+:)?Type\s*>\s*<(?:[\w.-]+:)?Simple_Hash_Value(?:\s[^>]*)?>([A-Fa-f0-9]{32,64})<\/(?:[\w.-]+:)?Simple_Hash_Value\s*>/gi;
  let hm;
  while ((hm = hashRe.exec(xml)) !== null) {
    const algo = hm[1].toUpperCase().replace('-', '');
    const type = algo === 'MD5' ? 'md5' : algo === 'SHA1' ? 'sha1' : algo === 'SHA256' ? 'sha256' : null;
    if (!type) continue;
    out.push({
      type,
      value: hm[2],
      role: 'malicious_file',
      membership: EVIDENCE_MEMBERSHIP.INDICATOR,
      diagnostics: [],
      locator: `hash:${type}`
    });
  }
  // Alternate: Simple_Hash_Value without paired Type in the same Hash window — length-based.
  if (!out.some((o) => ['md5', 'sha1', 'sha256'].includes(o.type))) {
    const simple = /<(?:[\w.-]+:)?Simple_Hash_Value(?:\s[^>]*)?>([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})<\/(?:[\w.-]+:)?Simple_Hash_Value\s*>/gi;
    let sm;
    while ((sm = simple.exec(xml)) !== null) {
      const hex = sm[1];
      const type = hex.length === 32 ? 'md5' : hex.length === 40 ? 'sha1' : 'sha256';
      out.push({
        type,
        value: hex,
        role: 'malicious_file',
        membership: EVIDENCE_MEMBERSHIP.INDICATOR,
        diagnostics: [],
        locator: `hash:${type}`
      });
    }
  }

  // DomainNameObj:Value (FQDN indicators)
  const domainNs = /<DomainNameObj:Value(?:\s[^>]*)?>([^<]+)<\/DomainNameObj:Value\s*>/gi;
  let dm;
  while ((dm = domainNs.exec(xml)) !== null) {
    const v = decodeXmlEntities(dm[1]).trim();
    if (v && !v.includes('@')) {
      out.push({
        type: 'domain',
        value: v,
        role: 'malicious_infrastructure',
        membership: EVIDENCE_MEMBERSHIP.INDICATOR,
        diagnostics: [],
        locator: 'DomainNameObj:Value'
      });
    }
  }
  if (!out.some((o) => o.type === 'domain') && /DomainNameObjectType/i.test(xml)) {
    const blocks = xml.split(/xsi:type="[^"]*DomainNameObjectType"/i).slice(1);
    for (const scope of blocks) {
      const pref = /<(?:[\w.-]+:)?Value(?:\s[^>]*)?>([^<]+)<\/(?:[\w.-]+:)?Value\s*>/i.exec(scope);
      if (!pref) continue;
      const v = decodeXmlEntities(pref[1]).trim();
      if (v && !v.includes('@')) {
        out.push({
          type: 'domain',
          value: v,
          role: 'malicious_infrastructure',
          membership: EVIDENCE_MEMBERSHIP.INDICATOR,
          diagnostics: [],
          locator: 'DomainNameObj:Value'
        });
      }
    }
  }

  // URIObj:Value → URL (add scheme if host/path only)
  const uriNs = /<URIObj:Value(?:\s[^>]*)?>([^<]+)<\/URIObj:Value\s*>/gi;
  let um;
  while ((um = uriNs.exec(xml)) !== null) {
    let v = decodeXmlEntities(um[1]).trim();
    if (!v) continue;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) v = `http://${v}`;
    out.push({
      type: 'url',
      value: v,
      role: 'malicious_infrastructure',
      membership: EVIDENCE_MEMBERSHIP.INDICATOR,
      diagnostics: [],
      locator: 'URIObj:Value'
    });
  }
  if (!out.some((o) => o.type === 'url') && /URIObjectType/i.test(xml)) {
    const blocks = xml.split(/xsi:type="[^"]*URIObjectType"/i).slice(1);
    for (const scope of blocks) {
      const pref = /<(?:[\w.-]+:)?Value(?:\s[^>]*)?>([^<]+)<\/(?:[\w.-]+:)?Value\s*>/i.exec(scope);
      if (!pref) continue;
      let v = decodeXmlEntities(pref[1]).trim();
      if (!v) continue;
      if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) v = `http://${v}`;
      out.push({
        type: 'url',
        value: v,
        role: 'malicious_infrastructure',
        membership: EVIDENCE_MEMBERSHIP.INDICATOR,
        diagnostics: [],
        locator: 'URIObj:Value'
      });
    }
  }

  // AddressObj — category discriminates email vs IP; never emit provider domain alone.
  const addrRe =
    /category="([^"]+)"[^>]*>\s*<(?:[\w.-]+:)?Address_Value(?:\s[^>]*)?>([^<]+)<\/(?:[\w.-]+:)?Address_Value\s*>/gi;
  let am;
  while ((am = addrRe.exec(xml)) !== null) {
    const category = String(am[1] || '').toLowerCase();
    const value = decodeXmlEntities(am[2]).trim();
    if (!value) continue;
    if (category === 'e-mail' || category === 'email' || value.includes('@')) {
      out.push({
        type: 'email',
        value,
        role: 'malicious_email',
        // Email is a publisher-asserted Indicator in STIX 1 "Malicious E-mail" packages,
        // but not a global NETWORK_IOC_TYPE — keep as context_only for membership safety
        // unless the indicator type explicitly names malicious e-mail (still not a domain).
        membership: EVIDENCE_MEMBERSHIP.CONTEXT_ONLY,
        diagnostics: ['email_address_not_domain', 'email_not_network_ioc_type'],
        locator: 'AddressObj:Address_Value'
      });
      continue;
    }
    if (category.includes('ipv6') || (value.includes(':') && !value.includes('.'))) {
      out.push({
        type: 'ipv6',
        value,
        role: 'malicious_infrastructure',
        membership: EVIDENCE_MEMBERSHIP.INDICATOR,
        diagnostics: [],
        locator: 'AddressObj:Address_Value'
      });
      continue;
    }
    if (category.includes('ipv4') || category === 'cidr' || /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d+)?$/.test(value)) {
      out.push({
        type: value.includes('/') ? 'cidr' : 'ip',
        value,
        role: 'malicious_infrastructure',
        membership: EVIDENCE_MEMBERSHIP.INDICATOR,
        diagnostics: [],
        locator: 'AddressObj:Address_Value'
      });
    }
  }

  // Fallback Address_Value without category when surrounding type is ipv4
  if (/AddressObjectType/i.test(xml) && !out.some((o) => o.locator === 'AddressObj:Address_Value')) {
    const bare = /<(?:[\w.-]+:)?Address_Value(?:\s[^>]*)?>([^<]+)<\/(?:[\w.-]+:)?Address_Value\s*>/gi;
    let bm;
    while ((bm = bare.exec(xml)) !== null) {
      const value = decodeXmlEntities(bm[1]).trim();
      if (!value || value.includes('@')) continue;
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
        out.push({
          type: 'ip',
          value,
          role: 'malicious_infrastructure',
          membership: EVIDENCE_MEMBERSHIP.INDICATOR,
          diagnostics: [],
          locator: 'AddressObj:Address_Value'
        });
      }
    }
  }

  void ctx;
  return out;
}

/**
 * @param {string} xmlText
 */
export function extractStixXmlEvidence(xmlText) {
  const xml = String(xmlText || '');
  if (!looksLikeStixXml(xml)) {
    return {
      ok: false,
      code: 'not_stix_xml',
      message: 'Content is not a STIX 1.x package',
      evidence: [],
      summary: summarizeEvidence([])
    };
  }

  const indicators = extractIndicatorElements(xml);
  /** @type {import('./evidence.js').StixEvidence[]} */
  const evidence = [];

  for (const ind of indicators) {
    const title = firstTagText(ind.xml, 'Title');
    const indType = firstTagText(ind.xml, 'Type') || title || '';
    const observables = extractObservablesFromCybox(ind.xml, {
      indicatorId: ind.id,
      indicatorType: indType
    });

    // Malicious E-mail: keep email as context_only (not domain). File/URL/Domain stay indicators.
    for (const obs of observables) {
      let membership = obs.membership;
      const diagnostics = [...obs.diagnostics];
      if (obs.type === 'email') {
        membership = EVIDENCE_MEMBERSHIP.CONTEXT_ONLY;
        if (!diagnostics.includes('email_address_not_domain')) diagnostics.push('email_address_not_domain');
      }

      const type = obs.type === 'ipv6' ? 'ipv6' : obs.type;
      const normBase = normalizeObservable(type === 'ipv6' ? 'ip' : type === 'email' ? 'domain' : type, obs.value);
      // For email, normalize to lowercase full address (normalizeObservable('domain') would wrong-path).
      const normalized =
        type === 'email'
          ? String(obs.value).trim().toLowerCase()
          : type === 'md5' || type === 'sha1' || type === 'sha256'
            ? String(obs.value).trim().toLowerCase()
            : normBase || String(obs.value).trim();

      if (!normalized) continue;
      // Skip email-provider domains mistakenly typed as domain (defense in depth).
      if (type === 'domain' && isMailProviderDomain(normalized)) {
        evidence.push(
          createStixEvidence({
            original_value: obs.value,
            normalized_value: normalized,
            observable_type: 'domain',
            source_format: 'stix_xml',
            stix_object_id: ind.id,
            evidence_locator: `${ind.id || 'indicator'}:${obs.locator}`,
            object_semantics: 'cybox_observable',
            evidence_role: 'mail_provider_reference',
            membership: EVIDENCE_MEMBERSHIP.EXCLUDED,
            diagnostics: ['mail_provider_domain_excluded'],
            meta: { indicator_type: indType, indicator_title: title }
          })
        );
        continue;
      }

      evidence.push(
        createStixEvidence({
          original_value: obs.value,
          normalized_value: normalized,
          observable_type: type === 'cidr' ? 'cidr' : type,
          source_format: 'stix_xml',
          stix_object_id: ind.id,
          evidence_locator: `${ind.id || 'indicator'}:${obs.locator}`,
          object_semantics: 'indicator',
          evidence_role: obs.role,
          membership,
          diagnostics,
          meta: { indicator_type: indType, indicator_title: title }
        })
      );
    }
  }

  return {
    ok: true,
    format: 'stix_xml',
    evidence,
    summary: summarizeEvidence(evidence),
    indicator_count: indicators.length
  };
}

const MAIL_PROVIDER_DOMAINS = new Set([
  'protonmail.com',
  'proton.me',
  'tutanota.com',
  'tuta.io',
  'tutamail.com',
  'mailfence.com',
  'skiff.com',
  'onionmail.org',
  'gmail.com',
  'outlook.com',
  'hotmail.com',
  'yahoo.com',
  'icloud.com',
  'aol.com',
  'gmx.com',
  'gmx.net',
  'mail.com',
  'yandex.com',
  'yandex.ru'
]);

function isMailProviderDomain(domain) {
  const d = String(domain || '').toLowerCase().replace(/\.$/, '');
  if (MAIL_PROVIDER_DOMAINS.has(d)) return true;
  // Only exact provider domains — not attacker subdomains on unrelated TLDs.
  return false;
}

/**
 * @param {string} text
 */
export function parseStixXmlSource(text) {
  return extractStixXmlEvidence(text);
}

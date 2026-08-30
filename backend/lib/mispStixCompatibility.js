/**
 * MISP import compatibility for TalonHound STIX 2.1 Indicator output.
 *
 * First-release path: produce a standards-valid STIX 2.1 Bundle (Phase 1) that
 * MISP can import. This module documents the Indicator pattern → MISP attribute
 * mapping used by that import. It does not emit MISP JSON or live-sync events.
 *
 * Supported (STIX pattern → typical MISP attribute type):
 *   ipv4-addr / ipv6-addr  → ip-dst  (CIDR uses ISSUBSET; still ip-dst)
 *   domain-name            → domain
 *   url                    → url
 *   file:hashes.MD5        → md5
 *   file:hashes.'SHA-1'    → sha1
 *   file:hashes.'SHA-256'  → sha256
 *
 * Unsupported (omitted from STIX, therefore not imported):
 *   ssdeep, imphash, tlsh, email, ja3, and any other IOC type without a
 *   STIX 2.1 comparison pattern in publishedFeedStix.stixPatternForIoc.
 *
 * Provenance: Indicator created/modified/valid_from and optional labels map to
 * MISP timestamps / tags when the importer preserves them. TalonHound does not
 * invent malware, campaign, or galaxy semantics.
 */

import { indicatorFromPublishedItem, stixPatternForIoc } from './publishedFeedStix.js';

const PATTERN_RULES = [
  { re: /^\[ipv4-addr:value(?:\s+=|\s+ISSUBSET)\s+'((?:\\'|\\\\|[^'\\])*)'\]$/, mispType: 'ip-dst' },
  { re: /^\[ipv6-addr:value(?:\s+=|\s+ISSUBSET)\s+'((?:\\'|\\\\|[^'\\])*)'\]$/, mispType: 'ip-dst' },
  { re: /^\[domain-name:value\s+=\s+'((?:\\'|\\\\|[^'\\])*)'\]$/, mispType: 'domain' },
  { re: /^\[url:value\s+=\s+'((?:\\'|\\\\|[^'\\])*)'\]$/, mispType: 'url' },
  { re: /^\[file:hashes\.MD5\s+=\s+'((?:\\'|\\\\|[^'\\])*)'\]$/, mispType: 'md5' },
  { re: /^\[file:hashes\.'SHA-1'\s+=\s+'((?:\\'|\\\\|[^'\\])*)'\]$/, mispType: 'sha1' },
  { re: /^\[file:hashes\.'SHA-256'\s+=\s+'((?:\\'|\\\\|[^'\\])*)'\]$/, mispType: 'sha256' }
];

export const MISP_UNSUPPORTED_IOC_TYPES = Object.freeze([
  'ssdeep',
  'imphash',
  'tlsh',
  'email',
  'ja3'
]);

function unescapeStixPatternString(value) {
  let out = '';
  const s = String(value || '');
  for (let i = 0; i < s.length; i += 1) {
    if (s[i] === '\\' && i + 1 < s.length) {
      out += s[i + 1];
      i += 1;
    } else {
      out += s[i];
    }
  }
  return out;
}

/**
 * Map a STIX 2.1 Indicator to a MISP-like attribute, or null when unsupported.
 *
 * @param {object} indicator
 * @returns {{ type: string, value: string, comment: string|null, to_ids: true } | null}
 */
export function mapStixIndicatorToMispAttribute(indicator) {
  if (!indicator || indicator.type !== 'indicator') return null;
  const pattern = String(indicator.pattern || '').trim();
  if (!pattern || String(indicator.pattern_type || 'stix') !== 'stix') return null;
  for (const rule of PATTERN_RULES) {
    const m = pattern.match(rule.re);
    if (!m) continue;
    return {
      type: rule.mispType,
      value: unescapeStixPatternString(m[1]),
      comment: indicator.name ? String(indicator.name) : null,
      to_ids: true
    };
  }
  return null;
}

/**
 * Map a published-feed IOC item through STIX then to a MISP-like attribute.
 * Returns { supported: false, reason } when the type is omitted from STIX.
 */
export function mapPublishedItemToMispAttribute(item) {
  const type = String(item?.type || item?.observable_type || '').trim().toLowerCase();
  const value = String(item?.value || '').trim();
  if (!stixPatternForIoc(type, value)) {
    return {
      supported: false,
      reason: MISP_UNSUPPORTED_IOC_TYPES.includes(type)
        ? `IOC type '${type}' is omitted from STIX 2.1 output and is not imported into MISP`
        : `IOC type '${type || 'unknown'}' has no STIX 2.1 pattern and is not imported into MISP`
    };
  }
  const indicator = indicatorFromPublishedItem(item);
  if (!indicator) {
    return { supported: false, reason: 'Item could not be serialized as a STIX Indicator' };
  }
  const attr = mapStixIndicatorToMispAttribute(indicator);
  if (!attr) {
    return { supported: false, reason: 'STIX Indicator pattern is not a supported MISP attribute' };
  }
  return { supported: true, indicator, attribute: attr };
}

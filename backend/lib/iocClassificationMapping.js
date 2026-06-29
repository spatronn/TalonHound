/**
 * Feed-to-classification mapping for import-time threat_classification assignment.
 *
 * Rules:
 * - Only map values that are clearly unambiguous. Unknown/unclear values return null.
 * - null return means: leave threat_classification unchanged (do not overwrite).
 * - Never overwrite a non-null, non-'unknown' classification already set on the row.
 * - No actor attribution, no malware family inference, no URL/ASN/country heuristics.
 */

const URLHAUS_MAP = Object.freeze({
  botnet_cc:        'c2',
  phishing:         'phishing',
  malspam:          'malware',
  malware_download: 'malware',
});

const THREATFOX_MAP = Object.freeze({
  botnet_cc:        'c2',
  phishing:         'phishing',
  ransomware:       'ransomware',
  exploit:          'exploit',
  payload_delivery: 'malware',
  payload:          'malware',
  infostealer:      'malware',
});

/**
 * Resolve a threat_classification slug from a feed's raw category/type value.
 * Returns null when the mapping is unknown — caller must not overwrite in that case.
 *
 * @param {'urlhaus-abusech'|'threatfox-abusech'|string} feedKey
 * @param {string|null|undefined} rawValue
 * @returns {string|null}
 */
export function resolveClassificationFromFeed(feedKey, rawValue) {
  if (!rawValue) return null;
  const v = String(rawValue).toLowerCase().trim().replace(/[- ]/g, '_');
  if (feedKey === 'urlhaus-abusech') return URLHAUS_MAP[v] || null;
  if (feedKey === 'threatfox-abusech') return THREATFOX_MAP[v] || null;
  return null;
}

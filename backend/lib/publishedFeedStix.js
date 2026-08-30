/**
 * STIX 2.1 Indicator serialization for Published Feeds.
 *
 * Output is a STIX 2.1 Bundle of Indicator SDOs. This is the single source of
 * truth for pattern construction, deterministic IDs, and the incremental writer
 * used by file-backed generation. Do not emit proprietary JSON and call it STIX.
 *
 * Scope (v1): Indicator objects only. No Identity, Relationship, Malware, or
 * Campaign objects — those would invent semantics TalonHound does not store.
 */

import crypto from 'node:crypto';
import { confidenceToScore } from './feedFormatter.js';
import { toIsoUtc, normalizeTags } from './publishedFeedJson.js';
import { inferExactHashType } from './fileArtifacts/hashNormalize.js';

export const STIX_SPEC_VERSION = '2.1';
export const STIX_CONTENT_TYPE = 'application/stix+json;version=2.1';

/** RFC 4122 URL namespace (used to derive TalonHound's STIX namespace). */
const RFC4122_URL_NAMESPACE = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';

/**
 * Stable namespace for TalonHound STIX IDs.
 * uuidv5(URL namespace, 'https://talonhound.local/stix/v1')
 */
export const TALONHOUND_STIX_NAMESPACE = uuidv5FromNamespace(
  RFC4122_URL_NAMESPACE,
  'https://talonhound.local/stix/v1'
);

function uuidToBytes(uuid) {
  const hex = String(uuid).replace(/-/g, '');
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error('invalid uuid');
  return Buffer.from(hex, 'hex');
}

function bytesToUuid(buf, version) {
  const b = Buffer.from(buf.subarray(0, 16));
  b[6] = (b[6] & 0x0f) | (version << 4);
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

export function uuidv5FromNamespace(namespaceUuid, name) {
  const hash = crypto.createHash('sha1')
    .update(uuidToBytes(namespaceUuid))
    .update(String(name), 'utf8')
    .digest();
  return bytesToUuid(hash, 5);
}

export function stixUuidv5(name) {
  return uuidv5FromNamespace(TALONHOUND_STIX_NAMESPACE, name);
}

/** STIX 2.1 patterning string-literal escape: \ and ' only. */
export function escapeStixPatternString(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'");
}

function stixTimestamp(value) {
  const iso = toIsoUtc(value);
  if (!iso) return null;
  // STIX 2.1 requires at least millisecond precision.
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(iso)) {
    return iso.replace('Z', '.000Z');
  }
  return iso;
}

function isIpv6Literal(value) {
  const host = String(value || '').split('/')[0];
  return host.includes(':');
}

function isCidr(value) {
  return /\/\d{1,3}$/.test(String(value || '').trim());
}

function resolveStixObservableType(observableType, value) {
  const type = String(observableType || '').trim().toLowerCase();
  if (type === 'hash' || type === 'file_hash') {
    return inferExactHashType(value);
  }
  return type || null;
}

/**
 * Build a STIX 2.1 comparison pattern for one IOC, or null when the type is
 * not representable without inventing a SCO.
 */
export function stixPatternForIoc(observableType, value) {
  const type = resolveStixObservableType(observableType, value);
  const v = String(value || '').trim();
  if (!type || !v) return null;
  const escaped = escapeStixPatternString(v);

  if (type === 'ipv6' || (type === 'ip' && isIpv6Literal(v))) {
    if (isCidr(v)) return `[ipv6-addr:value ISSUBSET '${escaped}']`;
    return `[ipv6-addr:value = '${escaped}']`;
  }
  if (type === 'ip' || type === 'ipv4') {
    if (isCidr(v)) return `[ipv4-addr:value ISSUBSET '${escaped}']`;
    return `[ipv4-addr:value = '${escaped}']`;
  }
  if (type === 'domain') {
    return `[domain-name:value = '${escaped}']`;
  }
  if (type === 'url') {
    return `[url:value = '${escaped}']`;
  }
  if (type === 'md5') {
    return `[file:hashes.MD5 = '${escaped}']`;
  }
  if (type === 'sha1') {
    return `[file:hashes.'SHA-1' = '${escaped}']`;
  }
  if (type === 'sha256') {
    return `[file:hashes.'SHA-256' = '${escaped}']`;
  }
  return null;
}

function identityKey(observableType, value) {
  const type = resolveStixObservableType(observableType, value) || String(observableType || '').trim().toLowerCase();
  return `${type}:${String(value || '').trim().toLowerCase()}`;
}

/**
 * Deterministic Indicator id for a type+value pair (stable across regenerations).
 */
export function stixIndicatorId(observableType, value) {
  return `indicator--${stixUuidv5(`indicator:${identityKey(observableType, value)}`)}`;
}

/**
 * Deterministic Bundle id for a published-feed slug (stable collection identity).
 */
export function stixBundleIdForFeed(slug) {
  const key = String(slug || '').trim().toLowerCase() || 'unpublished';
  return `bundle--${stixUuidv5(`bundle:published-feed:${key}`)}`;
}

function compact(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v == null) continue;
    if (Array.isArray(v) && v.length === 0) continue;
    out[k] = v;
  }
  return out;
}

/**
 * Map a published IOC (or raw row + metadata) to a STIX 2.1 Indicator, or null.
 *
 * @param {{ type?: string, observable_type?: string, value: string, timestamps?: object, classification?: object, confidence?: any }} item
 */
export function indicatorFromPublishedItem(item = {}) {
  const type = String(item.type || item.observable_type || '').trim().toLowerCase();
  const value = String(item.value || '').trim();
  const pattern = stixPatternForIoc(type, value);
  if (!pattern) return null;

  const ts = item.timestamps && typeof item.timestamps === 'object' ? item.timestamps : {};
  let created = stixTimestamp(ts.first_seen_in_source || ts.imported_at || ts.created_at);
  let modified = stixTimestamp(
    ts.last_confirmed_in_source || ts.last_changed_in_source || ts.first_seen_in_source || ts.imported_at
  );
  created = created || modified;
  modified = modified || created;
  const validFrom = created;
  // STIX 2.1 Indicator requires created, modified, and valid_from — skip rather than invent.
  if (!created || !modified || !validFrom) return null;

  const tags = normalizeTags(item.classification?.tags || item.tags || []);
  const confidenceRaw = item.classification?.confidence ?? item.confidence;
  let confidence = null;
  if (confidenceRaw != null && confidenceRaw !== '') {
    const n = typeof confidenceRaw === 'number'
      ? confidenceRaw
      : confidenceToScore(confidenceRaw);
    if (Number.isFinite(n)) confidence = Math.max(0, Math.min(100, Math.floor(n)));
  }

  return compact({
    type: 'indicator',
    spec_version: STIX_SPEC_VERSION,
    id: stixIndicatorId(type, value),
    created,
    modified: modified || created,
    name: value,
    pattern,
    pattern_type: 'stix',
    valid_from: validFrom,
    confidence,
    labels: tags.length ? tags : null
  });
}

/**
 * Incremental STIX 2.1 Bundle writer. Objects are serialized one at a time.
 * Bundle id is deterministic from the feed slug so the header can be written
 * without buffering. generated_at is not a STIX property — omitted on purpose
 * so an unchanged population re-hashes identically (stable ETag).
 */
export class StixBundleWriter {
  constructor({ slug } = {}) {
    this._slug = slug != null ? String(slug) : '';
    this._bundleId = stixBundleIdForFeed(this._slug);
    /** @type {string[]} */
    this._objectChunks = [];
    this._hash = crypto.createHash('sha256');
    this._hash.update(JSON.stringify({
      spec_version: STIX_SPEC_VERSION,
      bundle_id: this._bundleId
    }));
  }

  get bundleId() {
    return this._bundleId;
  }

  /** @param {object} indicator already-normalized Indicator SDO */
  addIndicator(indicator) {
    if (!indicator) return false;
    const chunk = JSON.stringify(indicator);
    this._objectChunks.push(chunk);
    this._hash.update('\n');
    this._hash.update(chunk);
    return true;
  }

  get itemCount() {
    return this._objectChunks.length;
  }

  /**
   * @returns {{ content: string, content_hash: string, item_count: number, bundle_id: string }}
   */
  finish() {
    const header = `{"type":"bundle","id":${JSON.stringify(this._bundleId)},"spec_version":${JSON.stringify(STIX_SPEC_VERSION)},"objects":[`;
    const content = `${header}${this._objectChunks.join(',')}]}\n`;
    return {
      content,
      content_hash: this._hash.digest('hex'),
      item_count: this._objectChunks.length,
      bundle_id: this._bundleId
    };
  }

  buildHeader() {
    return `{"type":"bundle","id":${JSON.stringify(this._bundleId)},"spec_version":${JSON.stringify(STIX_SPEC_VERSION)},"objects":[`;
  }

  buildFooter() {
    return ']}\n';
  }
}

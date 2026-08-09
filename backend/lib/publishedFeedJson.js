// Public JSON contract for Published Feeds (schema_version "1.0").
//
// This module is the single source of truth for:
//   * the JSON schema version constant,
//   * the normalization layer that maps TalonHound's internal storage into the
//     stable public shape (never a DB dump — no row ids, fks, storage paths,
//     provider secrets, or raw provider payloads), and
//   * an incremental writer that serializes the envelope one item at a time so a
//     200k+ item feed never materializes as a single giant nested JS object.
//
// Design notes:
//   * All serialization goes through JSON.stringify, so IOC / tag / feed names with
//     quotes, backslashes, Unicode, or control characters produce valid JSON.
//   * generated_at is intentionally EXCLUDED from content_hash so an unchanged feed
//     re-generates to the same hash (stable ETag / snapshot dedup), matching the TXT
//     path where content carries no timestamp.

import crypto from 'crypto';
import { confidenceToScore, feedCategoryForObservableType } from './feedFormatter.js';

/** Centralized JSON schema version. Do NOT duplicate this string literal elsewhere. */
export const PUBLISHED_FEED_SCHEMA_VERSION = '1.0';

/** Providers normalized into the public enrichment contract (deterministic order). */
export const PUBLISHED_FEED_ENRICHMENT_PROVIDERS = ['abuseipdb', 'ipinfo', 'rdap', 'spamhaus', 'virustotal'];

/** Coerce a DB timestamp (Date | ISO string | epoch-ish string) to an ISO-8601 UTC string, or null. */
export function toIsoUtc(value) {
  if (value == null || value === '') return null;
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** Drop null/undefined values from an object; return null if nothing remains. */
function compact(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v == null) continue;
    out[k] = v;
  }
  return Object.keys(out).length ? out : null;
}

function numOrNull(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

/**
 * Public lifecycle timestamps for one IOC. Only maps values TalonHound actually stores;
 * unavailable fields are omitted (never invented).
 * @param {{ imported_at?: any, first_seen_in_source?: any, last_confirmed_in_source?: any, expires_at?: any }} meta
 */
export function normalizeTimestamps(meta = {}) {
  return compact({
    imported_at: toIsoUtc(meta.imported_at),
    first_seen_in_source: toIsoUtc(meta.first_seen_in_source),
    last_confirmed_in_source: toIsoUtc(meta.last_confirmed_in_source),
    expires_at: toIsoUtc(meta.expires_at)
  }) || {};
}

/**
 * Deterministic, de-duplicated public source list. Each entry carries only stable public
 * feed metadata; internal membership / feed row ids are never exposed.
 * @param {Array<{ feed_key?: string, feed_name?: string, first_seen_in_source?: any, last_confirmed_in_source?: any }>} rows
 */
export function normalizeSourceMetadata(rows = []) {
  const byKey = new Map();
  for (const row of rows || []) {
    const feedKey = row?.feed_key != null ? String(row.feed_key) : null;
    const feedName = row?.feed_name != null ? String(row.feed_name) : null;
    if (!feedKey && !feedName) continue;
    const dedupKey = feedKey || `name:${feedName}`;
    const entry = compact({
      feed_key: feedKey,
      feed_name: feedName,
      first_seen_in_source: toIsoUtc(row.first_seen_in_source),
      last_confirmed_in_source: toIsoUtc(row.last_confirmed_in_source)
    });
    if (entry) byKey.set(dedupKey, entry);
  }
  return [...byKey.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([, v]) => v);
}

/**
 * Deterministic, de-duplicated tag names (canonical spelling preserved, case-insensitive dedup).
 * @param {Array<string>} tagNames
 */
export function normalizeTags(tagNames = []) {
  const byLower = new Map();
  for (const raw of tagNames || []) {
    const name = String(raw ?? '').trim();
    if (!name) continue;
    const lower = name.toLowerCase();
    if (!byLower.has(lower)) byLower.set(lower, name);
  }
  return [...byLower.values()].sort((a, b) => a.localeCompare(b));
}

/**
 * Normalized classification block: category (from the IOC row), effective confidence
 * (0-100), and tags. Returns null when nothing meaningful is present so the section can
 * be omitted cleanly.
 * @param {{ category?: any, confidence?: any }} row
 * @param {Array<string>} tagNames
 */
export function normalizeClassification(row = {}, tagNames = []) {
  const categoryRaw = row?.category != null ? String(row.category).trim() : '';
  const category = categoryRaw || null;
  const tags = normalizeTags(tagNames);
  const confidence = row?.confidence != null && String(row.confidence).trim() !== ''
    ? confidenceToScore(row.confidence)
    : null;
  const block = compact({
    category,
    confidence,
    tags: tags.length ? tags : null
  });
  return block;
}

// --- Enrichment provider normalizers -------------------------------------------------
// Each takes the provider's stored row and returns a small, safe public subset. Raw
// provider payloads (raw_json / raw_response / vendor_results) are never exposed.

function normalizeVirustotal(row) {
  if (!row) return null;
  const summary = row.normalized_summary && typeof row.normalized_summary === 'object'
    ? row.normalized_summary
    : {};
  const stats = summary.stats && typeof summary.stats === 'object' ? summary.stats : {};
  return compact({
    malicious: numOrNull(stats.malicious),
    suspicious: numOrNull(stats.suspicious),
    harmless: numOrNull(stats.harmless),
    undetected: numOrNull(stats.undetected),
    last_analysis_at: toIsoUtc(summary.last_analysis_date)
  });
}

function normalizeAbuseipdb(row) {
  if (!row) return null;
  const summary = row.normalized_summary && typeof row.normalized_summary === 'object'
    ? row.normalized_summary
    : {};
  return compact({
    abuse_confidence_score: numOrNull(summary.abuseConfidenceScore),
    country_code: summary.countryCode ? String(summary.countryCode) : null,
    usage_type: summary.usageType ? String(summary.usageType) : null,
    total_reports: numOrNull(summary.totalReports),
    last_reported_at: toIsoUtc(summary.lastReportedAt)
  });
}

function normalizeIpinfo(row) {
  if (!row) return null;
  return compact({
    country: row.country ? String(row.country) : null,
    country_code: row.country_code ? String(row.country_code) : null,
    asn: row.asn ? String(row.asn) : null,
    organization: row.as_name ? String(row.as_name) : null
  });
}

function normalizeRdap(row) {
  if (!row) return null;
  return compact({
    registrar: row.registrar ? String(row.registrar) : null,
    registration_date: toIsoUtc(row.registration_date),
    expiration_date: toIsoUtc(row.expiration_date)
  });
}

function normalizeSpamhaus(row) {
  if (!row) return null;
  const listed = row.listed === true || String(row.provider_status || '').toLowerCase() === 'listed';
  return compact({
    listed: typeof row.listed === 'boolean' ? row.listed : listed,
    list_type: row.list_type ? String(row.list_type) : null,
    matched_cidr: row.matched_cidr ? String(row.matched_cidr) : null
  });
}

const ENRICHMENT_NORMALIZERS = {
  abuseipdb: normalizeAbuseipdb,
  ipinfo: normalizeIpinfo,
  rdap: normalizeRdap,
  spamhaus: normalizeSpamhaus,
  virustotal: normalizeVirustotal
};

/**
 * Normalized enrichment block keyed by stable lowercase provider id, in deterministic
 * order. Providers with no usable data are omitted. Returns null when empty.
 * @param {{ [provider: string]: object }} providerRows
 */
export function normalizeEnrichment(providerRows = {}) {
  const out = {};
  for (const provider of PUBLISHED_FEED_ENRICHMENT_PROVIDERS) {
    const normalizer = ENRICHMENT_NORMALIZERS[provider];
    const normalized = normalizer ? normalizer(providerRows?.[provider]) : null;
    if (normalized) out[provider] = normalized;
  }
  return Object.keys(out).length ? out : null;
}

/**
 * Assemble one public IOC item from its base row + batched metadata, honoring the feed's
 * JSON include flags. `type` is the specific observable type (e.g. "sha256", "domain").
 * @param {{ value: string, observable_type: string, category?: any, confidence?: any }} base
 * @param {object} meta  batched metadata for this observable
 * @param {{ includeSourceMetadata: boolean, includeClassification: boolean, includeEnrichment: boolean }} flags
 */
export function normalizePublishedIoc(base, meta = {}, flags = {}) {
  const type = String(base.observable_type || feedCategoryForObservableType(base.observable_type) || '').toLowerCase();
  const item = {
    type,
    value: base.value,
    timestamps: normalizeTimestamps(meta)
  };

  if (flags.includeSourceMetadata) {
    item.sources = normalizeSourceMetadata(meta.sources || []);
  }

  if (flags.includeClassification) {
    const classification = normalizeClassification(base, meta.tags || []);
    if (classification) item.classification = classification;
  }

  if (flags.includeEnrichment) {
    const enrichment = normalizeEnrichment(meta.enrichment || {});
    if (enrichment) item.enrichment = enrichment;
  }

  return item;
}

/**
 * Incremental JSON feed writer. Items are serialized one at a time (never held as one big
 * array of nested objects). generated_at is excluded from content_hash so an unchanged
 * feed hashes identically across regenerations.
 */
export class JsonFeedWriter {
  /** @param {{ name?: string, includeSourceMetadata?: boolean, includeClassification?: boolean, includeEnrichment?: boolean }} feedMeta */
  constructor(feedMeta = {}) {
    this._name = feedMeta.name != null ? String(feedMeta.name) : null;
    this._flags = {
      include_source_metadata: Boolean(feedMeta.includeSourceMetadata),
      include_classification: Boolean(feedMeta.includeClassification),
      include_enrichment: Boolean(feedMeta.includeEnrichment)
    };
    /** @type {string[]} */
    this._itemChunks = [];
    this._hash = crypto.createHash('sha256');
    this._hash.update(JSON.stringify({
      schema_version: PUBLISHED_FEED_SCHEMA_VERSION,
      name: this._name,
      flags: this._flags
    }));
  }

  /** @param {object} item already-normalized public item */
  addItem(item) {
    const chunk = JSON.stringify(item);
    this._itemChunks.push(chunk);
    this._hash.update('\n');
    this._hash.update(chunk);
  }

  get itemCount() {
    return this._itemChunks.length;
  }

  /**
   * @param {{ generatedAt?: string }} [opts]
   * @returns {{ content: string, content_hash: string, item_count: number }}
   */
  finish(opts = {}) {
    const itemCount = this._itemChunks.length;
    const generatedAt = toIsoUtc(opts.generatedAt) || new Date().toISOString();
    const header = `{"schema_version":${JSON.stringify(PUBLISHED_FEED_SCHEMA_VERSION)},`
      + `"feed":${JSON.stringify({
        name: this._name,
        generated_at: generatedAt,
        item_count: itemCount,
        include_source_metadata: this._flags.include_source_metadata,
        include_classification: this._flags.include_classification,
        include_enrichment: this._flags.include_enrichment
      })},"items":[`;
    const content = `${header}${this._itemChunks.join(',')}]}\n`;
    // content_hash covers only the deterministic parts (config + items), not generated_at,
    // so an unchanged feed re-generates to the same hash (stable ETag / snapshot dedup).
    const content_hash = this._hash.digest('hex');
    return { content, content_hash, item_count: itemCount };
  }
}

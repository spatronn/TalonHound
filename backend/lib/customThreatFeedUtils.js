import crypto from 'crypto';
import { validateFeedUrlPolicy } from './customThreatFeedSsrf.js';

export const CUSTOM_FEED_JOB_NAME = 'custom-threat-feed-sync';
export const CUSTOM_FEED_RUN_JOB_TYPE = 'custom_threat_feed_sync';
export const CUSTOM_FEED_KEY_PREFIX = 'ctf-';

export const FEED_FORMATS = Object.freeze(['auto', 'txt', 'csv']);
export const IOC_TYPE_MODES = Object.freeze(['auto', 'fixed']);
export const FIXED_IOC_TYPES = Object.freeze(['domain', 'ip', 'url', 'file_hash']);
export const CONFIDENCE_LEVELS = Object.freeze(['low', 'medium', 'high']);

export const DUPLICATE_CUSTOM_FEED_NAME_ERROR = 'A custom threat feed with this name already exists.';

export function normalizeCustomFeedName(name) {
  return String(name || '').trim();
}

export function customFeedNameComparisonKey(name) {
  return normalizeCustomFeedName(name).toLowerCase();
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} name
 * @param {string|null} [excludeCustomFeedId]
 */
export async function findCustomFeedNameConflict(db, name, excludeCustomFeedId = null) {
  const key = customFeedNameComparisonKey(name);
  if (!key) return null;
  const excludeId = excludeCustomFeedId && /^[0-9a-f-]{36}$/i.test(String(excludeCustomFeedId))
    ? String(excludeCustomFeedId)
    : null;
  const { rows } = await db.query(
    `SELECT c.id, f.name
     FROM integration_feeds f
     INNER JOIN custom_threat_feeds c ON c.feed_id = f.integration_id
     WHERE f.feed_kind = 'custom'
       AND c.deactivated_at IS NULL
       AND f.archived_at IS NULL
       AND lower(trim(f.name)) = $1
       AND ($2::uuid IS NULL OR c.id <> $2::uuid)
     LIMIT 1`,
    [key, excludeId]
  );
  return rows[0] || null;
}

export function isCustomFeedNameUniqueViolation(err) {
  return err?.code === '23505'
    && String(err?.constraint || '').includes('integration_feeds_custom_name_unique');
}

export function extractUrlHost(urlString) {
  try {
    const u = new URL(String(urlString || '').trim());
    return String(u.hostname || '').toLowerCase();
  } catch {
    return '';
  }
}

export function sanitizeUrlForDisplay(urlString) {
  try {
    const u = new URL(String(urlString || '').trim());
    u.username = '';
    u.password = '';
    const path = u.pathname && u.pathname !== '/' ? u.pathname : '';
    return `${u.protocol}//${u.host}${path}`;
  } catch {
    return '[invalid-url]';
  }
}

/**
 * Sync feed URL gate used by create/update routes.
 * Shares the same http(s) + destination policy as fetch (SSRF-01/02);
 * DNS resolve + pin happens in fetchFeedUrl before connect.
 */
export function validateFeedUrl(urlString) {
  const check = validateFeedUrlPolicy(urlString);
  if (!check.ok) return { ok: false, error: check.error };
  return { ok: true, url: check.url, url_host: check.url_host };
}

export function generateCustomFeedKey() {
  const id = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
  return `${CUSTOM_FEED_KEY_PREFIX}${id}`;
}

export function mapFixedIocTypeToObservableType(fixedType) {
  const t = String(fixedType || '').trim().toLowerCase();
  if (t === 'file_hash') return 'hash';
  if (t === 'domain' || t === 'ip' || t === 'url') return t;
  return null;
}

export function normalizeConfidenceInput(value, fallback = 'medium') {
  const c = String(value ?? fallback).trim().toLowerCase();
  return CONFIDENCE_LEVELS.includes(c) ? c : fallback;
}

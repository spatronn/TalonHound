import crypto from 'crypto';
import { isPrivateOrReservedIp } from './feedFormatter.js';

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

const BLOCKED_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

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

function isPrivateOrLocalHost(hostname) {
  const host = String(hostname || '').trim().toLowerCase();
  if (!host) return true;
  if (BLOCKED_HOSTS.has(host)) return true;
  if (host.endsWith('.local') || host.endsWith('.localhost')) return true;
  if (isPrivateOrReservedIp(host)) return true;
  if (host.includes(':')) {
    const h = host.replace(/^\[|\]$/g, '');
    if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) return true;
  }
  return false;
}

export function validateFeedUrl(urlString) {
  const raw = String(urlString || '').trim();
  if (!raw) return { ok: false, error: 'URL is required' };
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: 'URL must be a valid http or https URL' };
  }
  const protocol = String(parsed.protocol || '').toLowerCase();
  if (protocol !== 'http:' && protocol !== 'https:') {
    return { ok: false, error: 'Only http and https URLs are allowed' };
  }
  if (isPrivateOrLocalHost(parsed.hostname)) {
    return { ok: false, error: 'Private, loopback, and localhost URLs are not allowed' };
  }
  return { ok: true, url: raw, url_host: extractUrlHost(raw) };
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

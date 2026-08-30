/**
 * CERT.PL / CERT Polska Dangerous Websites Warning List (v2 JSON).
 *
 * Source: https://hole.cert.pl/domains/v2/domains.json
 * Auth: none
 *
 * Lifecycle: CERT.PL is an ingestion source only. DeleteDate != null records and
 * domains absent from a later response must NEVER delete, deactivate, or detach
 * TalonHound IOCs / source relationships. Expiry remains TalonHound-owned.
 *
 * This module contains pure/testable helpers plus the HTTP client. DB import
 * orchestration lives in importer.js (runCertPlImport).
 */

import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';

export const CERTPL_FEED_KEY = 'certpl-warning-list';
export const CERTPL_SOURCE_NAME = 'CERT.PL:CERT-Polska';
export const CERTPL_DISPLAY_NAME = 'CERT.PL Dangerous Websites';
export const CERTPL_PROVIDER = 'CERT Polska / NASK';
export const CERTPL_DOMAINS_URL = 'https://hole.cert.pl/domains/v2/domains.json';
export const CERTPL_USER_AGENT = 'TalonHound/1.0';

export const CERTPL_TIMEOUT_MS_DEFAULT = 60_000;
export const CERTPL_MAX_RETRIES_DEFAULT = 3;
export const CERTPL_RETRYABLE_STATUS = Object.freeze(new Set([408, 425, 429, 500, 502, 503, 504]));

const CONTROL_CHARS = /[\u0000-\u001f\u007f]/
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export class CertPlError extends Error {
  constructor(message, { code = 'certpl_error', statusCode = null, retryable = false, cause = null } = {}) {
    super(message);
    this.name = 'CertPlError';
    this.code = code;
    this.statusCode = statusCode;
    this.retryable = Boolean(retryable);
    if (cause) this.cause = cause;
  }
}

function cleanValue(value, maxLength = 4096) {
  const raw = String(value ?? '').trim();
  if (!raw || raw.length > maxLength || CONTROL_CHARS.test(raw)) return '';
  return raw;
}

/**
 * Normalize a CERT.PL DomainAddress using the same domain rules as USOM.
 * @returns {string|null} ASCII lowercase domain or null when invalid
 */
export function normalizeCertPlDomain(value) {
  const raw = cleanValue(value, 253).replace(/\.+$/, '').toLowerCase();
  if (!raw || raw.startsWith('*.') || raw.includes('://') || /[/:?#\s]/.test(raw)) return null;
  let ascii;
  try {
    ascii = domainToASCII(raw).toLowerCase();
  } catch {
    return null;
  }
  if (!ascii || ascii.length > 253) return null;
  const labels = ascii.split('.');
  if (labels.length < 2 || labels.some((label) => !DOMAIN_LABEL.test(label))) return null;
  return ascii;
}

/** Parse CERT.PL InsertDate / DeleteDate. Returns Date or null; never throws. */
export function parseCertPlTimestamp(value) {
  if (value == null || value === '') return null;
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }
  const raw = String(value).trim();
  if (!raw) return null;
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return null;
  return dt;
}

export function isCertPlRecordActive(record) {
  if (!record || typeof record !== 'object') return false;
  return record.DeleteDate == null || record.DeleteDate === '';
}

/**
 * Map one raw CERT.PL JSON object into an ingest entry, or classify skip reason.
 * @returns {{ ok: true, entry: object } | { ok: false, reason: string }}
 */
export function mapCertPlRecord(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, reason: 'invalid_record' };
  }

  if (!isCertPlRecordActive(raw)) {
    return { ok: false, reason: 'upstream_deleted' };
  }

  const domain = normalizeCertPlDomain(raw.DomainAddress);
  if (!domain) {
    return { ok: false, reason: 'invalid_domain' };
  }

  const insertDate = parseCertPlTimestamp(raw.InsertDate);
  // Malformed InsertDate must not crash ingestion; firstSeen stays null → membership uses import time.
  const deleteDateParsed = raw.DeleteDate == null || raw.DeleteDate === ''
    ? null
    : parseCertPlTimestamp(raw.DeleteDate);
  // Active path already requires DeleteDate null/empty; keep parse for resilience if callers re-check.
  void deleteDateParsed;

  let registerPositionId = null;
  if (raw.RegisterPositionId != null && raw.RegisterPositionId !== '') {
    const n = Number(raw.RegisterPositionId);
    if (Number.isFinite(n) && Number.isInteger(n) && n >= 0) {
      registerPositionId = n;
    } else {
      const asStr = cleanValue(raw.RegisterPositionId, 64);
      registerPositionId = asStr || null;
    }
  }

  return {
    ok: true,
    entry: {
      observable: domain,
      observableType: 'domain',
      registerPositionId,
      insertDate,
      firstSeen: insertDate,
      referenceUrl: CERTPL_DOMAINS_URL
    }
  };
}

/**
 * Prefer earliest InsertDate (true source first-seen); tie-break by lower RegisterPositionId.
 */
export function preferCertPlEntry(a, b) {
  if (!a) return b;
  if (!b) return a;
  const aTs = a.insertDate instanceof Date ? a.insertDate.getTime() : Number.POSITIVE_INFINITY;
  const bTs = b.insertDate instanceof Date ? b.insertDate.getTime() : Number.POSITIVE_INFINITY;
  if (aTs !== bTs) return aTs <= bTs ? a : b;
  const aId = a.registerPositionId == null ? Number.POSITIVE_INFINITY : Number(a.registerPositionId);
  const bId = b.registerPositionId == null ? Number.POSITIVE_INFINITY : Number(b.registerPositionId);
  if (Number.isFinite(aId) && Number.isFinite(bId) && aId !== bId) {
    return aId <= bId ? a : b;
  }
  return a;
}

/**
 * Parse a CERT.PL v2 JSON payload into ingestible domain entries.
 * Non-destructive: upstream-deleted records are counted and skipped only.
 */
export function parseCertPlDomainsPayload(payload) {
  if (!Array.isArray(payload)) {
    throw new CertPlError('CERT.PL response must be a JSON array', {
      code: 'invalid_schema'
    });
  }

  const stats = {
    fetched: payload.length,
    active: 0,
    upstream_deleted_skipped: 0,
    invalid_skipped: 0,
    duplicate_normalized_collapsed: 0
  };

  const byDomain = new Map();

  for (const raw of payload) {
    const mapped = mapCertPlRecord(raw);
    if (!mapped.ok) {
      if (mapped.reason === 'upstream_deleted') {
        stats.upstream_deleted_skipped += 1;
      } else {
        stats.invalid_skipped += 1;
      }
      continue;
    }
    stats.active += 1;
    const prev = byDomain.get(mapped.entry.observable);
    if (prev) {
      stats.duplicate_normalized_collapsed += 1;
      byDomain.set(mapped.entry.observable, preferCertPlEntry(prev, mapped.entry));
    } else {
      byDomain.set(mapped.entry.observable, mapped.entry);
    }
  }

  const entries = [...byDomain.values()].sort((a, b) =>
    a.observable.localeCompare(b.observable)
  );

  return { entries, stats };
}

export function buildCertPlNote(entry) {
  const parts = ['Auto-imported from CERT.PL Dangerous Websites'];
  if (entry?.registerPositionId != null) {
    parts.push(`external_id=${entry.registerPositionId}`);
  }
  if (entry?.insertDate instanceof Date && Number.isFinite(entry.insertDate.getTime())) {
    parts.push(`insert_date=${entry.insertDate.toISOString()}`);
  }
  parts.push(`provider=${CERTPL_PROVIDER}`);
  return parts.join(' | ');
}

export function buildCertPlEvidenceMetadata(entry) {
  const meta = {
    provider: CERTPL_PROVIDER,
    feed: CERTPL_FEED_KEY
  };
  if (entry?.registerPositionId != null) {
    meta.provider_record_id = entry.registerPositionId;
  }
  if (entry?.insertDate instanceof Date && Number.isFinite(entry.insertDate.getTime())) {
    meta.provider_insert_date = entry.insertDate.toISOString();
  }
  return meta;
}

export function certPlDomainKeyHash(domain) {
  return createHash('sha256').update(`domain|${domain}`).digest('hex');
}

export function hashCertPlEntries(entries) {
  const payload = entries.map((e) => e.observable);
  return createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

export function buildCertPlCheckpoint(entries) {
  const key_hashes = entries.map((e) => certPlDomainKeyHash(e.observable));
  return { v: 1, key_hashes, count: key_hashes.length };
}

/** Previous-key Set from items_json (compact hashes or legacy full objects). Add-diff only. */
export function buildCertPlPreviousKeySet(itemsJson) {
  const set = new Set();
  if (Array.isArray(itemsJson)) {
    for (const x of itemsJson) {
      if (x && typeof x === 'object' && x.observable != null) {
        set.add(certPlDomainKeyHash(String(x.observable)));
      } else if (typeof x === 'string' && x) {
        set.add(x);
      }
    }
    return set;
  }
  if (itemsJson && typeof itemsJson === 'object' && Array.isArray(itemsJson.key_hashes)) {
    for (const h of itemsJson.key_hashes) {
      if (h) set.add(String(h));
    }
  }
  return set;
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
      return;
    }
    const timer = setTimeout(resolve, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function retryDelayMs(attempt, retryAfterHeader, randomFn = Math.random) {
  if (retryAfterHeader != null) {
    const sec = Number(retryAfterHeader);
    if (Number.isFinite(sec) && sec >= 0) return Math.min(Math.floor(sec * 1000), 60_000);
  }
  const base = Math.min(1000 * (2 ** attempt), 15_000);
  const jitter = Math.floor(randomFn() * 250);
  return base + jitter;
}

function assertHttpsUrl(url) {
  let parsed;
  try {
    parsed = new URL(String(url));
  } catch {
    throw new CertPlError('CERT.PL URL is invalid', { code: 'invalid_url' });
  }
  if (parsed.protocol !== 'https:') {
    throw new CertPlError('CERT.PL URL must use HTTPS', { code: 'https_required' });
  }
  return parsed.toString();
}

/**
 * Fetch and parse CERT.PL domains v2 JSON.
 * Built-in URL is fixed; retries are bounded; HTML/error pages are rejected.
 */
export async function fetchCertPlDomains({
  url = CERTPL_DOMAINS_URL,
  timeoutMs = CERTPL_TIMEOUT_MS_DEFAULT,
  maxRetries = CERTPL_MAX_RETRIES_DEFAULT,
  signal,
  fetchFn = fetch,
  sleepFn = sleep,
  randomFn = Math.random,
  logger = console
} = {}) {
  const requestUrl = assertHttpsUrl(url);
  const retries = Math.max(0, Math.min(Number(maxRetries) || 0, 8));
  const timeout = Math.max(5_000, Number(timeoutMs) || CERTPL_TIMEOUT_MS_DEFAULT);

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    if (signal?.aborted) {
      throw Object.assign(new Error('aborted'), { name: 'AbortError' });
    }

    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeout);
    const abortParent = () => controller.abort(signal?.reason);
    signal?.addEventListener('abort', abortParent, { once: true });

    try {
      const response = await fetchFn(requestUrl, {
        method: 'GET',
        redirect: 'error',
        headers: {
          Accept: 'application/json',
          'User-Agent': CERTPL_USER_AGENT
        },
        signal: controller.signal
      });

      if (!response.ok) {
        const retryable = CERTPL_RETRYABLE_STATUS.has(response.status);
        if (!retryable || attempt >= retries) {
          throw new CertPlError(`CERT.PL request failed (HTTP ${response.status})`, {
            code: 'http_error',
            statusCode: response.status,
            retryable
          });
        }
        logger.warn?.(`[certpl] retry attempt=${attempt + 1} reason=http_${response.status}`);
        await sleepFn(retryDelayMs(attempt, response.headers?.get?.('retry-after'), randomFn), signal);
        continue;
      }

      const contentType = String(response.headers?.get?.('content-type') || '').toLowerCase();
      const text = await response.text();
      if (contentType.includes('text/html') || /^\s*</.test(text)) {
        throw new CertPlError('CERT.PL returned HTML instead of JSON', {
          code: 'unexpected_content_type',
          statusCode: response.status
        });
      }

      let payload;
      try {
        payload = text ? JSON.parse(text) : null;
      } catch (cause) {
        throw new CertPlError('CERT.PL returned invalid JSON', {
          code: 'malformed_json',
          statusCode: response.status,
          cause
        });
      }

      const parsed = parseCertPlDomainsPayload(payload);
      return {
        ...parsed,
        httpStatus: response.status,
        contentType,
        byteLength: Buffer.byteLength(text, 'utf8')
      };
    } catch (err) {
      if (signal?.aborted) {
        throw Object.assign(new Error('aborted'), { name: 'AbortError' });
      }
      if (err instanceof CertPlError) {
        const retryablePayload = ['malformed_json'].includes(err.code);
        if ((!err.retryable && !retryablePayload) || attempt >= retries) throw err;
        logger.warn?.(`[certpl] retry attempt=${attempt + 1} reason=${err.code}`);
        await sleepFn(retryDelayMs(attempt, null, randomFn), signal);
        continue;
      }
      const networkRetryable = timedOut
        || err?.name === 'AbortError'
        || err?.name === 'TimeoutError'
        || ['ETIMEDOUT', 'ECONNRESET', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN'].includes(err?.code);
      if (!networkRetryable || attempt >= retries) {
        throw new CertPlError(
          timedOut ? 'CERT.PL request timed out' : (err?.message || 'CERT.PL network error'),
          {
            code: timedOut ? 'timeout' : 'network_error',
            retryable: networkRetryable,
            cause: err
          }
        );
      }
      logger.warn?.(`[certpl] retry attempt=${attempt + 1} reason=${timedOut ? 'timeout' : 'network'}`);
      await sleepFn(retryDelayMs(attempt, null, randomFn), signal);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abortParent);
    }
  }

  throw new CertPlError('CERT.PL retry budget exhausted', { code: 'retry_exhausted' });
}

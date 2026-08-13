/**
 * TAXII 2.1 read-only envelopes over STIX-enabled Published Feeds.
 *
 * Collection id = feed slug. Only enabled feeds with STIX among `formats`
 * are visible. Write/import is not implemented.
 */

import fs from 'node:fs/promises';
import {
  getLatestSnapshotMeta,
  getSnapshotContentByIdAndHash,
  getSnapshotArtifactByIdAndHash,
  resolveFeedIocTypes,
  resolveFeedFilterMode,
  FEED_FILTER_MODES,
  QUERY_FEED_SNAPSHOT_KEY
} from './feedPublisherService.js';
import { feedIocTypesKey } from './feedFormatter.js';
import { feedHasStixFormat } from './publishedFeedFormats.js';
import {
  getPublishedFeedArtifactConfig,
  resolveStoredArtifactPath
} from './publishedFeedArtifact/store.js';
import { STIX_CONTENT_TYPE } from './publishedFeedStix.js';

export const TAXII_CONTENT_TYPE = 'application/taxii+json;version=2.1';
export const STIX_OASIS_CONTENT_TYPE = 'application/vnd.oasis.stix+json;version=2.1';
export const TAXII_API_ROOT = 'talonhound';
export const TAXII_OBJECTS_DEFAULT_LIMIT = 100;
export const TAXII_OBJECTS_MAX_LIMIT = 1000;
export const TAXII_PARSE_MAX_BYTES = 32 * 1024 * 1024;

const SLUG_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/;

export function isValidTaxiiCollectionId(id) {
  return SLUG_RE.test(String(id || ''));
}

export function publicOrigin(req) {
  const proto = String(req?.headers?.['x-forwarded-proto'] || req?.protocol || 'https')
    .split(',')[0]
    .trim() || 'https';
  const host = String(req?.headers?.['x-forwarded-host'] || req?.headers?.host || 'localhost')
    .split(',')[0]
    .trim() || 'localhost';
  return `${proto}://${host}`;
}

export function taxiiApiRootUrl(origin) {
  return `${String(origin).replace(/\/+$/, '')}/taxii2/${TAXII_API_ROOT}/`;
}

export function discoveryResource(origin) {
  return {
    title: 'TalonHound TAXII 2.1',
    description: 'Read-only TAXII 2.1 server over STIX-enabled Published Feeds.',
    default: taxiiApiRootUrl(origin),
    api_roots: [taxiiApiRootUrl(origin)]
  };
}

export function apiRootResource(origin) {
  return {
    title: 'TalonHound',
    description: 'STIX 2.1 Indicator collections from enabled Published Feeds.',
    versions: ['application/taxii+json;version=2.1'],
    max_content_length: TAXII_PARSE_MAX_BYTES
  };
}

export function taxiiCollectionFromFeed(feed, _origin) {
  const slug = String(feed?.slug || '').trim();
  void _origin;
  return {
    id: slug,
    title: String(feed?.name || slug),
    description: feed?.description ? String(feed.description) : `Published Feed ${slug} (STIX 2.1)`,
    can_read: true,
    can_write: false,
    media_types: [STIX_CONTENT_TYPE, STIX_OASIS_CONTENT_TYPE]
  };
}

export function encodeTaxiiCursor(offset) {
  const n = Math.max(0, Math.trunc(Number(offset) || 0));
  return Buffer.from(JSON.stringify({ o: n }), 'utf8').toString('base64url');
}

export function decodeTaxiiCursor(raw) {
  if (raw == null || raw === '') return { ok: true, offset: 0 };
  try {
    const parsed = JSON.parse(Buffer.from(String(raw), 'base64url').toString('utf8'));
    const o = Number(parsed?.o);
    if (!Number.isInteger(o) || o < 0) return { ok: false, error: 'Invalid next cursor' };
    return { ok: true, offset: o };
  } catch {
    return { ok: false, error: 'Invalid next cursor' };
  }
}

export function parseTaxiiLimit(raw) {
  if (raw == null || raw === '') return { ok: true, value: TAXII_OBJECTS_DEFAULT_LIMIT };
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) return { ok: false, error: 'limit must be a positive integer' };
  return { ok: true, value: Math.min(n, TAXII_OBJECTS_MAX_LIMIT) };
}

/**
 * Slice a STIX objects array into a TAXII 2.1 envelope. `next` is an opaque
 * offset cursor — never includes credentials.
 */
export function pageTaxiiObjects(objects, { limit, next } = {}) {
  const list = Array.isArray(objects) ? objects : [];
  const lim = Math.min(
    Math.max(1, Math.trunc(Number(limit) || TAXII_OBJECTS_DEFAULT_LIMIT)),
    TAXII_OBJECTS_MAX_LIMIT
  );
  const decoded = decodeTaxiiCursor(next);
  if (!decoded.ok) return { ok: false, error: decoded.error };
  const offset = decoded.offset;
  const slice = list.slice(offset, offset + lim);
  const more = offset + slice.length < list.length;
  return {
    ok: true,
    envelope: {
      objects: slice,
      more,
      ...(more ? { next: encodeTaxiiCursor(offset + slice.length) } : {})
    }
  };
}

function taxiiResponseHeaders(res, extra) {
  const headers = {
    'Content-Type': TAXII_CONTENT_TYPE,
    ...extra
  };
  const www = res.getHeader('WWW-Authenticate');
  if (www && !headers['WWW-Authenticate']) headers['WWW-Authenticate'] = www;
  return headers;
}

export function sendTaxiiError(res, httpStatus, title, description) {
  const body = JSON.stringify({
    title: String(title || 'Error'),
    http_status: String(httpStatus),
    ...(description ? { description: String(description) } : {})
  });
  res.writeHead(httpStatus, taxiiResponseHeaders(res, { 'Cache-Control': 'no-store' }));
  return res.end(body);
}

export function sendTaxiiJson(res, httpStatus, body) {
  res.writeHead(httpStatus, taxiiResponseHeaders(res, { 'Cache-Control': 'private, max-age=60' }));
  return res.end(JSON.stringify(body));
}

/** Accept TAXII/STIX media types; missing Accept is allowed. */
export function taxiiAcceptOk(req) {
  const raw = String(req?.headers?.accept || '').trim();
  if (!raw || raw === '*/*') return true;
  const lower = raw.toLowerCase();
  return lower.includes('taxii+json')
    || lower.includes('stix+json')
    || lower.includes('application/json')
    || lower.includes('*/*');
}

export function isStixEnabledFeed(feed) {
  return Boolean(feed) && feed.enabled !== false && feedHasStixFormat(feed);
}

export async function listStixEnabledFeeds(pool) {
  const { rows } = await pool.query(
    `SELECT id, name, slug, description, enabled, formats, format,
            ioc_types, ioc_type, time_window, filter_mode, advanced_query
     FROM published_feeds
     WHERE enabled = TRUE
     ORDER BY slug ASC`
  );
  return rows.filter(isStixEnabledFeed);
}

export async function getStixEnabledFeedBySlug(pool, slug) {
  const id = String(slug || '').trim();
  if (!isValidTaxiiCollectionId(id)) return null;
  const { rows } = await pool.query(
    `SELECT id, name, slug, description, enabled, formats, format,
            ioc_types, ioc_type, time_window, filter_mode, advanced_query
     FROM published_feeds
     WHERE slug = $1
     LIMIT 1`,
    [id]
  );
  const feed = rows[0];
  if (!feed || !isStixEnabledFeed(feed)) return null;
  return feed;
}

function snapshotKeysForFeed(feed) {
  const queryMode = resolveFeedFilterMode(feed) === FEED_FILTER_MODES.QUERY;
  return {
    iocTypeKey: queryMode ? QUERY_FEED_SNAPSHOT_KEY : feedIocTypesKey(resolveFeedIocTypes(feed)),
    window: queryMode ? 'all' : (feed.time_window || 'all')
  };
}

export function parseStixBundleObjects(text) {
  const parsed = JSON.parse(String(text || ''));
  if (!parsed || parsed.type !== 'bundle' || !Array.isArray(parsed.objects)) {
    throw Object.assign(new Error('Snapshot is not a STIX 2.1 Bundle'), { code: 'INVALID_STIX_BUNDLE' });
  }
  return parsed.objects;
}

/**
 * Load Indicator objects from the latest STIX snapshot.
 * Large file-backed snapshots above TAXII_PARSE_MAX_BYTES are refused so TAXII
 * never JSON.parses a million-object file; clients should use Published Feed STIX pull.
 *
 * @returns {{ ok: true, objects: object[] } | { ok: false, code: string, status: number, title: string, description: string }}
 */
export async function loadStixObjectsFromFeed(pool, feed) {
  const { iocTypeKey, window } = snapshotKeysForFeed(feed);
  const meta = await getLatestSnapshotMeta(pool, feed.id, iocTypeKey, window, 'stix');
  if (!meta) {
    return {
      ok: false,
      code: 'NO_SNAPSHOT',
      status: 404,
      title: 'Resource Not Found',
      description: 'Collection has no STIX snapshot yet'
    };
  }

  const bytes = meta.content_bytes != null ? Number(meta.content_bytes) : null;
  if (Number.isFinite(bytes) && bytes > TAXII_PARSE_MAX_BYTES) {
    return {
      ok: false,
      code: 'SNAPSHOT_TOO_LARGE',
      status: 413,
      title: 'Payload Too Large',
      description: 'STIX snapshot exceeds the TAXII pagination size cap; use the Published Feed STIX pull instead'
    };
  }

  if (meta.storage_path) {
    const artifact = await getSnapshotArtifactByIdAndHash(pool, meta.id, meta.content_hash);
    if (!artifact?.storage_path) {
      return {
        ok: false,
        code: 'ARTIFACT_MISSING',
        status: 503,
        title: 'Service Unavailable',
        description: 'STIX snapshot is momentarily unavailable'
      };
    }
    const cfg = getPublishedFeedArtifactConfig();
    let absPath;
    try {
      absPath = resolveStoredArtifactPath(cfg.storageDir, artifact.storage_path);
    } catch {
      return {
        ok: false,
        code: 'ARTIFACT_MISSING',
        status: 503,
        title: 'Service Unavailable',
        description: 'STIX snapshot is momentarily unavailable'
      };
    }
    let st;
    try {
      st = await fs.stat(absPath);
    } catch {
      return {
        ok: false,
        code: 'ARTIFACT_MISSING',
        status: 503,
        title: 'Service Unavailable',
        description: 'STIX snapshot is momentarily unavailable'
      };
    }
    if (st.size > TAXII_PARSE_MAX_BYTES) {
      return {
        ok: false,
        code: 'SNAPSHOT_TOO_LARGE',
        status: 413,
        title: 'Payload Too Large',
        description: 'STIX snapshot exceeds the TAXII pagination size cap; use the Published Feed STIX pull instead'
      };
    }
    const text = await fs.readFile(absPath, 'utf8');
    try {
      return { ok: true, objects: parseStixBundleObjects(text) };
    } catch (err) {
      return {
        ok: false,
        code: err?.code || 'INVALID_STIX_BUNDLE',
        status: 503,
        title: 'Service Unavailable',
        description: 'STIX snapshot could not be parsed'
      };
    }
  }

  const snapshot = await getSnapshotContentByIdAndHash(pool, meta.id, meta.content_hash);
  if (!snapshot?.content) {
    return {
      ok: false,
      code: 'NO_SNAPSHOT',
      status: 404,
      title: 'Resource Not Found',
      description: 'Collection has no STIX snapshot yet'
    };
  }
  const contentBytes = Buffer.byteLength(String(snapshot.content), 'utf8');
  if (contentBytes > TAXII_PARSE_MAX_BYTES) {
    return {
      ok: false,
      code: 'SNAPSHOT_TOO_LARGE',
      status: 413,
      title: 'Payload Too Large',
      description: 'STIX snapshot exceeds the TAXII pagination size cap; use the Published Feed STIX pull instead'
    };
  }
  try {
    return { ok: true, objects: parseStixBundleObjects(snapshot.content) };
  } catch (err) {
    return {
      ok: false,
      code: err?.code || 'INVALID_STIX_BUNDLE',
      status: 503,
      title: 'Service Unavailable',
      description: 'STIX snapshot could not be parsed'
    };
  }
}

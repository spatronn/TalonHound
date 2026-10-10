/**
 * SSRF-safe fetch for Additional IOC Sources.
 * Reuses custom-feed URL policy and DNS pinning; never executes fetched content.
 */

import http from 'node:http';
import https from 'node:https';
import { createHash } from 'node:crypto';
import {
  assertSafeFeedDestination,
  stripUrlUserinfo,
  validateFeedUrlPolicy
} from '../../customThreatFeedSsrf.js';
import { validateThreatLibraryUrl } from '../urlIngest.js';
import { IOC_SOURCE_CONTENT_TYPES, IOC_SOURCE_FETCH } from './constants.js';

/**
 * @param {string} url
 */
export function validateIocSourceUrl(url) {
  return validateThreatLibraryUrl(url);
}

/**
 * @param {string} contentTypeHeader
 */
export function isAllowedIocSourceContentType(contentTypeHeader) {
  const ct = String(contentTypeHeader || '').split(';')[0].trim().toLowerCase();
  if (!ct) return true;
  if (IOC_SOURCE_CONTENT_TYPES.some((allowed) => ct === allowed || ct.endsWith(`+${allowed.split('/')[1]}`))) {
    return true;
  }
  if (ct.startsWith('text/')) return true;
  if (ct === 'application/vnd.github+json' || ct === 'application/json') return true;
  return false;
}

async function readLimitedBody(res, maxBytes) {
  const chunks = [];
  let fetchedBytes = 0;
  for await (const chunk of res) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    fetchedBytes += buf.byteLength;
    if (fetchedBytes > maxBytes) {
      res.destroy();
      const err = new Error(`Response exceeds maximum size (${maxBytes} bytes)`);
      err.code = 'response_too_large';
      throw err;
    }
    chunks.push(buf);
  }
  return { buffer: Buffer.concat(chunks, fetchedBytes), fetchedBytes };
}

function requestPinned(parsed, addresses, headers, signal) {
  const isHttps = parsed.protocol === 'https:';
  const requestFn = isHttps ? https.request : http.request;
  const pinned = addresses[0];
  const options = {
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || (isHttps ? 443 : 80),
    path: `${parsed.pathname || '/'}${parsed.search || ''}`,
    method: 'GET',
    headers: { ...headers, Host: parsed.host },
    lookup(hostname, opts, cb) {
      if (typeof opts === 'function') {
        cb = opts;
        opts = {};
      }
      if (opts && opts.all) {
        cb(null, [{ address: pinned.address, family: pinned.family }]);
        return;
      }
      cb(null, pinned.address, pinned.family);
    },
    signal
  };
  if (isHttps) options.servername = parsed.hostname;
  return new Promise((resolve, reject) => {
    const req = requestFn(options, (res) => resolve(res));
    req.on('error', reject);
    req.end();
  });
}

/**
 * Fetch a URL as untrusted bytes/text. Never forwards Authorization. Never executes content.
 * @param {string} url
 * @param {{ timeoutMs?: number, maxBytes?: number, headers?: Record<string,string>, fetchImpl?: Function }} [options]
 */
export async function fetchIocSourceUrl(url, options = {}) {
  if (typeof options.fetchImpl === 'function') {
    const result = await options.fetchImpl(url, options);
    const body = result.bodyText ?? result.body ?? result.text ?? '';
    const buffer = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ''), 'utf8');
    return {
      ok: true,
      finalUrl: result.finalUrl || result.url || url,
      statusCode: result.httpStatus || result.statusCode || result.status || 200,
      contentType: result.contentType || '',
      body: buffer.toString('utf8'),
      buffer,
      bytes: buffer.length,
      contentHash: createHash('sha256').update(buffer).digest('hex'),
      fetchedAt: new Date().toISOString()
    };
  }

  const sync = validateIocSourceUrl(url);
  if (!sync.ok) {
    const err = new Error(sync.error || 'URL is not allowed');
    err.code = 'blocked_url';
    throw err;
  }

  const timeoutMs = options.timeoutMs ?? IOC_SOURCE_FETCH.TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? IOC_SOURCE_FETCH.MAX_BYTES;
  const maxRedirects = IOC_SOURCE_FETCH.MAX_REDIRECTS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let currentUrl = stripUrlUserinfo(sync.parsed);
  let hop = 0;

  try {
    while (hop <= maxRedirects) {
      const destination = await assertSafeFeedDestination(currentUrl.href);
      const headers = {
        Accept: 'text/plain,text/csv,text/html,application/json,application/pdf,application/vnd.github+json,*/*',
        'User-Agent': 'TalonHound-ThreatLibrary-IocSource/1.0',
        Connection: 'close',
        ...(options.headers || {})
      };
      // Never allow caller to inject Authorization / Cookie
      delete headers.Authorization;
      delete headers.authorization;
      delete headers.Cookie;
      delete headers.cookie;

      let res;
      try {
        res = await requestPinned(destination.parsed, destination.addresses, headers, controller.signal);
      } catch (err) {
        if (err?.name === 'AbortError' || controller.signal.aborted) {
          const timeoutErr = new Error(`Fetch timed out after ${timeoutMs}ms`);
          timeoutErr.code = 'timeout';
          throw timeoutErr;
        }
        throw err;
      }

      const status = Number(res.statusCode || 0);
      if (status >= 300 && status < 400) {
        const location = res.headers?.location;
        res.resume();
        if (!location) {
          const err = new Error('Redirect response missing Location header');
          err.code = 'redirect_invalid';
          throw err;
        }
        if (hop >= maxRedirects) {
          const err = new Error(`Too many redirects (max ${maxRedirects})`);
          err.code = 'redirect_limit';
          throw err;
        }
        let nextUrl;
        try {
          nextUrl = stripUrlUserinfo(new URL(String(location), currentUrl));
        } catch {
          const err = new Error('Redirect target URL is not allowed');
          err.code = 'redirect_blocked';
          throw err;
        }
        const nextSync = validateFeedUrlPolicy(nextUrl.href);
        if (!nextSync.ok) {
          const err = new Error('Redirect target URL is not allowed');
          err.code = 'redirect_blocked';
          throw err;
        }
        currentUrl = nextSync.parsed;
        hop += 1;
        continue;
      }

      const contentType = String(res.headers?.['content-type'] || '');
      const { buffer, fetchedBytes } = await readLimitedBody(res, maxBytes);
      if (contentType && !isAllowedIocSourceContentType(contentType)) {
        const err = new Error(`Unsupported content type: ${contentType.slice(0, 80)}`);
        err.code = 'unsupported_content_type';
        throw err;
      }
      if (status < 200 || status >= 300) {
        const err = new Error(`HTTP ${status}`);
        err.code = 'http_error';
        throw err;
      }

      return {
        ok: true,
        finalUrl: destination.url || currentUrl.href,
        statusCode: status,
        contentType,
        body: buffer.toString('utf8'),
        buffer,
        bytes: fetchedBytes,
        contentHash: createHash('sha256').update(buffer).digest('hex'),
        fetchedAt: new Date().toISOString()
      };
    }

    const err = new Error(`Too many redirects (max ${maxRedirects})`);
    err.code = 'redirect_limit';
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Sanitize error messages for API / logs (no tokens, no large bodies).
 * @param {unknown} err
 */
export function publicFetchError(err) {
  const code = err?.code || 'fetch_failed';
  const message = String(err?.message || 'Fetch failed').slice(0, 240);
  const safe = message.replace(/(bearer\s+)\S+/gi, '$1[redacted]').replace(/(token[=:]\s*)\S+/gi, '$1[redacted]');
  return { code, message: safe };
}

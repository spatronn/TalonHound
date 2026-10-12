/**
 * SSRF-safe fetch for Additional IOC Sources: the single outbound boundary
 * for source inspection, extraction and GitHub API / raw downloads.
 *
 * Every hop (the first request and each redirect):
 *   1. sync URL policy: http(s) only, no embedded credentials, ports 80/443,
 *      no localhost / internal / single-label names or forbidden IP literals
 *   2. optional destination guard (TalonHound IOC intelligence, see
 *      destinationIntel.js): a known malicious destination is never contacted
 *   3. DNS resolution with EVERY A/AAAA record checked against the shared
 *      forbidden-range list (customThreatFeedSsrf.js); the connection is then
 *      pinned to a checked address (no second lookup, so no DNS rebinding) and
 *      the address is re-checked at socket lookup time
 * Requests use a dedicated agent, so HTTP(S)_PROXY / NODE_USE_ENV_PROXY can
 * never route a request around the pinned destination. Bodies are size- and
 * time-bounded; content is never executed. Authorization / Cookie headers are
 * never sent.
 */

import http from 'node:http';
import https from 'node:https';
import { createHash } from 'node:crypto';
import {
  assertSafeFeedDestination,
  isForbiddenFeedDestinationIp,
  stripUrlUserinfo
} from '../../customThreatFeedSsrf.js';
import { validateThreatLibraryUrl } from '../urlIngest.js';
import { IOC_SOURCE_CONTENT_TYPES, IOC_SOURCE_FETCH } from './constants.js';

/** Public IOC datasets are served on the default web ports only. */
const IOC_SOURCE_ALLOWED_PORTS = new Set(['', '80', '443']);

/**
 * Sync policy for an IOC Source URL (submission and every fetch hop).
 * @param {string} url
 */
export function validateIocSourceUrl(url) {
  const base = validateThreatLibraryUrl(url);
  if (!base.ok) return base;
  if (!IOC_SOURCE_ALLOWED_PORTS.has(String(base.parsed.port || ''))) {
    return { ok: false, error: 'IOC source URLs must use the default HTTP/HTTPS port (80 or 443)' };
  }
  return base;
}

function blockedError(message, code = 'blocked_url', extra = {}) {
  return Object.assign(new Error(message), { code, ...extra });
}

/**
 * Policy + guard for one hop. Throws a coded error; never contacts the host.
 * @param {string} url
 * @param {{ destinationGuard?: (url: string) => Promise<{ ok: boolean, code?: string, reason?: string, matches?: object[] }> }} options
 * @param {'blocked_url'|'redirect_blocked'} code
 */
async function assertHopAllowed(url, options, code) {
  // The guard only compares what the URL names with stored intelligence; it
  // runs first so a known malicious destination reports that reason.
  if (typeof options.destinationGuard === 'function') {
    const verdict = await options.destinationGuard(String(url || ''));
    if (verdict && verdict.ok === false) {
      throw blockedError(verdict.reason || 'Destination is not allowed', verdict.code || 'destination_blocked', {
        intel: verdict.matches || null
      });
    }
  }
  const sync = validateIocSourceUrl(url);
  if (!sync.ok) throw blockedError(sync.error || 'URL is not allowed', code);
  return sync;
}

/** Error codes that mean "this destination must not be contacted". */
export const BLOCKING_FETCH_CODES = Object.freeze(new Set([
  'blocked_url',
  'redirect_blocked',
  'destination_blocked',
  'known_malicious_destination'
]));

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

export function requestPinned(parsed, addresses, headers, signal) {
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
    // Dedicated, non-pooled agent: the global agent honours HTTP(S)_PROXY when
    // NODE_USE_ENV_PROXY is set, which would bypass the pinned destination.
    agent: isHttps ? new https.Agent({ keepAlive: false }) : new http.Agent({ keepAlive: false }),
    lookup(hostname, opts, cb) {
      if (typeof opts === 'function') {
        cb = opts;
        opts = {};
      }
      // Connection-time re-check: this runs when the socket asks for the
      // address it is about to connect to.
      if (isForbiddenFeedDestinationIp(pinned.address)) {
        cb(blockedError('Resolved address is not allowed', 'destination_blocked'));
        return;
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
    const req = requestFn(options, (res) => {
      const remote = res.socket?.remoteAddress;
      if (remote && isForbiddenFeedDestinationIp(remote)) {
        res.destroy();
        reject(blockedError('Connected address is not allowed', 'destination_blocked'));
        return;
      }
      resolve(res);
    });
    req.on('error', reject);
    req.end();
  });
}

/**
 * Fetch a URL as untrusted bytes/text. Never forwards Authorization. Never executes content.
 * `fetchImpl` replaces the transport only (tests): URL policy and the
 * destination guard still run before it.
 * @param {string} url
 * @param {{
 *   timeoutMs?: number,
 *   maxBytes?: number,
 *   headers?: Record<string,string>,
 *   fetchImpl?: Function,
 *   destinationGuard?: (url: string) => Promise<{ ok: boolean, code?: string, reason?: string }>,
 *   lookup?: Function,
 *   requestImpl?: Function
 * }} [options] `lookup` (DNS) and `requestImpl` (socket I/O, same signature
 *   as requestPinned) are test seams below the policy: every check still runs.
 */
export async function fetchIocSourceUrl(url, options = {}) {
  const sync = await assertHopAllowed(url, options, 'blocked_url');

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

  const timeoutMs = options.timeoutMs ?? IOC_SOURCE_FETCH.TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? IOC_SOURCE_FETCH.MAX_BYTES;
  const maxRedirects = IOC_SOURCE_FETCH.MAX_REDIRECTS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let currentUrl = stripUrlUserinfo(sync.parsed);
  let hop = 0;

  try {
    while (hop <= maxRedirects) {
      let destination;
      try {
        destination = await assertSafeFeedDestination(currentUrl.href, options.lookup ? { lookup: options.lookup } : {});
      } catch (err) {
        if (err?.code === 'invalid_url') throw blockedError(err.message, hop ? 'redirect_blocked' : 'blocked_url');
        throw err;
      }
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
        const request = typeof options.requestImpl === 'function' ? options.requestImpl : requestPinned;
        res = await request(destination.parsed, destination.addresses, headers, controller.signal);
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
          throw blockedError('Redirect target URL is not allowed', 'redirect_blocked');
        }
        const nextSync = await assertHopAllowed(nextUrl.href, options, 'redirect_blocked');
        currentUrl = nextSync.parsed;
        hop += 1;
        continue;
      }

      const contentType = String(res.headers?.['content-type'] || '');
      let body;
      try {
        body = await readLimitedBody(res, maxBytes);
      } catch (err) {
        if (controller.signal.aborted) throw blockedError(`Fetch timed out after ${timeoutMs}ms`, 'timeout');
        throw err;
      }
      const { buffer, fetchedBytes } = body;
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

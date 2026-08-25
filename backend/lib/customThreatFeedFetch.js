import http from 'node:http';
import https from 'node:https';
import { buildCustomFeedAuthHeaders } from './customThreatFeedAuth.js';
import {
  DEFAULT_MAX_FEED_REDIRECTS,
  assertSafeFeedDestination,
  isSameFeedOrigin,
  stripUrlUserinfo,
  validateFeedUrlPolicy
} from './customThreatFeedSsrf.js';

export const DEFAULT_MAX_FETCH_BYTES = Math.max(
  Number(process.env.CUSTOM_FEED_MAX_FETCH_BYTES || 52_428_800),
  1024
);

const BASE_ACCEPT = 'text/plain,text/csv,*/*';
const USER_AGENT = 'talonhound-custom-threat-feed/1.0';

/**
 * @param {import('http').IncomingMessage} res
 * @param {number} maxBytes
 */
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
  const body = Buffer.concat(chunks, fetchedBytes);
  return { bodyText: body.toString('utf-8'), fetchedBytes };
}

function buildHopHeaders(authHeaders, previousUrl, nextUrl, isFirstHop) {
  const headers = {
    Accept: BASE_ACCEPT,
    'User-Agent': USER_AGENT,
    Connection: 'close'
  };

  const mayAttachAuth = isFirstHop || (previousUrl && isSameFeedOrigin(previousUrl, nextUrl));
  if (mayAttachAuth && authHeaders && typeof authHeaders === 'object') {
    for (const [key, value] of Object.entries(authHeaders)) {
      if (value == null || value === '') continue;
      headers[key] = value;
    }
  }
  return headers;
}

/**
 * Issue one HTTP(S) GET with DNS pin (custom lookup returns only pre-validated addresses).
 * TLS validation stays enabled (no rejectUnauthorized: false).
 *
 * @param {URL} parsed
 * @param {{ address: string, family: number }[]} addresses
 * @param {Record<string, string>} headers
 * @param {AbortSignal} signal
 * @param {{ request?: typeof http.request, httpsRequest?: typeof https.request }} [deps]
 */
function requestPinned(parsed, addresses, headers, signal, deps = {}) {
  const isHttps = parsed.protocol === 'https:';
  const requestFn = isHttps
    ? (deps.httpsRequest || https.request)
    : (deps.request || http.request);
  const pinned = addresses[0];

  const options = {
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || (isHttps ? 443 : 80),
    path: `${parsed.pathname || '/'}${parsed.search || ''}`,
    method: 'GET',
    headers: {
      ...headers,
      Host: parsed.host
    },
    // Pin connect to validated address (prevents DNS rebinding TOCTOU).
    lookup(hostname, opts, cb) {
      if (typeof opts === 'function') {
        cb = opts;
        opts = {};
      }
      // Node may call with { all: true }; both shapes must return the pinned IP.
      if (opts && opts.all) {
        cb(null, [{ address: pinned.address, family: pinned.family }]);
        return;
      }
      cb(null, pinned.address, pinned.family);
    },
    signal
  };

  if (isHttps) {
    // Keep SNI / cert hostname checks against the original hostname.
    options.servername = parsed.hostname;
  }

  return new Promise((resolve, reject) => {
    const req = requestFn(options, (res) => resolve(res));
    req.on('error', reject);
    req.end();
  });
}

/**
 * SSRF-hardened custom feed fetch: shared policy, DNS resolve of every address,
 * hop-by-hop redirect validation, no cross-origin credential forwarding.
 *
 * @param {string} url
 * @param {{
 *   timeoutMs?: number,
 *   maxBytes?: number,
 *   credentials?: object|null,
 *   maxRedirects?: number,
 *   lookup?: Function,
 *   isForbiddenAddress?: (address: string) => boolean,
 *   request?: typeof http.request,
 *   httpsRequest?: typeof https.request
 * }} [options]
 */
export async function fetchFeedUrl(url, options = {}) {
  const syncCheck = validateFeedUrlPolicy(url);
  if (!syncCheck.ok) {
    const err = new Error(syncCheck.error);
    err.code = 'invalid_url';
    throw err;
  }

  const timeoutMs = Math.max(Number(options.timeoutMs || 30000), 1000);
  const maxBytes = Math.max(Number(options.maxBytes || DEFAULT_MAX_FETCH_BYTES), 1024);
  const maxRedirects = Math.max(
    0,
    Number(options.maxRedirects ?? DEFAULT_MAX_FEED_REDIRECTS)
  );
  const authHeaders = buildCustomFeedAuthHeaders(options.credentials || null);
  const resolveOpts = {
    lookup: options.lookup,
    isForbiddenAddress: options.isForbiddenAddress
  };
  const requestDeps = {
    request: options.request,
    httpsRequest: options.httpsRequest
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let currentUrl = stripUrlUserinfo(syncCheck.parsed);
  let previousUrl = null;
  let hop = 0;

  try {
    while (hop <= maxRedirects) {
      const destination = await assertSafeFeedDestination(currentUrl.href, resolveOpts);
      const headers = buildHopHeaders(authHeaders, previousUrl, destination.parsed, hop === 0);

      let res;
      try {
        res = await requestPinned(
          destination.parsed,
          destination.addresses,
          headers,
          controller.signal,
          requestDeps
        );
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
        // Drain/discard redirect body
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

        previousUrl = currentUrl;
        currentUrl = nextSync.parsed;
        hop += 1;
        continue;
      }

      const contentType = String(res.headers?.['content-type'] || '');
      const { bodyText, fetchedBytes } = await readLimitedBody(res, maxBytes);

      return {
        ok: status >= 200 && status < 300,
        httpStatus: status,
        contentType,
        bodyText,
        fetchedBytes,
        finalUrl: destination.url
      };
    }

    const err = new Error(`Too many redirects (max ${maxRedirects})`);
    err.code = 'redirect_limit';
    throw err;
  } catch (err) {
    if (err?.name === 'AbortError' || (err?.code === 'ABORT_ERR')) {
      const timeoutErr = new Error(`Fetch timed out after ${timeoutMs}ms`);
      timeoutErr.code = 'timeout';
      throw timeoutErr;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

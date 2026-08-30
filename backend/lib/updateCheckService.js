/**
 * Backend update-check service.
 * Fetches a trusted static channel manifest over HTTPS. Failures never affect health/readiness.
 */

import { getProductVersionInfo } from './productVersion.js';
import { compareSemVer, isValidSemVer } from './releaseSemver.js';
import {
  UPDATE_MANIFEST_MAX_BYTES,
  parseUpdateChannelManifestJson
} from './updateChannelManifest.js';
import {
  getUpdateCheckConfig,
  validateConfiguredManifestUrl
} from './updateCheckConfig.js';

/**
 * @typedef {'up_to_date'|'update_available'|'check_failed'|'no_release_published'|'development_build'|'unknown'} UpdateStatus
 */

/**
 * @typedef {object} UpdateCheckSnapshot
 * @property {string} currentVersion
 * @property {string|null} latestVersion
 * @property {string} channel
 * @property {UpdateStatus} status
 * @property {boolean} critical
 * @property {string|null} releaseUrl
 * @property {string|null} releasedAt
 * @property {string|null} lastCheckedAt
 * @property {string|null} lastSuccessfulCheckAt
 * @property {string|null} error
 * @property {boolean} automaticChecksEnabled
 * @property {string|null} minimumSupportedVersion
 */

/**
 * @returns {UpdateCheckSnapshot}
 */
function emptySnapshot(config, extras = {}) {
  const info = getProductVersionInfo();
  return {
    currentVersion: info.version,
    latestVersion: null,
    channel: config.channel,
    status: 'unknown',
    critical: false,
    releaseUrl: null,
    releasedAt: null,
    lastCheckedAt: null,
    lastSuccessfulCheckAt: null,
    error: null,
    automaticChecksEnabled: config.enabled,
    minimumSupportedVersion: null,
    ...extras
  };
}

/**
 * @param {unknown} err
 * @returns {string}
 */
function publicError(err) {
  const msg = String(err?.message || err || 'Update check failed');
  if (/ECONN|ENOTFOUND|ETIMEDOUT|certificate|TLS|network|fetch failed|timed out|AbortError/i.test(msg)) {
    return 'Unable to reach the update server';
  }
  if (/rate.?limit|HTTP 403/i.test(msg)) {
    return 'Update server rate-limited the request';
  }
  if (/HTTP 5\d\d/i.test(msg)) {
    return 'Update server returned an error';
  }
  if (/size limit|valid JSON|schema|channel|released_at|release_url|https|Unsupported|Invalid latest/i.test(msg)) {
    return 'Update manifest was invalid';
  }
  if (/must use https|credentials|not a valid URL|misconfigured/i.test(msg)) {
    return 'Update check is misconfigured';
  }
  return 'Update check failed';
}

/**
 * @param {Headers|undefined|null} headers
 * @returns {{ remaining: string|null, reset: string|null }}
 */
function rateLimitMeta(headers) {
  if (!headers?.get) return { remaining: null, reset: null };
  return {
    remaining: headers.get('x-ratelimit-remaining') || headers.get('X-RateLimit-Remaining'),
    reset: headers.get('x-ratelimit-reset') || headers.get('X-RateLimit-Reset')
  };
}

export function createUpdateCheckService(options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const nowFn = options.nowFn || (() => new Date());
  const logger = options.logger || console;
  const maxBytes = options.maxBytes || UPDATE_MANIFEST_MAX_BYTES;

  /** @type {UpdateCheckSnapshot} */
  let cache = emptySnapshot(getUpdateCheckConfig());
  /** @type {Promise<UpdateCheckSnapshot>|null} */
  let inFlight = null;
  let timer = null;

  /**
   * @param {AbortSignal|undefined} signal
   * @param {string} url
   * @param {number} timeoutMs
   * @returns {Promise<{ status: number, headers: Headers|null, text: string|null }>}
   */
  async function fetchManifest(signal, url, timeoutMs) {
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    signal?.addEventListener?.('abort', onAbort, { once: true });
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(url, {
        method: 'GET',
        redirect: 'error',
        signal: controller.signal,
        headers: {
          Accept: 'application/json',
          'User-Agent': 'TalonHound-UpdateCheck/1.0'
        }
      });

      const status = Number(res.status) || 0;
      if (!res.ok) {
        return { status, headers: res.headers || null, text: null };
      }

      const contentLength = Number(res.headers?.get?.('content-length') || 0);
      if (Number.isFinite(contentLength) && contentLength > maxBytes) {
        throw new Error(`Manifest exceeds size limit (${maxBytes} bytes)`);
      }

      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.byteLength > maxBytes) {
        throw new Error(`Manifest exceeds size limit (${maxBytes} bytes)`);
      }
      return { status, headers: res.headers || null, text: buf.toString('utf8') };
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener?.('abort', onAbort);
    }
  }

  /**
   * @param {{ force?: boolean }} [opts]
   * @returns {Promise<UpdateCheckSnapshot>}
   */
  async function check(opts = {}) {
    const force = Boolean(opts.force);
    const config = getUpdateCheckConfig();
    cache = {
      ...cache,
      currentVersion: getProductVersionInfo().version,
      channel: config.channel,
      automaticChecksEnabled: config.enabled
    };

    if (!force && inFlight) {
      return inFlight;
    }

    const run = (async () => {
      const checkedAt = nowFn().toISOString();
      const urlCheck = validateConfiguredManifestUrl(config.manifestUrl);
      if (!urlCheck.ok) {
        cache = {
          ...cache,
          status: 'check_failed',
          lastCheckedAt: checkedAt,
          error: publicError(urlCheck.error),
          automaticChecksEnabled: config.enabled
        };
        logger.warn?.('[update-check] misconfigured', {
          channel: config.channel,
          reason: 'invalid_manifest_url'
        });
        return cache;
      }

      const manifestUrl = urlCheck.url.toString();

      try {
        let fetched;
        try {
          fetched = await fetchManifest(undefined, manifestUrl, config.timeoutMs);
        } catch (err) {
          const timedOut = err?.name === 'AbortError';
          const reason = timedOut ? 'timeout' : 'network_error';
          cache = {
            ...cache,
            currentVersion: config.currentVersion,
            channel: config.channel,
            status: 'check_failed',
            lastCheckedAt: checkedAt,
            error: publicError(timedOut ? 'Update check timed out' : err),
            automaticChecksEnabled: config.enabled
          };
          logger.warn?.('[update-check] check failed', {
            channel: config.channel,
            repository: 'spatronn/TalonHound',
            manifestUrlHost: urlCheck.url.host,
            reason,
            error: cache.error
          });
          return cache;
        }

        if (fetched.status === 404) {
          cache = {
            ...cache,
            currentVersion: config.currentVersion,
            channel: config.channel,
            status: 'no_release_published',
            latestVersion: null,
            critical: false,
            releaseUrl: null,
            releasedAt: null,
            minimumSupportedVersion: null,
            lastCheckedAt: checkedAt,
            lastSuccessfulCheckAt: checkedAt,
            error: null,
            automaticChecksEnabled: config.enabled
          };
          logger.info?.('[update-check] no release published', {
            channel: config.channel,
            httpStatus: 404,
            manifestUrlHost: urlCheck.url.host
          });
          return cache;
        }

        if (fetched.status !== 200 || fetched.text == null) {
          const rate = rateLimitMeta(fetched.headers);
          const reason = fetched.status === 403 ? 'forbidden_or_rate_limited' : `http_${fetched.status}`;
          cache = {
            ...cache,
            currentVersion: config.currentVersion,
            channel: config.channel,
            status: 'check_failed',
            lastCheckedAt: checkedAt,
            error: publicError(`HTTP ${fetched.status}`),
            automaticChecksEnabled: config.enabled
          };
          logger.warn?.('[update-check] check failed', {
            channel: config.channel,
            repository: 'spatronn/TalonHound',
            manifestUrlHost: urlCheck.url.host,
            httpStatus: fetched.status,
            reason,
            rateLimitRemaining: rate.remaining,
            rateLimitReset: rate.reset,
            error: cache.error
          });
          return cache;
        }

        const parsed = parseUpdateChannelManifestJson(fetched.text, maxBytes);
        if (!parsed.ok) {
          cache = {
            ...cache,
            currentVersion: config.currentVersion,
            channel: config.channel,
            status: 'check_failed',
            lastCheckedAt: checkedAt,
            error: publicError(parsed.error),
            automaticChecksEnabled: config.enabled
          };
          logger.warn?.('[update-check] check failed', {
            channel: config.channel,
            manifestUrlHost: urlCheck.url.host,
            reason: 'invalid_manifest',
            error: cache.error
          });
          return cache;
        }

        const manifest = parsed.manifest;
        if (manifest.channel !== config.channel) {
          cache = {
            ...cache,
            currentVersion: config.currentVersion,
            channel: config.channel,
            status: 'check_failed',
            lastCheckedAt: checkedAt,
            error: publicError(`Unsupported channel: expected ${config.channel}, got ${manifest.channel}`),
            automaticChecksEnabled: config.enabled
          };
          logger.warn?.('[update-check] check failed', {
            channel: config.channel,
            reason: 'channel_mismatch',
            manifestChannel: manifest.channel,
            error: cache.error
          });
          return cache;
        }

        const discovered = {
          latestVersion: manifest.latest,
          critical: Boolean(manifest.critical),
          releaseUrl: manifest.releaseUrl,
          releasedAt: manifest.releasedAt,
          minimumSupportedVersion: manifest.minimumSupportedVersion
        };

        if (!isValidSemVer(config.currentVersion)) {
          cache = {
            currentVersion: config.currentVersion,
            ...discovered,
            channel: config.channel,
            status: 'development_build',
            lastCheckedAt: checkedAt,
            lastSuccessfulCheckAt: checkedAt,
            error: null,
            automaticChecksEnabled: config.enabled
          };
          logger.info?.('[update-check] development build; latest release discovered without comparison', {
            channel: config.channel,
            currentVersion: config.currentVersion,
            latestVersion: manifest.latest
          });
          return cache;
        }

        const cmp = compareSemVer(manifest.latest, config.currentVersion);
        if (cmp == null) {
          cache = {
            currentVersion: config.currentVersion,
            ...discovered,
            channel: config.channel,
            status: 'check_failed',
            lastCheckedAt: checkedAt,
            error: 'Update check failed',
            automaticChecksEnabled: config.enabled
          };
          logger.warn?.('[update-check] check failed', {
            channel: config.channel,
            reason: 'version_compare_failed',
            currentVersion: config.currentVersion,
            latestVersion: manifest.latest
          });
          return cache;
        }

        /** @type {UpdateStatus} */
        const status = cmp > 0 ? 'update_available' : 'up_to_date';
        cache = {
          currentVersion: config.currentVersion,
          ...discovered,
          channel: config.channel,
          status,
          lastCheckedAt: checkedAt,
          lastSuccessfulCheckAt: checkedAt,
          error: null,
          automaticChecksEnabled: config.enabled
        };
        return cache;
      } catch (err) {
        cache = {
          ...cache,
          currentVersion: config.currentVersion,
          channel: config.channel,
          status: 'check_failed',
          lastCheckedAt: checkedAt,
          error: publicError(err),
          automaticChecksEnabled: config.enabled
        };
        logger.warn?.('[update-check] check failed', {
          channel: config.channel,
          reason: 'unexpected_error',
          error: cache.error
        });
        return cache;
      }
    })();

    inFlight = run.finally(() => {
      if (inFlight === run) inFlight = null;
    });
    return inFlight;
  }

  function getStatus() {
    const config = getUpdateCheckConfig();
    return {
      ...cache,
      currentVersion: getProductVersionInfo().version,
      channel: config.channel,
      automaticChecksEnabled: config.enabled
    };
  }

  function startBackgroundChecks() {
    stopBackgroundChecks();
    const config = getUpdateCheckConfig();
    if (!config.enabled) {
      cache = { ...cache, automaticChecksEnabled: false };
      return;
    }
    const intervalMs = Math.max(1, config.intervalHours) * 60 * 60 * 1000;
    // Initial delayed check so startup is never blocked by outbound network.
    const initialDelayMs = Math.min(30_000, intervalMs);
    timer = setTimeout(function tick() {
      check({ force: false }).catch(() => {});
      timer = setTimeout(tick, intervalMs);
      if (typeof timer.unref === 'function') timer.unref();
    }, initialDelayMs);
    if (typeof timer.unref === 'function') timer.unref();
  }

  function stopBackgroundChecks() {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  }

  /** @internal test helper */
  function _setCacheForTests(snapshot) {
    cache = { ...cache, ...snapshot };
  }

  return {
    check,
    getStatus,
    startBackgroundChecks,
    stopBackgroundChecks,
    _setCacheForTests
  };
}

/** Process-wide singleton used by HTTP routes and the background poller. */
export const updateCheckService = createUpdateCheckService();

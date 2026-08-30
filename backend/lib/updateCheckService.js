/**
 * Backend update-check service.
 * Fetches a trusted static channel manifest over HTTPS. Failures never affect health/readiness.
 */

import { getProductVersionInfo } from './productVersion.js';
import { compareSemVer } from './releaseSemver.js';
import {
  UPDATE_MANIFEST_MAX_BYTES,
  parseUpdateChannelManifestJson
} from './updateChannelManifest.js';
import {
  getUpdateCheckConfig,
  validateConfiguredManifestUrl
} from './updateCheckConfig.js';

/** @typedef {'up_to_date'|'update_available'|'unknown'} UpdateStatus */

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

  function publicError(message) {
    const msg = String(message || 'Update check failed');
    // Never expose stack traces or internal host details to the API surface.
    if (/ECONN|ENOTFOUND|ETIMEDOUT|certificate|TLS|network|fetch failed/i.test(msg)) {
      return 'Unable to reach the update server';
    }
    if (/size limit|valid JSON|schema|channel|version|released_at|release_url|https/i.test(msg)) {
      return 'Update manifest was invalid';
    }
    if (/must use https|credentials|not a valid URL/i.test(msg)) {
      return 'Update check is misconfigured';
    }
    return 'Update check failed';
  }

  /**
   * @param {AbortSignal} signal
   * @param {string} url
   * @param {number} timeoutMs
   */
  async function fetchManifestText(signal, url, timeoutMs) {
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
        if (!res.ok) {
        throw new Error(res.status === 404 || res.status === 403
          ? 'Unable to reach the update server'
          : `HTTP ${res.status}`);
      }

      const contentLength = Number(res.headers?.get?.('content-length') || 0);
      if (Number.isFinite(contentLength) && contentLength > maxBytes) {
        throw new Error(`Manifest exceeds size limit (${maxBytes} bytes)`);
      }

      // Bound body size without requiring streaming support from every mock.
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.byteLength > maxBytes) {
        throw new Error(`Manifest exceeds size limit (${maxBytes} bytes)`);
      }
      return buf.toString('utf8');
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
          status: 'unknown',
          lastCheckedAt: checkedAt,
          error: publicError(urlCheck.error),
          automaticChecksEnabled: config.enabled
        };
        logger.warn?.('[update-check] misconfigured manifest URL');
        return cache;
      }

      try {
        const text = await fetchManifestText(undefined, urlCheck.url.toString(), config.timeoutMs);
        const parsed = parseUpdateChannelManifestJson(text, maxBytes);
        if (!parsed.ok) {
          throw new Error(parsed.error);
        }
        const manifest = parsed.manifest;
        if (manifest.channel !== config.channel) {
          throw new Error(`Unsupported channel: expected ${config.channel}, got ${manifest.channel}`);
        }

        const cmp = compareSemVer(manifest.latest, config.currentVersion);
        if (cmp == null) {
          throw new Error('Unable to compare versions');
        }
        /** @type {UpdateStatus} */
        const status = cmp > 0 ? 'update_available' : 'up_to_date';

        cache = {
          currentVersion: config.currentVersion,
          latestVersion: manifest.latest,
          channel: config.channel,
          status,
          critical: Boolean(manifest.critical),
          releaseUrl: manifest.releaseUrl,
          releasedAt: manifest.releasedAt,
          lastCheckedAt: checkedAt,
          lastSuccessfulCheckAt: checkedAt,
          error: null,
          automaticChecksEnabled: config.enabled,
          minimumSupportedVersion: manifest.minimumSupportedVersion
        };
        return cache;
      } catch (err) {
        const raw = err?.name === 'AbortError' ? 'Update check timed out' : (err?.message || String(err));
        cache = {
          ...cache,
          currentVersion: config.currentVersion,
          channel: config.channel,
          status: 'unknown',
          lastCheckedAt: checkedAt,
          error: publicError(raw),
          automaticChecksEnabled: config.enabled
        };
        logger.warn?.('[update-check] check failed', { error: publicError(raw) });
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

/**
 * Update-check configuration (env-driven; no DB persistence required).
 */

import { releaseChannel } from './releaseSemver.js';
import { getProductVersionInfo } from './productVersion.js';
import { SUPPORTED_UPDATE_CHANNELS } from './updateChannelManifest.js';

const DEFAULT_GITHUB_OWNER_REPO = 'spatronn/TalonHound';
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_INTERVAL_HOURS = 24;

/**
 * @param {string|undefined} value
 * @param {boolean} fallback
 */
function parseBool(value, fallback) {
  if (value == null || value === '') return fallback;
  const v = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(v)) return true;
  if (['0', 'false', 'no', 'off'].includes(v)) return false;
  return fallback;
}

/**
 * @param {string|undefined} value
 * @param {number} fallback
 * @param {{ min?: number, max?: number }} [bounds]
 */
function parsePositiveNumber(value, fallback, bounds = {}) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  let out = n;
  if (bounds.min != null && out < bounds.min) out = bounds.min;
  if (bounds.max != null && out > bounds.max) out = bounds.max;
  return out;
}

/**
 * Default static channel manifest URL (HTTPS). Overridable via UPDATE_MANIFEST_URL.
 * Designed so a later host like https://update.talonhound.io/v1/releases/beta.json
 * is a config change only.
 *
 * @param {string} channel
 */
export function defaultUpdateManifestUrl(channel) {
  const ch = SUPPORTED_UPDATE_CHANNELS.includes(channel) ? channel : 'beta';
  return `https://raw.githubusercontent.com/${DEFAULT_GITHUB_OWNER_REPO}/main/updates/${ch}.json`;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function getUpdateCheckConfig(env = process.env) {
  const versionInfo = getProductVersionInfo();
  const derivedChannel = releaseChannel(versionInfo.version) || 'beta';
  const configuredChannel = String(env.UPDATE_CHANNEL || '').trim().toLowerCase();
  const channel = SUPPORTED_UPDATE_CHANNELS.includes(configuredChannel)
    ? configuredChannel
    : (SUPPORTED_UPDATE_CHANNELS.includes(derivedChannel) ? derivedChannel : 'beta');

  const manifestUrlRaw = String(env.UPDATE_MANIFEST_URL || '').trim();
  const manifestUrl = manifestUrlRaw || defaultUpdateManifestUrl(channel);

  return {
    enabled: parseBool(env.UPDATE_CHECK_ENABLED, true),
    intervalHours: parsePositiveNumber(env.UPDATE_CHECK_INTERVAL_HOURS, DEFAULT_INTERVAL_HOURS, {
      min: 1,
      max: 168
    }),
    timeoutMs: parsePositiveNumber(env.UPDATE_CHECK_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, {
      min: 1000,
      max: 60_000
    }),
    manifestUrl,
    channel,
    currentVersion: versionInfo.version
  };
}

/**
 * Validate that a configured manifest URL is HTTPS-only and not user-controlled at runtime.
 * @param {string} urlString
 * @returns {{ ok: true, url: URL } | { ok: false, error: string }}
 */
export function validateConfiguredManifestUrl(urlString) {
  const raw = String(urlString || '').trim();
  if (!raw) return { ok: false, error: 'UPDATE_MANIFEST_URL is empty' };
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: 'UPDATE_MANIFEST_URL is not a valid URL' };
  }
  if (parsed.protocol !== 'https:') {
    return { ok: false, error: 'UPDATE_MANIFEST_URL must use https' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: 'UPDATE_MANIFEST_URL must not include credentials' };
  }
  return { ok: true, url: parsed };
}

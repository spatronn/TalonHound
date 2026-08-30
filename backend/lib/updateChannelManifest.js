/**
 * Channel update manifest (lightweight HTTPS JSON used by the update checker).
 * Distinct from the full per-release release-manifest.json (images/digests).
 */

import { isValidSemVer, releaseChannel } from './releaseSemver.js';

export const UPDATE_CHANNEL_MANIFEST_SCHEMA_VERSION = 1;
export const UPDATE_MANIFEST_MAX_BYTES = 64 * 1024;
export const SUPPORTED_UPDATE_CHANNELS = Object.freeze(['stable', 'beta']);

/**
 * @param {unknown} value
 * @returns {string}
 */
function asTrimmedString(value) {
  return String(value ?? '').trim();
}

/**
 * @param {unknown} raw
 * @returns {{ ok: true, manifest: object } | { ok: false, error: string }}
 */
export function parseUpdateChannelManifest(raw) {
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, error: 'Manifest must be a JSON object' };
  }
  const data = /** @type {Record<string, unknown>} */ (raw);

  const schemaVersion = Number(data.schemaVersion ?? data.schema_version ?? 1);
  if (!Number.isInteger(schemaVersion) || schemaVersion !== UPDATE_CHANNEL_MANIFEST_SCHEMA_VERSION) {
    return { ok: false, error: `Unsupported schemaVersion: ${String(data.schemaVersion ?? data.schema_version)}` };
  }

  const channel = asTrimmedString(data.channel).toLowerCase();
  if (!SUPPORTED_UPDATE_CHANNELS.includes(channel)) {
    return { ok: false, error: `Unsupported channel: ${channel || '(empty)'}` };
  }

  const latest = asTrimmedString(data.latest);
  if (!isValidSemVer(latest)) {
    return { ok: false, error: `Invalid latest version: ${latest || '(empty)'}` };
  }

  const latestChannel = releaseChannel(latest);
  if (latestChannel !== channel && !(channel === 'stable' && latestChannel === 'stable')) {
    // Allow stable channel only for non-prerelease; beta for beta prereleases.
    if (channel === 'beta' && latestChannel !== 'beta') {
      return { ok: false, error: `latest version ${latest} is not a beta channel release` };
    }
    if (channel === 'stable' && latestChannel !== 'stable') {
      return { ok: false, error: `latest version ${latest} is not a stable channel release` };
    }
  }

  const releasedAt = asTrimmedString(data.released_at ?? data.releasedAt);
  if (!releasedAt) {
    return { ok: false, error: 'released_at is required' };
  }
  const releasedMs = Date.parse(releasedAt);
  if (!Number.isFinite(releasedMs)) {
    return { ok: false, error: 'released_at must be a valid ISO-8601 timestamp' };
  }

  const minimumSupported = asTrimmedString(
    data.minimum_supported_version ?? data.minimumSupportedVersion ?? ''
  );
  if (minimumSupported && !isValidSemVer(minimumSupported)) {
    return { ok: false, error: `Invalid minimum_supported_version: ${minimumSupported}` };
  }

  const releaseUrl = asTrimmedString(data.release_url ?? data.releaseUrl);
  if (!releaseUrl) {
    return { ok: false, error: 'release_url is required' };
  }
  let parsedReleaseUrl;
  try {
    parsedReleaseUrl = new URL(releaseUrl);
  } catch {
    return { ok: false, error: 'release_url must be a valid URL' };
  }
  if (parsedReleaseUrl.protocol !== 'https:') {
    return { ok: false, error: 'release_url must use https' };
  }

  const critical = Boolean(data.critical);

  const releaseManifestUrl = asTrimmedString(
    data.release_manifest_url ?? data.releaseManifestUrl ?? ''
  );
  if (releaseManifestUrl) {
    let parsedManifestUrl;
    try {
      parsedManifestUrl = new URL(releaseManifestUrl);
    } catch {
      return { ok: false, error: 'release_manifest_url must be a valid URL' };
    }
    if (parsedManifestUrl.protocol !== 'https:') {
      return { ok: false, error: 'release_manifest_url must use https' };
    }
  }

  return {
    ok: true,
    manifest: {
      schemaVersion: UPDATE_CHANNEL_MANIFEST_SCHEMA_VERSION,
      channel,
      latest,
      releasedAt: new Date(releasedMs).toISOString(),
      minimumSupportedVersion: minimumSupported || null,
      releaseUrl,
      critical,
      releaseManifestUrl: releaseManifestUrl || null
    }
  };
}

/**
 * @param {string} text
 * @param {number} [maxBytes]
 */
export function parseUpdateChannelManifestJson(text, maxBytes = UPDATE_MANIFEST_MAX_BYTES) {
  const raw = String(text ?? '');
  const byteLength = Buffer.byteLength(raw, 'utf8');
  if (byteLength > maxBytes) {
    return { ok: false, error: `Manifest exceeds size limit (${maxBytes} bytes)` };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, error: 'Manifest is not valid JSON' };
  }
  return parseUpdateChannelManifest(parsed);
}

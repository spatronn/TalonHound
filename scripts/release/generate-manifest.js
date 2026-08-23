/**
 * Generate a TalonHound release manifest from build outputs.
 */

import {
  isPrereleaseVersion,
  isValidSemVer,
  releaseChannel,
  validateReleaseTagMatchesVersion
} from '../../backend/lib/releaseSemver.js';

/** @typedef {{ repository: string, tag: string, digest: string }} ReleaseImage */

/**
 * @param {object} input
 * @param {string} input.version
 * @param {string} input.gitTag
 * @param {string} input.gitCommit
 * @param {string} input.releasedAt
 * @param {Record<string, ReleaseImage>} input.images
 * @param {string|number|null} [input.latestMigration]
 */
export function buildReleaseManifest(input) {
  const version = String(input.version || '').trim();
  const gitTag = String(input.gitTag || '').trim();
  const gitCommit = String(input.gitCommit || '').trim();
  const releasedAt = String(input.releasedAt || '').trim();
  const images = input.images || {};

  if (!isValidSemVer(version)) {
    throw new Error(`Invalid SemVer version: ${version}`);
  }
  const tagCheck = validateReleaseTagMatchesVersion(gitTag, version);
  if (!tagCheck.ok) {
    throw new Error(tagCheck.error);
  }
  if (!gitCommit) {
    throw new Error('gitCommit is required');
  }
  if (!releasedAt) {
    throw new Error('releasedAt is required');
  }
  if (!images || typeof images !== 'object' || Array.isArray(images) || !Object.keys(images).length) {
    throw new Error('At least one release image is required');
  }

  for (const [key, image] of Object.entries(images)) {
    if (!image?.repository || !image?.tag || !image?.digest) {
      throw new Error(`Image ${key} must include repository, tag, and digest`);
    }
    if (image.tag !== version) {
      throw new Error(`Image ${key} tag ${image.tag} must match release version ${version}`);
    }
    if (!/^sha256:[a-f0-9]{64}$/.test(image.digest)) {
      throw new Error(`Image ${key} digest must be sha256:<64 hex chars>`);
    }
  }

  return {
    schemaVersion: 1,
    product: 'TalonHound',
    version,
    channel: releaseChannel(version),
    prerelease: isPrereleaseVersion(version),
    gitTag,
    gitCommit,
    releasedAt,
    images,
    database: {
      latestMigration: input.latestMigration ?? null
    },
    upgrade: {
      supportedFrom: []
    }
  };
}

/** @param {unknown} manifest */
export function validateReleaseManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('Manifest must be an object');
  }
  const data = /** @type {Record<string, unknown>} */ (manifest);
  if (data.schemaVersion !== 1) {
    throw new Error(`Unsupported schemaVersion: ${String(data.schemaVersion)}`);
  }
  return buildReleaseManifest({
    version: String(data.version || ''),
    gitTag: String(data.gitTag || ''),
    gitCommit: String(data.gitCommit || ''),
    releasedAt: String(data.releasedAt || ''),
    images: /** @type {Record<string, ReleaseImage>} */ (data.images || {}),
    latestMigration: data.database && typeof data.database === 'object'
      ? /** @type {{ latestMigration?: string|number|null }} */ (data.database).latestMigration ?? null
      : null
  });
}

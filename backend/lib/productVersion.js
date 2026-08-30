/**
 * Canonical TalonHound product version and build metadata.
 * VERSION file at repository root is the single source of truth for product version.
 */

import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { releaseChannel } from './releaseSemver.js';

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(MODULE_DIR, '../..');

const VERSION_CANDIDATES = Object.freeze([
  process.env.TALONHOUND_VERSION_FILE,
  '/VERSION',
  path.join(REPO_ROOT, 'VERSION')
].filter(Boolean));

/** @returns {string} */
export function readCanonicalVersion() {
  for (const candidate of VERSION_CANDIDATES) {
    try {
      if (existsSync(candidate)) {
        const value = readFileSync(candidate, 'utf8').trim();
        if (value) return value;
      }
    } catch {
      /* try next candidate */
    }
  }
  throw new Error('Canonical VERSION file not found');
}

/**
 * Dockerfiles default BUILD_VERSION/BUILD_COMMIT to the placeholder "dev".
 * Treat that placeholder as unset so the canonical VERSION file wins for
 * official source installs and any build that did not intentionally stamp a
 * real SemVer via TALONHOUND_VERSION / BUILD_VERSION.
 *
 * @param {string} value
 * @returns {boolean}
 */
function isUnsetBuildPlaceholder(value) {
  const v = String(value || '').trim().toLowerCase();
  return !v || v === 'dev';
}

/** @returns {string} */
function resolveVersion() {
  const fromEnv = String(process.env.TALONHOUND_VERSION || '').trim();
  if (!isUnsetBuildPlaceholder(fromEnv)) return fromEnv;
  return readCanonicalVersion();
}

/** @returns {string} */
function resolveCommit() {
  const fromEnv = String(
    process.env.TALONHOUND_COMMIT
    || process.env.GIT_SHA
    || process.env.SOURCE_COMMIT
    || ''
  ).trim();
  if (!isUnsetBuildPlaceholder(fromEnv)) return fromEnv;
  return 'unknown';
}

/** @returns {string} */
function resolveBuildDate() {
  const fromEnv = String(process.env.TALONHOUND_BUILD_DATE || '').trim();
  if (fromEnv) return fromEnv;
  return 'unknown';
}

/** @returns {{ product: string, version: string, channel: string, commit: string, buildDate: string }} */
export function getProductVersionInfo() {
  const version = resolveVersion();
  const channel = releaseChannel(version) || 'unknown';
  return {
    product: 'TalonHound',
    version,
    channel,
    commit: resolveCommit(),
    buildDate: resolveBuildDate()
  };
}

/** @param {string} commit */
export function abbreviateCommit(commit) {
  const value = String(commit || '').trim();
  if (!value || value === 'unknown' || value === 'dev') return value;
  return value.slice(0, 7);
}

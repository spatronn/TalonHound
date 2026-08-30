/**
 * Minimal SemVer 2.0.0 parsing and release-tag validation for TalonHound releases.
 */

const SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

/** @param {string} version */
export function parseSemVer(version) {
  const raw = String(version || '').trim();
  const match = raw.match(SEMVER_RE);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] || null,
    build: match[5] || null,
    raw
  };
}

/** @param {string} version */
export function isValidSemVer(version) {
  return parseSemVer(version) !== null;
}

/**
 * Compare two SemVer 2.0 versions.
 * @param {string} a
 * @param {string} b
 * @returns {-1|0|1|null} null when either version is invalid
 */
export function compareSemVer(a, b) {
  const pa = parseSemVer(a);
  const pb = parseSemVer(b);
  if (!pa || !pb) return null;

  if (pa.major !== pb.major) return pa.major < pb.major ? -1 : 1;
  if (pa.minor !== pb.minor) return pa.minor < pb.minor ? -1 : 1;
  if (pa.patch !== pb.patch) return pa.patch < pb.patch ? -1 : 1;

  // A version without prerelease has higher precedence than one with prerelease.
  if (!pa.prerelease && !pb.prerelease) return 0;
  if (!pa.prerelease) return 1;
  if (!pb.prerelease) return -1;

  const aParts = pa.prerelease.split('.');
  const bParts = pb.prerelease.split('.');
  const len = Math.max(aParts.length, bParts.length);
  for (let i = 0; i < len; i++) {
    const x = aParts[i];
    const y = bParts[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    if (xNum && yNum) {
      const xn = Number(x);
      const yn = Number(y);
      if (xn !== yn) return xn < yn ? -1 : 1;
      continue;
    }
    if (xNum) return -1;
    if (yNum) return 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * @param {string} candidate
 * @param {string} current
 * @returns {boolean}
 */
export function isNewerVersion(candidate, current) {
  return compareSemVer(candidate, current) === 1;
}

/**
 * Derive release channel from SemVer.
 * @param {string} version
 * @returns {'stable'|'beta'|'rc'|'alpha'|'prerelease'|string|null}
 */
export function releaseChannel(version) {
  const parsed = parseSemVer(version);
  if (!parsed) return null;
  if (!parsed.prerelease) return 'stable';
  const first = parsed.prerelease.split('.')[0];
  if (/^\d+$/.test(first)) return 'prerelease';
  return first.toLowerCase();
}

/** @param {string} version */
export function isPrereleaseVersion(version) {
  return Boolean(parseSemVer(version)?.prerelease);
}

/** @param {string} tag */
export function normalizeReleaseTag(tag) {
  const value = String(tag || '').trim();
  if (!value.startsWith('v')) return null;
  const body = value.slice(1).trim();
  return body || null;
}

/**
 * @param {string} tag e.g. v0.1.0-beta.1
 * @param {string} version e.g. 0.1.0-beta.1
 */
export function validateReleaseTagMatchesVersion(tag, version) {
  const normalized = normalizeReleaseTag(tag);
  const canonical = String(version || '').trim();
  if (!normalized || !canonical) {
    return { ok: false, error: 'Release tag and VERSION are required' };
  }
  if (!isValidSemVer(normalized)) {
    return { ok: false, error: `Release tag body is not valid SemVer: ${normalized}` };
  }
  if (!isValidSemVer(canonical)) {
    return { ok: false, error: `VERSION is not valid SemVer: ${canonical}` };
  }
  if (normalized !== canonical) {
    return {
      ok: false,
      error: `Release tag v${normalized} does not match canonical VERSION ${canonical}`
    };
  }
  return { ok: true, tag: `v${canonical}`, version: canonical };
}

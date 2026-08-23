import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isPrereleaseVersion,
  isValidSemVer,
  parseSemVer,
  releaseChannel,
  validateReleaseTagMatchesVersion
} from './releaseSemver.js';

test('isValidSemVer accepts stable and prerelease versions', () => {
  assert.equal(isValidSemVer('0.1.0-beta.1'), true);
  assert.equal(isValidSemVer('1.0.0'), true);
  assert.equal(isValidSemVer('0.2.0-rc.1'), true);
  assert.equal(isValidSemVer('v0.1.0'), false);
  assert.equal(isValidSemVer('not-a-version'), false);
});

test('parseSemVer extracts prerelease identifiers', () => {
  const parsed = parseSemVer('0.1.0-beta.1');
  assert.deepEqual(parsed, {
    major: 0,
    minor: 1,
    patch: 0,
    prerelease: 'beta.1',
    build: null,
    raw: '0.1.0-beta.1'
  });
});

test('releaseChannel distinguishes beta, rc, and stable', () => {
  assert.equal(releaseChannel('0.1.0-beta.1'), 'beta');
  assert.equal(releaseChannel('0.2.0-rc.1'), 'rc');
  assert.equal(releaseChannel('1.0.0'), 'stable');
  assert.equal(isPrereleaseVersion('0.1.0-beta.1'), true);
  assert.equal(isPrereleaseVersion('1.0.0'), false);
});

test('validateReleaseTagMatchesVersion requires exact v${VERSION} match', () => {
  assert.deepEqual(validateReleaseTagMatchesVersion('v0.1.0-beta.1', '0.1.0-beta.1'), {
    ok: true,
    tag: 'v0.1.0-beta.1',
    version: '0.1.0-beta.1'
  });

  const mismatch = validateReleaseTagMatchesVersion('v0.1.0-beta.2', '0.1.0-beta.1');
  assert.equal(mismatch.ok, false);
  assert.match(mismatch.error, /does not match/);

  const invalidTag = validateReleaseTagMatchesVersion('0.1.0-beta.1', '0.1.0-beta.1');
  assert.equal(invalidTag.ok, false);
});

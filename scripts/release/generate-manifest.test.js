import test from 'node:test';
import assert from 'node:assert/strict';
import { buildReleaseManifest, validateReleaseManifest } from './generate-manifest.js';

const sampleImages = {
  backend: {
    repository: 'ghcr.io/spatronn/talonhound-backend',
    tag: '0.1.0-beta.1',
    digest: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  },
  frontend: {
    repository: 'ghcr.io/spatronn/talonhound-frontend',
    tag: '0.1.0-beta.1',
    digest: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
  }
};

test('buildReleaseManifest marks beta releases as prerelease', () => {
  const manifest = buildReleaseManifest({
    version: '0.1.0-beta.1',
    gitTag: 'v0.1.0-beta.1',
    gitCommit: 'abc123',
    releasedAt: '2026-08-23T12:00:00.000Z',
    images: sampleImages,
    latestMigration: 2
  });

  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.channel, 'beta');
  assert.equal(manifest.prerelease, true);
  assert.equal(manifest.database.latestMigration, 2);
});

test('buildReleaseManifest rejects tag/version mismatch', () => {
  assert.throws(() => buildReleaseManifest({
    version: '0.1.0-beta.1',
    gitTag: 'v0.1.0-beta.2',
    gitCommit: 'abc123',
    releasedAt: '2026-08-23T12:00:00.000Z',
    images: sampleImages
  }), /does not match/);
});

test('validateReleaseManifest round-trips generated manifests', () => {
  const manifest = buildReleaseManifest({
    version: '1.0.0',
    gitTag: 'v1.0.0',
    gitCommit: 'abc123',
    releasedAt: '2026-08-23T12:00:00.000Z',
    images: {
      backend: {
        repository: 'ghcr.io/spatronn/talonhound-backend',
        tag: '1.0.0',
        digest: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
      }
    },
    latestMigration: 1
  });
  assert.equal(manifest.channel, 'stable');
  assert.equal(manifest.prerelease, false);
  assert.deepEqual(validateReleaseManifest(manifest), manifest);
});

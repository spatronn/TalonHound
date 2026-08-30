import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseUpdateChannelManifest,
  parseUpdateChannelManifestJson,
  UPDATE_MANIFEST_MAX_BYTES
} from './updateChannelManifest.js';

const valid = {
  schemaVersion: 1,
  channel: 'beta',
  latest: '0.1.0-beta.3',
  released_at: '2026-09-04T12:00:00Z',
  minimum_supported_version: '0.1.0-beta.1',
  release_url: 'https://github.com/spatronn/TalonHound/releases/tag/v0.1.0-beta.3',
  critical: false
};

test('parseUpdateChannelManifest accepts a valid beta manifest', () => {
  const result = parseUpdateChannelManifest(valid);
  assert.equal(result.ok, true);
  assert.equal(result.manifest.latest, '0.1.0-beta.3');
  assert.equal(result.manifest.channel, 'beta');
  assert.equal(result.manifest.critical, false);
  assert.equal(result.manifest.releasedAt, '2026-09-04T12:00:00.000Z');
});

test('parseUpdateChannelManifest rejects invalid JSON shapes and fields', () => {
  assert.equal(parseUpdateChannelManifest(null).ok, false);
  assert.equal(parseUpdateChannelManifest({ ...valid, channel: 'nightly' }).ok, false);
  assert.equal(parseUpdateChannelManifest({ ...valid, latest: 'not-semver' }).ok, false);
  assert.equal(parseUpdateChannelManifest({ ...valid, latest: '1.0.0' }).ok, false);
  assert.equal(parseUpdateChannelManifest({ ...valid, released_at: 'yesterday' }).ok, false);
  assert.equal(parseUpdateChannelManifest({ ...valid, release_url: 'http://insecure.example/x' }).ok, false);
  assert.equal(parseUpdateChannelManifest({ ...valid, schemaVersion: 99 }).ok, false);
});

test('parseUpdateChannelManifestJson rejects oversized and malformed payloads', () => {
  assert.equal(parseUpdateChannelManifestJson('{').ok, false);
  const huge = `{"schemaVersion":1,"channel":"beta","latest":"0.1.0-beta.1","released_at":"2026-09-04T12:00:00Z","release_url":"https://example.com/r","pad":"${'x'.repeat(UPDATE_MANIFEST_MAX_BYTES)}"}`;
  assert.equal(parseUpdateChannelManifestJson(huge).ok, false);
  assert.equal(parseUpdateChannelManifestJson(JSON.stringify(valid)).ok, true);
});

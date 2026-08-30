import test from 'node:test';
import assert from 'node:assert/strict';
import {
  API_SCOPE,
  ACCESS_PROFILE,
  scopesForAccessProfile,
  hasApiScope,
  listCreatableAccessProfiles,
  getAccessProfile
} from './apiKeyProfiles.js';

test('published_feed profile maps to published_feeds:read only', () => {
  assert.deepEqual(scopesForAccessProfile(ACCESS_PROFILE.PUBLISHED_FEED), [API_SCOPE.PUBLISHED_FEEDS_READ]);
  assert.equal(hasApiScope(scopesForAccessProfile('published_feed'), API_SCOPE.IOC_CREATE), false);
});

test('ioc_management profile maps to create+update', () => {
  const scopes = scopesForAccessProfile(ACCESS_PROFILE.IOC_MANAGEMENT);
  assert.deepEqual(scopes, [API_SCOPE.IOC_CREATE, API_SCOPE.IOC_UPDATE]);
  assert.equal(hasApiScope(scopes, API_SCOPE.IOC_CREATE), true);
  assert.equal(hasApiScope(scopes, API_SCOPE.PUBLISHED_FEEDS_READ), false);
});

test('legacy feed_access also maps to feed-read scope', () => {
  assert.deepEqual(scopesForAccessProfile(ACCESS_PROFILE.FEED_ACCESS), [API_SCOPE.PUBLISHED_FEEDS_READ]);
});

test('creatable profiles are the three UI presets', () => {
  const ids = listCreatableAccessProfiles().map((p) => p.id).sort();
  assert.deepEqual(ids, ['ioc_management', 'ioc_read', 'published_feed']);
  assert.equal(getAccessProfile('ioc_management').creatable, true);
  assert.equal(getAccessProfile('feed_access').creatable, false);
});

test('ioc_read profile maps to read+export only', () => {
  const scopes = scopesForAccessProfile(ACCESS_PROFILE.IOC_READ);
  assert.deepEqual(scopes, [API_SCOPE.IOC_READ, API_SCOPE.IOC_EXPORT]);
  assert.equal(hasApiScope(scopes, API_SCOPE.IOC_CREATE), false);
  assert.equal(hasApiScope(scopes, API_SCOPE.IOC_UPDATE), false);
});

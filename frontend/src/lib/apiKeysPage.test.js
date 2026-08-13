import test from 'node:test';
import assert from 'node:assert/strict';
import {
  API_KEYS_PAGE_DESCRIPTION,
  ACCESS_PROFILE_OPTIONS,
  apiKeyCreatePayload,
  accessProfilePermissionSummary,
  accessProfileLabel,
  API_DOCS_PATH
} from './apiKeysPage.js';

test('page description is generic (not Published Feed-only)', () => {
  assert.match(API_KEYS_PAGE_DESCRIPTION, /programmatic access/i);
  assert.doesNotMatch(API_KEYS_PAGE_DESCRIPTION, /Published Feed keys let/i);
});

test('three fixed access profiles are exposed', () => {
  assert.equal(ACCESS_PROFILE_OPTIONS.length, 3);
  assert.deepEqual(
    ACCESS_PROFILE_OPTIONS.map((o) => o.id).sort(),
    ['ioc_management', 'ioc_read', 'published_feed']
  );
});

test('create payload maps profile selection correctly', () => {
  const pf = apiKeyCreatePayload({ name: 'fw-1', accessProfile: 'published_feed' });
  assert.equal(pf.ok, true);
  assert.equal(pf.body.access_profile, 'published_feed');
  assert.equal(pf.body.key_type, 'published_feed');

  const ioc = apiKeyCreatePayload({ name: 'bot', accessProfile: 'ioc_management' });
  assert.equal(ioc.ok, true);
  assert.equal(ioc.body.access_profile, 'ioc_management');

  const read = apiKeyCreatePayload({ name: 'siem', accessProfile: 'ioc_read' });
  assert.equal(read.ok, true);
  assert.equal(read.body.access_profile, 'ioc_read');

  const bad = apiKeyCreatePayload({ name: '', accessProfile: 'published_feed' });
  assert.equal(bad.ok, false);
});

test('table labels and permission summaries', () => {
  assert.equal(accessProfileLabel('published_feed'), 'Published Feed');
  assert.equal(accessProfileLabel('ioc_management'), 'IOC Management');
  assert.equal(accessProfilePermissionSummary('published_feed'), 'Read feeds');
  assert.equal(accessProfilePermissionSummary('ioc_management'), 'Create + Update IOCs');
  assert.equal(accessProfileLabel('ioc_read'), 'IOC Read');
  assert.equal(accessProfilePermissionSummary('ioc_read'), 'Read + Search + Export IOCs');
  assert.equal(API_DOCS_PATH, '/api/docs');
});

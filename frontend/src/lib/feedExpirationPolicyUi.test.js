import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  EXPIRATION_MODE_OPTIONS,
  EXPIRATION_TYPE_OVERRIDE_MODES,
  LEGACY_EXPIRATION_MODE_LAST_SEEN_TTL,
  MISSING_FROM_FEED_HELP,
  MISSING_FROM_FEED_DISABLED_HELP,
  coerceExpirationModeForUi,
  expirationModeOptionDisabled,
  expirationPolicyModeHint,
  defaultExpirationDraft,
  buildExpirationPatchPayload,
  buildExpirationFullPatchPayload,
  expirationShowsTtlDays,
  expirationShowsGraceDays
} from './feedExpirationPolicyUi.js';

const mainSrc = readFileSync(
  fileURLToPath(new URL('../main.jsx', import.meta.url)),
  'utf8'
);

test('UI options are the 3-policy set with the source-removed label', () => {
  assert.deepEqual(EXPIRATION_MODE_OPTIONS.map((o) => o.id), [
    'never',
    'fixed_ttl',
    'missing_from_feed_ttl'
  ]);
  assert.equal(
    EXPIRATION_MODE_OPTIONS.find((o) => o.id === 'missing_from_feed_ttl').label,
    'Expire when removed from source'
  );
  assert.equal(EXPIRATION_MODE_OPTIONS.some((o) => o.id === 'last_seen_ttl'), false);
  assert.equal(EXPIRATION_MODE_OPTIONS.some((o) => /last seen ttl/i.test(o.label)), false);
});

test('IOC type override modes do not include Last seen TTL', () => {
  assert.deepEqual(EXPIRATION_TYPE_OVERRIDE_MODES.map((o) => o.id), [
    'inherit',
    'no_expire',
    'fixed_ttl'
  ]);
});

test('create/edit payload never emits last_seen_ttl', () => {
  const fromLegacy = buildExpirationPatchPayload({
    enabled: true,
    expiration_mode: 'last_seen_ttl',
    ttl_days: 30
  });
  assert.equal(fromLegacy.expiration_mode, 'fixed_ttl');
  assert.equal(fromLegacy.ttl_days, 30);

  const full = buildExpirationFullPatchPayload({
    enabled: true,
    expiration_mode: 'fixed_ttl',
    ttl_days: 14,
    type_overrides: { domain: { mode: 'last_seen_ttl', ttl_days: 7 } }
  });
  assert.equal(full.expiration_mode, 'fixed_ttl');
  assert.equal(full.expiration_type_policies.find((e) => e.ioc_type === 'domain').mode, 'inherit');
});

test('legacy last_seen_ttl draft does not crash the edit form', () => {
  const draft = defaultExpirationDraft({
    enabled: true,
    expiration_mode: 'last_seen_ttl',
    ttl_days: 30
  });
  assert.equal(draft.expiration_mode, 'fixed_ttl');
  assert.equal(draft.ttl_days, 30);
  assert.equal(expirationShowsTtlDays(draft), true);
  assert.equal(EXPIRATION_MODE_OPTIONS.some((o) => o.id === draft.expiration_mode), true);
});

test('coerceExpirationModeForUi maps last_seen_ttl to fixed_ttl', () => {
  assert.equal(coerceExpirationModeForUi('last_seen_ttl'), 'fixed_ttl');
  assert.equal(coerceExpirationModeForUi(LEGACY_EXPIRATION_MODE_LAST_SEEN_TTL), 'fixed_ttl');
  assert.equal(coerceExpirationModeForUi('never'), 'never');
  assert.equal(coerceExpirationModeForUi('missing_from_feed_ttl'), 'missing_from_feed_ttl');
});

test('Expire when removed from source is disabled for non-snapshot feeds', () => {
  assert.equal(expirationModeOptionDisabled('missing_from_feed_ttl', 'incremental'), true);
  assert.equal(expirationModeOptionDisabled('missing_from_feed_ttl', 'snapshot'), false);
  assert.equal(expirationModeOptionDisabled('fixed_ttl', 'incremental'), false);
  assert.equal(expirationModeOptionDisabled('missing_from_feed_ttl', null), false);
});

test('snapshot help vs incremental disabled help', () => {
  assert.equal(
    expirationPolicyModeHint('missing_from_feed_ttl', 'snapshot'),
    MISSING_FROM_FEED_HELP
  );
  assert.equal(
    expirationPolicyModeHint('never', 'incremental'),
    MISSING_FROM_FEED_DISABLED_HELP
  );
  assert.equal(expirationPolicyModeHint('fixed_ttl', 'snapshot'), null);
});

test('grace days only for missing-from-feed; ttl days only for fixed_ttl', () => {
  assert.equal(expirationShowsGraceDays({ enabled: true, expiration_mode: 'missing_from_feed_ttl' }), true);
  assert.equal(expirationShowsTtlDays({ enabled: true, expiration_mode: 'missing_from_feed_ttl' }), false);
  assert.equal(expirationShowsTtlDays({ enabled: true, expiration_mode: 'last_seen_ttl' }), true);
  assert.equal(expirationShowsGraceDays({ enabled: true, expiration_mode: 'last_seen_ttl' }), false);
});

test('main.jsx no longer shows Last seen TTL or the old missing-from-feed label', () => {
  assert.equal(mainSrc.includes('Last seen TTL'), false);
  assert.equal(mainSrc.includes('Missing from feed (snapshot feeds)'), false);
  assert.equal(mainSrc.includes("id: 'last_seen_ttl'"), false);
  assert.ok(mainSrc.includes("from './lib/feedExpirationPolicyUi.js'"));
  assert.ok(mainSrc.includes('expirationModeOptionDisabled'));
  assert.ok(mainSrc.includes('EXPIRATION_TYPE_OVERRIDE_MODES'));
  assert.ok(mainSrc.includes('expirationPolicyModeHint'));
});

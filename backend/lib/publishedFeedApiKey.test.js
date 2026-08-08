import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PUBLISHED_FEED_KEY_TYPE,
  PUBLISHED_FEED_KEY_PREFIX,
  generatePublishedFeedApiKey,
  hashApiKey,
  lastFourOf,
  maskApiKey,
  timingSafeHashEqual,
  redactApiKeyInText,
  isRevealableKeyRow,
  keyStatus
} from './publishedFeedApiKey.js';

test('generates prefixed, unique keys', () => {
  const a = generatePublishedFeedApiKey();
  const b = generatePublishedFeedApiKey();
  assert.ok(a.startsWith(PUBLISHED_FEED_KEY_PREFIX));
  assert.notEqual(a, b);
});

test('hashApiKey is deterministic 64-hex', () => {
  const key = generatePublishedFeedApiKey();
  const h = hashApiKey(key);
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.equal(h, hashApiKey(key));
});

test('mask shows prefix + last four only', () => {
  const key = 'th_pf_ABCDEFGHijklmnop';
  const masked = maskApiKey({ key_prefix: PUBLISHED_FEED_KEY_PREFIX, last_four: lastFourOf(key) });
  assert.equal(masked, 'th_pf_••••••••••••mnop');
  assert.ok(!masked.includes('ABCDEF'));
});

test('timing-safe hash compare', () => {
  const h1 = hashApiKey('one');
  const h2 = hashApiKey('two');
  assert.equal(timingSafeHashEqual(h1, h1), true);
  assert.equal(timingSafeHashEqual(h1, h2), false);
  assert.equal(timingSafeHashEqual(h1, 'zz'), false);
  assert.equal(timingSafeHashEqual('', ''), false);
});

test('redacts api_key, Bearer, th_pf_ and th_ioc_ tokens in text', () => {
  const url = 'GET /api/published-feeds/malware?api_key=th_pf_SECRETVALUE123 200';
  const out = redactApiKeyInText(url);
  assert.ok(!out.includes('SECRETVALUE123'));
  assert.match(out, /api_key=\[REDACTED\]/);
  assert.equal(redactApiKeyInText('bare th_pf_abcDEF012 token'), 'bare th_pf_[REDACTED] token');
  assert.equal(redactApiKeyInText('bare th_ioc_abcDEF012 token'), 'bare th_ioc_[REDACTED] token');
  assert.match(redactApiKeyInText('Authorization: Bearer th_ioc_SECRET'), /Bearer \[REDACTED\]/);
  assert.match(redactApiKeyInText('?token=abc123&x=1'), /token=\[REDACTED\]/);
});

test('isRevealableKeyRow requires modern profile + ciphertext', () => {
  assert.equal(isRevealableKeyRow({ key_type: PUBLISHED_FEED_KEY_TYPE, secret_ciphertext: Buffer.from('x') }), true);
  assert.equal(isRevealableKeyRow({ key_type: 'ioc_management', secret_ciphertext: Buffer.from('x') }), true);
  assert.equal(isRevealableKeyRow({ key_type: PUBLISHED_FEED_KEY_TYPE, secret_ciphertext: null }), false);
  assert.equal(isRevealableKeyRow({ key_type: 'feed_access', secret_ciphertext: Buffer.from('x') }), false);
});

test('keyStatus resolves deleted/expired/disabled/active', () => {
  const past = new Date(Date.now() - 1000).toISOString();
  const future = new Date(Date.now() + 100000).toISOString();
  assert.equal(keyStatus({ deleted_at: past, enabled: true }), 'deleted');
  // Legacy revoked rows also read as deleted (defense-in-depth for un-migrated rows).
  assert.equal(keyStatus({ revoked_at: past, enabled: true }), 'deleted');
  assert.equal(keyStatus({ enabled: true, expires_at: past }), 'expired');
  assert.equal(keyStatus({ enabled: false }), 'disabled');
  assert.equal(keyStatus({ enabled: true, expires_at: future }), 'active');
  assert.equal(keyStatus({ enabled: true }), 'active');
});

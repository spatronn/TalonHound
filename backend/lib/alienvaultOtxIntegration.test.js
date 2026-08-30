import test from 'node:test';
import assert from 'node:assert/strict';
import {
  maskOtxApiKey,
  sanitizeOtxErrorMessage,
  formatOtxCredentialsSummary,
  testOtxConnection,
  ALIENVAULT_OTX_FEED_KEY
} from './alienvaultOtxIntegration.js';
import {
  AUTH_KEY_FEED_KEYS,
  formatFeedCredentialsSummary,
  sanitizeFeedErrorMessage
} from './urlhausIntegration.js';
import { FEED_SOURCE_RULES, feedKeyForSourceName } from './iocExpiration.js';

test('maskOtxApiKey masks all but last 4', () => {
  assert.equal(maskOtxApiKey('abcd1234efgh5678'), '************5678');
  assert.equal(maskOtxApiKey(''), null);
});

test('sanitizeOtxErrorMessage redacts key', () => {
  assert.equal(sanitizeOtxErrorMessage('X-OTX-API-KEY: secret').includes('secret'), false);
});

test('formatOtxCredentialsSummary reports configured + masked, never raw', () => {
  const summary = formatOtxCredentialsSummary({ auth_key: 'abcd1234efgh5678' });
  assert.equal(summary.auth_key_configured, true);
  assert.equal(summary.masked_auth_key, '************5678');
  assert.equal(JSON.stringify(summary).includes('abcd1234efgh5678'), false);
});

test('formatOtxCredentialsSummary handles empty credentials', () => {
  const summary = formatOtxCredentialsSummary({});
  assert.equal(summary.auth_key_configured, false);
  assert.equal(summary.masked_auth_key, null);
});

test('AUTH_KEY_FEED_KEYS includes OTX (credentials UI enabled)', () => {
  assert.equal(AUTH_KEY_FEED_KEYS.has(ALIENVAULT_OTX_FEED_KEY), true);
});

test('formatFeedCredentialsSummary dispatches OTX', () => {
  const summary = formatFeedCredentialsSummary(ALIENVAULT_OTX_FEED_KEY, { auth_key: 'zzzz9999' });
  assert.equal(summary.auth_key_configured, true);
  assert.equal(summary.masked_auth_key, '************9999');
});

test('sanitizeFeedErrorMessage dispatches OTX redaction', () => {
  const out = sanitizeFeedErrorMessage(ALIENVAULT_OTX_FEED_KEY, 'X-OTX-API-KEY: leak');
  assert.equal(out.includes('leak'), false);
});

test('FEED_SOURCE_RULES maps AlienVault OTX source name to feed key', () => {
  assert.equal(feedKeyForSourceName('AlienVault OTX'), 'alienvault-otx');
  assert.ok(FEED_SOURCE_RULES.some((r) => r.key === 'alienvault-otx' && r.exact === 'AlienVault OTX'));
});

test('testOtxConnection returns friendly message on 401/403', async () => {
  const origFetch = global.fetch;
  global.fetch = async () => ({ status: 403, ok: false, text: async () => '' });
  try {
    const r = await testOtxConnection({ authKey: 'k' });
    assert.equal(r.ok, false);
    assert.match(r.message, /invalid or unauthorized/i);
  } finally {
    global.fetch = origFetch;
  }
});

test('testOtxConnection returns rate-limit message on 429', async () => {
  const origFetch = global.fetch;
  global.fetch = async () => ({ status: 429, ok: false, text: async () => '' });
  try {
    const r = await testOtxConnection({ authKey: 'k' });
    assert.equal(r.ok, false);
    assert.match(r.message, /rate limit/i);
  } finally {
    global.fetch = origFetch;
  }
});

test('testOtxConnection succeeds on 200 with results array', async () => {
  const origFetch = global.fetch;
  let sentKey = null;
  global.fetch = async (_url, init) => {
    sentKey = init.headers['X-OTX-API-KEY'];
    return { status: 200, ok: true, text: async () => JSON.stringify({ results: [] }) };
  };
  try {
    const r = await testOtxConnection({ authKey: 'mykey' });
    assert.equal(r.ok, true);
    assert.equal(sentKey, 'mykey');
  } finally {
    global.fetch = origFetch;
  }
});

test('testOtxConnection requires api key', async () => {
  const r = await testOtxConnection({ authKey: '' });
  assert.equal(r.ok, false);
  assert.match(r.message, /missing/i);
});

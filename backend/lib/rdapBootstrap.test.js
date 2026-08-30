import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildTldBootstrapMap,
  joinRdapDomainUrl,
  publicSuffixForDomain,
  resetRdapBootstrapCacheForTests,
  resolveRdapDomainUrlCandidates
} from './rdapBootstrap.js';

test('joinRdapDomainUrl builds RFC-style domain path', () => {
  assert.equal(
    joinRdapDomainUrl('https://rdap.radix.host/rdap/', 'boatbeach.online'),
    'https://rdap.radix.host/rdap/domain/boatbeach.online'
  );
  assert.equal(
    joinRdapDomainUrl('https://rdap.verisign.com/com/v1/', 'example.com'),
    'https://rdap.verisign.com/com/v1/domain/example.com'
  );
});

test('publicSuffixForDomain uses registrable public suffix', () => {
  assert.equal(publicSuffixForDomain('boatbeach.online'), 'online');
  assert.equal(publicSuffixForDomain('example.co.uk'), 'co.uk');
});

test('buildTldBootstrapMap indexes TLD to base URLs', () => {
  const map = buildTldBootstrapMap({
    services: [
      [['online'], ['https://rdap.radix.host/rdap/']],
      [['com', 'net'], ['https://rdap.verisign.com/com/v1/']]
    ]
  });
  assert.deepEqual(map.get('online'), ['https://rdap.radix.host/rdap/']);
  assert.deepEqual(map.get('com'), ['https://rdap.verisign.com/com/v1/']);
});

test('IANA bootstrap fetch uses AbortController timeout', async () => {
  resetRdapBootstrapCacheForTests();
  const prevUrl = process.env.RDAP_IANA_BOOTSTRAP_URL;
  const prevTimeout = process.env.RDAP_IANA_BOOTSTRAP_TIMEOUT_MS;
  process.env.RDAP_IANA_BOOTSTRAP_URL = 'https://example.invalid/rdap/dns.json';
  process.env.RDAP_IANA_BOOTSTRAP_TIMEOUT_MS = '50';

  const originalFetch = globalThis.fetch;
  let sawSignal = false;
  globalThis.fetch = (_url, opts = {}) => {
    assert.ok(opts.signal, 'fetch must pass AbortSignal');
    sawSignal = true;
    return new Promise((_resolve, reject) => {
      opts.signal.addEventListener('abort', () => {
        const err = new Error('aborted');
        err.name = 'AbortError';
        reject(err);
      });
    });
  };

  try {
    // Should fall back to rdap.org after bootstrap timeout/failure.
    const urls = await resolveRdapDomainUrlCandidates('example.com', { fallbackBase: 'https://rdap.org' });
    assert.equal(sawSignal, true);
    assert.ok(urls.some((u) => u.includes('rdap.org')));
  } finally {
    globalThis.fetch = originalFetch;
    if (prevUrl === undefined) delete process.env.RDAP_IANA_BOOTSTRAP_URL;
    else process.env.RDAP_IANA_BOOTSTRAP_URL = prevUrl;
    if (prevTimeout === undefined) delete process.env.RDAP_IANA_BOOTSTRAP_TIMEOUT_MS;
    else process.env.RDAP_IANA_BOOTSTRAP_TIMEOUT_MS = prevTimeout;
    resetRdapBootstrapCacheForTests();
  }
});

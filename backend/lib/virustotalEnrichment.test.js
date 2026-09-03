import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildVtNotIndexedResponse,
  isVtResourceNotFound,
  vtHttpErrorMessage,
  buildVirusTotalGuiUrl,
  vtBase64UrlEncode,
  ensureVtGuiPermalink
} from './virustotalEnrichment.js';

test('isVtResourceNotFound detects VT 404 only', () => {
  assert.equal(isVtResourceNotFound(404), true);
  assert.equal(isVtResourceNotFound(403), false);
  assert.equal(isVtResourceNotFound(429), false);
});

test('buildVtNotIndexedResponse is non-error not_found payload', () => {
  const body = buildVtNotIndexedResponse({ fetched_at: '2026-05-31T00:00:00.000Z' });
  assert.equal(body.status, 'not_found');
  assert.equal(body.provider, 'virustotal');
  assert.equal(body.is_error, false);
  assert.match(body.message, /no report/i);
  assert.equal(body.fetched_at, '2026-05-31T00:00:00.000Z');
});

test('vtHttpErrorMessage distinguishes auth and rate limit', () => {
  assert.match(vtHttpErrorMessage(401), /API key/i);
  assert.match(vtHttpErrorMessage(403), /API key/i);
  assert.match(vtHttpErrorMessage(429), /rate limit/i);
  assert.match(vtHttpErrorMessage(502), /failed/i);
});

const VT_URL_ID = '08425c9691b5a3edb3235eb50ff3adee336a4cb024c71d266cb4621b1cabe1d5';
const SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

test('buildVirusTotalGuiUrl maps URL IOC to the GUI url route using VT object id', () => {
  const href = buildVirusTotalGuiUrl({ type: 'url', observable: 'http://42.59.71.140:35247/bin.sh', vtObjectId: VT_URL_ID });
  assert.equal(href, `https://www.virustotal.com/gui/url/${VT_URL_ID}`);
});

test('buildVirusTotalGuiUrl URL fallback is unpadded base64url of the original URL', () => {
  const original = 'http://42.59.71.140:35247/bin.sh';
  const href = buildVirusTotalGuiUrl({ type: 'url', observable: original });
  assert.equal(href, `https://www.virustotal.com/gui/url/${vtBase64UrlEncode(original)}`);
  assert.doesNotMatch(href, /=$/); // no base64 padding
});

test('buildVirusTotalGuiUrl maps domain', () => {
  assert.equal(
    buildVirusTotalGuiUrl({ type: 'domain', observable: 'example.com' }),
    'https://www.virustotal.com/gui/domain/example.com'
  );
});

test('buildVirusTotalGuiUrl maps IPv4 to ip-address route (not ip_addresses)', () => {
  const href = buildVirusTotalGuiUrl({ type: 'ip', observable: '8.8.8.8' });
  assert.equal(href, 'https://www.virustotal.com/gui/ip-address/8.8.8.8');
  assert.doesNotMatch(href, /ip_addresses/);
});

test('buildVirusTotalGuiUrl maps IPv6 preserving literal colons', () => {
  const href = buildVirusTotalGuiUrl({ type: 'ipv6', observable: '2001:4860:4860::8888' });
  assert.equal(href, 'https://www.virustotal.com/gui/ip-address/2001:4860:4860::8888');
});

test('buildVirusTotalGuiUrl maps SHA256 hash to file route', () => {
  assert.equal(
    buildVirusTotalGuiUrl({ type: 'hash', observable: SHA256 }),
    `https://www.virustotal.com/gui/file/${SHA256}`
  );
});

test('buildVirusTotalGuiUrl prefers VT canonical file id (SHA256) for an MD5 query', () => {
  const href = buildVirusTotalGuiUrl({ type: 'md5', observable: 'd41d8cd98f00b204e9800998ecf8427e', vtObjectId: SHA256 });
  assert.equal(href, `https://www.virustotal.com/gui/file/${SHA256}`);
});

test('buildVirusTotalGuiUrl falls back to the original MD5/SHA1 when no object id', () => {
  const md5 = 'd41d8cd98f00b204e9800998ecf8427e';
  assert.equal(buildVirusTotalGuiUrl({ type: 'md5', observable: md5 }), `https://www.virustotal.com/gui/file/${md5}`);
  const sha1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
  assert.equal(buildVirusTotalGuiUrl({ type: 'sha1', observable: sha1 }), `https://www.virustotal.com/gui/file/${sha1}`);
});

test('buildVirusTotalGuiUrl returns null for unsupported / empty input', () => {
  assert.equal(buildVirusTotalGuiUrl({ type: 'email', observable: 'a@b.com' }), null);
  assert.equal(buildVirusTotalGuiUrl({ type: 'url', observable: '' }), null);
  assert.equal(buildVirusTotalGuiUrl({}), null);
});

test('no generated GUI link contains /api/v3/', () => {
  const cases = [
    { type: 'url', observable: 'http://x/y', vtObjectId: VT_URL_ID },
    { type: 'domain', observable: 'example.com' },
    { type: 'ip', observable: '8.8.8.8' },
    { type: 'ipv6', observable: '2001:db8::1' },
    { type: 'hash', observable: SHA256 }
  ];
  for (const c of cases) {
    const href = buildVirusTotalGuiUrl(c);
    assert.ok(href, `expected a href for ${c.type}`);
    assert.doesNotMatch(href, /\/api\/v3\//);
    assert.ok(href.startsWith('https://www.virustotal.com/gui/'));
  }
});

test('ensureVtGuiPermalink replaces an API self-link with the GUI permalink', () => {
  const stale = {
    provider: 'virustotal',
    ioc_type: 'url',
    ioc_value: 'http://42.59.71.140:35247/bin.sh',
    vt_object_id: VT_URL_ID,
    permalink: `https://www.virustotal.com/api/v3/urls/${VT_URL_ID}` // must not survive
  };
  const healed = ensureVtGuiPermalink(stale);
  assert.equal(healed.permalink, `https://www.virustotal.com/gui/url/${VT_URL_ID}`);
  assert.doesNotMatch(healed.permalink, /\/api\/v3\//);
  // original object is not mutated
  assert.match(stale.permalink, /\/api\/v3\//);
});

test('ensureVtGuiPermalink self-heals a legacy row that lacks vt_object_id (URL base64url fallback)', () => {
  const original = 'http://42.59.71.140:35247/bin.sh';
  const legacy = {
    ioc_type: 'url',
    ioc_value: original,
    permalink: 'https://www.virustotal.com/api/v3/urls/whatever'
  };
  const healed = ensureVtGuiPermalink(legacy);
  assert.equal(healed.permalink, `https://www.virustotal.com/gui/url/${vtBase64UrlEncode(original)}`);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractHostFromIocValue,
  getApplicableProvidersForIocType,
  getDerivedApplicableProviders,
  getDerivedInfrastructure,
  getDerivedInfrastructureContext,
  getDerivedInfrastructureProviders,
  getDirectApplicableProviders,
  isIpAddress,
  isProviderApplicable,
  normalizeIocType
} from './iocProviderApplicability.js';
import { computeLayeredProviderCoverage, computeProviderCoverage, providerStateStyle } from './intelligenceSummary.js';

test('normalizeIocType maps hash aliases to hash', () => {
  assert.equal(normalizeIocType('sha256'), 'hash');
  assert.equal(normalizeIocType('file_hash'), 'hash');
  assert.equal(normalizeIocType('md5'), 'hash');
});

test('normalizeIocType maps ip aliases to ip', () => {
  assert.equal(normalizeIocType('ip'), 'ip');
  assert.equal(normalizeIocType('ip6'), 'ip');
  assert.equal(normalizeIocType('ipv6'), 'ip');
});

test('hash IOC only includes VirusTotal', () => {
  assert.deepEqual(getApplicableProvidersForIocType('sha256'), ['virustotal']);
  assert.equal(isProviderApplicable('ipinfo', 'sha256'), false);
  assert.equal(isProviderApplicable('abuseipdb', 'sha256'), false);
  assert.equal(isProviderApplicable('rdap', 'sha256', { rdapEligible: true }), false);
  assert.equal(isProviderApplicable('dnsmania', 'sha256'), false);
});

test('IP IOC includes VT, IPinfo, AbuseIPDB, Spamhaus DROP, and DNSMania but not RDAP', () => {
  const providers = getApplicableProvidersForIocType('ip');
  assert.deepEqual(providers, ['virustotal', 'ipinfo', 'abuseipdb', 'spamhaus_drop', 'dnsmania']);
  assert.equal(isProviderApplicable('rdap', 'ip', { rdapEligible: true }), false);
  assert.equal(isProviderApplicable('dnsmania', 'ip'), true);
});

test('domain IOC includes RDAP only when eligible and always DNSMania', () => {
  assert.deepEqual(
    getApplicableProvidersForIocType('domain', { rdapEligible: true }),
    ['virustotal', 'rdap', 'dnsmania']
  );
  assert.deepEqual(getApplicableProvidersForIocType('domain', { rdapEligible: false }), ['virustotal', 'dnsmania']);
  assert.equal(isProviderApplicable('ipinfo', 'domain'), false);
  assert.equal(isProviderApplicable('abuseipdb', 'domain'), false);
});

test('URL IOC includes VirusTotal and DNSMania in direct coverage', () => {
  assert.deepEqual(getApplicableProvidersForIocType('url'), ['virustotal', 'dnsmania']);
  assert.equal(isProviderApplicable('ipinfo', 'url'), false);
  assert.equal(isProviderApplicable('abuseipdb', 'url'), false);
  assert.equal(isProviderApplicable('rdap', 'url', { rdapEligible: true }), false);
  assert.equal(isProviderApplicable('dnsmania', 'url'), true);
});

test('computeProviderCoverage filters non-applicable providers for hash IOC', () => {
  const coverage = computeProviderCoverage({}, { iocType: 'sha256' });
  assert.deepEqual(coverage.map((p) => p.key), ['virustotal']);
});

test('computeProviderCoverage includes IP providers for IP IOC', () => {
  const coverage = computeProviderCoverage({}, { iocType: 'ip' });
  assert.deepEqual(coverage.map((p) => p.key), ['virustotal', 'ipinfo', 'abuseipdb', 'spamhaus_drop', 'dnsmania']);
});

test('computeProviderCoverage omits RDAP for hash even with stale snapshots', () => {
  const coverage = computeProviderCoverage({
    virustotal: { status: 'not_found' },
    ipinfo: { status: 'not_found' },
    abuseipdb: { status: 'not_found' },
    rdap: { status: 'not_found' }
  }, { iocType: 'sha256' });
  assert.equal(coverage.length, 1);
  assert.equal(coverage[0].key, 'virustotal');
  assert.equal(coverage[0].state, 'not_found');
});

test('extractHostFromIocValue parses IP host with port and path', () => {
  assert.equal(
    extractHostFromIocValue('http://222.138.182.107:48022/bin.sh', 'url'),
    '222.138.182.107'
  );
});

test('isIpAddress detects IPv4 literals', () => {
  assert.equal(isIpAddress('222.138.182.107'), true);
  assert.equal(isIpAddress('example.com'), false);
});

test('URL with IP host yields derived IP providers only', () => {
  const url = 'http://222.138.182.107:48022/bin.sh';
  assert.deepEqual(getDerivedInfrastructureProviders(url, 'url'), ['ipinfo', 'abuseipdb', 'spamhaus_drop']);
  const ctx = getDerivedInfrastructureContext(url, 'url');
  assert.equal(ctx.host, '222.138.182.107');
  assert.equal(ctx.hostKind, 'ip');
});

test('URL with domain host yields RDAP when eligible', () => {
  const url = 'https://example.com/path';
  assert.deepEqual(
    getDerivedInfrastructureProviders(url, 'url', { rdapEligible: true }),
    ['rdap']
  );
  assert.deepEqual(getDerivedInfrastructureProviders(url, 'url', { rdapEligible: false }), []);
  const ctx = getDerivedInfrastructureContext(url, 'url', { rdapEligible: true });
  assert.equal(ctx.host, 'example.com');
  assert.equal(ctx.hostKind, 'domain');
});

test('extractHostFromIocValue returns null for malformed URLs', () => {
  assert.equal(extractHostFromIocValue('not-a-url', 'url'), null);
  assert.equal(extractHostFromIocValue('ftp://example.com/x', 'url'), null);
});

// Schemeless URL IOC hostname extraction (USOM-style imports without http/https prefix)
test('extractHostFromIocValue schemeless URL with path', () => {
  assert.equal(
    extractHostFromIocValue('bu-haftaninsonkampanyasi.shop/sadece-online-ozel/', 'url'),
    'bu-haftaninsonkampanyasi.shop'
  );
});

test('extractHostFromIocValue https URL with path matches schemeless result', () => {
  assert.equal(
    extractHostFromIocValue('https://bu-haftaninsonkampanyasi.shop/sadece-online-ozel/', 'url'),
    'bu-haftaninsonkampanyasi.shop'
  );
});

test('extractHostFromIocValue lowercases host and strips port', () => {
  assert.equal(extractHostFromIocValue('http://Sub.Example.com:8080/a?b=1#x', 'url'), 'sub.example.com');
});

test('extractHostFromIocValue protocol-relative URL', () => {
  assert.equal(extractHostFromIocValue('//example.com/path', 'url'), 'example.com');
});

test('extractHostFromIocValue bare domain without path (url type)', () => {
  assert.equal(extractHostFromIocValue('example.com', 'url'), 'example.com');
});

test('extractHostFromIocValue returns null for relative path', () => {
  assert.equal(extractHostFromIocValue('/only/path', 'url'), null);
});

test('extractHostFromIocValue returns null for string with spaces', () => {
  assert.equal(extractHostFromIocValue('not a valid url', 'url'), null);
});

test('extractHostFromIocValue returns null for empty value', () => {
  assert.equal(extractHostFromIocValue('', 'url'), null);
  assert.equal(extractHostFromIocValue(null, 'url'), null);
});

test('extractHostFromIocValue handles IPv6 literal in schemeless URL', () => {
  assert.equal(extractHostFromIocValue('[2001:db8::1]/path', 'url'), '2001:db8::1');
  assert.equal(extractHostFromIocValue('https://[2001:db8::1]/path', 'url'), '2001:db8::1');
});

test('extractHostFromIocValue sub.example.com with path and query', () => {
  assert.equal(extractHostFromIocValue('sub.example.com/path?q=1', 'url'), 'sub.example.com');
  assert.equal(extractHostFromIocValue('https://sub.example.com:8443/path?q=1', 'url'), 'sub.example.com');
});

// RDAP card visibility via getDerivedInfrastructureContext

test('schemeless URL IOC yields RDAP in derived context when eligible', () => {
  const ctx = getDerivedInfrastructureContext(
    'bu-haftaninsonkampanyasi.shop/sadece-online-ozel/',
    'url',
    { rdapEligible: true }
  );
  assert.ok(ctx !== null, 'derived context must not be null for schemeless domain URL');
  assert.equal(ctx.host, 'bu-haftaninsonkampanyasi.shop');
  assert.equal(ctx.hostKind, 'domain');
  assert.ok(ctx.providers.includes('rdap'), 'rdap must be in derived providers');
});

test('scheme-present URL IOC preserves existing RDAP behaviour', () => {
  const ctx = getDerivedInfrastructureContext('https://example.com/path', 'url', { rdapEligible: true });
  assert.ok(ctx !== null);
  assert.equal(ctx.host, 'example.com');
  assert.ok(ctx.providers.includes('rdap'));
});

test('schemeless URL without eligible domain has no RDAP in derived context', () => {
  const ctx = getDerivedInfrastructureContext(
    'bu-haftaninsonkampanyasi.shop/sadece-online-ozel/',
    'url',
    { rdapEligible: false }
  );
  assert.equal(ctx, null, 'context must be null when rdapEligible is false');
});

test('invalid URL IOC yields no derived context', () => {
  const ctx = getDerivedInfrastructureContext('not a valid url', 'url', { rdapEligible: true });
  assert.equal(ctx, null);
});

test('domain IOC does not produce derived context (direct RDAP only)', () => {
  const ctx = getDerivedInfrastructureContext('example.com', 'domain', { rdapEligible: true });
  assert.equal(ctx, null);
});

test('computeProviderCoverage supports explicit providerKeys for derived section', () => {
  const coverage = computeProviderCoverage(
    { ipinfo: { status: 'success' }, abuseipdb: { status: 'not_found' } },
    { providerKeys: ['ipinfo', 'abuseipdb'] }
  );
  assert.deepEqual(coverage.map((p) => p.key), ['ipinfo', 'abuseipdb']);
  assert.equal(coverage[0].state, 'available');
  assert.equal(coverage[1].state, 'not_found');
});

test('getDirectApplicableProviders matches direct IOC rules', () => {
  assert.deepEqual(getDirectApplicableProviders('url'), ['virustotal', 'dnsmania']);
  assert.deepEqual(getDirectApplicableProviders('ip'), ['virustotal', 'ipinfo', 'abuseipdb', 'spamhaus_drop', 'dnsmania']);
});

test('getDerivedApplicableProviders returns IP providers for ip host kind', () => {
  assert.deepEqual(getDerivedApplicableProviders('ip'), ['ipinfo', 'abuseipdb', 'spamhaus_drop']);
  assert.deepEqual(getDerivedApplicableProviders('domain', { rdapEligible: true }), ['rdap']);
});

test('computeLayeredProviderCoverage splits direct and derived for URL with IP host', () => {
  const url = 'http://196.189.3.1:54492/i';
  const derivedContext = getDerivedInfrastructure(url, 'url');
  const layered = computeLayeredProviderCoverage({
    directSnapshots: { virustotal: { status: 'success' } },
    derivedSnapshots: {
      ipinfo: { status: 'success' },
      abuseipdb: { status: 'not_found' }
    },
    iocType: 'url',
    derivedContext
  });
  assert.deepEqual(layered.direct.map((p) => p.key), ['virustotal', 'dnsmania']);
  assert.equal(layered.direct[0].state, 'available');
  assert.equal(layered.derivedHost, '196.189.3.1');
  assert.deepEqual(layered.derived.map((p) => p.key), ['ipinfo', 'abuseipdb', 'spamhaus_drop']);
  assert.equal(layered.derived[0].state, 'available');
  assert.equal(layered.derived[1].state, 'not_found');
});

test('computeLayeredProviderCoverage returns direct-only for IP IOC', () => {
  const layered = computeLayeredProviderCoverage({
    directSnapshots: { virustotal: { status: 'success' }, ipinfo: { status: 'success' } },
    iocType: 'ip',
    derivedContext: null
  });
  assert.deepEqual(layered.direct.map((p) => p.key), ['virustotal', 'ipinfo', 'abuseipdb', 'spamhaus_drop', 'dnsmania']);
  assert.equal(layered.derived, null);
});

// ---------------------------------------------------------------------------
// Spamhaus DROP coverage badge colors
// ---------------------------------------------------------------------------

test('spamhaus_drop listed status maps to available (green badge)', () => {
  const coverage = computeProviderCoverage(
    { spamhaus_drop: { status: 'listed' } },
    { providerKeys: ['spamhaus_drop'] }
  );
  assert.equal(coverage[0].state, 'available');
  assert.equal(providerStateStyle('available').dot, '#22c55e');
});

test('spamhaus_drop not_listed status maps to available (green badge)', () => {
  const coverage = computeProviderCoverage(
    { spamhaus_drop: { status: 'not_listed' } },
    { providerKeys: ['spamhaus_drop'] }
  );
  assert.equal(coverage[0].state, 'available');
});

test('spamhaus_drop not_run status maps to not_run (gray badge)', () => {
  const coverage = computeProviderCoverage(
    { spamhaus_drop: { status: 'not_run' } },
    { providerKeys: ['spamhaus_drop'] }
  );
  assert.equal(coverage[0].state, 'not_run');
});

test('spamhaus_drop missing snapshot maps to not_run (gray badge)', () => {
  const coverage = computeProviderCoverage({}, { providerKeys: ['spamhaus_drop'] });
  assert.equal(coverage[0].state, 'not_run');
});

test('spamhaus_drop disabled status maps to disabled (yellow badge)', () => {
  const coverage = computeProviderCoverage(
    { spamhaus_drop: { status: 'disabled' } },
    { providerKeys: ['spamhaus_drop'] }
  );
  assert.equal(coverage[0].state, 'disabled');
  assert.equal(providerStateStyle('disabled').dot, '#f59e0b');
});

test('spamhaus_drop dataset_not_synced status maps to not_configured (yellow badge)', () => {
  const coverage = computeProviderCoverage(
    { spamhaus_drop: { status: 'dataset_not_synced' } },
    { providerKeys: ['spamhaus_drop'] }
  );
  assert.equal(coverage[0].state, 'not_configured');
  assert.equal(providerStateStyle('not_configured').dot, '#f59e0b');
});

test('spamhaus_drop suspicious status maps to not_configured (yellow badge)', () => {
  const coverage = computeProviderCoverage(
    { spamhaus_drop: { status: 'suspicious' } },
    { providerKeys: ['spamhaus_drop'] }
  );
  assert.equal(coverage[0].state, 'not_configured');
});

test('spamhaus_drop is applicable for ip IOC type', () => {
  assert.equal(isProviderApplicable('spamhaus_drop', 'ip'), true);
});

test('spamhaus_drop is not applicable for hash IOC type', () => {
  assert.equal(isProviderApplicable('spamhaus_drop', 'hash'), false);
  assert.equal(isProviderApplicable('spamhaus_drop', 'sha256'), false);
});

test('spamhaus_drop is not applicable for domain IOC type', () => {
  assert.equal(isProviderApplicable('spamhaus_drop', 'domain'), false);
});

test('computeProviderCoverage includes spamhaus_drop for ip IOC', () => {
  const coverage = computeProviderCoverage({}, { iocType: 'ip' });
  const keys = coverage.map((p) => p.key);
  assert.ok(keys.includes('spamhaus_drop'), 'spamhaus_drop must be included for ip IOC');
});

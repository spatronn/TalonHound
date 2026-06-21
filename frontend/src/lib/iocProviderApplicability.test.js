import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getApplicableProvidersForIocType,
  isProviderApplicable,
  normalizeIocType
} from './iocProviderApplicability.js';
import { computeProviderCoverage } from './intelligenceSummary.js';

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
});

test('IP IOC includes VT, IPinfo, and AbuseIPDB but not RDAP', () => {
  const providers = getApplicableProvidersForIocType('ip');
  assert.deepEqual(providers, ['virustotal', 'ipinfo', 'abuseipdb']);
  assert.equal(isProviderApplicable('rdap', 'ip', { rdapEligible: true }), false);
});

test('domain IOC includes RDAP only when eligible', () => {
  assert.deepEqual(
    getApplicableProvidersForIocType('domain', { rdapEligible: true }),
    ['virustotal', 'rdap']
  );
  assert.deepEqual(getApplicableProvidersForIocType('domain', { rdapEligible: false }), ['virustotal']);
  assert.equal(isProviderApplicable('ipinfo', 'domain'), false);
  assert.equal(isProviderApplicable('abuseipdb', 'domain'), false);
});

test('URL IOC only includes VirusTotal in direct coverage', () => {
  assert.deepEqual(getApplicableProvidersForIocType('url'), ['virustotal']);
  assert.equal(isProviderApplicable('ipinfo', 'url'), false);
  assert.equal(isProviderApplicable('abuseipdb', 'url'), false);
  assert.equal(isProviderApplicable('rdap', 'url', { rdapEligible: true }), false);
});

test('computeProviderCoverage filters non-applicable providers for hash IOC', () => {
  const coverage = computeProviderCoverage({}, { iocType: 'sha256' });
  assert.deepEqual(coverage.map((p) => p.key), ['virustotal']);
});

test('computeProviderCoverage includes IP providers for IP IOC', () => {
  const coverage = computeProviderCoverage({}, { iocType: 'ip' });
  assert.deepEqual(coverage.map((p) => p.key), ['virustotal', 'ipinfo', 'abuseipdb']);
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
  assert.equal(coverage[0].state, 'not_run');
});

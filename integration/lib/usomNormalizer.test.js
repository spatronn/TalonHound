import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildUsomCanonicalSnapshotHash,
  buildUsomProviderMetadata,
  compareUsomHighwaters,
  computeUsomProviderFingerprint,
  normalizeUsomModel,
  parseProviderDate,
  sanitizeUsomLogValue
} from './usomNormalizer.js';

function lookupMap() {
  return {
    descriptions: new Map([['PH', { tr_title: 'Oltalama', en_title: 'Phishing' }]]),
    sources: new Map([['US', { tr_title: 'USOM', en_title: 'TR-CERT' }]]),
    connectionTypes: new Map([['BC', { tr_title: 'Botnet C&C', en_title: 'Botnet C&C' }]])
  };
}

test('normalizes valid domains and rejects domain artifacts', () => {
  assert.equal(normalizeUsomModel({ url: ' Example.COM. ', type: 'domain' }, 'domain').entry.observable, 'example.com');
  assert.equal(normalizeUsomModel({ url: 'https://example.com/x', type: 'domain' }, 'domain').ok, false);
  assert.equal(normalizeUsomModel({ url: '*.example.com', type: 'domain' }, 'domain').ok, false);
  assert.equal(normalizeUsomModel({ url: 'bad domain.com', type: 'domain' }, 'domain').ok, false);
});

test('normalizes full URLs without dropping query and drops fragment', () => {
  const result = normalizeUsomModel({
    url: 'HTTPS://Example.COM:443/Case/Path?q=Value#fragment',
    type: 'url'
  }, 'url');
  assert.equal(result.ok, true);
  assert.equal(result.entry.observable, 'https://example.com/Case/Path?q=Value');
});

test('validates scheme-less provider URLs without inventing stored scheme', () => {
  const result = normalizeUsomModel({
    url: 'Example.COM/Login?Next=Case',
    type: 'url'
  }, 'url');
  assert.equal(result.ok, true);
  assert.equal(result.entry.observable, 'example.com/Login?Next=Case');
});

test('validates IPv4 and rejects CIDR as a host', () => {
  assert.equal(normalizeUsomModel({ url: '203.0.113.8', type: 'ip' }, 'ip').entry.observable, '203.0.113.8');
  assert.equal(normalizeUsomModel({ url: '999.0.0.1', type: 'ip' }, 'ip').ok, false);
  assert.equal(normalizeUsomModel({ url: '203.0.113.0/24', type: 'ip' }, 'ip').ok, false);
});

test('canonicalizes IPv6 hosts and strips bracket/port artifacts', () => {
  const plain = normalizeUsomModel({ url: '2001:0DB8:0:0:0:0:0:1', type: 'ip6' }, 'ip6');
  assert.equal(plain.entry.observable, '2001:db8::1');
  const bracketed = normalizeUsomModel({ url: '[2001:db8::1]:443', type: 'ip6' }, 'ip6');
  assert.equal(bracketed.entry.observable, '2001:db8::1');
});

test('skips IPv6 networks instead of importing them as host IPs', () => {
  const result = normalizeUsomModel({ url: '2001:db8::/32', type: 'ip6net' }, 'ip6net');
  assert.deepEqual(result, { ok: false, reason: 'unsupported_ip_network' });
});

test('maps provider metadata and optional lookup titles without tags', () => {
  const metadata = buildUsomProviderMetadata({
    id: 123,
    type: 'domain',
    desc: 'PH',
    source: 'US',
    date: '2026-07-18 11:00:37.802028',
    criticality_level: 8,
    connectiontype: 'BC'
  }, lookupMap());
  assert.equal(metadata.provider_record_id, 123);
  assert.equal(metadata.provider_description_title_tr, 'Oltalama');
  assert.equal(metadata.provider_source_title_en, 'TR-CERT');
  assert.equal(metadata.provider_connection_type_title_tr, 'Botnet C&C');
  assert.equal(metadata.provider_criticality_level, 8);
  assert.equal(Object.hasOwn(metadata, 'tags'), false);
});

test('invalid provider dates are retained raw and do not invalidate the IOC', () => {
  assert.deepEqual(parseProviderDate('not-a-date'), { raw: 'not-a-date', valid: false, utc: null });
  const result = normalizeUsomModel({ url: 'example.com', type: 'domain', date: 'not-a-date' }, 'domain');
  assert.equal(result.ok, true);
  assert.equal(result.entry.providerMetadata.provider_date, 'not-a-date');
  assert.equal(result.entry.providerMetadata.provider_date_valid, false);
});

test('parses provider timestamps as UTC while preserving the raw value', () => {
  assert.deepEqual(parseProviderDate('2026-07-18 11:00:37.802028'), {
    raw: '2026-07-18 11:00:37.802028',
    valid: true,
    utc: '2026-07-18T11:00:37.802Z'
  });
  assert.equal(parseProviderDate('2026-02-31 10:00:00').valid, false);
});

test('semantic fingerprints include provider id, date and metadata', () => {
  const first = normalizeUsomModel({
    id: 1,
    type: 'domain',
    url: 'example.com',
    date: '2026-07-18 10:00:00',
    desc: 'PH',
    source: 'US'
  }, 'domain').entry;
  const replay = normalizeUsomModel({
    id: 99,
    type: 'domain',
    url: 'example.com',
    date: '2026-07-19 10:00:00',
    desc: 'PH',
    source: 'US'
  }, 'domain').entry;
  assert.notEqual(first.providerFingerprint, replay.providerFingerprint);
  replay.providerMetadata.provider_record_id = first.providerMetadata.provider_record_id;
  replay.providerMetadata.provider_date = first.providerMetadata.provider_date;
  replay.providerMetadata.provider_date_utc = first.providerMetadata.provider_date_utc;
  assert.equal(first.providerFingerprint, computeUsomProviderFingerprint(replay));
  replay.providerMetadata.provider_description_code = 'MW';
  assert.notEqual(first.providerFingerprint, computeUsomProviderFingerprint(replay));
});

test('canonical snapshot hash is order-independent and deduplicated', () => {
  assert.equal(
    buildUsomCanonicalSnapshotHash(['url|b', 'domain|a', 'domain|a']),
    buildUsomCanonicalSnapshotHash(['domain|a', 'url|b'])
  );
});

test('highwaters compare timestamp then numeric provider id', () => {
  assert.equal(compareUsomHighwaters(
    { timestamp: '2026-07-18T10:00:00.000Z', providerId: '10' },
    { timestamp: '2026-07-18T10:00:00.000Z', providerId: '9' }
  ), 1);
});

test('sanitizes control characters and credential-like query values in logs', () => {
  const value = sanitizeUsomLogValue('bad\r\nline?token=secret&x=1');
  assert.equal(value.includes('\n'), false);
  assert.match(value, /token=\*\*\*/);
  assert.doesNotMatch(value, /secret/);
});

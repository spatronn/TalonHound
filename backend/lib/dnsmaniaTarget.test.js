import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeDnsmaniaLookup, isDnsmaniaSupportedIocType } from './dnsmaniaTarget.js';

test('domain IOC is lowercased and trailing-dot stripped', () => {
  const r = normalizeDnsmaniaLookup('domain', 'EXAMPLE.COM.');
  assert.equal(r.ok, true);
  assert.equal(r.lookup_type, 'domain');
  assert.equal(r.lookup_value, 'example.com');
  assert.equal(r.lookup_key, 'domain:example.com');
});

test('URL IOC extracts hostname for domain endpoint', () => {
  const r = normalizeDnsmaniaLookup('url', 'https://example.com/path/file.js');
  assert.equal(r.ok, true);
  assert.equal(r.ioc_type, 'url');
  assert.equal(r.lookup_type, 'domain');
  assert.equal(r.lookup_value, 'example.com');
});

test('URL with IP literal uses IP lookup', () => {
  const r = normalizeDnsmaniaLookup('url', 'http://91.92.241.13/file');
  assert.equal(r.ok, true);
  assert.equal(r.lookup_type, 'ip');
  assert.equal(r.lookup_value, '91.92.241.13');
  assert.equal(r.lookup_key, 'ip:91.92.241.13');
});

test('IP IOC uses IP lookup', () => {
  const r = normalizeDnsmaniaLookup('ip', '1.2.3.4');
  assert.equal(r.ok, true);
  assert.equal(r.lookup_type, 'ip');
  assert.equal(r.lookup_value, '1.2.3.4');
});

test('hash IOC is rejected', () => {
  const r = normalizeDnsmaniaLookup('hash', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'unsupported');
});

test('malformed URL is rejected', () => {
  const r = normalizeDnsmaniaLookup('url', 'http://');
  assert.equal(r.ok, false);
});

test('empty value is rejected', () => {
  const r = normalizeDnsmaniaLookup('domain', '  ');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'empty');
});

test('isDnsmaniaSupportedIocType covers domain url ip only', () => {
  assert.equal(isDnsmaniaSupportedIocType('domain'), true);
  assert.equal(isDnsmaniaSupportedIocType('url'), true);
  assert.equal(isDnsmaniaSupportedIocType('ip'), true);
  assert.equal(isDnsmaniaSupportedIocType('hash'), false);
});

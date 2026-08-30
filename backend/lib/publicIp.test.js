import test from 'node:test';
import assert from 'node:assert/strict';
import { isValidIpAddress, normalizeIpAddress, validatePublicIp } from './publicIp.js';

test('normalizes equivalent IPv6 spellings to one canonical cache key', () => {
  assert.equal(normalizeIpAddress('2001:4860:4860:0:0:0:0:8888'), '2001:4860:4860::8888');
  assert.equal(normalizeIpAddress('2001:4860:4860::8888'), '2001:4860:4860::8888');
});

test('validates public IPv4 and rejects malformed or private values', () => {
  assert.equal(validatePublicIp('8.8.8.8'), '8.8.8.8');
  assert.equal(validatePublicIp('10.0.0.1'), null);
  assert.equal(validatePublicIp('999.1.1.1'), null);
  assert.equal(isValidIpAddress('01.2.3.4'), false);
});

test('canonicalizes IPv4-mapped IPv6 without duplicate spelling', () => {
  assert.equal(normalizeIpAddress('::ffff:192.0.2.1'), '::ffff:c000:201');
});

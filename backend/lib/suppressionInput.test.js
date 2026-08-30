import test from 'node:test';
import assert from 'node:assert/strict';
import {
  detectSuppressionType,
  isSupportedSuppressionType,
  normalizeSuppressionInput
} from './suppressionInput.js';

test('detectSuppressionType classifies ipv4/ipv6/domain/url/hashes', () => {
  assert.equal(detectSuppressionType('1.1.1.1'), 'ip');
  assert.equal(detectSuppressionType('2001:db8::1'), 'ipv6');
  assert.equal(detectSuppressionType('evil.com'), 'domain');
  assert.equal(detectSuppressionType('sub.evil.co.uk'), 'domain');
  assert.equal(detectSuppressionType('https://evil.com/path'), 'url');
  assert.equal(detectSuppressionType('a'.repeat(32)), 'md5');
  assert.equal(detectSuppressionType('a'.repeat(40)), 'sha1');
  assert.equal(detectSuppressionType('a'.repeat(64)), 'sha256');
  assert.equal(detectSuppressionType('not a value with spaces'), null);
});

test('isSupportedSuppressionType only accepts concrete types', () => {
  assert.equal(isSupportedSuppressionType('ip'), true);
  assert.equal(isSupportedSuppressionType('sha256'), true);
  assert.equal(isSupportedSuppressionType('file_hash'), false);
  assert.equal(isSupportedSuppressionType('hash'), false);
  assert.equal(isSupportedSuppressionType(''), false);
});

test('normalizeSuppressionInput auto-detects type when omitted', () => {
  const r = normalizeSuppressionInput({ ioc_value: '  1.1.1.1  ' });
  assert.deepEqual(r, { ok: true, iocType: 'ip', iocValue: '1.1.1.1' });
});

test('normalizeSuppressionInput canonicalizes IPv6 spellings', () => {
  const a = normalizeSuppressionInput({ ioc_value: '2001:0DB8:0000:0000:0000:0000:0000:0001', ioc_type: 'ipv6' });
  const b = normalizeSuppressionInput({ ioc_value: '2001:db8::1', ioc_type: 'ipv6' });
  assert.equal(a.ok, true);
  assert.equal(b.ok, true);
  assert.equal(a.iocValue, b.iocValue, 'equivalent IPv6 spellings collapse to same value');
});

test('normalizeSuppressionInput lowercases domain and strips trailing dot', () => {
  const r = normalizeSuppressionInput({ ioc_value: 'Evil.COM.', ioc_type: 'domain' });
  assert.deepEqual(r, { ok: true, iocType: 'domain', iocValue: 'evil.com' });
});

test('normalizeSuppressionInput lowercases hashes and validates length', () => {
  const ok = normalizeSuppressionInput({ ioc_value: 'AB'.repeat(16), ioc_type: 'md5' });
  assert.equal(ok.ok, true);
  assert.equal(ok.iocValue, 'ab'.repeat(16));
  const bad = normalizeSuppressionInput({ ioc_value: 'abc', ioc_type: 'sha256' });
  assert.equal(bad.ok, false);
});

test('normalizeSuppressionInput normalizes URL default ports/path', () => {
  const r = normalizeSuppressionInput({ ioc_value: 'HTTP://Evil.com:80', ioc_type: 'url' });
  assert.equal(r.ok, true);
  assert.equal(r.iocValue, 'http://evil.com/');
});

test('normalizeSuppressionInput rejects empty value and mismatched ip family', () => {
  assert.equal(normalizeSuppressionInput({ ioc_value: '' }).ok, false);
  assert.equal(normalizeSuppressionInput({ ioc_value: '1.1.1.1', ioc_type: 'ipv6' }).ok, false);
  assert.equal(normalizeSuppressionInput({ ioc_value: '2001:db8::1', ioc_type: 'ip' }).ok, false);
  assert.equal(normalizeSuppressionInput({ ioc_value: 'nota_domain', ioc_type: 'domain' }).ok, false);
});

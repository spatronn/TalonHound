import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDomainOrUrlInput } from './domainRoot.js';

test('parseDomainOrUrlInput extracts eTLD+1 for co.uk', () => {
  const r = parseDomainOrUrlInput('login.example.co.uk', 'domain');
  assert.equal(r.ok, true);
  assert.equal(r.root_domain, 'example.co.uk');
  assert.equal(r.observable_value, 'login.example.co.uk');
});

test('parseDomainOrUrlInput parses URL hostname', () => {
  const r = parseDomainOrUrlInput('https://sub.example.com:8080/login', 'url');
  assert.equal(r.ok, true);
  assert.equal(r.root_domain, 'example.com');
  assert.equal(r.observable_value, 'sub.example.com');
  assert.equal(r.ioc_type, 'url');
});

test('parseDomainOrUrlInput rejects IP', () => {
  const r = parseDomainOrUrlInput('192.0.2.1', 'ip');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'unsupported');
});

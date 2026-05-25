import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeRdapTarget, parseDomainOrUrlInput } from './domainRoot.js';

test('netlify tenant URL resolves to netlify.app', () => {
  const r = normalizeRdapTarget('https://bright-tapioca-7bf43e.netlify.app/');
  assert.equal(r.ok, true);
  assert.equal(r.normalized_host, 'bright-tapioca-7bf43e.netlify.app');
  assert.equal(r.rdap_domain, 'netlify.app');
  assert.equal(r.root_domain, 'netlify.app');
  assert.equal(r.input_type, 'url');
});

test('netlify bare hostname resolves to netlify.app', () => {
  const r = normalizeRdapTarget('bright-tapioca-7bf43e.netlify.app');
  assert.equal(r.ok, true);
  assert.equal(r.rdap_domain, 'netlify.app');
  assert.equal(r.input_type, 'domain');
});

test('co.uk subdomain URL resolves to example.co.uk', () => {
  const r = normalizeRdapTarget('https://sub.example.co.uk/login');
  assert.equal(r.ok, true);
  assert.equal(r.normalized_host, 'sub.example.co.uk');
  assert.equal(r.rdap_domain, 'example.co.uk');
});

test('example.co.uk path without subdomain', () => {
  const r = normalizeRdapTarget('http://example.co.uk/path?a=1');
  assert.equal(r.ok, true);
  assert.equal(r.normalized_host, 'example.co.uk');
  assert.equal(r.rdap_domain, 'example.co.uk');
});

test('example.com/path host parse', () => {
  const r = normalizeRdapTarget('example.com/path');
  assert.equal(r.ok, true);
  assert.equal(r.normalized_host, 'example.com');
  assert.equal(r.rdap_domain, 'example.com');
});

test('deep subdomain resolves to registrable domain', () => {
  const r = normalizeRdapTarget('sub.login.example.com');
  assert.equal(r.ok, true);
  assert.equal(r.normalized_host, 'sub.login.example.com');
  assert.equal(r.rdap_domain, 'example.com');
});

test('IP is unsupported', () => {
  const r = normalizeRdapTarget('1.2.3.4');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'unsupported');
});

test('sha256 hash is unsupported', () => {
  const r = normalizeRdapTarget('a'.repeat(64));
  assert.equal(r.ok, false);
  assert.equal(r.code, 'unsupported');
});

test('parseDomainOrUrlInput wrapper matches normalizeRdapTarget', () => {
  const r = parseDomainOrUrlInput('https://bright-tapioca-7bf43e.netlify.app/', 'url');
  assert.equal(r.ok, true);
  assert.equal(r.root_domain, 'netlify.app');
});

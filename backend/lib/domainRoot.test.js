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



test('com.tr public suffix subdomain resolves to example.com.tr', () => {
  const r = normalizeRdapTarget('sub.example.com.tr');
  assert.equal(r.ok, true);
  assert.equal(r.normalized_host, 'sub.example.com.tr');
  assert.equal(r.rdap_domain, 'example.com.tr');
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

// Schemeless URL IOC RDAP normalization (USOM-style imports without http/https prefix)

test('schemeless URL with path extracts correct hostname and domain', () => {
  const r = normalizeRdapTarget('bu-haftaninsonkampanyasi.shop/sadece-online-ozel/', 'url');
  assert.equal(r.ok, true, `expected ok but got: ${r.message || r.code}`);
  assert.equal(r.normalized_host, 'bu-haftaninsonkampanyasi.shop');
  assert.equal(r.rdap_domain, 'bu-haftaninsonkampanyasi.shop');
  assert.equal(r.ioc_type, 'url');
});

test('schemeless URL result matches https-prefixed equivalent', () => {
  const schemeless = normalizeRdapTarget('bu-haftaninsonkampanyasi.shop/sadece-online-ozel/', 'url');
  const full = normalizeRdapTarget('https://bu-haftaninsonkampanyasi.shop/sadece-online-ozel/', 'url');
  assert.equal(schemeless.ok, true);
  assert.equal(full.ok, true);
  assert.equal(schemeless.normalized_host, full.normalized_host);
  assert.equal(schemeless.rdap_domain, full.rdap_domain);
});

test('path is not included in schemeless URL RDAP lookup value', () => {
  const r = normalizeRdapTarget('example.com/some/very/deep/path?a=1', 'url');
  assert.equal(r.ok, true);
  assert.equal(r.normalized_host, 'example.com', 'path must not appear in normalized_host');
  assert.ok(!r.rdap_domain.includes('/'), 'rdap_domain must not contain a path');
});

test('invalid schemeless value returns controlled error not a throw', () => {
  const r = normalizeRdapTarget('/only/a/path', 'url');
  assert.equal(r.ok, false);
  assert.ok(r.code, 'error response must have a code');
  assert.ok(r.message, 'error response must have a message');
});

test('same root domain resolves to same rdap_domain as cache key', () => {
  const sub = normalizeRdapTarget('campaign.login.sub.example.co.uk/path', 'url');
  const root = normalizeRdapTarget('example.co.uk', 'domain');
  assert.equal(sub.ok, true);
  assert.equal(root.ok, true);
  assert.equal(sub.rdap_domain, root.rdap_domain, 'subdomain URL must share cache key with root domain');
});

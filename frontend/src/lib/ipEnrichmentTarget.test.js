import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseIpEnrichmentTarget,
  getIpEnrichmentEligibility,
  getAbuseIpdbEligibility
} from './ipEnrichmentTarget.js';

describe('parseIpEnrichmentTarget', () => {
  it('parses public IP from URL-with-IP IOC', () => {
    const r = parseIpEnrichmentTarget('https://167.233.67.224/', 'url');
    assert.equal(r.ip, '167.233.67.224');
    assert.equal(r.isIpLiteral, true);
    assert.equal(r.privateIp, false);
  });

  it('parses IP from URL with port and path', () => {
    const r = parseIpEnrichmentTarget('http://167.233.67.224:8080/x', 'url');
    assert.equal(r.ip, '167.233.67.224');
  });

  it('parses bare IP IOC', () => {
    const r = parseIpEnrichmentTarget('167.233.67.224', 'ip');
    assert.equal(r.ip, '167.233.67.224');
  });

  it('returns null for domain URL', () => {
    const r = parseIpEnrichmentTarget('https://example.com/a', 'url');
    assert.equal(r.ip, null);
    assert.equal(r.isIpLiteral, false);
  });

  it('returns null for hash IOC', () => {
    const r = parseIpEnrichmentTarget('abc123', 'hash');
    assert.equal(r.ip, null);
  });

  it('flags private IP in URL host', () => {
    const r = parseIpEnrichmentTarget('https://10.0.0.1/', 'url');
    assert.equal(r.ip, '10.0.0.1');
    assert.equal(r.privateIp, true);
  });
});

describe('getAbuseIpdbEligibility', () => {
  it('eligible for URL-with-public-IP', () => {
    const r = getAbuseIpdbEligibility('https://167.233.67.224/', 'url');
    assert.equal(r.eligible, true);
    assert.equal(r.ip, '167.233.67.224');
  });

  it('eligible but private for private IP URL', () => {
    const r = getAbuseIpdbEligibility('https://10.0.0.1/', 'url');
    assert.equal(r.eligible, true);
    assert.equal(r.privateIp, true);
  });

  it('not eligible for domain URL', () => {
    const r = getAbuseIpdbEligibility('https://example.com/', 'url');
    assert.equal(r.eligible, false);
  });
});

describe('getIpEnrichmentEligibility', () => {
  it('eligible for URL-with-public-IP', () => {
    const r = getIpEnrichmentEligibility('https://167.233.67.224/', 'url');
    assert.equal(r.eligible, true);
    assert.equal(r.ip, '167.233.67.224');
  });

  it('not eligible for private IP URL', () => {
    const r = getIpEnrichmentEligibility('https://10.0.0.1/', 'url');
    assert.equal(r.eligible, false);
  });
});

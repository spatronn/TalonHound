import test from 'node:test';
import assert from 'node:assert/strict';
import { requireRole, ROLES } from '../lib/rbac.js';
import { IPINFO_LITE_TRUSTED_BASE_URL, getIpinfoLiteConfig } from '../services/ipinfoLiteService.js';

test('AUTH-01/02: requireRole(ADMIN) rejects analyst', () => {
  const handler = requireRole(ROLES.ADMIN);
  for (const role of ['analyst', 'readonly']) {
    const req = { user: { role }, authVia: 'cookie' };
    let status = null;
    handler(req, { status(c) { status = c; return { json() {} }; } }, () => {});
    assert.equal(status, 403, `${role} must be forbidden`);
  }
});

test('AUTH-01/02: requireRole(ADMIN) allows admin', () => {
  const handler = requireRole(ROLES.ADMIN);
  const req = { user: { role: 'admin' }, authVia: 'cookie' };
  let next = false;
  handler(req, { status() { return { json() {} }; } }, () => { next = true; });
  assert.equal(next, true);
});

test('SSRF-03: IPinfo trusted base URL is fixed official origin', () => {
  assert.equal(IPINFO_LITE_TRUSTED_BASE_URL, 'https://api.ipinfo.io/lite');
});

test('SSRF-03: getIpinfoLiteConfig ignores attacker base_url in DB/env', async () => {
  const pool = {
    async query() {
      return {
        rows: [{
          provider: 'ipinfo_lite',
          enabled: true,
          api_key: 'tok',
          timeout_ms: 6000,
          config: { base_url: 'http://169.254.169.254/latest/meta-data' }
        }]
      };
    }
  };
  const prev = process.env.IPINFO_LITE_BASE_URL;
  process.env.IPINFO_LITE_BASE_URL = 'http://127.0.0.1:9';
  try {
    const cfg = await getIpinfoLiteConfig(pool);
    assert.equal(cfg.base_url, IPINFO_LITE_TRUSTED_BASE_URL);
  } finally {
    if (prev === undefined) delete process.env.IPINFO_LITE_BASE_URL;
    else process.env.IPINFO_LITE_BASE_URL = prev;
  }
});

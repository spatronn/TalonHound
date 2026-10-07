import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { registerAbuseIpdbEnrichmentRoutes, runAbuseIpdbRefresh } from './abuseipdbEnrichment.js';
import { registerIpEnrichmentRoutes, runIpinfoRefresh } from './ipEnrichment.js';
import { registerRdapEnrichmentRoutes, runRdapRefresh } from './rdapEnrichment.js';
import { registerSpamhausDropEnrichmentRoutes, runSpamhausDropRefresh } from './spamhausDropEnrichment.js';
import {
  getEnrichmentExecutor,
  listEnrichmentProviders,
  resetEnrichmentExecutorsForTests
} from '../lib/enrichmentProviderRegistry.js';

const here = path.dirname(fileURLToPath(import.meta.url));

function fakeApp() {
  const routes = new Map();
  const add = (method) => (p, ...handlers) => routes.set(`${method} ${p}`, handlers[handlers.length - 1]);
  return { routes, get: add('GET'), post: add('POST'), put: add('PUT'), delete: add('DELETE') };
}

function fakeRes() {
  return {
    statusCode: 200,
    body: null,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; }
  };
}

// No query should be needed for the validation / RBAC paths below.
const noDbPool = { query: async () => { throw new Error('unexpected DB access'); } };
const noAudit = { auditSuccess: async () => {}, auditFailure: async () => {} };

test('every enrichment route module registers its canonical refresh as the provider executor', () => {
  resetEnrichmentExecutorsForTests();
  const app = fakeApp();
  registerAbuseIpdbEnrichmentRoutes(app, noDbPool, noAudit);
  registerIpEnrichmentRoutes(app, noDbPool, noAudit);
  registerRdapEnrichmentRoutes(app, noDbPool, noAudit);
  registerSpamhausDropEnrichmentRoutes(app, noDbPool, noAudit);
  for (const key of ['abuseipdb', 'ipinfo_lite', 'rdap', 'spamhaus_drop']) {
    assert.equal(typeof getEnrichmentExecutor(key), 'function', key);
  }
  // VirusTotal's refresh lives in server.js and registers there.
  const server = readFileSync(path.join(here, '..', 'server.js'), 'utf8');
  assert.match(server, /registerEnrichmentExecutor\(VT_PROVIDER, \(ctx\) => runVirusTotalRefresh\(/);
  assert.match(server, /app\.post\('\/api\/ioc\/:id\/enrichments\/virustotal\/refresh', async \(req, res\) => \{\n  const out = await runVirusTotalRefresh\(req, req\.params\.id\);/);
  // Every registry provider is covered by some executor registration site.
  const keys = listEnrichmentProviders().map((p) => p.key).filter((k) => !k.startsWith('t_'));
  assert.deepEqual(keys.sort(), ['abuseipdb', 'ipinfo_lite', 'rdap', 'spamhaus_drop', 'virustotal']);
  resetEnrichmentExecutorsForTests();
});

test('refresh routes are thin wrappers over the shared functions (same status/body)', async () => {
  const app = fakeApp();
  registerAbuseIpdbEnrichmentRoutes(app, noDbPool, noAudit);
  registerIpEnrichmentRoutes(app, noDbPool, noAudit);
  registerRdapEnrichmentRoutes(app, noDbPool, noAudit);

  const analyst = { role: 'analyst' };
  // Force refresh stays admin-only exactly as before.
  let res = fakeRes();
  await app.routes.get('POST /api/enrichment/abuseipdb/ip/:ip/refresh')(
    { params: { ip: '8.8.8.8' }, query: { force: 'true' }, body: {}, user: analyst }, res
  );
  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, (await runAbuseIpdbRefresh(noDbPool, noAudit, { user: analyst, body: {} }, { ip: '8.8.8.8', force: true })).body);

  res = fakeRes();
  await app.routes.get('POST /api/enrichment/ip/:ip/refresh')(
    { params: { ip: '8.8.8.8' }, query: {}, body: { force: true }, user: analyst }, res
  );
  assert.equal(res.statusCode, 403);

  res = fakeRes();
  await app.routes.get('POST /api/enrichment/rdap/refresh')(
    { params: {}, query: {}, body: { value: 'example.org', force: true }, user: analyst }, res
  );
  assert.equal(res.statusCode, 403);
});

test('shared refresh functions refuse private / invalid / unsupported targets before any external call', async () => {
  const admin = { user: { role: 'admin' }, body: {} };
  assert.equal((await runAbuseIpdbRefresh(noDbPool, noAudit, admin, { ip: '10.1.2.3' })).status, 422);
  assert.equal((await runAbuseIpdbRefresh(noDbPool, noAudit, admin, { ip: 'not-an-ip' })).status, 400);
  assert.equal((await runIpinfoRefresh(noDbPool, noAudit, admin, { ip: '192.168.1.1' })).status, 422);
  assert.equal((await runRdapRefresh(noDbPool, noAudit, admin, { value: '' })).status, 400);
  assert.equal((await runRdapRefresh(noDbPool, noAudit, admin, { value: '8.8.8.8', hintType: 'domain' })).status, 422);
  assert.equal((await runRdapRefresh(noDbPool, noAudit, admin, { value: 'example.org', hintType: 'ip' })).status, 422);
  assert.equal((await runSpamhausDropRefresh(noDbPool, noAudit, admin, { iocValue: '', iocType: 'ip' })).status, 400);
});

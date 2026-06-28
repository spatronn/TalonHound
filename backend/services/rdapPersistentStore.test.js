import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeRdapTarget } from '../lib/domainRoot.js';
import { refreshRdapEnrichment } from './rdapEnrichmentService.js';

function sampleRdap(registrar = 'Example Registrar') {
  return {
    objectClassName: 'domain',
    ldhName: 'example.test',
    status: ['active'],
    events: [
      { eventAction: 'registration', eventDate: '2024-01-01T00:00:00Z' },
      { eventAction: 'expiration', eventDate: '2027-01-01T00:00:00Z' },
      { eventAction: 'last changed', eventDate: '2024-02-01T00:00:00Z' }
    ],
    entities: [
      { roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', registrar]]] }
    ]
  };
}

function createFakePool() {
  const byRoot = new Map();
  let idSeq = 1;
  return {
    byRoot,
    queries: [],
    async query(sql, params = []) {
      this.queries.push({ sql, params });
      if (/SELECT \* FROM ioc_domain_enrichment WHERE root_domain = \$1/i.test(sql)) {
        return { rows: byRoot.has(params[0]) ? [byRoot.get(params[0])] : [] };
      }
      if (/INSERT INTO ioc_domain_enrichment/i.test(sql)) {
        const root = params[1];
        const prev = byRoot.get(root) || {};
        const row = {
          ...prev,
          id: prev.id || idSeq++,
          observable_value: params[0],
          root_domain: root,
          ioc_type: params[2],
          rdap_status: params[3],
          registrar: params[4],
          registration_date: params[5],
          expiration_date: params[6],
          last_changed_date: params[7],
          domain_age_days: params[8],
          nameservers: JSON.parse(params[9] || '[]'),
          statuses: JSON.parse(params[10] || '[]'),
          derived_signals: JSON.parse(params[11] || '{}'),
          rdap_raw_json: params[12] ? JSON.parse(params[12]) : null,
          error_message: params[13],
          last_enriched_at: params[14],
          last_success_at: params[15] ?? (params[3] === 'success' ? params[14] : prev.last_success_at ?? null),
          last_attempt_at: params[16] ?? params[14],
          last_error: params[17] ?? (params[3] === 'success' ? null : params[13]),
          created_at: prev.created_at || new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        byRoot.set(root, row);
        return { rows: [row] };
      }
      if (/UPDATE ioc_domain_enrichment/i.test(sql)) {
        const root = params[3];
        const prev = byRoot.get(root);
        const row = { ...prev, last_attempt_at: params[0], last_error: params[1], error_message: params[1], derived_signals: JSON.parse(params[2] || '{}'), updated_at: new Date().toISOString() };
        byRoot.set(root, row);
        return { rows: [row] };
      }
      throw new Error(`Unexpected SQL in fake pool: ${sql}`);
    }
  };
}

function fetcherFactory(responses, calls) {
  return async (rootDomain) => {
    calls.push(rootDomain);
    const next = responses.shift();
    if (next instanceof Error) throw next;
    return next;
  };
}

test('first subdomain lookup calls provider and stores by registrable root domain', async () => {
  const pool = createFakePool();
  const calls = [];
  const parsed = normalizeRdapTarget('ygl9tk3l.ekhtelalattabrizi.xyz');
  const result = await refreshRdapEnrichment(pool, parsed, { fetchRdapDomainFn: fetcherFactory([sampleRdap('Registrar A')], calls) });
  assert.deepEqual(calls, ['ekhtelalattabrizi.xyz']);
  assert.equal(result.row.root_domain, 'ekhtelalattabrizi.xyz');
  assert.equal(pool.byRoot.has('ekhtelalattabrizi.xyz'), true);
  assert.equal(result.dataSource, 'provider');
});

test('second subdomain for same root returns DB record without provider call', async () => {
  const pool = createFakePool();
  await refreshRdapEnrichment(pool, normalizeRdapTarget('ygl9tk3l.ekhtelalattabrizi.xyz'), { fetchRdapDomainFn: fetcherFactory([sampleRdap('Registrar A')], []) });
  const calls = [];
  const result = await refreshRdapEnrichment(pool, normalizeRdapTarget('deneme.ekhtelalattabrizi.xyz'), { fetchRdapDomainFn: fetcherFactory([sampleRdap('Should Not Be Used')], calls) });
  assert.deepEqual(calls, []);
  assert.equal(result.row.root_domain, 'ekhtelalattabrizi.xyz');
  assert.equal(result.dataSource, 'db');
});

test('URL IOC normalizes observed host and stores DB key as public-suffix registrable domain', async () => {
  const pool = createFakePool();
  const calls = [];
  const parsed = normalizeRdapTarget('https://login.example.co.uk/a/b?x=1');
  const result = await refreshRdapEnrichment(pool, parsed, { fetchRdapDomainFn: fetcherFactory([sampleRdap('UK Registrar')], calls) });
  assert.equal(parsed.normalized_host, 'login.example.co.uk');
  assert.equal(parsed.root_domain, 'example.co.uk');
  assert.deepEqual(calls, ['example.co.uk']);
  assert.equal(result.row.root_domain, 'example.co.uk');
  assert.equal(pool.byRoot.has('example.co.uk'), true);
});

test('normal refresh returns existing DB record even when cache age is old', async () => {
  const pool = createFakePool();
  const old = new Date(Date.now() - 10 * 86400000).toISOString();
  pool.byRoot.set('ekhtelalattabrizi.xyz', { id: 1, observable_value: 'ygl9tk3l.ekhtelalattabrizi.xyz', root_domain: 'ekhtelalattabrizi.xyz', ioc_type: 'domain', rdap_status: 'success', registrar: 'Stored Registrar', nameservers: [], statuses: [], derived_signals: {}, last_enriched_at: old, last_success_at: old, last_attempt_at: old, last_error: null });
  const calls = [];
  const result = await refreshRdapEnrichment(pool, normalizeRdapTarget('abc.ekhtelalattabrizi.xyz'), { fetchRdapDomainFn: fetcherFactory([sampleRdap('Should Not Be Used')], calls) });
  assert.deepEqual(calls, []);
  assert.equal(result.row.registrar, 'Stored Registrar');
  assert.equal(result.dataSource, 'db');
});

test('force refresh calls provider despite DB record and updates success timestamps', async () => {
  const pool = createFakePool();
  const old = new Date(Date.now() - 10 * 86400000).toISOString();
  pool.byRoot.set('ekhtelalattabrizi.xyz', { id: 1, observable_value: 'ygl9tk3l.ekhtelalattabrizi.xyz', root_domain: 'ekhtelalattabrizi.xyz', ioc_type: 'domain', rdap_status: 'success', registrar: 'Stored Registrar', nameservers: [], statuses: [], derived_signals: {}, last_enriched_at: old, last_success_at: old, last_attempt_at: old, last_error: null });
  const calls = [];
  const result = await refreshRdapEnrichment(pool, normalizeRdapTarget('deneme.ekhtelalattabrizi.xyz'), { force: true, fetchRdapDomainFn: fetcherFactory([sampleRdap('Fresh Registrar')], calls) });
  assert.deepEqual(calls, ['ekhtelalattabrizi.xyz']);
  assert.equal(result.row.registrar, 'Fresh Registrar');
  assert.notEqual(result.row.last_success_at, old);
  assert.equal(result.dataSource, 'forced_provider');
});

test('provider error preserves old successful data and records latest failure metadata', async () => {
  const pool = createFakePool();
  const old = new Date(Date.now() - 10 * 86400000).toISOString();
  pool.byRoot.set('ekhtelalattabrizi.xyz', { id: 1, observable_value: 'ygl9tk3l.ekhtelalattabrizi.xyz', root_domain: 'ekhtelalattabrizi.xyz', ioc_type: 'domain', rdap_status: 'success', registrar: 'Stored Registrar', nameservers: [], statuses: [], derived_signals: {}, rdap_raw_json: { ok: true }, error_message: null, last_enriched_at: old, last_success_at: old, last_attempt_at: old, last_error: null });
  const calls = [];
  const boom = new Error('provider timeout');
  const result = await refreshRdapEnrichment(pool, normalizeRdapTarget('abc.ekhtelalattabrizi.xyz'), { force: true, fetchRdapDomainFn: fetcherFactory([boom], calls) });
  assert.deepEqual(calls, ['ekhtelalattabrizi.xyz']);
  assert.equal(result.row.rdap_status, 'success');
  assert.equal(result.row.registrar, 'Stored Registrar');
  assert.equal(result.row.last_success_at, old);
  assert.match(result.row.last_error, /provider timeout/);
  assert.notEqual(result.row.last_attempt_at, old);
  assert.equal(result.dataSource, 'error');
  assert.equal(result.error, boom);
});

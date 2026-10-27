/**
 * Network observable identity (CIDR IOC records): canonical host / network
 * forms, invalid networks, equivalence, and the storage identity every IOC
 * write path (manual / API / MCP / Threat Library Create IOCs) shares.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseNetworkObservable, isCidrObservable } from './networkObservable.js';
import { resolveIocStorageIdentity } from './manualIocCreate.js';
import { normalizeApiIocValue } from './apiIocService.js';
import { resolveMcpIocInput } from './mcpIocService.js';
import { API_ERROR_CODE } from './apiV1Errors.js';
import { catalogLookupIdentity, bulkMatchCandidates, preserveStoredIocLinks } from './threatLibrary/iocMatch.js';

test('IPv4 CIDR: canonical network + prefix, equivalent spellings share one identity', () => {
  assert.deepEqual(parseNetworkObservable('162.220.232.0/22'), { ok: true, type: 'ip', value: '162.220.232.0/22', kind: 'cidr', prefix: 22 });
  // 162.220.234.0/22 as a publisher wrote it is the same /22 block
  assert.equal(parseNetworkObservable('162.220.234.0/22').value, '162.220.232.0/22');
  assert.equal(parseNetworkObservable(' 69.46.46.17/24 ').value, '69.46.46.0/24');
  assert.equal(parseNetworkObservable('8.8.8.8/32').value, '8.8.8.8/32');
});

test('IPv6 CIDR: host bits cleared, RFC 5952 text, the prefix is kept', () => {
  assert.deepEqual(parseNetworkObservable('2607:99c0::/32'), { ok: true, type: 'ipv6', value: '2607:99c0::/32', kind: 'cidr', prefix: 32 });
  assert.equal(parseNetworkObservable('2607:99C0:0:0:0:0:0:5/32').value, '2607:99c0::/32');
  assert.equal(parseNetworkObservable('2001:0db8:0000:0000:0001:0000:0000:0001/128').value, '2001:db8::1:0:0:1/128');
});

test('host addresses: IPv4 stays ip, IPv6 is ipv6 (RFC 5952), IPv4-mapped keeps its dotted tail', () => {
  assert.deepEqual(parseNetworkObservable('162.220.232.0'), { ok: true, type: 'ip', value: '162.220.232.0', kind: 'host' });
  assert.deepEqual(parseNetworkObservable('2400:8d60:2:0:0:1:841d:5dd'), { ok: true, type: 'ipv6', value: '2400:8d60:2::1:841d:5dd', kind: 'host' });
  assert.equal(parseNetworkObservable('::FFFF:1.2.3.4').value, '::ffff:1.2.3.4');
});

test('a host and the network that starts at it are different identities', () => {
  const host = parseNetworkObservable('162.220.232.0');
  const net = parseNetworkObservable('162.220.232.0/22');
  assert.equal(host.type, net.type);
  assert.notEqual(host.value, net.value);
  assert.equal(isCidrObservable('162.220.232.0'), false);
  assert.equal(isCidrObservable('162.220.232.0/22'), true);
});

test('invalid networks are rejected, never truncated to a host', () => {
  for (const v of ['198.51.100.0/33', '2001:db8::/129', '198.51.100.0/-1', '198.51.100.0/ab', '198.51.100.0/', '0.0.0.0/0', '::/0', '999.1.2.0/24']) {
    const r = parseNetworkObservable(v);
    assert.equal(r?.ok, false, v);
    assert.ok(r.error, v);
  }
});

test('non-IP values are not network observables (callers keep their own inference)', () => {
  for (const v of ['evil.example', 'https://evil.example/a/b', 'd41d8cd98f00b204e9800998ecf8427e', 'C:\\Windows\\x.exe', '']) {
    assert.equal(parseNetworkObservable(v), null, v);
  }
});

test('IOC create storage identity: CIDR is an ip / ipv6 network, IPv6 never a domain, a URL stays a URL', () => {
  assert.deepEqual(resolveIocStorageIdentity('162.220.234.0/22'), { ok: true, type: 'ip', value: '162.220.232.0/22' });
  assert.deepEqual(resolveIocStorageIdentity('2607:99c0::/32'), { ok: true, type: 'ipv6', value: '2607:99c0::/32' });
  assert.deepEqual(resolveIocStorageIdentity('2604:4500:6:10b:0:2:ee45:2201'), { ok: true, type: 'ipv6', value: '2604:4500:6:10b:0:2:ee45:2201' });
  assert.deepEqual(resolveIocStorageIdentity('1.2.3.4'), { ok: true, type: 'ip', value: '1.2.3.4' });
  assert.equal(resolveIocStorageIdentity('http://1.2.3.4/x').type, 'url');
  assert.equal(resolveIocStorageIdentity('evil.example').type, 'domain');
  assert.equal(resolveIocStorageIdentity('198.51.100.0/33').ok, false);
});

test('API type "ip": IPv4 / IPv6 addresses and networks resolve to their storage type; malformed values are rejected', () => {
  assert.deepEqual(normalizeApiIocValue('ip', '69.46.46.9/24'), { ok: true, type: 'ip', value: '69.46.46.0/24' });
  assert.deepEqual(normalizeApiIocValue('ip', '2607:99c0::/32'), { ok: true, type: 'ipv6', value: '2607:99c0::/32' });
  assert.deepEqual(normalizeApiIocValue('ip', '2400:8d60:2::1:841d:5dd'), { ok: true, type: 'ipv6', value: '2400:8d60:2::1:841d:5dd' });
  for (const v of ['198.51.100.0/33', 'not-an-ip', '1.2.3']) {
    assert.equal(normalizeApiIocValue('ip', v).code, API_ERROR_CODE.INVALID_IOC_VALUE, v);
  }
});

test('MCP lookup input: a CIDR or IPv6 value without an explicit type is an IP value', () => {
  const cfg = { valueMaxChars: 2048 };
  assert.deepEqual(
    (({ ok, type, value }) => ({ ok, type, value }))(resolveMcpIocInput('162.220.234.0/22', null, cfg)),
    { ok: true, type: 'ip', value: '162.220.232.0/22' }
  );
  const v6 = resolveMcpIocInput('2607:99c0::/32', null, cfg);
  assert.equal(v6.type, 'ipv6');
  assert.equal(v6.value, '2607:99c0::/32');
  assert.equal(resolveMcpIocInput('evil.example', null, cfg).type, 'domain');
});

test('Threat Library catalog lookup: cidr candidates look up their ip / ipv6 network IOC, never a host', () => {
  assert.deepEqual(catalogLookupIdentity('cidr', '162.220.232.0/22'), { type: 'ip', value: '162.220.232.0/22' });
  assert.deepEqual(catalogLookupIdentity('cidr', '2607:99c0::/32'), { type: 'ipv6', value: '2607:99c0::/32' });
  assert.deepEqual(catalogLookupIdentity('ip', '162.220.232.0'), { type: 'ip', value: '162.220.232.0' });
  assert.equal(catalogLookupIdentity('cidr', '162.220.232.0'), null, 'a cidr row without a prefix is not looked up as a host');
  assert.equal(catalogLookupIdentity('ip', '162.220.232.0/22'), null, 'an ip row with a prefix is not looked up as a network');
  assert.deepEqual(catalogLookupIdentity('domain', 'Evil.Example'), { type: 'domain', value: 'evil.example' });
});

function catalogPool(rows) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (/unnest/.test(sql)) {
        const keys = new Set(params[0].map((t, i) => `${t}\0${params[1][i]}`));
        return { rows: rows.filter((r) => keys.has(`${r.observable_type}\0${r.observable}`)) };
      }
      if (/WHERE id = ANY/.test(sql)) return { rows: rows.filter((r) => params[0].includes(Number(r.id))) };
      return { rows: [] };
    }
  };
}

test('bulkMatchCandidates links a CIDR candidate to its existing ip network IOC and a host only to the host', async () => {
  const pool = catalogPool([
    { id: 11, public_id: 'n', observable: '162.220.232.0/22', observable_type: 'ip', status: 'active' },
    { id: 12, public_id: 'h', observable: '162.220.232.0', observable_type: 'ip', status: 'active' },
    { id: 13, public_id: 'v6', observable: '2607:99c0::/32', observable_type: 'ipv6', status: 'active' }
  ]);
  const { candidates } = await bulkMatchCandidates(pool, [
    { candidate_type: 'cidr', normalized_value: '162.220.232.0/22', assessment: 'malicious', is_ioc: true },
    { candidate_type: 'ip', normalized_value: '162.220.232.0', assessment: 'malicious', is_ioc: true },
    { candidate_type: 'cidr', normalized_value: '2607:99c0::/32', assessment: 'malicious', is_ioc: true },
    { candidate_type: 'cidr', normalized_value: '69.46.46.0/24', assessment: 'malicious', is_ioc: true }
  ]);
  assert.deepEqual(candidates.map((c) => [c.matched_ioc_id, c.matched_ioc_observable_type]), [[11, 'ip'], [12, 'ip'], [13, 'ipv6'], [null, null]]);
});

test('preserveStoredIocLinks keeps a CIDR row linked to its ip network IOC across a refresh', async () => {
  const pool = catalogPool([{ id: 11, observable: '162.220.232.0/22', observable_type: 'ip' }]);
  const prior = { candidate_type: 'cidr', normalized_value: '162.220.232.0/22', matched_ioc_id: 11, matched_ioc_observable_type: 'ip' };
  // re-read as non-IOC by a later contract: lookup skipped, the stored link is carried
  const fresh = { ...prior, matched_ioc_id: null, is_ioc: false, assessment: 'malicious' };
  const { candidates, preserved } = await preserveStoredIocLinks(pool, [fresh], [prior]);
  assert.equal(candidates[0].matched_ioc_id, 11);
  assert.deepEqual(preserved, [{ identity: 'cidr:162.220.232.0/22', matched_ioc_id: 11 }]);
});

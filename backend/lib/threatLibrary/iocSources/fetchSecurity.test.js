/**
 * IOC Source fetch security: URL policy, DNS / redirect / connection-time
 * destination checks, size + time bounds, and the IOC-intelligence guard.
 * No test contacts a real host: DNS is a stub, transport is a stub or a
 * loopback server that the policy must refuse before any request is sent.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Readable } from 'node:stream';
import { fetchIocSourceUrl, requestPinned, validateIocSourceUrl, BLOCKING_FETCH_CODES } from './fetchSafe.js';
import { isForbiddenFeedDestinationIp, validateFeedUrlPolicy } from '../../customThreatFeedSsrf.js';
import {
  assessIocSourceDestination,
  createIocSourceDestinationGuard,
  destinationObservableKeys,
  KNOWN_MALICIOUS_DESTINATION
} from './destinationIntel.js';
import { inspectIocSource } from './inspect.js';

const PUBLIC_V4 = '140.82.112.3';

function lookupTo(map) {
  return async (host) => {
    const v = map[host];
    if (!v) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    return (Array.isArray(v) ? v : [v]).map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  };
}

/** Transport stub: scripted responses per URL path; records every request it is asked to make. */
function scriptedTransport(script) {
  const seen = [];
  const impl = async (parsed, addresses) => {
    seen.push({ href: parsed.href, address: addresses[0].address });
    const step = script[parsed.href];
    if (!step) throw new Error(`unexpected request ${parsed.href}`);
    const body = step.body ?? '';
    const stream = step.stream || Readable.from(body ? [Buffer.from(body)] : []);
    stream.statusCode = step.status ?? 200;
    stream.headers = step.headers || { 'content-type': 'text/plain' };
    return stream;
  };
  return { impl, seen };
}

async function rejectsWithCode(promise, code) {
  await assert.rejects(promise, (err) => {
    assert.equal(err.code, code, `${err.code}: ${err.message}`);
    return true;
  });
}

test('URL policy: schemes, credentials, ports, internal names and forbidden literals are refused', () => {
  const refused = [
    'file:///etc/passwd',
    'ftp://example.com/iocs.txt',
    'gopher://example.com/',
    'javascript:alert(1)',
    'https://user:secret@example.com/iocs.txt',
    'https://example.com:8080/iocs.txt',
    'http://example.com:22/',
    'http://localhost/iocs.txt',
    'http://localhost./iocs.txt',
    'http://metadata.google.internal./computeMetadata/v1/',
    'http://db/iocs.txt',
    'http://redis:6379/',
    'http://127.0.0.1/',
    'http://2130706433/',
    'http://0x7f.1/',
    'http://10.1.2.3/',
    'http://172.16.0.9/',
    'http://192.168.1.190/',
    'http://169.254.169.254/latest/meta-data/',
    'http://100.64.0.1/',
    'http://[::1]/',
    'http://[::ffff:127.0.0.1]/',
    'http://[::ffff:a9fe:a9fe]/',
    'http://[fd00:ec2::254]/',
    'http://[fe80::1]/'
  ];
  for (const url of refused) assert.equal(validateIocSourceUrl(url).ok, false, url);
  for (const url of [
    'https://github.com/org/ioc/tree/main/Pack',
    'https://raw.githubusercontent.com/org/ioc/main/Pack/iocs.csv',
    'https://vendor.example/research/iocs.json',
    'http://vendor.example:80/iocs.txt',
    'https://vendor.example:443/iocs.txt'
  ]) {
    assert.equal(validateIocSourceUrl(url).ok, true, url);
  }
});

test('forbidden ranges: IPv4 special-use, IPv6 internal and IPv4-embedding prefixes', () => {
  for (const ip of [
    '0.0.0.0', '127.0.0.1', '10.0.0.1', '172.31.255.255', '192.168.0.1', '169.254.169.254', '100.64.0.1',
    '192.0.0.8', '192.0.2.10', '198.18.0.1', '198.51.100.7', '203.0.113.5', '224.0.0.1', '255.255.255.255',
    '::', '::1', '::127.0.0.1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '0:0:0:0:0:ffff:7f00:1',
    '64:ff9b::7f00:1', '64:ff9b:1::a', '2002:7f00:1::', '2001::1', '2001:db8::1', '100::1',
    'fc00::1', 'fd00:ec2::254', 'fe80::1', 'fec0::1', 'ff02::1', 'not-an-ip', ''
  ]) {
    assert.equal(isForbiddenFeedDestinationIp(ip), true, ip);
  }
  for (const ip of [PUBLIC_V4, '8.8.8.8', '185.199.108.133', '2606:4700::1111', '2a00:1450:4001::200e']) {
    assert.equal(isForbiddenFeedDestinationIp(ip), false, ip);
  }
  // Trailing-dot / single-label names are refused by the shared policy too.
  assert.equal(validateFeedUrlPolicy('http://localhost./x').ok, false);
  assert.equal(validateFeedUrlPolicy('http://backend/x').ok, false);
});

test('DNS: every resolved address is checked (rebinding / mixed answers) before connecting', async () => {
  const transport = scriptedTransport({});
  for (const answer of [['10.0.0.5'], [PUBLIC_V4, '127.0.0.1'], ['::ffff:169.254.169.254'], ['fd00::5']]) {
    await rejectsWithCode(
      fetchIocSourceUrl('https://dataset.example/iocs.txt', {
        lookup: lookupTo({ 'dataset.example': answer }),
        requestImpl: transport.impl
      }),
      'destination_blocked'
    );
  }
  assert.equal(transport.seen.length, 0, 'no request is made to a forbidden destination');
});

test('redirects: each hop is re-validated; private, credentialed, scheme and port changes are refused', async () => {
  const cases = [
    ['http://169.254.169.254/latest/meta-data/', 'redirect_blocked'],
    ['http://user:pw@127.0.0.1/', 'redirect_blocked'],
    ['file:///etc/passwd', 'redirect_blocked'],
    ['https://dataset.example:8443/x', 'redirect_blocked'],
    ['http://internal.example/x', 'destination_blocked'] // resolves to RFC1918
  ];
  for (const [location, code] of cases) {
    const transport = scriptedTransport({
      'https://dataset.example/iocs.txt': { status: 302, headers: { location } }
    });
    await rejectsWithCode(
      fetchIocSourceUrl('https://dataset.example/iocs.txt', {
        lookup: lookupTo({ 'dataset.example': PUBLIC_V4, 'internal.example': '10.20.30.40' }),
        requestImpl: transport.impl
      }),
      code
    );
    assert.deepEqual(transport.seen.map((s) => s.href), ['https://dataset.example/iocs.txt'], location);
  }
});

test('redirect limit, response size and timeout are bounded', async () => {
  const loop = {};
  for (let i = 0; i < 8; i += 1) loop[`https://dataset.example/r${i}`] = { status: 302, headers: { location: `/r${i + 1}` } };
  await rejectsWithCode(
    fetchIocSourceUrl('https://dataset.example/r0', {
      lookup: lookupTo({ 'dataset.example': PUBLIC_V4 }),
      requestImpl: scriptedTransport(loop).impl
    }),
    'redirect_limit'
  );

  await rejectsWithCode(
    fetchIocSourceUrl('https://dataset.example/big.txt', {
      lookup: lookupTo({ 'dataset.example': PUBLIC_V4 }),
      maxBytes: 1024,
      requestImpl: scriptedTransport({ 'https://dataset.example/big.txt': { body: 'x'.repeat(4096) } }).impl
    }),
    'response_too_large'
  );

  const slow = new Readable({ read() {} });
  slow.push('203.0.113.9\n'); // never ends
  await rejectsWithCode(
    fetchIocSourceUrl('https://dataset.example/slow.txt', {
      lookup: lookupTo({ 'dataset.example': PUBLIC_V4 }),
      timeoutMs: 1000,
      requestImpl: async (parsed, addresses, headers, signal) => {
        signal.addEventListener('abort', () => slow.destroy(Object.assign(new Error('aborted'), { name: 'AbortError' })));
        slow.statusCode = 200;
        slow.headers = { 'content-type': 'text/plain' };
        return slow;
      }
    }),
    'timeout'
  );
});

test('network failure surfaces a coded, sanitized error', async () => {
  await assert.rejects(
    fetchIocSourceUrl('https://dataset.example/iocs.txt', { lookup: lookupTo({}) }),
    (err) => err.code === 'dns_lookup_failed'
  );
});

test('legitimate public dataset over a redirect to raw GitHub is fetched', async () => {
  const transport = scriptedTransport({
    'https://github.com/org/ioc/raw/main/pack/iocs.txt': {
      status: 302,
      headers: { location: 'https://raw.githubusercontent.com/org/ioc/main/pack/iocs.txt' }
    },
    'https://raw.githubusercontent.com/org/ioc/main/pack/iocs.txt': { body: 'evil.example\n198.51.100.0\n' }
  });
  const result = await fetchIocSourceUrl('https://github.com/org/ioc/raw/main/pack/iocs.txt', {
    lookup: lookupTo({ 'github.com': PUBLIC_V4, 'raw.githubusercontent.com': '185.199.108.133' }),
    requestImpl: transport.impl
  });
  assert.equal(result.ok, true);
  assert.equal(result.statusCode, 200);
  assert.match(result.body, /evil\.example/);
  assert.equal(result.finalUrl, 'https://raw.githubusercontent.com/org/ioc/main/pack/iocs.txt');
  assert.equal(transport.seen[1].address, '185.199.108.133', 'connection pinned to the checked address');
});

test('connection-time re-check: a socket never connects to a forbidden pinned address', async (t) => {
  let hits = 0;
  const server = http.createServer((req, res) => { hits += 1; res.end('secret'); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const { port } = server.address();
  await assert.rejects(
    requestPinned(new URL(`http://dataset.example:${port}/`), [{ address: '127.0.0.1', family: 4 }], {}, new AbortController().signal),
    (err) => err.code === 'destination_blocked'
  );
  assert.equal(hits, 0, 'no request reached the loopback server');
});

test('test seam (fetchImpl) cannot skip URL policy or the destination guard', async () => {
  let called = 0;
  const fetchImpl = async () => { called += 1; return { body: 'x' }; };
  await rejectsWithCode(fetchIocSourceUrl('http://169.254.169.254/', { fetchImpl }), 'blocked_url');
  await rejectsWithCode(
    fetchIocSourceUrl('https://c2.example/payload', {
      fetchImpl,
      destinationGuard: async () => ({ ok: false, code: KNOWN_MALICIOUS_DESTINATION, reason: 'known' })
    }),
    KNOWN_MALICIOUS_DESTINATION
  );
  assert.equal(called, 0);
  assert.equal(BLOCKING_FETCH_CODES.has(KNOWN_MALICIOUS_DESTINATION), true);
});

/** Fake pool answering the two guard queries from in-memory intelligence. */
function intelPool({ inventory = [], candidates = [] } = {}) {
  const queries = [];
  return {
    queries,
    query: async (sql, params) => {
      queries.push(sql);
      const [types, values] = /FROM ioc_items/.test(sql) ? params : [params[1], params[2]];
      const wanted = new Set(types.map((t, i) => `${t}\0${values[i]}`));
      if (/FROM ioc_items/.test(sql)) {
        return { rows: inventory.filter((r) => wanted.has(`${r.observable_type}\0${r.observable}`)) };
      }
      if (/FROM threat_report_candidates/.test(sql)) {
        const excluded = new Set(params[3]);
        return {
          rows: candidates.filter((c) => c.report_id === params[0] && c.is_ioc && !excluded.has(c.assessment)
            && wanted.has(`${c.candidate_type}\0${c.normalized_value}`))
        };
      }
      throw new Error(`unexpected SQL ${sql.slice(0, 60)}`);
    }
  };
}

test('intel keys: URL (both schemes), host as domain, IP literal; never resolved addresses', () => {
  assert.deepEqual(destinationObservableKeys('http://45.138.12.177:8080/w'), [
    { type: 'url', value: 'http://45.138.12.177:8080/w' },
    { type: 'ip', value: '45.138.12.177' }
  ]);
  assert.deepEqual(destinationObservableKeys('https://www.evil.example/iocs.txt').map((k) => `${k.type}:${k.value}`), [
    'url:https://www.evil.example/iocs.txt',
    'url:http://www.evil.example/iocs.txt',
    'domain:www.evil.example',
    'domain:evil.example'
  ]);
  assert.deepEqual(destinationObservableKeys('not a url'), []);
});

test('intel guard: C2 URL in inventory or as a report indicator is blocked with an auditable reason (18637 shape)', async () => {
  const pool = intelPool({
    inventory: [{ observable_type: 'url', observable: 'http://45.138.12.177:8080/w', status: 'active' }],
    candidates: [{ report_id: 18637, candidate_type: 'ip', normalized_value: '45.138.12.177', is_ioc: true, assessment: 'malicious' }]
  });
  const verdict = await assessIocSourceDestination(pool, { url: 'http://45.138.12.177:8080/w', reportId: 18637 });
  assert.equal(verdict.ok, false);
  assert.equal(verdict.code, KNOWN_MALICIOUS_DESTINATION);
  assert.match(verdict.reason, /url http:\/\/45\.138\.12\.177:8080\/w is IOC inventory \(active\)/);
  assert.deepEqual(verdict.matches.map((m) => m.kind).sort(), ['inventory', 'report_indicator']);

  // Report-local only (not yet in inventory): still blocked.
  const local = intelPool({
    candidates: [{ report_id: 7, candidate_type: 'domain', normalized_value: 'workinghardo.link', is_ioc: true, assessment: 'malicious' }]
  });
  assert.equal((await assessIocSourceDestination(local, { url: 'http://workinghardo.link/payload.txt', reportId: 7 })).ok, false);
  // Same indicator, other report: the report-local rule is scoped to its report.
  assert.equal((await assessIocSourceDestination(local, { url: 'http://workinghardo.link/payload.txt', reportId: 8 })).ok, true);
});

test('intel guard: Context Only / benign mentions and shared-CDN addresses do not block public datasets', async () => {
  const pool = intelPool({
    // GitHub raw CDN address is an (expired) IP IOC in production: resolved addresses are never compared.
    inventory: [{ observable_type: 'ip', observable: '185.199.108.133', status: 'expired' }],
    candidates: [{ report_id: 1, candidate_type: 'domain', normalized_value: 'tria.ge', is_ioc: true, assessment: 'context_only' }]
  });
  assert.equal((await assessIocSourceDestination(pool, { url: 'https://raw.githubusercontent.com/org/ioc/main/x.csv', reportId: 1 })).ok, true);
  assert.equal((await assessIocSourceDestination(pool, { url: 'https://tria.ge/reports?q=family:winlol', reportId: 1 })).ok, true);
});

test('intel guard runs on every hop: a redirect into known C2 is never followed', async () => {
  const pool = intelPool({ inventory: [{ observable_type: 'domain', observable: 'havefunnn.win', status: 'active' }] });
  const transport = scriptedTransport({
    'https://dataset.example/iocs.txt': { status: 301, headers: { location: 'https://havefunnn.win/iocs.txt' } }
  });
  await rejectsWithCode(
    fetchIocSourceUrl('https://dataset.example/iocs.txt', {
      lookup: lookupTo({ 'dataset.example': PUBLIC_V4, 'havefunnn.win': '103.193.173.199' }),
      requestImpl: transport.impl,
      destinationGuard: createIocSourceDestinationGuard(pool, null)
    }),
    KNOWN_MALICIOUS_DESTINATION
  );
  assert.equal(transport.seen.length, 1);
});

test('inspect: a known-malicious source URL is blocked with its reason before any fetch (GitHub API included)', async () => {
  const source = {
    id: 9,
    public_id: 's-9',
    report_id: 5,
    lifecycle_status: 'discovered',
    canonical_url: 'https://github.com/actor/payloads',
    original_url: 'https://github.com/actor/payloads'
  };
  const writes = [];
  const pool = {
    query: async (sql, params) => {
      if (/^\s*UPDATE threat_report_ioc_sources/.test(sql)) {
        writes.push({ lifecycle: params[1], code: params[9], detail: params[10] });
        return { rows: [{ ...source, lifecycle_status: params[1] }] };
      }
      if (/SELECT \* FROM threat_report_ioc_sources/.test(sql)) return { rows: [source] };
      return { rows: [] };
    }
  };
  let fetched = 0;
  const result = await inspectIocSource(pool, source, {
    fetchImpl: async () => { fetched += 1; return { body: '[]' }; },
    destinationGuard: async (url) => (url.includes('actor/payloads')
      ? { ok: false, code: KNOWN_MALICIOUS_DESTINATION, reason: 'Not fetched: known malicious destination; url … is IOC inventory (active)' }
      : { ok: true })
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, KNOWN_MALICIOUS_DESTINATION);
  assert.equal(fetched, 0, 'nothing fetched, not even api.github.com');
  const last = writes.at(-1);
  assert.equal(last.lifecycle, 'blocked');
  assert.equal(last.code, KNOWN_MALICIOUS_DESTINATION);
  assert.match(last.detail, /known malicious destination/);
});

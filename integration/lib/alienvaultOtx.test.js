import test from 'node:test';
import assert from 'node:assert/strict';
import {
  maskOtxApiKey,
  sanitizeOtxErrorMessage,
  clampOtxPageLimit,
  classifyOtxIndicatorType,
  normalizeOtxIndicator,
  mapOtxPulseIndicator,
  buildOtxNote,
  buildOtxEvidenceMetadata,
  buildOtxSubscribedUrl,
  buildOtxPulseReferenceUrl,
  collectOtxEntries,
  fetchOtxSubscribedPage,
  walkOtxSubscribedPulses,
  resolveOtxApiKey,
  OTX_PAGE_LIMIT_MAX,
  ALIENVAULT_OTX_FEED_KEY
} from './alienvaultOtx.js';

test('maskOtxApiKey masks all but last 4', () => {
  assert.equal(maskOtxApiKey('abcd1234efgh5678'), '************5678');
  assert.equal(maskOtxApiKey('key'), '****');
  assert.equal(maskOtxApiKey(''), null);
});

test('sanitizeOtxErrorMessage redacts api key header and query', () => {
  assert.match(sanitizeOtxErrorMessage('X-OTX-API-KEY: secretvalue failed'), /X-OTX-API-KEY: \*\*\*/);
  assert.match(sanitizeOtxErrorMessage('GET /api/v1/pulses/subscribed?apikey=abc123&page=1'), /apikey=\*\*\*/);
  assert.equal(sanitizeOtxErrorMessage('X-OTX-API-KEY: secretvalue').includes('secretvalue'), false);
});

test('clampOtxPageLimit bounds to [1, MAX]', () => {
  assert.equal(clampOtxPageLimit(50), 50);
  assert.equal(clampOtxPageLimit(0), 50); // fallback default
  assert.equal(clampOtxPageLimit(9999), OTX_PAGE_LIMIT_MAX);
  assert.equal(clampOtxPageLimit('abc'), 50);
});

test('classifyOtxIndicatorType flags supported vs unsupported', () => {
  assert.equal(classifyOtxIndicatorType('IPv4'), 'supported');
  assert.equal(classifyOtxIndicatorType('FileHash-SHA256'), 'supported');
  assert.equal(classifyOtxIndicatorType('CVE'), 'unsupported');
  assert.equal(classifyOtxIndicatorType('YARA'), 'unsupported');
  assert.equal(classifyOtxIndicatorType('email'), 'unsupported');
});

test('normalizeOtxIndicator maps IPv4 and validates', () => {
  assert.deepEqual(normalizeOtxIndicator('IPv4', '8.8.8.8'), { observable: '8.8.8.8', observableType: 'ip' });
  assert.equal(normalizeOtxIndicator('IPv4', '999.1.1.1'), null);
});

test('normalizeOtxIndicator maps IPv6 to ipv6 lowercased', () => {
  assert.deepEqual(
    normalizeOtxIndicator('IPv6', '2001:DB8::1'),
    { observable: '2001:db8::1', observableType: 'ipv6' }
  );
  assert.equal(normalizeOtxIndicator('IPv6', 'not-an-ip'), null);
});

test('normalizeOtxIndicator domain lowercases and strips trailing dot', () => {
  assert.deepEqual(normalizeOtxIndicator('domain', 'Evil.COM.'), { observable: 'evil.com', observableType: 'domain' });
  assert.deepEqual(normalizeOtxIndicator('hostname', 'Host.Bad.NET'), { observable: 'host.bad.net', observableType: 'domain' });
});

test('normalizeOtxIndicator reclassifies domain-with-scheme as url', () => {
  const out = normalizeOtxIndicator('domain', 'http://evil.com/path');
  assert.equal(out.observableType, 'url');
  assert.equal(out.observable, 'http://evil.com/path');
});

test('normalizeOtxIndicator maps URL and URI to url', () => {
  assert.equal(normalizeOtxIndicator('URL', 'https://Bad.com/x').observableType, 'url');
  assert.equal(normalizeOtxIndicator('URI', 'https://Bad.com/y').observableType, 'url');
});

test('normalizeOtxIndicator validates hash lengths', () => {
  assert.deepEqual(
    normalizeOtxIndicator('FileHash-MD5', 'D41D8CD98F00B204E9800998ECF8427E'),
    { observable: 'd41d8cd98f00b204e9800998ecf8427e', observableType: 'md5' }
  );
  assert.equal(normalizeOtxIndicator('FileHash-SHA256', 'tooshort'), null);
  assert.equal(normalizeOtxIndicator('FileHash-SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709').observableType, 'sha1');
});

test('normalizeOtxIndicator returns null for unsupported types (CVE/email/mutex/yara)', () => {
  assert.equal(normalizeOtxIndicator('CVE', 'CVE-2024-1234'), null);
  assert.equal(normalizeOtxIndicator('email', 'a@b.com'), null);
  assert.equal(normalizeOtxIndicator('Mutex', 'Global\\x'), null);
  assert.equal(normalizeOtxIndicator('YARA', 'rule x {}'), null);
});

test('mapOtxPulseIndicator returns supported entry with pulse context', () => {
  const pulse = {
    id: 'pulse123',
    name: 'Phishing Campaign',
    author_name: 'analyst1',
    tlp: 'white',
    tags: ['phishing', 'apt'],
    created: '2026-06-01T00:00:00Z',
    modified: '2026-06-10T12:00:00Z'
  };
  const indicator = { id: 42, indicator: 'evil.com', type: 'domain', created: '2026-06-02T00:00:00Z' };
  const out = mapOtxPulseIndicator(pulse, indicator);
  assert.equal(out.supported, true);
  assert.equal(out.entry.observable, 'evil.com');
  assert.equal(out.entry.observableType, 'domain');
  assert.equal(out.entry.pulseId, 'pulse123');
  assert.equal(out.entry.pulseAuthor, 'analyst1');
  assert.deepEqual(out.entry.pulseTags, ['phishing', 'apt']);
  assert.equal(out.entry.referenceUrl, 'https://otx.alienvault.com/pulse/pulse123');
  assert.equal(out.entry.indicatorId, '42');
});

test('mapOtxPulseIndicator flags unsupported with rawType', () => {
  const out = mapOtxPulseIndicator({ id: 'p1' }, { indicator: 'CVE-2024-1', type: 'CVE' });
  assert.equal(out.supported, false);
  assert.equal(out.rawType, 'CVE');
});

test('buildOtxNote embeds pulse metadata as key=value', () => {
  const { entry } = mapOtxPulseIndicator(
    { id: 'p9', name: 'Camp', author_name: 'bob', tags: ['x'], modified: '2026-06-10T12:00:00Z' },
    { indicator: '1.2.3.4', type: 'IPv4' }
  );
  const note = buildOtxNote(entry);
  assert.match(note, /pulse_id=p9/);
  assert.match(note, /pulse_author=bob/);
  assert.match(note, /reference=https:\/\/otx\.alienvault\.com\/pulse\/p9/);
});

test('buildOtxEvidenceMetadata includes provider + pulse fields', () => {
  const { entry } = mapOtxPulseIndicator(
    { id: 'p9', name: 'Camp', author_name: 'bob', tlp: 'green', tags: ['x'], modified: '2026-06-10T12:00:00Z' },
    { indicator: '1.2.3.4', type: 'IPv4', created: '2026-06-05T00:00:00Z' }
  );
  const meta = buildOtxEvidenceMetadata(entry);
  assert.equal(meta.provider, 'alienvault_otx');
  assert.equal(meta.pulse_id, 'p9');
  assert.equal(meta.pulse_tlp, 'green');
  assert.equal(meta.indicator_type, 'ip');
  assert.equal(meta.otx_reference, 'https://otx.alienvault.com/pulse/p9');
});

test('buildOtxSubscribedUrl sets limit, page, modified_since', () => {
  const url = buildOtxSubscribedUrl({ modifiedSince: '2026-06-01T00:00:00Z', page: 2, limit: 25 });
  assert.match(url, /\/api\/v1\/pulses\/subscribed/);
  assert.match(url, /limit=25/);
  assert.match(url, /page=2/);
  assert.match(url, /modified_since=2026-06-01/);
});

test('buildOtxSubscribedUrl omits modified_since when empty', () => {
  const url = buildOtxSubscribedUrl({ limit: 50 });
  assert.equal(url.includes('modified_since'), false);
});

test('buildOtxPulseReferenceUrl builds pulse permalink', () => {
  assert.equal(buildOtxPulseReferenceUrl('abc'), 'https://otx.alienvault.com/pulse/abc');
  assert.equal(buildOtxPulseReferenceUrl(''), null);
});

test('fetchOtxSubscribedPage sends X-OTX-API-KEY header', async () => {
  let capturedHeaders = null;
  const fetchFn = async (_url, init) => {
    capturedHeaders = init.headers;
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ count: 1, next: null, results: [{ id: 'p1', indicators: [] }] })
    };
  };
  const { pulses, next } = await fetchOtxSubscribedPage({ apiKey: 'secretkey', fetchFn });
  assert.equal(capturedHeaders['X-OTX-API-KEY'], 'secretkey');
  assert.equal(pulses.length, 1);
  assert.equal(next, null);
});

test('fetchOtxSubscribedPage throws auth error on 401/403', async () => {
  const fetchFn = async () => ({ ok: false, status: 403, text: async () => '' });
  await assert.rejects(
    () => fetchOtxSubscribedPage({ apiKey: 'k', fetchFn }),
    (err) => err.statusCode === 403 && /authentication failed/.test(err.message)
  );
});

test('fetchOtxSubscribedPage throws rate-limit error on 429', async () => {
  const fetchFn = async () => ({
    ok: false,
    status: 429,
    headers: { get: () => '60' },
    text: async () => ''
  });
  await assert.rejects(
    () => fetchOtxSubscribedPage({ apiKey: 'k', fetchFn }),
    (err) => err.statusCode === 429 && /rate limit/i.test(err.message)
  );
});

test('fetchOtxSubscribedPage requires api key', async () => {
  await assert.rejects(() => fetchOtxSubscribedPage({ apiKey: '', fetchFn: async () => ({}) }), /API key is missing/);
});

test('walkOtxSubscribedPulses follows next across pages and bounds by maxPages', async () => {
  const pages = {
    page1: { count: 3, next: 'https://otx.alienvault.com/api/v1/pulses/subscribed?page=2', results: [{ id: 'a', indicators: [] }, { id: 'b', indicators: [] }] },
    page2: { count: 3, next: null, results: [{ id: 'c', indicators: [] }] }
  };
  let call = 0;
  const fetchFn = async (url) => {
    call += 1;
    const body = url.includes('page=2') ? pages.page2 : pages.page1;
    return { ok: true, status: 200, text: async () => JSON.stringify(body) };
  };
  const seen = [];
  const stats = await walkOtxSubscribedPulses({
    apiKey: 'k',
    fetchFn,
    onPulse: (p) => { seen.push(p.id); }
  });
  assert.deepEqual(seen, ['a', 'b', 'c']);
  assert.equal(stats.pages, 2);
  assert.equal(stats.fetchedPulses, 3);
  assert.equal(stats.truncated, false);
});

test('walkOtxSubscribedPulses truncates when maxPages exceeded', async () => {
  const fetchFn = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ count: 100, next: 'https://otx.alienvault.com/api/v1/pulses/subscribed?page=99', results: [{ id: 'x', indicators: [] }] })
  });
  const stats = await walkOtxSubscribedPulses({ apiKey: 'k', fetchFn, maxPages: 2, onPulse: () => {} });
  assert.equal(stats.pages, 2);
  assert.equal(stats.truncated, true);
});

test('resolveOtxApiKey prefers DB credentials over env', async () => {
  const client = {
    query: async () => ({ rows: [{ credentials: { auth_key: 'db-key' } }] })
  };
  const key = await resolveOtxApiKey(client, 'env-key');
  assert.equal(key, 'db-key');
});

test('resolveOtxApiKey falls back to env when DB empty', async () => {
  const client = { query: async () => ({ rows: [{ credentials: {} }] }) };
  assert.equal(await resolveOtxApiKey(client, 'env-key'), 'env-key');
  assert.equal(await resolveOtxApiKey(client, ''), null);
});

test('ALIENVAULT_OTX_FEED_KEY is hyphenated per codebase convention', () => {
  assert.equal(ALIENVAULT_OTX_FEED_KEY, 'alienvault-otx');
});

test('collectOtxEntries dedupes same observable across pulses, keeping latest pulse', () => {
  const pulses = [
    {
      id: 'old', name: 'Old', modified: '2026-06-01T00:00:00Z',
      indicators: [{ indicator: 'evil.com', type: 'domain' }]
    },
    {
      id: 'new', name: 'New', modified: '2026-06-20T00:00:00Z',
      indicators: [{ indicator: 'evil.com', type: 'domain' }, { indicator: '8.8.8.8', type: 'IPv4' }]
    }
  ];
  const { entries, fetchedIndicators } = collectOtxEntries(pulses);
  assert.equal(fetchedIndicators, 3);
  assert.equal(entries.length, 2); // evil.com deduped
  const domain = entries.find((e) => e.observable === 'evil.com');
  assert.equal(domain.pulseId, 'new'); // latest pulse context wins
});

test('collectOtxEntries counts unsupported types with breakdown', () => {
  const pulses = [
    {
      id: 'p1', modified: '2026-06-20T00:00:00Z',
      indicators: [
        { indicator: '1.2.3.4', type: 'IPv4' },
        { indicator: 'CVE-2024-1', type: 'CVE' },
        { indicator: 'a@b.com', type: 'email' },
        { indicator: 'CVE-2024-2', type: 'CVE' },
        { indicator: 'rule x {}', type: 'YARA' }
      ]
    }
  ];
  const { entries, unsupportedIndicators, unsupportedBreakdown } = collectOtxEntries(pulses);
  assert.equal(entries.length, 1);
  assert.equal(unsupportedIndicators, 4);
  assert.equal(unsupportedBreakdown.CVE, 2);
  assert.equal(unsupportedBreakdown.email, 1);
  assert.equal(unsupportedBreakdown.YARA, 1);
});

test('collectOtxEntries counts allow-listed-but-invalid values as unsupported', () => {
  const pulses = [
    {
      id: 'p1', modified: '2026-06-20T00:00:00Z',
      indicators: [
        { indicator: 'deadbeef', type: 'FileHash-SHA256' }, // too short -> invalid
        { indicator: 'good.com', type: 'domain' }
      ]
    }
  ];
  const { entries, unsupportedIndicators, unsupportedBreakdown } = collectOtxEntries(pulses);
  assert.equal(entries.length, 1);
  assert.equal(unsupportedIndicators, 1);
  assert.equal(unsupportedBreakdown['FileHash-SHA256'], 1);
});

test('collectOtxEntries handles empty/missing indicators safely', () => {
  const { entries, fetchedIndicators, unsupportedIndicators } = collectOtxEntries([{ id: 'p1' }, {}]);
  assert.equal(entries.length, 0);
  assert.equal(fetchedIndicators, 0);
  assert.equal(unsupportedIndicators, 0);
});

// --- Initial lookback / cursor behavior ---
// Regression guard for the doom loop where no checkpoint meant every run fetched
// the entire OTX subscription history, always timing out before saving a cursor.

test('buildOtxSubscribedUrl omits modified_since when cursor is null (used for first-run before lookback)', () => {
  const url = buildOtxSubscribedUrl({ modifiedSince: null });
  assert.equal(new URL(url).searchParams.has('modified_since'), false);
});

test('buildOtxSubscribedUrl includes modified_since when cursor is provided', () => {
  const cursor = '2026-06-01T00:00:00.000Z';
  const url = buildOtxSubscribedUrl({ modifiedSince: cursor });
  assert.equal(new URL(url).searchParams.get('modified_since'), cursor);
});

test('buildOtxSubscribedUrl includes modified_since when initial lookback cursor is applied', () => {
  // Simulate the initial-lookback cursor (now - 30 days)
  const lookbackCursor = new Date(Date.now() - 30 * 86_400_000).toISOString();
  const url = buildOtxSubscribedUrl({ modifiedSince: lookbackCursor });
  assert.ok(new URL(url).searchParams.has('modified_since'), 'modified_since must be set to bound first run');
});

test('walkOtxSubscribedPulses sends modified_since when cursor supplied', async () => {
  let capturedUrl = null;
  const fetchFn = async (url) => {
    capturedUrl = url;
    return { ok: true, status: 200, text: async () => JSON.stringify({ count: 1, next: null, results: [] }) };
  };
  await walkOtxSubscribedPulses({ apiKey: 'k', modifiedSince: '2026-06-01T00:00:00.000Z', fetchFn, maxPages: 1 });
  assert.ok(capturedUrl.includes('modified_since='), 'URL must include modified_since');
});

test('walkOtxSubscribedPulses without cursor sends no modified_since (before lookback applied)', async () => {
  let capturedUrl = null;
  const fetchFn = async (url) => {
    capturedUrl = url;
    return { ok: true, status: 200, text: async () => JSON.stringify({ count: 1, next: null, results: [] }) };
  };
  await walkOtxSubscribedPulses({ apiKey: 'k', modifiedSince: null, fetchFn, maxPages: 1 });
  assert.equal(new URL(capturedUrl).searchParams.has('modified_since'), false);
});

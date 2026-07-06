import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isCacheFresh,
  isFilescanSupportedType,
  rowToApiPayload,
  fetchFilescanSearch,
  FILESCAN_PROVIDER
} from './filescanService.js';

// --- isCacheFresh ---

test('isCacheFresh returns false when no last_enriched_at', () => {
  assert.equal(isCacheFresh({}, { cache_ttl_hours: 24 }), false);
  assert.equal(isCacheFresh(null, { cache_ttl_hours: 24 }), false);
});

test('isCacheFresh returns true for recent success within TTL', () => {
  const recentAt = new Date(Date.now() - 1000 * 60 * 30).toISOString(); // 30 min ago
  const row = { last_enriched_at: recentAt, provider_status: 'success' };
  assert.equal(isCacheFresh(row, { cache_ttl_hours: 24 }), true);
});

test('isCacheFresh returns false for stale success beyond TTL', () => {
  const staleAt = new Date(Date.now() - 1000 * 60 * 60 * 25).toISOString(); // 25h ago
  const row = { last_enriched_at: staleAt, provider_status: 'success' };
  assert.equal(isCacheFresh(row, { cache_ttl_hours: 24 }), false);
});

test('isCacheFresh applies 1h cooldown for failed status', () => {
  const recentAt = new Date(Date.now() - 1000 * 60 * 30).toISOString();
  const row = { last_enriched_at: recentAt, provider_status: 'failed' };
  assert.equal(isCacheFresh(row, { cache_ttl_hours: 24 }), true); // within 1h
  const oldAt = new Date(Date.now() - 1000 * 60 * 61).toISOString();
  const oldRow = { last_enriched_at: oldAt, provider_status: 'failed' };
  assert.equal(isCacheFresh(oldRow, { cache_ttl_hours: 24 }), false); // beyond 1h
});

test('isCacheFresh force=true bypasses TTL when not in cooldown', () => {
  const recentAt = new Date(Date.now() - 1000 * 60 * 60 * 3).toISOString(); // 3h ago
  const row = { last_enriched_at: recentAt, provider_status: 'success', normalized_summary: {} };
  // force=true and no last_force_refresh_at → not in cooldown → should be refreshed
  assert.equal(isCacheFresh(row, { cache_ttl_hours: 24 }, { force: true }), false);
});

test('isCacheFresh force=true within 5min cooldown returns true (skip re-fetch)', () => {
  const recentAt = new Date(Date.now() - 1000 * 60 * 2).toISOString(); // 2 min ago
  const row = {
    last_enriched_at: recentAt,
    provider_status: 'success',
    normalized_summary: {
      last_force_refresh_at: new Date(Date.now() - 1000 * 60 * 2).toISOString()
    }
  };
  assert.equal(isCacheFresh(row, { cache_ttl_hours: 24 }, { force: true }), true);
});

// --- isFilescanSupportedType ---

test('isFilescanSupportedType returns true for supported types', () => {
  for (const t of ['hash', 'file_hash', 'md5', 'sha1', 'sha256', 'url', 'domain', 'hostname', 'ip', 'ipv4', 'ipv6', 'ip6']) {
    assert.equal(isFilescanSupportedType(t), true, `${t} should be supported`);
  }
});

test('isFilescanSupportedType returns false for unsupported types', () => {
  assert.equal(isFilescanSupportedType('email'), false);
  assert.equal(isFilescanSupportedType('user_agent'), false);
  assert.equal(isFilescanSupportedType(''), false);
  assert.equal(isFilescanSupportedType(null), false);
});

// --- rowToApiPayload ---

test('rowToApiPayload returns not-enriched when row is null and no providerStatus', () => {
  const p = rowToApiPayload(null, { iocType: 'hash', iocValue: 'abc' });
  assert.equal(p.enriched, false);
  assert.equal(p.provider, FILESCAN_PROVIDER);
  assert.equal(p.ioc_type, 'hash');
  assert.equal(p.ioc_value, 'abc');
});

test('rowToApiPayload returns providerStatus payload when row is null with providerStatus', () => {
  const p = rowToApiPayload(null, { providerStatus: 'disabled', iocType: 'ip', iocValue: '1.2.3.4' });
  assert.equal(p.enriched, false);
  assert.equal(p.provider_status, 'disabled');
});

test('rowToApiPayload marks enriched=true for success row', () => {
  const row = {
    ioc_type: 'hash',
    ioc_value: 'abc',
    provider_status: 'success',
    normalized_summary: { found: true, verdict: 'malicious', report_count: 1 },
    error_message: null,
    last_enriched_at: new Date().toISOString()
  };
  const p = rowToApiPayload(row, { cached: true });
  assert.equal(p.enriched, true);
  assert.equal(p.cached, true);
  assert.equal(p.verdict, 'malicious');
});

// --- fetchFilescanSearch ---

test('fetchFilescanSearch passes X-Api-Key header when apiKey is provided', async () => {
  let capturedHeaders;
  const mockFetch = async (url, opts) => {
    capturedHeaders = opts.headers;
    return {
      ok: true,
      json: async () => ({ items: [], count: 0 })
    };
  };
  await fetchFilescanSearch('abc123', { apiKey: 'test-key', timeout_ms: 5000 }, { fetchImpl: mockFetch });
  assert.equal(capturedHeaders['X-Api-Key'], 'test-key');
});

test('fetchFilescanSearch omits X-Api-Key header when no apiKey', async () => {
  let capturedHeaders;
  const mockFetch = async (url, opts) => {
    capturedHeaders = opts.headers;
    return {
      ok: true,
      json: async () => ({ items: [], count: 0 })
    };
  };
  await fetchFilescanSearch('abc123', { apiKey: null, timeout_ms: 5000 }, { fetchImpl: mockFetch });
  assert.equal(capturedHeaders['X-Api-Key'], undefined);
});

test('fetchFilescanSearch throws auth error on 401', async () => {
  const mockFetch = async () => ({
    ok: false,
    status: 401,
    headers: { get: () => null }
  });
  await assert.rejects(
    () => fetchFilescanSearch('abc', { apiKey: 'bad-key', timeout_ms: 5000 }, { fetchImpl: mockFetch }),
    (err) => {
      assert.equal(err.code, 'auth');
      assert.equal(err.provider_status, 'auth_error');
      return true;
    }
  );
});

test('fetchFilescanSearch throws rate_limit error on 429', async () => {
  const mockFetch = async () => ({
    ok: false,
    status: 429,
    headers: { get: (h) => h === 'retry-after' ? '60' : null }
  });
  await assert.rejects(
    () => fetchFilescanSearch('abc', { apiKey: null, timeout_ms: 5000 }, { fetchImpl: mockFetch }),
    (err) => {
      assert.equal(err.code, 'rate_limit');
      assert.equal(err.provider_status, 'rate_limited');
      assert.equal(err.retryAfter, '60');
      return true;
    }
  );
});

test('fetchFilescanSearch URL-encodes the query parameter', async () => {
  let capturedUrl;
  const mockFetch = async (url, opts) => {
    capturedUrl = url;
    return { ok: true, json: async () => ({ items: [], count: 0 }) };
  };
  await fetchFilescanSearch('http://evil.com/path?x=1', { apiKey: null, timeout_ms: 5000 }, { fetchImpl: mockFetch });
  assert.ok(capturedUrl.includes('query='), 'URL must contain query param');
  assert.ok(!capturedUrl.includes(' '), 'URL must not contain spaces');
});

// --- IOC global status immutability (contract test) ---

test('normalizeFilescanResponse never touches ioc_items confidence or status fields', async () => {
  const { normalizeFilescanResponse } = await import('../lib/filescanEnrichment.js');
  const raw = {
    items: [{ id: '1', state: 'success', verdict: 'malicious', date: '2026-01-01', file: {}, scan_init: { id: 'f1' }, tags: [] }],
    count: 1
  };
  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: 'abc' });
  // These IOC-global fields must NOT exist in normalized output
  const forbiddenFields = ['status', 'threat_classification', 'confidence', 'override', 'analyst_override'];
  for (const f of forbiddenFields) {
    assert.equal(out[f], undefined, `Field "${f}" must not appear in enrichment output`);
  }
});

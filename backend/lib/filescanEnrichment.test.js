import test from 'node:test';
import assert from 'node:assert/strict';
import {
  maskApiKey,
  aggregateVerdict,
  verdictToConfidenceHint,
  normalizeFilescanResponse,
  filescanHttpError,
  normalizeFilescanCacheKey
} from './filescanEnrichment.js';

test('maskApiKey redacts API key', () => {
  assert.equal(maskApiKey('abcd1234efgh'), 'abcd********');
  assert.equal(maskApiKey('abcd'), '****');
  assert.equal(maskApiKey('ab'), '****');
  assert.equal(maskApiKey(''), null);
  assert.equal(maskApiKey(null), null);
});

test('maskApiKey never exposes full key', () => {
  const key = 'super-secret-api-key-12345';
  const masked = maskApiKey(key);
  assert.ok(masked !== key, 'masked key must not equal raw key');
  assert.ok(masked.includes('*'), 'masked key must contain asterisks');
  assert.ok(!masked.includes('secret'), 'masked key must not contain sensitive portion');
});

test('aggregateVerdict precedence', () => {
  assert.equal(aggregateVerdict(['no_threat', 'malicious', 'benign']), 'malicious');
  assert.equal(aggregateVerdict(['no_threat', 'suspicious', 'benign']), 'suspicious');
  assert.equal(aggregateVerdict(['benign', 'no_threat']), 'benign');
  assert.equal(aggregateVerdict(['no_threat']), 'no_threat');
  assert.equal(aggregateVerdict([]), 'unknown');
  assert.equal(aggregateVerdict(null), 'unknown');
});

test('verdictToConfidenceHint mapping', () => {
  assert.equal(verdictToConfidenceHint('malicious'), 'high');
  assert.equal(verdictToConfidenceHint('suspicious'), 'medium');
  assert.equal(verdictToConfidenceHint('benign'), 'low');
  assert.equal(verdictToConfidenceHint('no_threat'), 'low');
  assert.equal(verdictToConfidenceHint('unknown'), null);
  assert.equal(verdictToConfidenceHint(null), null);
});

test('normalizeFilescanResponse with successful hash lookup', () => {
  const raw = {
    items: [
      {
        id: 'item-1',
        state: 'success',
        verdict: 'malicious',
        date: '2026-07-06T10:00:00Z',
        file: { name: 'evil.exe', sha256: 'abc123', link: null },
        scan_init: { id: 'flow-1' },
        tags: [
          {
            source: 'SIGNAL',
            isRootTag: true,
            isMalwareFamilyTag: false,
            tag: { name: 'anti-debug', synonyms: [], descriptions: [], verdict: {} }
          }
        ]
      },
      {
        id: 'item-2',
        state: 'success',
        verdict: 'suspicious',
        date: '2026-07-05T08:00:00Z',
        file: { name: 'maybe.exe', sha256: 'def456', link: null },
        scan_init: { id: 'flow-2' },
        tags: []
      }
    ],
    count: 2,
    method: 'and'
  };

  const out = normalizeFilescanResponse(raw, { iocType: 'hash', iocValue: 'abc123' });

  assert.equal(out.provider, 'filescan');
  assert.equal(out.found, true);
  assert.equal(out.verdict, 'malicious');
  assert.equal(out.confidence_hint, 'high');
  assert.equal(out.report_count, 2);
  assert.equal(out.reports.length, 2);
  assert.equal(out.reports[0].report_id, 'item-1');
  assert.equal(out.reports[0].flow_id, 'flow-1');
  assert.equal(out.reports[0].verdict, 'malicious');
  assert.equal(out.reports[0].file_hash, 'abc123');
  assert.ok(out.reports[0].link.includes('flow-1'));
  assert.ok(Array.isArray(out.tags));
  assert.ok(out.tags.includes('anti-debug'));
  assert.equal(out.provider_status, 'success');
  assert.equal(out.raw_summary.count, 2);
  // Verify no raw_json field in normalized output (only raw_summary)
  assert.equal(out.raw_json, undefined);
});

test('normalizeFilescanResponse with empty result (not found)', () => {
  const raw = { items: [], count: 0, method: 'and' };
  const out = normalizeFilescanResponse(raw, { iocType: 'domain', iocValue: 'example.com' });

  assert.equal(out.found, false);
  assert.equal(out.verdict, 'unknown');
  assert.equal(out.confidence_hint, null);
  assert.equal(out.report_count, 0);
  assert.deepEqual(out.reports, []);
  assert.equal(out.provider_status, 'success');
});

test('normalizeFilescanResponse with URL IOC', () => {
  const raw = {
    items: [{
      id: 'url-item-1',
      state: 'success',
      verdict: 'no_threat',
      date: '2026-07-01T00:00:00Z',
      file: { name: null, sha256: null, link: 'http://example.com/path' },
      scan_init: { id: 'flow-url-1' },
      tags: []
    }],
    count: 1
  };
  const out = normalizeFilescanResponse(raw, { iocType: 'url', iocValue: 'http://example.com/path' });
  assert.equal(out.found, true);
  assert.equal(out.verdict, 'no_threat');
  assert.equal(out.confidence_hint, 'low');
  assert.equal(out.reports[0].file_link, 'http://example.com/path');
});

test('normalizeFilescanResponse with IP IOC', () => {
  const raw = { items: [], count: 0 };
  const out = normalizeFilescanResponse(raw, { iocType: 'ip', iocValue: '1.2.3.4' });
  assert.equal(out.ioc_type, 'ip');
  assert.equal(out.ioc_value, '1.2.3.4');
  assert.equal(out.found, false);
});

test('filescanHttpError auth', () => {
  const r401 = filescanHttpError(401);
  assert.equal(r401.provider_status, 'auth_error');
  assert.equal(r401.code, 'auth');
  const r403 = filescanHttpError(403);
  assert.equal(r403.provider_status, 'auth_error');
  assert.equal(r403.code, 'auth');
});

test('filescanHttpError rate limit', () => {
  const r = filescanHttpError(429);
  assert.equal(r.provider_status, 'rate_limited');
  assert.equal(r.code, 'rate_limit');
});

test('filescanHttpError 5xx', () => {
  const r = filescanHttpError(503);
  assert.equal(r.provider_status, 'provider_error');
  assert.equal(r.code, 'provider_error');
});

test('filescanHttpError other', () => {
  const r = filescanHttpError(400);
  assert.equal(r.provider_status, 'failed');
  assert.equal(r.code, 'http_error');
});

test('normalizeFilescanCacheKey is consistent and lowercased', () => {
  const k1 = normalizeFilescanCacheKey('hash', 'ABC123');
  const k2 = normalizeFilescanCacheKey('HASH', 'abc123');
  assert.equal(k1, k2);
  assert.ok(k1.startsWith('hash:'));
});

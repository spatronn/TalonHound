import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  isCacheFresh,
  enrichIocWithUrlscan,
  getUrlscanConfig,
  rowToApiPayload
} from './urlscanService.js';
import { URLSCAN_ASSESSMENT, validateUrlscanRequest } from '../lib/urlscanEnrichment.js';

function configRow(overrides = {}) {
  return {
    provider: 'urlscan',
    enabled: true,
    api_key: 'test-key-12345',
    ttl_hours: 24,
    timeout_ms: 8000,
    config: { lookback_days: 30, search_size: 10, detail_limit: 2, no_result_ttl_hours: 6 },
    ...overrides
  };
}

function mockPool({ config = configRow(), existing = null, onUpsert } = {}) {
  return {
    query: async (sql, params) => {
      if (/threat_intel_provider_configs/.test(sql) && /SELECT/.test(sql)) {
        return { rows: [config] };
      }
      if (/threat_intel_provider_configs/.test(sql) && /UPDATE/.test(sql)) {
        return { rows: [] };
      }
      if (/FROM ioc_enrichments/.test(sql) && /SELECT/.test(sql)) {
        return { rows: existing ? [existing] : [] };
      }
      if (/INSERT INTO ioc_enrichments/.test(sql)) {
        const row = {
          ioc_id: params[0],
          ioc_value: params[1],
          ioc_type: params[2],
          provider: 'urlscan',
          status: params[4],
          normalized_summary: JSON.parse(params[5]),
          raw_response: params[6] ? JSON.parse(params[6]) : null,
          error_message: params[7],
          fetched_at: params[8],
          expires_at: params[9]
        };
        if (onUpsert) onUpsert(row, params);
        return { rows: [row] };
      }
      return { rows: [] };
    }
  };
}

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
    arrayBuffer: async () => Buffer.from(JSON.stringify(body))
  };
}

test('missing API key returns not_configured without fetch', async () => {
  let fetchCalled = false;
  const pool = mockPool({ config: configRow({ api_key: null }) });
  // Also clear env
  const prev = process.env.URLSCAN_API_KEY;
  delete process.env.URLSCAN_API_KEY;
  try {
    const result = await enrichIocWithUrlscan(pool, {
      iocId: 1,
      iocValue: 'https://example.com/login',
      iocType: 'url',
      fetchImpl: async () => { fetchCalled = true; return jsonResponse({}); }
    });
    assert.equal(result.provider_status, 'not_configured');
    assert.equal(fetchCalled, false);
  } finally {
    if (prev !== undefined) process.env.URLSCAN_API_KEY = prev;
  }
});

test('unsupported hash type skips without external request', async () => {
  let fetchCalled = false;
  const pool = mockPool();
  const result = await enrichIocWithUrlscan(pool, {
    iocId: 1,
    iocValue: 'd41d8cd98f00b204e9800998ecf8427e',
    iocType: 'md5',
    fetchImpl: async () => { fetchCalled = true; return jsonResponse({}); }
  });
  assert.equal(result.skipped, true);
  assert.equal(result.provider_status, 'unsupported');
  assert.equal(fetchCalled, false);
});

test('private IP skipped without external request', async () => {
  let fetchCalled = false;
  const pool = mockPool();
  const result = await enrichIocWithUrlscan(pool, {
    iocId: 1,
    iocValue: '10.0.0.1',
    iocType: 'ip',
    fetchImpl: async () => { fetchCalled = true; return jsonResponse({}); }
  });
  assert.equal(result.provider_status, 'unsupported_private_ip');
  assert.equal(fetchCalled, false);
});

test('sensitive URL is stored as privacy_restricted without calling urlscan', async () => {
  let fetchCalled = false;
  const pool = mockPool();
  const result = await enrichIocWithUrlscan(pool, {
    iocId: 1,
    iocValue: 'https://example.com/path?access_token=abc',
    iocType: 'url',
    fetchImpl: async () => { fetchCalled = true; return jsonResponse({}); }
  });
  assert.equal(result.assessment, URLSCAN_ASSESSMENT.PRIVACY_RESTRICTED);
  assert.equal(result.row.status, 'skipped');
  assert.equal(fetchCalled, false);
});

test('empty search stores no_results and never submits a scan', async () => {
  const urls = [];
  const pool = mockPool();
  const result = await enrichIocWithUrlscan(pool, {
    iocId: 7,
    iocValue: 'https://example.com/never-scanned-xyz',
    iocType: 'url',
    fetchImpl: async (url, init) => {
      urls.push({ url: String(url), method: init.method });
      assert.equal(init.method, 'GET');
      assert.equal(validateUrlscanRequest(init.method, url).ok, true);
      assert.doesNotMatch(String(url), /\/api\/v1\/scan/);
      return jsonResponse({ results: [], total: 0 });
    }
  });
  assert.equal(result.assessment, URLSCAN_ASSESSMENT.NO_RESULTS);
  assert.equal(result.row.status, 'not_found');
  assert.equal(result.row.normalized_summary.evidence_assessment_label, 'No results');
  assert.equal(urls.length, 1);
  assert.match(urls[0].url, /\/api\/v1\/search/);
});

test('successful search with exact malicious match stores malicious_evidence', async () => {
  const uuid = '11111111-1111-4111-8111-111111111111';
  const pool = mockPool();
  const result = await enrichIocWithUrlscan(pool, {
    iocId: 3,
    iocValue: 'https://evil.example/login',
    iocType: 'url',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/search')) {
        return jsonResponse({
          total: 1,
          results: [{
            _id: uuid,
            task: { uuid, url: 'https://evil.example/login', time: '2024-06-01T00:00:00.000Z' },
            page: { url: 'https://evil.example/login', domain: 'evil.example', ip: '1.2.3.4' },
            verdicts: { malicious: true, score: 90, urlscan: { malicious: true, categories: ['phishing'] } }
          }]
        });
      }
      if (String(url).includes('/api/v1/result/')) {
        return jsonResponse({
          task: { uuid, url: 'https://evil.example/login', time: '2024-06-01T00:00:00.000Z' },
          page: { url: 'https://evil.example/login', domain: 'evil.example', ip: '1.2.3.4' },
          verdicts: { malicious: true, urlscan: { malicious: true, score: 90, categories: ['phishing'] } },
          lists: { ips: ['1.2.3.4'], domains: ['evil.example'] }
        });
      }
      throw new Error(`unexpected url ${url}`);
    }
  });
  assert.equal(result.assessment, URLSCAN_ASSESSMENT.MALICIOUS_EVIDENCE);
  assert.equal(result.row.normalized_summary.is_authoritative_verdict, false);
  assert.equal(result.row.normalized_summary.score_is_not_confidence, true);
  assert.equal(result.row.normalized_summary.exact_match_count, 1);
});

test('related contacted IP malicious does not mark IP as authoritative malicious', async () => {
  const uuid = '22222222-2222-4222-8222-222222222222';
  const pool = mockPool();
  const result = await enrichIocWithUrlscan(pool, {
    iocId: 4,
    iocValue: '8.8.8.8',
    iocType: 'ip',
    fetchImpl: async (url) => {
      if (String(url).includes('/api/v1/search')) {
        return jsonResponse({
          total: 1,
          results: [{
            _id: uuid,
            task: { uuid, url: 'https://victim.example/', time: '2024-06-01T00:00:00.000Z' },
            page: { url: 'https://victim.example/', domain: 'victim.example', ip: '9.9.9.9' },
            verdicts: { malicious: true, score: 95, urlscan: { malicious: true } }
          }]
        });
      }
      return jsonResponse({
        task: { uuid },
        page: { ip: '9.9.9.9' },
        verdicts: { malicious: true },
        lists: { ips: ['8.8.8.8', '9.9.9.9'] }
      });
    }
  });
  assert.equal(result.assessment, URLSCAN_ASSESSMENT.INSUFFICIENT_EVIDENCE);
  assert.equal(result.row.normalized_summary.scans[0].match_relation, 'contacted_ip');
});

test('cache hit prevents external fetch', async () => {
  let fetchCalled = false;
  const fresh = {
    ioc_id: 1,
    ioc_value: 'https://example.com/',
    ioc_type: 'url',
    status: 'success',
    normalized_summary: { evidence_assessment: 'no_malicious_evidence' },
    fetched_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600_000).toISOString()
  };
  const pool = mockPool({ existing: fresh });
  const config = await getUrlscanConfig(pool);
  assert.equal(isCacheFresh(fresh, config), true);
  const result = await enrichIocWithUrlscan(pool, {
    iocId: 1,
    iocValue: 'https://example.com/',
    iocType: 'url',
    fetchImpl: async () => { fetchCalled = true; return jsonResponse({}); }
  });
  assert.equal(result.cached, true);
  assert.equal(fetchCalled, false);
});

test('429 is stored as rate_limited', async () => {
  const pool = mockPool();
  const result = await enrichIocWithUrlscan(pool, {
    iocId: 9,
    iocValue: 'example.com',
    iocType: 'domain',
    fetchImpl: async () => ({
      ok: false,
      status: 429,
      headers: { get: (n) => (String(n).toLowerCase() === 'retry-after' ? '12' : null) },
      arrayBuffer: async () => Buffer.from('{}')
    })
  });
  assert.equal(result.provider_status, 'rate_limited');
  assert.equal(result.assessment, URLSCAN_ASSESSMENT.RATE_LIMITED);
});

const http403Result = JSON.parse(readFileSync(new URL('../lib/fixtures/urlscan-result-http403.json', import.meta.url), 'utf8'));
const SCAN_403 = '01a12594-300b-76cc-b97f-3b9e154c93fc';
const IOC_403 = 'https://video-remb-annulfr.com/?r=prime/';

// Search hit exactly as returned on a non-Pro plan: no verdicts in search results.
const http403SearchHit = {
  task: { visibility: 'public', method: 'api', domain: 'video-remb-annulfr.com', apexDomain: 'video-remb-annulfr.com', time: '2026-10-10T11:30:37.899Z', uuid: SCAN_403, url: IOC_403 },
  stats: { uniqIPs: 1, uniqCountries: 1, dataLength: 544, encodedDataLength: 945, requests: 2 },
  page: {
    country: 'US', server: 'Apache', ip: '45.74.61.10', mimeType: 'text/html', title: '403 Forbidden', url: IOC_403,
    tlsValidDays: 3650, tlsAgeDays: 54, tlsValidFrom: '2026-08-17T11:05:13.000Z', domain: 'video-remb-annulfr.com',
    apexDomain: 'video-remb-annulfr.com', asnname: 'AS-69HOST 69HOST LLC, US', asn: 'AS205397', tlsIssuer: 'blackhole.invalid', status: '403'
  },
  _id: SCAN_403,
  sort: [1791631837899, SCAN_403]
};

function recordingFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), method: init.method });
    assert.equal(init.method, 'GET');
    assert.equal(validateUrlscanRequest(init.method, url).ok, true);
    assert.doesNotMatch(String(url), /\/api\/v1\/scan/);
    for (const [re, body] of routes) {
      if (re.test(String(url))) return jsonResponse(typeof body === 'function' ? body(String(url)) : body);
    }
    throw new Error(`unexpected url ${url}`);
  };
  return { calls, fetchImpl };
}

test('target 403 scan end-to-end: unclassified + limited visibility, engine signal is insufficient evidence, 1 search + 1 result', async () => {
  let stored;
  const pool = mockPool({ onUpsert: (row) => { stored = row; } });
  const { calls, fetchImpl } = recordingFetch([
    [/\/api\/v1\/search/, { results: [http403SearchHit], total: 1, has_more: false, search_date_limit_days: 90 }],
    [/\/api\/v1\/result\//, http403Result]
  ]);
  const result = await enrichIocWithUrlscan(pool, { iocId: 3606863, iocValue: IOC_403, iocType: 'url', fetchImpl });
  assert.equal(calls.length, 2);
  assert.equal(calls.filter((c) => /\/search/.test(c.url)).length, 1);
  assert.equal(calls.filter((c) => /\/result\//.test(c.url)).length, 1);

  const s = stored.normalized_summary;
  assert.equal(s.summary_version, 2);
  assert.equal(s.primary_scan_id, SCAN_403);
  assert.equal(s.classification.state, 'unclassified');
  assert.equal(s.classification.label, 'Unclassified');
  assert.ok(s.observations.some((o) => o.label === 'Limited page visibility — HTTP 403 Forbidden'));
  assert.ok(s.observations.some((o) => o.code === 'engine_signal_conflict'));
  // The overall verdict is not malicious; the ML engine flag is a signal, not "no malicious evidence".
  assert.equal(s.scans[0].malicious, false);
  assert.equal(s.scans[0].engine_malicious, true);
  assert.equal(s.scans[0].page_status, '403');
  assert.equal(s.malicious_scan_count, 0);
  assert.equal(result.assessment, URLSCAN_ASSESSMENT.INSUFFICIENT_EVIDENCE);
  assert.equal(s.is_authoritative_verdict, false);
  assert.equal(s.history.compared_scans, 1);
  assert.equal(s.history.changed.primary_ip, false);
  assert.ok(JSON.stringify(s).length < 32 * 1024, 'stored summary stays bounded');
  assert.doesNotMatch(JSON.stringify(stored), /test-key-12345/, 'API key never persisted');
});

test('Result API overall.malicious marks the scan malicious (search hit had no verdicts)', async () => {
  const uuid = '44444444-4444-4444-8444-444444444444';
  const pool = mockPool();
  const { fetchImpl } = recordingFetch([
    [/\/api\/v1\/search/, { total: 1, results: [{ _id: uuid, task: { uuid, url: 'https://phish.example/login', time: '2026-10-01T00:00:00.000Z' }, page: { url: 'https://phish.example/login', domain: 'phish.example', ip: '203.0.113.5', status: '200' } }] }],
    [/\/api\/v1\/result\//, {
      task: { uuid, url: 'https://phish.example/login', time: '2026-10-01T00:00:00.000Z' },
      page: { url: 'https://phish.example/login', domain: 'phish.example', ip: '203.0.113.5', status: '200', title: 'Sign in' },
      verdicts: {
        overall: { score: 100, categories: ['phishing'], brands: [{ key: 'msft', name: 'Microsoft' }], malicious: true, hasVerdicts: true },
        urlscan: { score: 100, categories: ['phishing'], malicious: true, hasVerdicts: true },
        engines: { score: 0, malicious: false, hasVerdicts: false },
        community: { score: 0, malicious: false, hasVerdicts: false }
      }
    }]
  ]);
  const result = await enrichIocWithUrlscan(pool, { iocId: 5, iocValue: 'https://phish.example/login', iocType: 'url', fetchImpl });
  assert.equal(result.assessment, URLSCAN_ASSESSMENT.MALICIOUS_EVIDENCE);
  const s = result.row.normalized_summary;
  assert.equal(s.scans[0].malicious, true);
  assert.equal(s.scans[0].urlscan_score, 100);
  assert.deepEqual(s.scans[0].categories, ['phishing']);
  assert.equal(s.classification.state, 'malicious');
  assert.deepEqual(s.classification.brands, ['Microsoft']);
});

test('Result API detail fetches stay bounded by detail_limit (no N+1 over the search sample)', async () => {
  const pool = mockPool();
  const ids = Array.from({ length: 10 }, (_, i) => `55555555-5555-4555-8555-${String(i).padStart(12, '0')}`);
  const { calls, fetchImpl } = recordingFetch([
    [/\/api\/v1\/search/, { total: 10, results: ids.map((id, i) => ({ _id: id, task: { uuid: id, url: 'https://many.example/', time: `2026-10-0${(i % 9) + 1}T00:00:00.000Z` }, page: { url: 'https://many.example/', domain: 'many.example', ip: '203.0.113.9' } })) }],
    [/\/api\/v1\/result\//, (url) => ({ task: { uuid: url.match(/result\/([^/]+)/)[1], url: 'https://many.example/' }, page: { url: 'https://many.example/' } })]
  ]);
  const result = await enrichIocWithUrlscan(pool, { iocId: 6, iocValue: 'https://many.example/', iocType: 'url', fetchImpl });
  // configRow detail_limit = 2
  assert.equal(calls.filter((c) => /\/result\//.test(c.url)).length, 2);
  assert.equal(calls.length, 3);
  assert.equal(result.row.normalized_summary.history.compared_scans, 10);
});

test('legacy v1 cached rows are served unchanged (no forced refresh, no crash)', () => {
  const legacy = {
    ioc_id: 1,
    ioc_value: IOC_403,
    ioc_type: 'url',
    status: 'success',
    normalized_summary: {
      evidence_assessment: 'no_malicious_evidence',
      evidence_assessment_label: 'No malicious evidence observed',
      scans: [{ scan_id: SCAN_403, page_title: '403 Forbidden', malicious: false }],
      detail_scans: [{ scan_id: SCAN_403, page_status: '403', overall_malicious: false }]
    },
    fetched_at: '2026-10-10T11:43:09.743Z'
  };
  const payload = rowToApiPayload(legacy, { cached: true, iocId: 1 });
  assert.equal(payload.summary.summary_version, undefined);
  assert.equal(payload.summary.detail_scans[0].page_status, '403');
  assert.equal(payload.is_authoritative_verdict, false);
});

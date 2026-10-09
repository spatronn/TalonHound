import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isCacheFresh,
  enrichIocWithUrlscan,
  getUrlscanConfig
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

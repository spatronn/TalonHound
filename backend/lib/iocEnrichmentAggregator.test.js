import test from 'node:test';
import assert from 'node:assert/strict';
import { collectIocEnrichments } from './iocEnrichmentAggregator.js';
import { buildVirusTotalNotFoundMessage } from './virustotalEnrichment.js';

const STALE_URL =
  'VirusTotal has no report for this URL yet. The URL may not have been submitted or indexed.';

function makePool(enrichmentRows) {
  return {
    query: async (sql) => {
      if (String(sql).includes('FROM ioc_enrichments')) {
        return { rows: enrichmentRows };
      }
      // Optional provider tables: empty / missing is fine for these tests.
      throw Object.assign(new Error('relation does not exist'), { code: '42P01' });
    }
  };
}

test('collectIocEnrichments self-heals VT not_found messages by ioc_type matrix', async () => {
  const matrix = [
    ['sha256', 'file hash'],
    ['sha1', 'file hash'],
    ['md5', 'file hash'],
    ['hash', 'file hash'],
    ['file', 'file hash'],
    ['file_hash', 'file hash'],
    ['url', 'URL'],
    ['domain', 'domain'],
    ['ip', 'IP address'],
    ['ipv4', 'IP address'],
    ['ipv6', 'IP address'],
    ['ip_address', 'IP address'],
    ['ip-address', 'IP address'],
    ['unknown', 'indicator']
  ];

  for (const [iocType, label] of matrix) {
    const pool = makePool([{
      provider: 'virustotal',
      status: 'not_found',
      ioc_type: iocType,
      normalized_summary: null,
      fetched_at: '2026-09-06T00:00:00.000Z',
      expires_at: '2026-09-07T00:00:00.000Z',
      error_message: STALE_URL
    }]);
    const entries = await collectIocEnrichments(pool, {
      iocId: 1,
      type: iocType,
      value: 'x'
    });
    assert.equal(entries.length, 1, iocType);
    assert.equal(entries[0].status, 'not_found', iocType);
    assert.equal(
      entries[0].error_message,
      `VirusTotal has no report for this ${label} yet. The ${label} may not have been submitted or indexed.`,
      iocType
    );
    assert.equal(entries[0].error_message, buildVirusTotalNotFoundMessage(iocType), iocType);
  }
});

test('collectIocEnrichments self-heals URL web_analysis from raw_response', async () => {
  const sha = '235195e7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaacd04f3e1';
  const pool = makePool([{
    provider: 'virustotal',
    status: 'success',
    ioc_type: 'url',
    normalized_summary: {
      provider: 'virustotal',
      ioc_type: 'url',
      ioc_value: 'https://example.invalid/phish',
      stats: { malicious: 3, suspicious: 1, harmless: 0, undetected: 0, timeout: 0 },
      detection_ratio: { detected: 4, total: 4 }
    },
    raw_response: {
      data: {
        attributes: {
          targeted_brand: { PhishTank: 'Allegro' },
          tags: ['password-input', 'iframes'],
          last_http_response_content_sha256: sha,
          last_http_response_code: 200,
          last_http_response_headers: { server: 'cloudflare', 'set-cookie': 'session=SECRET' },
          outgoing_links: Array.from({ length: 30 }, (_, i) => `https://out.example/${i}`),
          cookies: [{ value: 'SECRET' }]
        }
      }
    },
    fetched_at: '2026-09-07T00:00:00.000Z',
    expires_at: null,
    error_message: null
  }]);
  const entries = await collectIocEnrichments(pool, {
    iocId: 1,
    type: 'url',
    value: 'https://example.invalid/phish'
  });
  const wa = entries[0].summary.web_analysis;
  assert.equal(wa.targeted_brand.value, 'Allegro');
  assert.deepEqual(wa.behavior_tags, ['password-input', 'iframes']);
  assert.equal(wa.content_sha256, sha);
  assert.equal(wa.http.server, 'cloudflare');
  assert.equal(wa.outgoing_links.truncated, true);
  assert.ok(wa.outgoing_links.items.length <= 20);
  // Existing VT fields preserved.
  assert.equal(entries[0].summary.stats.malicious, 3);
  assert.equal(JSON.stringify(wa).includes('SECRET'), false);
});

test('collectIocEnrichments does not invent web_analysis for hash VT rows', async () => {
  const pool = makePool([{
    provider: 'virustotal',
    status: 'success',
    ioc_type: 'sha256',
    normalized_summary: {
      provider: 'virustotal',
      ioc_type: 'sha256',
      stats: { malicious: 1, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 }
    },
    raw_response: {
      data: { attributes: { tags: ['password-input'], targeted_brand: { PhishTank: 'X' } } }
    },
    fetched_at: null,
    expires_at: null,
    error_message: null
  }]);
  const entries = await collectIocEnrichments(pool, { iocId: 1, type: 'sha256', value: 'a'.repeat(64) });
  assert.equal(entries[0].summary.web_analysis, undefined);
});

  const msg = 'VirusTotal rate limit reached. Try again later.';
  const pool = makePool([{
    provider: 'virustotal',
    status: 'error',
    ioc_type: 'sha256',
    normalized_summary: null,
    fetched_at: null,
    expires_at: null,
    error_message: msg
  }]);
  const entries = await collectIocEnrichments(pool, { iocId: 1, type: 'sha256', value: 'x' });
  assert.equal(entries[0].error_message, msg);
});

test('collectIocEnrichments does not rewrite non-VirusTotal error_message', async () => {
  const msg = 'some other provider error';
  const pool = makePool([{
    provider: 'other',
    status: 'not_found',
    ioc_type: 'sha256',
    normalized_summary: null,
    fetched_at: null,
    expires_at: null,
    error_message: msg
  }]);
  const entries = await collectIocEnrichments(pool, { iocId: 1, type: 'sha256', value: 'x' });
  assert.equal(entries[0].error_message, msg);
});

test('collectIocEnrichments reuses a VT success across exact-hash aliases (one VT entry, success preferred)', async () => {
  // Canonical SHA256 (id 100) has no VT row; the SHA1 alias (id 200) holds a success.
  const pool = makePool([
    { provider: 'virustotal', status: 'not_found', ioc_type: 'sha256', normalized_summary: null,
      fetched_at: '2026-09-01T00:00:00.000Z', expires_at: null, error_message: null },
    { provider: 'virustotal', status: 'success', ioc_type: 'sha1',
      normalized_summary: { file: { sha256: 'a', sha1: 'b', md5: 'c' } },
      fetched_at: '2026-09-07T00:00:00.000Z', expires_at: null, error_message: null }
  ]);
  const entries = await collectIocEnrichments(pool, {
    iocId: 100, type: 'sha256', value: 'a', linkedIocIds: [100, 200]
  });
  const vt = entries.filter((e) => e.provider === 'virustotal');
  assert.equal(vt.length, 1, 'exactly one VirusTotal entry after dedup');
  assert.equal(vt[0].status, 'success', 'success is preferred over not_found');
  assert.ok(vt[0].summary && vt[0].summary.file, 'the successful summary is surfaced');
});

test('collectIocEnrichments dedup prefers freshest when statuses tie', async () => {
  const pool = makePool([
    { provider: 'virustotal', status: 'success', ioc_type: 'sha256', normalized_summary: { v: 'old' },
      fetched_at: '2026-09-01T00:00:00.000Z', expires_at: null, error_message: null },
    { provider: 'virustotal', status: 'success', ioc_type: 'sha1', normalized_summary: { v: 'new' },
      fetched_at: '2026-09-07T00:00:00.000Z', expires_at: null, error_message: null }
  ]);
  const entries = await collectIocEnrichments(pool, { iocId: 100, type: 'sha256', value: 'a', linkedIocIds: [100, 200] });
  const vt = entries.filter((e) => e.provider === 'virustotal');
  assert.equal(vt.length, 1);
  assert.equal(vt[0].summary.v, 'new');
});

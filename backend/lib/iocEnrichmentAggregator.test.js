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

test('collectIocEnrichments leaves non-not_found VT error_message unchanged', async () => {
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

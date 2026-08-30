import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createUsomApiClient,
  createUsomRunDetails,
  UsomApiError
} from './usomOfficialApi.js';

function response(payload, status = 200, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (key) => headers[String(key).toLowerCase()] ?? null },
    json: async () => {
      if (payload instanceof Error) throw payload;
      return payload;
    }
  };
}

function page({ totalCount, models, page, pageCount }) {
  return { totalCount, count: models.length, models, page, pageCount };
}

test('rejects third-party API bridges and credential-bearing base URLs', () => {
  assert.throws(
    () => createUsomApiClient({ baseUrl: 'https://example.net/usom' }),
    /official/
  );
  assert.throws(
    () => createUsomApiClient({ baseUrl: 'https://user:secret@siberguvenlik.gov.tr/api' }),
    /official/
  );
});

test('walkPages supports one page and the live API response offset', async () => {
  const client = createUsomApiClient({
    fetchFn: async () => response(page({
      totalCount: 1,
      models: [{ id: 1 }],
      page: 0,
      pageCount: 1
    })),
    requestDelayMs: 0
  });
  const pages = [];
  const result = await client.walkPages('/address/index', { type: 'domain' }, { request_count: 0, retry_count: 0, rate_limit_count: 0 }, null, async (models) => {
    pages.push(models);
  });
  assert.equal(result.totalCount, 1);
  assert.equal(result.pages, 1);
  assert.equal(pages.length, 1);
});

test('walkPages fetches every page without repeating progress', async () => {
  const requested = [];
  const client = createUsomApiClient({
    fetchFn: async (url) => {
      const requestPage = Number(url.searchParams.get('page'));
      requested.push(requestPage);
      return response(page({
        totalCount: 3,
        models: [{ id: requestPage }],
        page: requestPage - 1,
        pageCount: 3
      }));
    },
    sleepFn: async () => {},
    requestDelayMs: 0
  });
  const result = await client.walkPages('/address/index', { type: 'domain' }, { request_count: 0, retry_count: 0, rate_limit_count: 0 }, null, async () => {});
  assert.deepEqual(requested, [1, 2, 3]);
  assert.equal(result.rawCount, 3);
});

test('walkPages accepts a legitimate empty feed', async () => {
  const client = createUsomApiClient({
    fetchFn: async () => response(page({ totalCount: 0, models: [], page: 0, pageCount: 0 })),
    requestDelayMs: 0
  });
  const result = await client.walkPages('/address/index', { type: 'ip6net' }, { request_count: 0, retry_count: 0, rate_limit_count: 0 }, null, async () => {});
  assert.equal(result.totalCount, 0);
  assert.equal(result.pages, 1);
});

test('walkPages rejects missing pageCount and malformed JSON', async () => {
  const missing = createUsomApiClient({
    fetchFn: async () => response({ totalCount: 0, count: 0, models: [], page: 0 }),
    maxRetries: 0,
    requestDelayMs: 0
  });
  await assert.rejects(
    missing.walkPages('/address/index', {}, { request_count: 0, retry_count: 0, rate_limit_count: 0 }, null, async () => {}),
    (err) => err instanceof UsomApiError && err.code === 'invalid_schema'
  );

  const malformed = createUsomApiClient({
    fetchFn: async () => response(new SyntaxError('bad JSON')),
    maxRetries: 0,
    requestDelayMs: 0
  });
  await assert.rejects(
    malformed.walkPages('/address/index', {}, { request_count: 0, retry_count: 0, rate_limit_count: 0 }, null, async () => {}),
    (err) => err.code === 'malformed_json'
  );
});

test('walkPages rejects repeated or mismatched response pages', async () => {
  const client = createUsomApiClient({
    fetchFn: async () => response(page({ totalCount: 2, models: [{ id: 1 }], page: 0, pageCount: 2 })),
    sleepFn: async () => {},
    requestDelayMs: 0
  });
  await assert.rejects(
    client.walkPages('/address/index', {}, { request_count: 0, retry_count: 0, rate_limit_count: 0 }, null, async () => {}),
    (err) => ['pagination_stalled', 'pagination_mismatch'].includes(err.code)
  );
});

test('full reconciliation can finish conservatively when pagination totals change', async () => {
  const payloads = [
    page({ totalCount: 2, models: [{ id: 1 }], page: 0, pageCount: 2 }),
    page({ totalCount: 3, models: [{ id: 2 }, { id: 3 }], page: 1, pageCount: 2 })
  ];
  const client = createUsomApiClient({
    fetchFn: async () => response(payloads.shift()),
    requestDelayMs: 0
  });
  const result = await client.walkPages(
    '/address/index',
    {},
    { request_count: 0, retry_count: 0, rate_limit_count: 0 },
    null,
    async () => {},
    { allowPaginationChanges: true }
  );
  assert.equal(result.rawCount, 3);
  assert.equal(result.paginationStable, false);
});

test('retries 429 using Retry-After before succeeding', async () => {
  let calls = 0;
  const delays = [];
  const stats = { request_count: 0, retry_count: 0, rate_limit_count: 0 };
  const client = createUsomApiClient({
    fetchFn: async () => {
      calls += 1;
      if (calls === 1) return response({}, 429, { 'retry-after': '2' });
      return response(page({ totalCount: 0, models: [], page: 0, pageCount: 0 }));
    },
    sleepFn: async (ms) => delays.push(ms),
    requestDelayMs: 0
  });
  await client.walkPages('/address/index', {}, stats, null, async () => {});
  assert.equal(calls, 2);
  assert.equal(stats.retry_count, 1);
  assert.equal(stats.rate_limit_count, 1);
  assert.deepEqual(delays, [2000]);
});

test('retries HTTP 500 and timeout-like network errors', async () => {
  for (const first of [
    () => response({}, 500),
    () => { throw Object.assign(new Error('timed out'), { name: 'TimeoutError', code: 'ETIMEDOUT' }); }
  ]) {
    let calls = 0;
    const client = createUsomApiClient({
      fetchFn: async () => {
        calls += 1;
        if (calls === 1) return first();
        return response(page({ totalCount: 0, models: [], page: 0, pageCount: 0 }));
      },
      sleepFn: async () => {},
      randomFn: () => 0,
      requestDelayMs: 0
    });
    await client.walkPages('/address/index', {}, { request_count: 0, retry_count: 0, rate_limit_count: 0 }, null, async () => {});
    assert.equal(calls, 2);
  }
});

test('retries transient malformed or schema-invalid success payloads', async () => {
  for (const first of [
    () => response({ models: [], totalCount: null, count: 0, page: 0, pageCount: 0 }),
    () => ({ ok: true, status: 200, headers: new Headers(), json: async () => { throw new Error('bad json'); } })
  ]) {
    let calls = 0;
    const stats = { request_count: 0, retry_count: 0, rate_limit_count: 0 };
    const client = createUsomApiClient({
      fetchFn: async () => {
        calls += 1;
        return calls === 1
          ? first()
          : response(page({ totalCount: 0, models: [], page: 0, pageCount: 0 }));
      },
      sleepFn: async () => {},
      randomFn: () => 0,
      requestDelayMs: 0
    });
    await client.walkPages('/address/index', { type: 'domain' }, stats, null, async () => {});
    assert.equal(calls, 2);
    assert.equal(stats.retry_count, 1);
  }
});

test('does not retry permanent HTTP 400', async () => {
  let calls = 0;
  const client = createUsomApiClient({
    fetchFn: async () => {
      calls += 1;
      return response({}, 400);
    },
    sleepFn: async () => {},
    requestDelayMs: 0
  });
  await assert.rejects(
    client.walkPages('/address/index', {}, { request_count: 0, retry_count: 0, rate_limit_count: 0 }, null, async () => {}),
    (err) => err.statusCode === 400 && err.retryable === false
  );
  assert.equal(calls, 1);
});

test('lookup failures are optional and IOC collection continues', async () => {
  const client = createUsomApiClient({
    fetchFn: async (url) => {
      if (url.pathname.includes('address-description')) return response({}, 400);
      if (url.pathname.includes('address-source') || url.pathname.includes('address-connection-type')) {
        return response(page({ totalCount: 0, models: [], page: 0, pageCount: 0 }));
      }
      return response(page({
        totalCount: 1,
        models: [{ id: 1, url: 'example.com', type: 'domain' }],
        page: 0,
        pageCount: 1
      }));
    },
    sleepFn: async () => {},
    requestDelayMs: 0,
    logger: { warn() {} }
  });
  const batches = [];
  const { stats } = await client.collect({
    types: ['domain'],
    onEntries: async (entries) => batches.push(entries)
  });
  assert.equal(stats.lookup_refresh_failed, 1);
  assert.equal(stats.lookup_refresh_success, 2);
  assert.equal(batches[0][0].observable, 'example.com');
});

test('incremental collection uses inclusive overlap, fixed upper bound and tuple highwater', async () => {
  const addressUrls = [];
  const runStartedAt = new Date('2026-07-20T12:00:00.000Z');
  const client = createUsomApiClient({
    fetchFn: async (url) => {
      if (!url.pathname.endsWith('/address/index')) {
        return response(page({ totalCount: 0, models: [], page: 0, pageCount: 0 }));
      }
      addressUrls.push(url);
      return response(page({
        totalCount: 2,
        models: [
          { id: 9, type: 'domain', url: 'a.example', date: '2026-07-20 10:00:00' },
          { id: 10, type: 'domain', url: 'b.example', date: '2026-07-20 10:00:00' }
        ],
        page: 0,
        pageCount: 1
      }));
    },
    requestDelayMs: 0,
    cursorOverlapHours: 24
  });
  const result = await client.collect({
    types: ['domain'],
    mode: 'incremental',
    runStartedAt,
    cursors: {
      domain: { timestamp: '2026-07-20T10:00:00.000Z', providerId: '9' }
    }
  });
  assert.equal(addressUrls[0].searchParams.get('date_gte'), '2026-07-19T10:00:00.000Z');
  assert.equal(addressUrls[0].searchParams.get('date_lte'), runStartedAt.toISOString());
  assert.deepEqual(result.highwaters.domain, {
    timestamp: '2026-07-20T10:00:00.000Z',
    providerId: '10'
  });
});

test('incremental highwater never regresses and empty responses do not advance it', async () => {
  let models = [{ id: 1, type: 'domain', url: 'old.example', date: '2026-07-19 10:00:00' }];
  const client = createUsomApiClient({
    fetchFn: async (url) => url.pathname.endsWith('/address/index')
      ? response(page({ totalCount: models.length, models, page: 0, pageCount: models.length ? 1 : 0 }))
      : response(page({ totalCount: 0, models: [], page: 0, pageCount: 0 })),
    requestDelayMs: 0
  });
  const options = {
    types: ['domain'],
    mode: 'incremental',
    runStartedAt: new Date('2026-07-21T12:00:00.000Z'),
    cursors: { domain: { timestamp: '2026-07-20T10:00:00.000Z', providerId: '5' } }
  };
  const replay = await client.collect(options);
  assert.equal(Object.hasOwn(replay.highwaters, 'domain'), false);
  models = [];
  const empty = await client.collect(options);
  assert.equal(Object.hasOwn(empty.highwaters, 'domain'), false);
});

test('rejects future cursors and provider responses that ignore filters', async () => {
  const client = createUsomApiClient({
    fetchFn: async (url) => url.pathname.endsWith('/address/index')
      ? response(page({
          totalCount: 1,
          models: [{ id: 1, type: 'url', url: 'https://example.com', date: '2026-07-20 10:00:00' }],
          page: 0,
          pageCount: 1
        }))
      : response(page({ totalCount: 0, models: [], page: 0, pageCount: 0 })),
    requestDelayMs: 0
  });
  await assert.rejects(client.collect({
    types: ['domain'],
    mode: 'incremental',
    runStartedAt: new Date('2026-07-20T12:00:00.000Z'),
    cursors: { domain: { timestamp: '2026-07-21T00:00:00.000Z', providerId: '1' } }
  }), (err) => err.code === 'future_cursor');
  await assert.rejects(client.collect({
    types: ['domain'],
    mode: 'incremental',
    runStartedAt: new Date('2026-07-20T12:00:00.000Z'),
    cursors: { domain: { timestamp: '2026-07-20T09:00:00.000Z', providerId: '1' } }
  }), (err) => err.code === 'filter_ignored');
});

test('uses fresh durable lookup cache without network refresh', async () => {
  let calls = 0;
  const client = createUsomApiClient({
    fetchFn: async () => {
      calls += 1;
      throw new Error('should not fetch');
    },
    requestDelayMs: 0
  });
  const now = new Date('2026-07-20T12:00:00.000Z');
  const cacheEntry = {
    rows: [{ id: 'PH', tr_title: 'Oltalama' }],
    updatedAt: new Date(now.getTime() - 60_000).toISOString()
  };
  const stats = createUsomRunDetails();
  const lookups = await client.refreshLookups(stats, null, {
    now,
    lookupCache: {
      descriptions: cacheEntry,
      sources: cacheEntry,
      connectionTypes: cacheEntry
    }
  });
  assert.equal(calls, 0);
  assert.equal(stats.lookup_cache_fresh, 3);
  assert.equal(lookups.descriptions.get('PH').tr_title, 'Oltalama');
});

test('falls back to stale lookup cache when refresh fails', async () => {
  const client = createUsomApiClient({
    fetchFn: async () => response({}, 400),
    requestDelayMs: 0,
    logger: { warn() {} }
  });
  const stats = createUsomRunDetails();
  const stale = {
    rows: [{ id: 'PH', en_title: 'Phishing' }],
    updatedAt: '2026-07-01T00:00:00.000Z',
    lastModified: 'Wed, 01 Jul 2026 00:00:00 GMT'
  };
  const lookups = await client.refreshLookups(stats, null, {
    now: new Date('2026-07-20T12:00:00.000Z'),
    lookupCache: {
      descriptions: stale,
      sources: stale,
      connectionTypes: stale
    }
  });
  assert.equal(stats.lookup_cache_stale_fallback, 3);
  assert.equal(lookups.sources.get('PH').en_title, 'Phishing');
});

test('revalidates stale lookup cache with Last-Modified and accepts 304', async () => {
  const seenHeaders = [];
  const persisted = [];
  const client = createUsomApiClient({
    fetchFn: async (_url, init) => {
      seenHeaders.push(init.headers);
      return response(null, 304, { 'last-modified': 'Tue, 21 Jul 2026 10:00:00 GMT' });
    },
    requestDelayMs: 0
  });
  const stale = {
    rows: [{ id: 'PH', en_title: 'Phishing' }],
    updatedAt: '2026-07-01T00:00:00.000Z',
    lastModified: 'Mon, 20 Jul 2026 10:00:00 GMT'
  };
  const stats = createUsomRunDetails();
  const lookups = await client.refreshLookups(stats, null, {
    now: new Date('2026-07-21T12:00:00.000Z'),
    lookupCache: {
      descriptions: stale,
      sources: stale,
      connectionTypes: stale
    },
    persistLookup: async (group, value) => persisted.push({ group, value })
  });
  assert.equal(seenHeaders[0]['If-Modified-Since'], stale.lastModified);
  assert.equal(stats.lookup_cache_not_modified, 3);
  assert.equal(persisted.length, 3);
  assert.equal(lookups.connectionTypes.get('PH').en_title, 'Phishing');
});

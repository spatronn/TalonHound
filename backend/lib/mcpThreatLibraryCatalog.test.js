/**
 * MCP threat_library_list_reports / threat_library_check_report_urls — unit
 * level (no database): input parsing, cursor binding, URL identity, ambiguity,
 * ordering of batch answers, authorization and the read-only SQL contract.
 * Real-PostgreSQL ordering / day boundaries / paging live in
 * threatLibrary/reportCatalog.integration.test.js.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { registerMcpTools } from './mcpTools.js';
import { authorizeMcpTool, MCP_TOOL_SCOPES } from './mcpPermissions.js';
import { ACCESS_PROFILE, API_SCOPE, scopesForAccessProfile } from './apiKeyProfiles.js';
import {
  parseCatalogBound,
  parseCatalogQuery,
  listReportCatalog,
  checkReportUrls,
  serializeCatalogReport,
  CatalogInputError,
  CATALOG_URL_CHECK_MAX
} from './threatLibrary/reportCatalog.js';
import { canonicalizeReportUrl } from './threatLibrary/importIdentity.js';

const READ_SCOPES = scopesForAccessProfile(ACCESS_PROFILE.MCP_READ);
const CATALOG_TOOLS = ['threat_library_list_reports', 'threat_library_check_report_urls'];

let seq = 0;
function reportRow(over = {}) {
  seq += 1;
  return {
    id: seq,
    public_id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`,
    title: `Report ${seq}`,
    source_type: 'url',
    source_name: 'Example Labs',
    source_url: `https://example.com/r/${seq}`,
    source_url_canonical: `https://example.com/r/${seq}`,
    tlp: 'clear',
    import_status: 'ready',
    analysis_status: 'ready',
    failure_stage: null,
    failure_code: null,
    created_at: new Date('2026-10-30T10:00:00.000Z'),
    created_at_key: '2026-10-30T10:00:00.000123Z',
    finalized_at: new Date('2026-10-30T12:00:00.000Z'),
    published_at: null,
    published_at_key: null,
    published_at_precision: null,
    published_at_source: null,
    published_at_raw: null,
    ...over
  };
}

/** Records every statement; answers the catalog queries from `rows`. */
function recordingPool(rows = []) {
  const queries = [];
  return {
    queries,
    async query(sql, params) {
      queries.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params });
      if (/identity_match_count/.test(sql)) {
        const wanted = new Set(params[0]);
        const hits = rows.filter((r) => r.source_type === 'url' && wanted.has(r.source_url_canonical));
        return {
          rows: hits.map((r) => ({
            ...r,
            identity_match_count: hits.filter((h) => h.source_url_canonical === r.source_url_canonical).length
          }))
        };
      }
      if (/source_type <> 'url'/.test(sql)) {
        // Host prefilter of the stored source_url (the SQL extracts the authority host).
        const hosts = new Set(params[0]);
        return {
          rows: rows.filter((r) => {
            if (r.source_type === 'url' || !r.source_url) return false;
            try { return hosts.has(new URL(r.source_url.trim()).hostname); } catch { return false; }
          })
        };
      }
      return { rows };
    }
  };
}

async function callTool(pool, name, args, { scopes = READ_SCOPES, role = 'readonly' } = {}) {
  const tools = new Map();
  const req = {
    headers: {},
    authVia: 'mcp',
    user: { id: 9, role, username: 'agent' },
    mcpAuth: { scopes, ownerRole: role, apiKeyId: 5, apiKeyName: 'discovery-agent', keyType: ACCESS_PROFILE.MCP_READ }
  };
  registerMcpTools({ registerTool: (n, def, handler) => tools.set(n, { def, handler }) }, {
    pool,
    getRequestContext: () => ({ req })
  });
  const res = await tools.get(name).handler(args);
  return { res, data: res.structuredContent, error: res.isError ? res.structuredContent.error : null };
}

// ---------------------------------------------------------------------------
// Discovery + authorization
// ---------------------------------------------------------------------------

test('both catalog tools are discoverable, read-only annotated and need only mcp:ioc:read', () => {
  const tools = new Map();
  registerMcpTools({ registerTool: (n, def) => tools.set(n, def) }, {
    pool: recordingPool(),
    getRequestContext: () => ({})
  });
  for (const name of CATALOG_TOOLS) {
    const def = tools.get(name);
    assert.ok(def, `${name} registered`);
    assert.equal(def.annotations.readOnlyHint, true);
    assert.equal(def.annotations.destructiveHint, false);
    assert.match(def.description, /Read-only/);
    assert.deepEqual(MCP_TOOL_SCOPES[name], [API_SCOPE.MCP_IOC_READ]);
  }
  assert.deepEqual(Object.keys(tools.get('threat_library_list_reports').inputSchema).sort(), [
    'cursor', 'import_status', 'imported_from', 'imported_to', 'limit', 'published_from',
    'published_to', 'publisher', 'review_phase', 'sort'
  ]);
  assert.deepEqual(Object.keys(tools.get('threat_library_check_report_urls').inputSchema), ['urls']);
  // Schema bounds: 100 URLs, limit 200.
  const urls = tools.get('threat_library_check_report_urls').inputSchema.urls;
  assert.equal(urls.safeParse(Array(CATALOG_URL_CHECK_MAX).fill('https://a.example/x')).success, true);
  assert.equal(urls.safeParse(Array(CATALOG_URL_CHECK_MAX + 1).fill('https://a.example/x')).success, false);
  assert.equal(urls.safeParse([]).success, false);
  const limit = tools.get('threat_library_list_reports').inputSchema.limit;
  assert.equal(limit.safeParse(200).success, true);
  assert.equal(limit.safeParse(201).success, false);
});

test('authorization: any app role with mcp:ioc:read; missing scope or role is denied before any query', async () => {
  for (const name of CATALOG_TOOLS) {
    for (const role of ['admin', 'analyst', 'readonly']) {
      assert.deepEqual(authorizeMcpTool(name, { scopes: READ_SCOPES, ownerRole: role }), { ok: true });
    }
    const noScope = authorizeMcpTool(name, { scopes: [API_SCOPE.MCP_SOURCES_READ], ownerRole: 'admin' });
    assert.equal(noScope.code, 'MISSING_SCOPE');
    const noRole = authorizeMcpTool(name, { scopes: READ_SCOPES, ownerRole: 'nobody' });
    assert.equal(noRole.code, 'RBAC_DENIED');
  }
  const pool = recordingPool([reportRow()]);
  const listDenied = await callTool(pool, 'threat_library_list_reports', {}, { scopes: [API_SCOPE.MCP_SOURCES_READ] });
  assert.equal(listDenied.error.code, 'MISSING_SCOPE');
  const checkDenied = await callTool(pool, 'threat_library_check_report_urls', { urls: ['https://example.com/r/1'] }, { role: 'nobody' });
  assert.equal(checkDenied.error.code, 'RBAC_DENIED');
  assert.equal(pool.queries.length, 0, 'denied calls never reach the database');
});

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------

test('date bounds: a day covers the whole UTC day, timestamps are exact and offset-less = UTC', () => {
  assert.deepEqual(parseCatalogBound('2026-10-30', 'from', 'f'), { op: '>=', at: '2026-10-30T00:00:00.000Z' });
  assert.deepEqual(parseCatalogBound('2026-10-30', 'to', 't'), { op: '<', at: '2026-10-31T00:00:00.000Z' });
  assert.deepEqual(parseCatalogBound('2026-12-31', 'to', 't'), { op: '<', at: '2027-01-01T00:00:00.000Z' });
  assert.deepEqual(parseCatalogBound('2026-10-30T08:15:00Z', 'to', 't'), { op: '<=', at: '2026-10-30T08:15:00.000Z' });
  assert.deepEqual(parseCatalogBound('2026-10-30T08:15:00', 'from', 'f'), { op: '>=', at: '2026-10-30T08:15:00.000Z' });
  assert.deepEqual(parseCatalogBound('2026-10-30T10:15:00+02:00', 'from', 'f'), { op: '>=', at: '2026-10-30T08:15:00.000Z' });
  for (const bad of ['2026-02-30', '30/10/2026', 'yesterday', '2026-13-01']) {
    assert.throws(() => parseCatalogBound(bad, 'from', 'imported_from'), (e) => e instanceof CatalogInputError && e.code === 'INVALID_DATE', bad);
  }
});

test('filters are validated against the persisted vocabularies', () => {
  const q = parseCatalogQuery({ import_status: ['failed', 'READY', 'failed'], review_phase: 'review_ready', limit: 500 });
  assert.deepEqual(q.import_status, ['failed', 'ready']);
  assert.deepEqual(q.review_phase, ['review_ready']);
  assert.equal(q.limit, 200);
  assert.equal(parseCatalogQuery({}).limit, 50);
  assert.equal(parseCatalogQuery({}).sort, 'imported_desc');
  assert.throws(() => parseCatalogQuery({ import_status: 'done' }), { code: 'INVALID_FILTER' });
  assert.throws(() => parseCatalogQuery({ review_phase: 'reviewed' }), { code: 'INVALID_FILTER' });
  assert.throws(() => parseCatalogQuery({ sort: 'title' }), { code: 'INVALID_SORT' });
});

test('list SQL: parameterised filters, deleted rows excluded, id tie-breaker, catalog columns only', async () => {
  const pool = recordingPool([]);
  await listReportCatalog(pool, {
    imported_from: '2026-10-30', imported_to: '2026-10-30', publisher: '50%_off', review_phase: ['failed', 'review_ready']
  });
  const { sql, params } = pool.queries[0];
  assert.match(sql, /^SELECT /);
  assert.match(sql, /r\.deleted_at IS NULL/);
  assert.match(sql, /ORDER BY r\.created_at DESC, r\.id DESC/);
  assert.match(sql, /r\.source_name ILIKE \$3 ESCAPE/);
  assert.deepEqual(params.slice(0, 3), ['2026-10-30T00:00:00.000Z', '2026-10-31T00:00:00.000Z', '%50\\%\\_off%']);
  assert.equal(params.at(-1), 51, 'limit + 1 to detect has_more');
  for (const col of ['summary', 'canonical_document', 'ai_result', 'candidate_summary', 'r.*']) {
    assert.ok(!sql.includes(col), `never selects ${col}`);
  }
});

test('cursor: next_cursor round-trips with µs precision and is bound to the same filters and sort', async () => {
  const rows = [reportRow({ id: 7, created_at_key: '2026-10-30T10:00:00.000123Z' }), reportRow({ id: 6 }), reportRow({ id: 5 })];
  const pool = recordingPool(rows);
  const first = await listReportCatalog(pool, { limit: 2, publisher: 'Example' });
  assert.equal(first.has_more, true);
  assert.equal(first.count, 2);
  await listReportCatalog(pool, { limit: 2, publisher: 'Example', cursor: first.next_cursor });
  const { sql, params } = pool.queries[1];
  assert.match(sql, /\(r\.created_at, r\.id\) < \(\$\d+::timestamptz, \$\d+::bigint\)/);
  assert.ok(params.includes(rows[1].created_at_key), 'cursor carries the exact microsecond timestamp');
  assert.ok(params.includes(String(rows[1].id)));

  await assert.rejects(listReportCatalog(pool, { limit: 2, publisher: 'Other', cursor: first.next_cursor }), { code: 'INVALID_CURSOR' });
  await assert.rejects(listReportCatalog(pool, { limit: 2, publisher: 'Example', sort: 'imported_asc', cursor: first.next_cursor }), { code: 'INVALID_CURSOR' });
  await assert.rejects(listReportCatalog(pool, { cursor: 'not-a-cursor' }), { code: 'INVALID_CURSOR' });
  const forged = Buffer.from(JSON.stringify({ v: 1, f: 'x', c: "2026'; DROP", i: '1' })).toString('base64url');
  await assert.rejects(listReportCatalog(pool, { cursor: forged }), { code: 'INVALID_CURSOR' });
});

test('MCP list: input errors are tool errors, results carry the catalog item shape only', async () => {
  const pool = recordingPool([reportRow({ analysis_status: 'review_required', import_status: 'review_required', finalized_at: null })]);
  const bad = await callTool(pool, 'threat_library_list_reports', { imported_from: 'last week' });
  assert.equal(bad.error.code, 'INVALID_DATE');
  const ok = await callTool(pool, 'threat_library_list_reports', { limit: 5 });
  assert.equal(ok.error, null);
  const item = ok.data.items[0];
  assert.deepEqual(Object.keys(item).sort(), [
    'analysis_status', 'failure', 'finalized', 'finalized_at', 'fully_processed', 'import_status', 'imported_at',
    'next_action', 'processing_state', 'published_at', 'published_at_precision', 'published_date', 'publisher',
    'report_id', 'requires_further_processing', 'requires_review', 'review_phase', 'source_type', 'source_url',
    'source_url_identity', 'title', 'tlp'
  ]);
  assert.equal(item.review_phase, 'review_ready');
  assert.equal(item.requires_review, true);
  assert.equal(item.finalized, false);
});

// ---------------------------------------------------------------------------
// Report state
// ---------------------------------------------------------------------------

test('report state: failed and pending-review reports exist but are never fully processed', () => {
  const failed = serializeCatalogReport(reportRow({ import_status: 'failed', analysis_status: 'failed', failure_stage: 'fetch', failure_code: 'http_404', finalized_at: null }));
  assert.equal(failed.review_phase, 'failed');
  assert.equal(failed.processing_state, 'failed');
  assert.equal(failed.requires_further_processing, true);
  assert.equal(failed.fully_processed, false);
  assert.deepEqual(failed.failure, { stage: 'fetch', code: 'http_404' });
  // import_status failed alone (analysis never ran) is still a failure, not "processing".
  const importFailed = serializeCatalogReport(reportRow({ import_status: 'failed', analysis_status: 'pending', finalized_at: null }));
  assert.equal(importFailed.processing_state, 'failed');
  const review = serializeCatalogReport(reportRow({ import_status: 'review_required', analysis_status: 'review_required', finalized_at: null }));
  assert.deepEqual([review.processing_state, review.next_action, review.finalized], ['needs_review', 'analyst_review', false]);
  const preparing = serializeCatalogReport(reportRow({ import_status: 'processing', analysis_status: 'analyzing', finalized_at: null }));
  assert.deepEqual([preparing.processing_state, preparing.next_action], ['processing', 'wait_for_processing']);
  const done = serializeCatalogReport(reportRow());
  assert.deepEqual([done.finalized, done.fully_processed, done.next_action, done.failure], [true, true, 'none', null]);
  const noUrl = serializeCatalogReport(reportRow({ source_type: 'pdf', source_url: null, source_url_canonical: null }));
  assert.equal(noUrl.source_url, null);
  assert.equal(noUrl.published_at, null);
});

// ---------------------------------------------------------------------------
// Batch URL check
// ---------------------------------------------------------------------------

test('URL identity: reuses the import canonicalizer — equivalent spellings match, different documents do not', () => {
  const same = [
    'https://Example.COM/blog/post', 'https://example.com:443/blog/post', 'https://example.com/blog/post/',
    'https://example.com/blog/post#section', 'https://user:pw@example.com/blog/post', '  https://example.com/blog/post?  '
  ];
  for (const u of same) assert.equal(canonicalizeReportUrl(u), 'https://example.com/blog/post', u);
  const distinct = [
    'http://example.com/blog/post', 'https://example.com/Blog/Post', 'https://example.com/blog/post?id=2',
    'https://www.example.com/blog/post', 'https://example.com/blog/post//', 'https://example.com/blog'
  ];
  for (const u of distinct) assert.notEqual(canonicalizeReportUrl(u), 'https://example.com/blog/post', u);
});

test('batch check: one query, input order kept, matches / misses / invalid / duplicates answered per position', async () => {
  const done = reportRow({ source_url: 'https://Example.com/a/', source_url_canonical: 'https://example.com/a' });
  const failed = reportRow({
    source_url_canonical: 'https://example.com/failed', import_status: 'failed', analysis_status: 'failed', finalized_at: null
  });
  const review = reportRow({
    source_url_canonical: 'https://example.com/review', import_status: 'review_required', analysis_status: 'review_required', finalized_at: null
  });
  const dupOld = reportRow({ source_url_canonical: 'https://example.com/dup', created_at: new Date('2026-01-01T00:00:00Z') });
  const dupNew = reportRow({ source_url_canonical: 'https://example.com/dup', analysis_status: 'review_required', import_status: 'review_required', finalized_at: null });
  const pdf = reportRow({ source_type: 'pdf', source_url_canonical: 'https://example.com/pdf' });
  const pool = recordingPool([done, failed, review, dupOld, dupNew, pdf]);

  const { data, error } = await callTool(pool, 'threat_library_check_report_urls', {
    urls: [
      'https://example.com/missing',
      'https://EXAMPLE.com/a#top',
      'ftp://example.com/a',
      null,
      'https://example.com/failed',
      'https://example.com/review',
      'https://example.com/dup',
      'http://example.com/a',
      'https://example.com/a'
    ]
  });
  assert.equal(error, null);
  assert.equal(pool.queries.length, 2, 'two batched statements per request (no N+1)');
  assert.deepEqual(pool.queries[1].params, [['example.com']], 'stored-URL lookup prefiltered on the queried hosts');
  assert.match(pool.queries[0].sql, /^SELECT /);
  assert.match(pool.queries[0].sql, /source_type = 'url' AND r\.deleted_at IS NULL/);
  assert.deepEqual(
    [...pool.queries[0].params[0]].sort(),
    ['http://example.com/a', 'https://example.com/a', 'https://example.com/dup', 'https://example.com/failed', 'https://example.com/missing', 'https://example.com/review']
  );

  const r = data.results;
  assert.deepEqual(r.map((x) => x.index), [0, 1, 2, 3, 4, 5, 6, 7, 8]);
  assert.deepEqual(r.map((x) => x.queried_url), [
    'https://example.com/missing', 'https://EXAMPLE.com/a#top', 'ftp://example.com/a', null,
    'https://example.com/failed', 'https://example.com/review', 'https://example.com/dup', 'http://example.com/a', 'https://example.com/a'
  ]);
  // miss
  assert.deepEqual([r[0].valid, r[0].exists, r[0].matched_report_id, r[0].report], [true, false, null, null]);
  // equivalent spelling → the stored original URL is returned untouched
  assert.equal(r[1].normalized_url, 'https://example.com/a');
  assert.equal(r[1].matched_report_id, done.public_id);
  assert.equal(r[1].report.source_url, 'https://Example.com/a/');
  assert.deepEqual([r[1].finalized, r[1].requires_review, r[1].requires_further_processing], [true, false, false]);
  // invalid inputs
  assert.deepEqual([r[2].valid, r[2].invalid_reason, r[2].exists], [false, 'not_http_url', false]);
  assert.deepEqual([r[3].valid, r[3].invalid_reason], [false, 'empty']);
  // failed: exists, not finalized, needs processing
  assert.deepEqual([r[4].exists, r[4].finalized, r[4].requires_further_processing, r[4].report.review_phase], [true, false, true, 'failed']);
  // needs review
  assert.deepEqual([r[5].exists, r[5].finalized, r[5].requires_review, r[5].report.next_action], [true, false, true, 'analyst_review']);
  // duplicate identity: ambiguity exposed, nothing silently chosen
  assert.equal(r[6].ambiguous, true);
  assert.equal(r[6].match_count, 2);
  assert.equal(r[6].matched_report_id, null);
  assert.equal(r[6].report, null);
  assert.deepEqual(r[6].matches.map((m) => m.report_id).sort(), [dupNew.public_id, dupOld.public_id].sort());
  assert.equal(r[6].finalized, false, 'not finalized while any duplicate is still in review');
  // http vs https are different reports; repeated input answered identically
  assert.equal(r[7].exists, false);
  assert.deepEqual(r[8], { ...r[1], index: 8, queried_url: 'https://example.com/a' });
  // PDF upload with the same canonical text is not a URL import identity
  assert.equal(r.find((x) => x.normalized_url === 'https://example.com/pdf'), undefined);

  assert.deepEqual(data.summary, {
    queried: 9, valid: 7, invalid: 2, existing: 5, missing: 2, ambiguous: 1, finalized: 2, requiring_action: 3
  });
  assert.ok(r[1].matches.every((m) => m.match_basis === 'import_identity'));
  assert.equal(r[1].import_would_deduplicate, true);
});

test('batch check: a PDF upload whose stored source_url is the queried report URL exists (match_basis source_url)', async () => {
  // Production shape: the article was uploaded as a PDF and the analyst set
  // source_url to the article; URL import dedup cannot see it.
  const pdf = reportRow({
    source_type: 'pdf', source_url: ' https://www.Sophos.com/en-us/blog/aur0ra/ ', source_url_canonical: null
  });
  const pdfOtherPath = reportRow({ source_type: 'pdf', source_url: 'https://www.sophos.com/en-us/blog/other', source_url_canonical: null });
  const pdfQuery = reportRow({ source_type: 'pdf', source_url: 'https://www.sophos.com/en-us/blog/aur0ra?page=2', source_url_canonical: null });
  const urlCopy = reportRow({ source_url_canonical: 'https://news.example/x' });
  const pdfCopy = reportRow({ source_type: 'pdf', source_url: 'https://news.example/x#ref', source_url_canonical: null });
  const pool = recordingPool([pdf, pdfOtherPath, pdfQuery, urlCopy, pdfCopy]);
  const { results } = await checkReportUrls(pool, [
    'https://www.sophos.com/en-us/blog/aur0ra',
    'http://www.sophos.com/en-us/blog/aur0ra',
    'https://news.example/x'
  ]);
  assert.deepEqual(
    [results[0].exists, results[0].match_count, results[0].matched_report_id, results[0].import_would_deduplicate],
    [true, 1, pdf.public_id, false]
  );
  assert.equal(results[0].report.match_basis, 'source_url');
  assert.equal(results[0].report.source_type, 'pdf');
  assert.equal(results[1].exists, false, 'scheme still distinguishes');
  // A URL import and a PDF of the same article: both shown, nothing chosen.
  assert.deepEqual([results[2].ambiguous, results[2].match_count, results[2].matched_report_id], [true, 2, null]);
  assert.deepEqual(results[2].matches.map((m) => m.match_basis).sort(), ['import_identity', 'source_url']);
  assert.equal(results[2].import_would_deduplicate, true);
});

test('batch check: limits enforced in the service as well as the schema', async () => {
  const pool = recordingPool();
  await assert.rejects(checkReportUrls(pool, []), { code: 'INVALID_URLS' });
  await assert.rejects(checkReportUrls(pool, Array(101).fill('https://a.example/')), { code: 'TOO_MANY_URLS' });
  const allInvalid = await checkReportUrls(pool, ['', 'not a url']);
  assert.equal(pool.queries.length, 0, 'no identities → no query');
  assert.equal(allInvalid.summary.invalid, 2);
});

test('read-only: every statement either tool issues is a single SELECT', async () => {
  const pool = recordingPool([reportRow(), reportRow({ source_url_canonical: 'https://example.com/x' })]);
  await callTool(pool, 'threat_library_list_reports', { sort: 'published_desc', import_status: 'ready', published_from: '2026-01-01' });
  const page = await callTool(pool, 'threat_library_list_reports', { sort: 'published_asc', limit: 1 });
  await callTool(pool, 'threat_library_list_reports', { sort: 'published_asc', limit: 1, cursor: page.data.next_cursor });
  await callTool(pool, 'threat_library_check_report_urls', { urls: ['https://example.com/x', 'https://example.com/y'] });
  assert.ok(pool.queries.length >= 4);
  for (const { sql } of pool.queries) {
    assert.match(sql, /^SELECT /);
    assert.doesNotMatch(sql, /\b(INSERT|UPDATE|DELETE|MERGE|TRUNCATE|ALTER|CREATE|DROP|FOR UPDATE|pg_advisory)\b/i);
    assert.equal(sql.split(';').filter((s) => s.trim()).length, 1);
  }
});

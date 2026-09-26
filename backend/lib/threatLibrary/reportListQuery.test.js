import test from 'node:test';
import assert from 'node:assert/strict';
import {
  REPORT_LIST_DEFAULT_PAGE_SIZE,
  REPORT_LIST_MAX_LIMIT,
  REPORT_LIST_PAGE_SIZES,
  REPORT_LIST_SEARCH_COLUMNS,
  REPORT_LIST_SEARCH_MAX_LENGTH,
  buildReportListWhere,
  normalizeReportListSearch,
  parseReportListPageSize,
  parseReportListQuery
} from './reportListQuery.js';
import { listThreatReports } from './store.js';

// --- HTTP page size (25 / 50) ---------------------------------------------

test('parseReportListPageSize serves only the UI page sizes and falls back to 25', () => {
  assert.deepEqual([...REPORT_LIST_PAGE_SIZES], [25, 50]);
  assert.equal(REPORT_LIST_DEFAULT_PAGE_SIZE, 25);
  assert.equal(parseReportListPageSize(undefined), 25);
  assert.equal(parseReportListPageSize('25'), 25);
  assert.equal(parseReportListPageSize('50'), 50);
  assert.equal(parseReportListPageSize(' 50 '), 50);
  assert.equal(parseReportListPageSize(50), 50);
  for (const junk of ['', '0', '10', '49', '51', '100', '200', '-25', '50.0', '5e1', '0x32', 'abc', ['50'], { n: 50 }, null, NaN]) {
    assert.equal(parseReportListPageSize(junk), 25, JSON.stringify(junk));
  }
});

// --- normalisation ----------------------------------------------------------

test('normalizeReportListSearch trims surrounding whitespace', () => {
  assert.equal(normalizeReportListSearch('  iranian \t'), 'iranian');
  assert.equal(normalizeReportListSearch('   '), '');
  assert.equal(normalizeReportListSearch(''), '');
});

test('normalizeReportListSearch treats missing / non-string input as no search', () => {
  assert.equal(normalizeReportListSearch(undefined), '');
  assert.equal(normalizeReportListSearch(null), '');
  assert.equal(normalizeReportListSearch(['a', 'b']), '', 'repeated ?search= params (array) are ignored');
  assert.equal(normalizeReportListSearch({ $gt: '' }), '', 'object-shaped query input is ignored');
  assert.equal(normalizeReportListSearch(42), '');
});

test('normalizeReportListSearch bounds the length and strips control characters', () => {
  const long = 'x'.repeat(REPORT_LIST_SEARCH_MAX_LENGTH + 500);
  assert.equal(normalizeReportListSearch(long).length, REPORT_LIST_SEARCH_MAX_LENGTH);
  // NUL bytes would be rejected by Postgres as a parameter -> must never reach the driver.
  assert.equal(normalizeReportListSearch('ncsc\u0000'), 'ncsc');
  assert.equal(normalizeReportListSearch('a\u0000b'), 'a b');
  assert.equal(normalizeReportListSearch('\u0001\u0002'), '');
});

test('parseReportListQuery keeps the existing limit/offset bounds and adds search', () => {
  assert.deepEqual(parseReportListQuery({}), { limit: 50, offset: 0, search: '' });
  assert.deepEqual(parseReportListQuery({ limit: '100', offset: '0' }), { limit: 100, offset: 0, search: '' });
  assert.deepEqual(parseReportListQuery({ limit: '9999', offset: '-5', search: ' ncsc ' }), {
    limit: REPORT_LIST_MAX_LIMIT,
    offset: 0,
    search: 'ncsc'
  });
  assert.deepEqual(parseReportListQuery({ limit: 'abc', offset: 'abc', search: 'x' }), { limit: 50, offset: 0, search: 'x' });
});

test('parseReportListQuery never lets a non-finite or unsafe offset reach the driver', () => {
  assert.equal(parseReportListQuery({ offset: '1e400' }).offset, 0);
  assert.equal(parseReportListQuery({ offset: 'Infinity' }).offset, 0);
  assert.equal(parseReportListQuery({ offset: '9007199254740993' }).offset, 0);
  assert.equal(parseReportListQuery({ offset: '2.9' }).offset, 2);
  assert.equal(parseReportListQuery({ offset: '150' }).offset, 150);
  assert.equal(parseReportListQuery({ limit: '1e400' }).limit, REPORT_LIST_MAX_LIMIT);
  assert.equal(parseReportListQuery({ limit: '25.7' }).limit, 25);
  // Page-style requests from the UI: page 7 of a 25-per-page list.
  assert.deepEqual(parseReportListQuery({ limit: '25', offset: '150' }), { limit: 25, offset: 150, search: '' });
});

// --- WHERE clause -------------------------------------------------------------

test('no search -> the WHERE clause is exactly the pre-existing soft-delete filter', () => {
  for (const search of [undefined, '', '   ', null]) {
    const w = buildReportListWhere({ search }, 1);
    assert.equal(w.sql, 'WHERE r.deleted_at IS NULL');
    assert.deepEqual(w.params, []);
    assert.equal(w.nextParamIndex, 1);
  }
});

test('search is a single bound parameter matched case-insensitively across the metadata columns only', () => {
  const w = buildReportListWhere({ search: 'Iranian' }, 1);
  assert.deepEqual(w.params, ['%Iranian%']);
  assert.equal(w.nextParamIndex, 2);
  assert.match(w.sql, /^WHERE r\.deleted_at IS NULL AND \(/);
  for (const col of ['r.title', 'r.source_name', 'r.source_url', 'r.source_file_name']) {
    assert.ok(w.sql.includes(`${col} ILIKE $1 ESCAPE '\\'`), `${col} searched`);
  }
  assert.equal((w.sql.match(/ILIKE/g) || []).length, REPORT_LIST_SEARCH_COLUMNS.length);
  // Never the heavy / extracted content.
  for (const forbidden of ['summary', 'canonical_document', 'ai_result', 'candidate', 'entit', 'lower(']) {
    assert.equal(w.sql.includes(forbidden), false, `${forbidden} must not be part of the search`);
  }
});

test('search never matches on report_type: the list no longer shows it, so a row must not match on a hidden value', () => {
  assert.deepEqual([...REPORT_LIST_SEARCH_COLUMNS], ['r.title', 'r.source_name', 'r.source_url', 'r.source_file_name']);
  assert.equal(REPORT_LIST_SEARCH_COLUMNS.includes('r.report_type'), false);
  const w = buildReportListWhere({ search: 'advisory' }, 1);
  assert.doesNotMatch(w.sql, /report_type/);
  // Exactly one ILIKE per visible column, all bound to the same single parameter.
  assert.equal((w.sql.match(/ILIKE \$1 ESCAPE '\\'/g) || []).length, 4);
  assert.deepEqual(w.params, ['%advisory%']);
});

test('search honours the caller-supplied parameter start index', () => {
  const w = buildReportListWhere({ search: 'ncsc' }, 3);
  assert.match(w.sql, /ILIKE \$3 ESCAPE/);
  assert.doesNotMatch(w.sql, /\$1\b|\$2\b/);
  assert.equal(w.nextParamIndex, 4);
});

test('LIKE wildcards and the escape char in user input are escaped so they match literally', () => {
  assert.deepEqual(buildReportListWhere({ search: '100%' }).params, ['%100\\%%']);
  assert.deepEqual(buildReportListWhere({ search: 'threat_report' }).params, ['%threat\\_report%']);
  assert.deepEqual(buildReportListWhere({ search: 'a\\b' }).params, ['%a\\\\b%']);
  assert.deepEqual(buildReportListWhere({ search: '%_\\' }).params, ['%\\%\\_\\\\%']);
});

test('SQL-injection-like input stays inside the bound parameter and never alters the SQL text', () => {
  const evil = "'; DROP TABLE threat-reports; --";
  const w = buildReportListWhere({ search: evil }, 1);
  assert.deepEqual(w.params, [`%${evil}%`]);
  assert.equal(w.sql.includes('DROP'), false);
  assert.equal(w.sql, buildReportListWhere({ search: 'benign' }, 1).sql, 'SQL text is independent of the search value');
  const quoted = `x' OR 1=1 --`;
  assert.deepEqual(buildReportListWhere({ search: quoted }).params, [`%${quoted}%`]);
});

// --- listThreatReports (store) ----------------------------------------------

function capturePool(pageRows = [], total = 0) {
  const queries = [];
  return {
    queries,
    async query(sql, params) {
      queries.push({ sql, params });
      if (/COUNT\(\*\)::int AS total/.test(sql)) return { rows: [{ total }] };
      return { rows: pageRows };
    }
  };
}

test('listThreatReports without search issues the unchanged baseline page + count queries', async () => {
  const pool = capturePool([{ id: 1 }], 7);
  const result = await listThreatReports(pool, { limit: 100, offset: 0 });
  assert.equal(pool.queries.length, 2);
  const [page, count] = pool.queries;
  assert.match(page.sql, /FROM threat_reports r\s+WHERE r\.deleted_at IS NULL\s+ORDER BY r\.created_at DESC\s+LIMIT \$1 OFFSET \$2/);
  assert.deepEqual(page.params, [100, 0]);
  assert.match(count.sql, /SELECT COUNT\(\*\)::int AS total FROM threat_reports r WHERE r\.deleted_at IS NULL$/);
  assert.deepEqual(count.params, []);
  assert.deepEqual(result, { items: [{ id: 1 }], total: 7, search: '', limit: 100, offset: 0 });
});

test('listThreatReports applies the same search filter to the page and the count, before LIMIT/OFFSET', async () => {
  const pool = capturePool([{ id: 2 }], 12);
  const result = await listThreatReports(pool, { limit: 100, offset: 100, search: '  iran ' });
  const [page, count] = pool.queries;
  assert.match(page.sql, /WHERE r\.deleted_at IS NULL AND \([\s\S]*ILIKE \$1 ESCAPE[\s\S]*\)\s+ORDER BY r\.created_at DESC\s+LIMIT \$2 OFFSET \$3/);
  assert.deepEqual(page.params, ['%iran%', 100, 100]);
  assert.match(count.sql, /WHERE r\.deleted_at IS NULL AND \([\s\S]*ILIKE \$1 ESCAPE/);
  assert.deepEqual(count.params, ['%iran%']);
  // The count is the filtered total, not the library size.
  assert.equal(result.total, 12);
  assert.equal(result.search, 'iran');
  // Both statements use the identical WHERE text.
  const whereOf = (sql) => sql.slice(sql.lastIndexOf('WHERE r.deleted_at'), sql.indexOf('ORDER BY') > 0 ? sql.indexOf('ORDER BY') : undefined).trim();
  assert.equal(whereOf(page.sql), whereOf(count.sql));
});

test('listThreatReports never interpolates the search value into SQL text', async () => {
  const pool = capturePool([], 0);
  const evil = `'; DELETE FROM threat-reports; --`;
  await listThreatReports(pool, { search: evil });
  for (const q of pool.queries) {
    assert.equal(q.sql.includes('DELETE'), false);
    assert.equal(q.sql.includes(evil), false);
  }
  assert.deepEqual(pool.queries[1].params, [`%${evil}%`]);
});

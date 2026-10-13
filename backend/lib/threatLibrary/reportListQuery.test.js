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
  parseReportListQuery,
  parseReportListSort,
  buildReportListOrderBy,
  REPORT_LIST_DEFAULT_ORDER_SQL,
  REPORT_LIST_SORT_FIELDS,
  REPORT_LIST_SORT_TIEBREAK_SQL,
  REPORT_LIST_IMPORTED_WINDOWS,
  REPORT_LIST_PHASE_SQL,
  REPORT_LIST_SOURCE_FILTERS,
  REPORT_LIST_STATUS_FILTERS,
  REPORT_LIST_TLP_FILTERS,
  buildReportListCountSql,
  parseReportListFilters,
  reportListPhaseCounts,
  reportListStatusSql,
  reportListTagSearchSql
} from './reportListQuery.js';
import { resolveReportPhase } from './reportPhase.js';
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
  assert.deepEqual(parseReportListQuery({}), { limit: 50, offset: 0, search: '', sort: null, order: null, status: null, tlp: null, source: null, imported: null });
  assert.deepEqual(parseReportListQuery({ limit: '100', offset: '0' }), { limit: 100, offset: 0, search: '', sort: null, order: null, status: null, tlp: null, source: null, imported: null });
  assert.deepEqual(parseReportListQuery({ limit: '9999', offset: '-5', search: ' ncsc ' }), {
    limit: REPORT_LIST_MAX_LIMIT,
    offset: 0,
    search: 'ncsc',
    sort: null,
    order: null,
    status: null,
    tlp: null,
    source: null,
    imported: null
  });
  assert.deepEqual(parseReportListQuery({ limit: 'abc', offset: 'abc', search: 'x' }), { limit: 50, offset: 0, search: 'x', sort: null, order: null, status: null, tlp: null, source: null, imported: null });
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
  assert.deepEqual(parseReportListQuery({ limit: '25', offset: '150' }), { limit: 25, offset: 150, search: '', sort: null, order: null, status: null, tlp: null, source: null, imported: null });
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
  // One ILIKE per metadata column plus one for the (row-visible) report tag names.
  assert.equal((w.sql.match(/ILIKE/g) || []).length, REPORT_LIST_SEARCH_COLUMNS.length + 1);
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
  // Exactly one ILIKE per visible column + tag names, all bound to the same single parameter.
  assert.equal((w.sql.match(/ILIKE \$1 ESCAPE '\\'/g) || []).length, 5);
  assert.deepEqual(w.params, ['%advisory%']);
});

test('search matches enabled report tag names (row chips) via EXISTS on the report/tag key, same bound parameter', () => {
  const w = buildReportListWhere({ search: 'ransom' }, 1);
  assert.ok(w.sql.includes(reportListTagSearchSql('$1')));
  assert.match(w.sql, /EXISTS \(SELECT 1 FROM threat_report_tags rt JOIN tags t ON t\.id = rt\.tag_id AND t\.enabled = TRUE WHERE rt\.report_id = r\.id AND t\.name ILIKE \$1 ESCAPE '\\'\)/);
  assert.deepEqual(w.params, ['%ransom%']);
  // Disabled tags are never rendered as chips, so they never match.
  assert.match(reportListTagSearchSql('$9'), /t\.enabled = TRUE/);
});

// --- filters -------------------------------------------------------------------

test('parseReportListFilters keeps only whitelisted values (case-insensitive) and drops junk / arrays / objects', () => {
  assert.deepEqual(parseReportListFilters({}), { status: null, tlp: null, source: null, imported: null });
  assert.deepEqual(
    parseReportListFilters({ status: ' Review_Ready ', tlp: 'AMBER_STRICT', source: 'PDF', imported: '7D' }),
    { status: 'review_ready', tlp: 'amber_strict', source: 'pdf', imported: '7d' }
  );
  for (const junk of ['', 'ready', 'needs_review', 'all', "finalized' OR 1=1 --", ['failed'], { $ne: 1 }, 7, null]) {
    assert.equal(parseReportListFilters({ status: junk }).status, null, JSON.stringify(junk));
  }
  assert.equal(parseReportListFilters({ tlp: 'white' }).tlp, null, 'only stored CHECK values are filterable');
  assert.equal(parseReportListFilters({ source: 'feed' }).source, null);
  assert.equal(parseReportListFilters({ imported: '365d' }).imported, null);
  assert.deepEqual([...REPORT_LIST_STATUS_FILTERS], ['preparing', 'review_ready', 'finalized', 'failed']);
  assert.deepEqual([...REPORT_LIST_TLP_FILTERS], ['clear', 'green', 'amber', 'amber_strict', 'red']);
  assert.deepEqual([...REPORT_LIST_SOURCE_FILTERS], ['url', 'pdf', 'thib']);
  assert.deepEqual(Object.keys(REPORT_LIST_IMPORTED_WINDOWS), ['24h', '7d', '30d', '90d']);
});

test('TLP / source filters are bound parameters after the search parameter; imported is a fixed whitelisted predicate', () => {
  const w = buildReportListWhere({ search: 'iran', tlp: 'amber', source: 'url', imported: '30d' }, 1);
  assert.deepEqual(w.params, ['%iran%', 'amber', 'url']);
  assert.match(w.sql, /AND r\.tlp = \$2 AND r\.source_type = \$3 AND r\.created_at >= NOW\(\) - INTERVAL '30 days'$/);
  assert.equal(w.nextParamIndex, 4);
  const noSearch = buildReportListWhere({ tlp: 'red' }, 1);
  assert.equal(noSearch.sql, 'WHERE r.deleted_at IS NULL AND r.tlp = $1');
  assert.deepEqual(noSearch.params, ['red']);
  // Injection-shaped filter values are simply "no filter".
  const evil = buildReportListWhere({ tlp: "red' OR '1'='1", source: 'url; DROP', imported: "1 day'; --" }, 1);
  assert.equal(evil.sql, 'WHERE r.deleted_at IS NULL');
  assert.deepEqual(evil.params, []);
});

test('the status phase SQL mirrors resolveReportPhase for every stored analysis_status', () => {
  const expected = {
    pending: 'preparing', fetching: 'preparing', extracting: 'preparing', analyzing: 'preparing', matching: 'preparing',
    review_required: 'review_ready', ready: 'finalized', skipped: 'finalized', failed: 'failed', cancelled: 'failed'
  };
  for (const [status, phase] of Object.entries(expected)) {
    assert.equal(resolveReportPhase({ analysis_status: status }), phase, status);
    // Evaluate each predicate against the literal status (tiny SQL subset: IN / NOT IN / =).
    const matches = REPORT_LIST_STATUS_FILTERS.filter((p) => evalPhaseSql(REPORT_LIST_PHASE_SQL[p], status));
    assert.deepEqual(matches, [phase], `${status} belongs to exactly one phase`);
  }
});

function evalPhaseSql(sql, status) {
  const list = (s) => [...s.matchAll(/'([^']+)'/g)].map((m) => m[1]);
  if (/NOT IN \(/.test(sql)) return !list(sql).includes(status);
  if (/ IN \(/.test(sql)) return list(sql).includes(status);
  return list(sql)[0] === status;
}

test('count SQL: one statement, total honours the status filter, phase counts and all ignore it', () => {
  const where = buildReportListWhere({ search: 'x', tlp: 'clear' }, 1).sql;
  const unfiltered = buildReportListCountSql(where, null);
  assert.match(unfiltered, /^SELECT COUNT\(\*\)::int AS total, COUNT\(\*\)::int AS phase_all, /);
  for (const phase of REPORT_LIST_STATUS_FILTERS) {
    assert.ok(unfiltered.includes(`COUNT(*) FILTER (WHERE ${REPORT_LIST_PHASE_SQL[phase]})::int AS phase_${phase}`));
  }
  assert.ok(unfiltered.endsWith(`FROM threat_reports r ${where}`));
  const filtered = buildReportListCountSql(where, 'review_ready');
  assert.match(filtered, /^SELECT COUNT\(\*\) FILTER \(WHERE r\.analysis_status = 'review_required'\)::int AS total, COUNT\(\*\)::int AS phase_all/);
  assert.equal(buildReportListCountSql(where, 'bogus'), unfiltered);
  assert.equal(reportListStatusSql('bogus'), null);
  assert.deepEqual(
    reportListPhaseCounts({ phase_all: 9, phase_preparing: 1, phase_review_ready: 2, phase_finalized: 5, phase_failed: 1 }),
    { all: 9, preparing: 1, review_ready: 2, finalized: 5, failed: 1 }
  );
  assert.deepEqual(reportListPhaseCounts(undefined), { all: 0, preparing: 0, review_ready: 0, finalized: 0, failed: 0 });
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
      if (/::int AS total/.test(sql)) {
        return { rows: [{ total, phase_all: total, phase_preparing: 0, phase_review_ready: 0, phase_finalized: total, phase_failed: 0 }] };
      }
      return { rows: pageRows };
    }
  };
}

const NO_FILTERS = Object.freeze({ status: null, tlp: null, source: null, imported: null });

test('listThreatReports without search issues the unchanged baseline page query + one count statement', async () => {
  const pool = capturePool([{ id: 1 }], 7);
  const result = await listThreatReports(pool, { limit: 100, offset: 0 });
  assert.equal(pool.queries.length, 2);
  const [page, count] = pool.queries;
  assert.match(page.sql, /FROM threat_reports r\s+WHERE r\.deleted_at IS NULL\s+ORDER BY r\.created_at DESC\s+LIMIT \$1 OFFSET \$2/);
  assert.deepEqual(page.params, [100, 0]);
  assert.match(count.sql, /^SELECT COUNT\(\*\)::int AS total, COUNT\(\*\)::int AS phase_all, [\s\S]* FROM threat_reports r WHERE r\.deleted_at IS NULL$/);
  assert.doesNotMatch(count.sql, /threat_report_candidates|threat_report_entities/, 'counts never touch per-report subselects');
  assert.deepEqual(count.params, []);
  assert.deepEqual(result, {
    items: [{ id: 1 }],
    total: 7,
    phase_counts: { all: 7, preparing: 0, review_ready: 0, finalized: 7, failed: 0 },
    search: '',
    filters: NO_FILTERS,
    limit: 100,
    offset: 0
  });
});

test('listThreatReports applies the status phase to the page only; counts keep the base filter set', async () => {
  const pool = capturePool([], 3);
  const result = await listThreatReports(pool, { limit: 25, offset: 0, search: 'apt', status: 'failed', tlp: 'amber', source: 'pdf', imported: '7d' });
  const [page, count] = pool.queries;
  assert.match(page.sql, /WHERE r\.deleted_at IS NULL AND \([\s\S]*\) AND r\.tlp = \$2 AND r\.source_type = \$3 AND r\.created_at >= NOW\(\) - INTERVAL '7 days' AND r\.analysis_status IN \('failed', 'cancelled'\)\s+ORDER BY r\.created_at DESC\s+LIMIT \$4 OFFSET \$5/);
  assert.deepEqual(page.params, ['%apt%', 'amber', 'pdf', 25, 0]);
  assert.match(count.sql, /^SELECT COUNT\(\*\) FILTER \(WHERE r\.analysis_status IN \('failed', 'cancelled'\)\)::int AS total/);
  assert.ok(count.sql.endsWith("r.created_at >= NOW() - INTERVAL '7 days'"), 'count WHERE has no status predicate');
  assert.deepEqual(count.params, ['%apt%', 'amber', 'pdf']);
  assert.deepEqual(result.filters, { status: 'failed', tlp: 'amber', source: 'pdf', imported: '7d' });
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

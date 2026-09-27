/**
 * Threat Library report-list sorting: whitelist, SQL ORDER BY, NULLS LAST,
 * numeric counts, tie-breakers, search composition, and ORDER BY before LIMIT.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  REPORT_LIST_DEFAULT_ORDER_SQL,
  REPORT_LIST_SORT_FIELDS,
  REPORT_LIST_SORT_TIEBREAK_SQL,
  buildReportListOrderBy,
  parseReportListQuery,
  parseReportListSort
} from './reportListQuery.js';
import { listThreatReports } from './store.js';

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

async function listSql(opts) {
  const pool = capturePool();
  await listThreatReports(pool, opts);
  return pool.queries[0].sql;
}

test('whitelist is the list columns; default ORDER BY is the pre-existing created_at DESC', () => {
  assert.deepEqual([...REPORT_LIST_SORT_FIELDS], [
    'report', 'source', 'tlp', 'entities', 'indicators', 'matched', 'status', 'published', 'imported'
  ]);
  assert.equal(buildReportListOrderBy({}).sql, REPORT_LIST_DEFAULT_ORDER_SQL);
  assert.equal(buildReportListOrderBy({ sort: null, order: null }).sql, 'ORDER BY r.created_at DESC');
  assert.equal(REPORT_LIST_SORT_TIEBREAK_SQL, 'r.created_at DESC, r.id DESC');
});

test('TEST A — Published ASC: oldest known first, NULLS LAST', () => {
  const { sql, sort, order } = buildReportListOrderBy({ sort: 'published', order: 'asc' });
  assert.equal(sort, 'published');
  assert.equal(order, 'asc');
  assert.match(sql, /ORDER BY r\.published_at ASC NULLS LAST, r\.created_at DESC, r\.id DESC/);
});

test('TEST B — Published DESC: newest known first, NULLS LAST', () => {
  const { sql } = buildReportListOrderBy({ sort: 'published', order: 'desc' });
  assert.match(sql, /ORDER BY r\.published_at DESC NULLS LAST, r\.created_at DESC, r\.id DESC/);
});

test('TEST C — Published NULLS LAST in both directions and never uses created_at as the publication value', () => {
  const asc = buildReportListOrderBy({ sort: 'published', order: 'asc' }).sql;
  const desc = buildReportListOrderBy({ sort: 'published', order: 'desc' }).sql;
  assert.match(asc, /published_at ASC NULLS LAST/);
  assert.match(desc, /published_at DESC NULLS LAST/);
  assert.doesNotMatch(asc, /COALESCE\(\s*r\.published_at\s*,\s*r\.created_at/);
  assert.doesNotMatch(desc, /COALESCE\(\s*r\.published_at\s*,\s*r\.created_at/);
});

test('TEST D — Imported ASC/DESC uses created_at with an id tie-breaker', () => {
  assert.equal(buildReportListOrderBy({ sort: 'imported', order: 'asc' }).sql, 'ORDER BY r.created_at ASC, r.id ASC');
  assert.equal(buildReportListOrderBy({ sort: 'imported', order: 'desc' }).sql, 'ORDER BY r.created_at DESC, r.id DESC');
});

test('TEST E — Entities / Indicators / Matched sort as integers, not text', () => {
  const entities = buildReportListOrderBy({ sort: 'entities', order: 'asc' }).sql;
  const indicators = buildReportListOrderBy({ sort: 'indicators', order: 'asc' }).sql;
  const matched = buildReportListOrderBy({ sort: 'matched', order: 'desc' }).sql;
  assert.match(entities, /ORDER BY entity_count ASC, r\.created_at DESC, r\.id DESC/);
  assert.match(indicators, /ORDER BY indicator_count ASC, r\.created_at DESC, r\.id DESC/);
  assert.match(matched, /ORDER BY matched_count DESC, r\.created_at DESC, r\.id DESC/);
  for (const sql of [entities, indicators, matched]) {
    assert.doesNotMatch(sql, /::text|::varchar|CAST\(/i);
  }
});

test('TEST F — Report/title sorting is case-insensitive on the stored title', () => {
  const { sql } = buildReportListOrderBy({ sort: 'report', order: 'asc' });
  assert.match(sql, /ORDER BY LOWER\(NULLIF\(BTRIM\(r\.title\), ''\)\) ASC NULLS LAST, r\.created_at DESC, r\.id DESC/);
});

test('TEST G — Source sorting uses the list display source, not a formatted string', () => {
  const { sql } = buildReportListOrderBy({ sort: 'source', order: 'asc' });
  assert.match(sql, /r\.source_name/);
  assert.match(sql, /r\.source_url/);
  assert.match(sql, /r\.source_file_name/);
  assert.match(sql, /NULLS LAST/);
});

test('TEST H — Status sorting uses analysis_status; TLP uses the stored restriction rank', () => {
  assert.match(
    buildReportListOrderBy({ sort: 'status', order: 'asc' }).sql,
    /ORDER BY r\.analysis_status ASC NULLS LAST, r\.created_at DESC, r\.id DESC/
  );
  const tlp = buildReportListOrderBy({ sort: 'tlp', order: 'desc' }).sql;
  assert.match(tlp, /WHEN 'clear' THEN 0/);
  assert.match(tlp, /WHEN 'red' THEN 4/);
  assert.match(tlp, /END DESC, r\.created_at DESC, r\.id DESC/);
});

test('TEST I — unsupported sort field cannot alter or inject SQL', () => {
  const evil = 'published; DROP TABLE threat_reports; --';
  assert.deepEqual(parseReportListSort(evil, 'asc'), { sort: null, order: null });
  assert.equal(buildReportListOrderBy({ sort: evil, order: 'asc' }).sql, REPORT_LIST_DEFAULT_ORDER_SQL);
  assert.equal(buildReportListOrderBy({ sort: 'created_at', order: 'asc' }).sql, REPORT_LIST_DEFAULT_ORDER_SQL);
  assert.equal(buildReportListOrderBy({ sort: ['published'], order: 'asc' }).sql, REPORT_LIST_DEFAULT_ORDER_SQL);
});

test('TEST J — unsupported order cannot alter or inject SQL', () => {
  const evil = 'asc; DROP TABLE threat_reports; --';
  assert.deepEqual(parseReportListSort('published', evil), { sort: null, order: null });
  assert.equal(buildReportListOrderBy({ sort: 'published', order: evil }).sql, REPORT_LIST_DEFAULT_ORDER_SQL);
  assert.equal(buildReportListOrderBy({ sort: 'published', order: 'ASCENDING' }).sql, REPORT_LIST_DEFAULT_ORDER_SQL);
  assert.equal(buildReportListOrderBy({ sort: 'published', order: true }).sql, REPORT_LIST_DEFAULT_ORDER_SQL);
  assert.deepEqual(parseReportListQuery({ sort: 'published' }), {
    limit: 50, offset: 0, search: '', sort: null, order: null
  });
});

test('TEST K — every explicit sort has a deterministic tie-breaker', () => {
  for (const field of REPORT_LIST_SORT_FIELDS) {
    for (const dir of ['asc', 'desc']) {
      const { sql } = buildReportListOrderBy({ sort: field, order: dir });
      assert.match(sql, /r\.id (ASC|DESC)/, `${field} ${dir}`);
      if (field !== 'imported') {
        assert.match(sql, /r\.created_at DESC, r\.id DESC/, `${field} ${dir} recency tie-break`);
      }
    }
  }
});

test('TEST L — search + sort share one WHERE and still ORDER BY before LIMIT', async () => {
  const sql = await listSql({ search: 'zscaler', sort: 'published', order: 'desc', limit: 25, offset: 0 });
  const orderAt = sql.indexOf('ORDER BY r.published_at DESC NULLS LAST');
  const limitAt = sql.indexOf('LIMIT');
  const whereAt = sql.lastIndexOf('WHERE r.deleted_at');
  assert.ok(whereAt > 0 && orderAt > whereAt && limitAt > orderAt);
  assert.match(sql, /ILIKE \$1 ESCAPE/);
  assert.match(sql, /published_at DESC NULLS LAST/);
});

test('TEST M — ORDER BY applies to the full filtered set before LIMIT/OFFSET', async () => {
  const pool = capturePool([{ id: 9 }], 100);
  await listThreatReports(pool, { sort: 'published', order: 'desc', limit: 25, offset: 25 });
  const page = pool.queries[0];
  const orderAt = page.sql.indexOf('ORDER BY r.published_at DESC NULLS LAST');
  const limitAt = page.sql.indexOf('LIMIT');
  const offsetAt = page.sql.indexOf('OFFSET');
  assert.ok(orderAt > 0 && limitAt > orderAt && offsetAt > limitAt);
  assert.deepEqual(page.params, [25, 25]);
  assert.match(page.sql, /ORDER BY r\.published_at DESC NULLS LAST, r\.created_at DESC, r\.id DESC\s+LIMIT \$1 OFFSET \$2/);
  assert.doesNotMatch(page.sql, /LIMIT[\s\S]*ORDER BY/);
});

test('listThreatReports default path is unchanged when sort is absent or rejected', async () => {
  const sql = await listSql({ limit: 25, offset: 0 });
  assert.match(sql, /FROM threat_reports r\s+WHERE r\.deleted_at IS NULL\s+ORDER BY r\.created_at DESC\s+LIMIT \$1 OFFSET \$2/);
  const rejected = await listSql({ sort: 'title; DROP', order: 'desc', limit: 25, offset: 0 });
  assert.match(rejected, /ORDER BY r\.created_at DESC\s+LIMIT/);
  assert.equal(rejected.includes('DROP'), false);
});

test('count query is never sorted; page query uses the whitelist expression only', async () => {
  const pool = capturePool();
  await listThreatReports(pool, { sort: 'entities', order: 'asc', limit: 25, offset: 50 });
  const [page, count] = pool.queries;
  assert.match(page.sql, /ORDER BY entity_count ASC, r\.created_at DESC, r\.id DESC\s+LIMIT \$1 OFFSET \$2/);
  assert.doesNotMatch(count.sql, /ORDER BY/);
  assert.deepEqual(page.params, [25, 50]);
});

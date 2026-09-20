/**
 * Source-level contract for the Threat Library report-list search + pagination:
 * toolbar placement, debounce, single loader (stale guard + clamp), URL state,
 * Refresh semantics, footer pager and the search-specific empty state.
 * Complements reportList.test.js (pure helpers) and reportListLoader.test.js
 * (request state machine).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const pageSrc = readFileSync(path.join(here, 'ThreatLibraryPage.jsx'), 'utf8');

const headerEnd = pageSrc.indexOf('Import Intelligence\n');
const tableStart = pageSrc.indexOf('<table');
const toolbar = pageSrc.slice(headerEnd, tableStart);
const footer = pageSrc.slice(pageSrc.indexOf('{total > 0 ? ('), pageSrc.indexOf('<ImportIntelligenceModal'));

test('search input renders above the table, outside the header actions and the table header', () => {
  assert.ok(headerEnd > 0 && tableStart > headerEnd);
  assert.match(toolbar, /<input\s+id="tl-report-search"\s+type="search"/);
  assert.match(toolbar, /placeholder="Search reports\.\.\."/);
  assert.match(toolbar, /<label htmlFor="tl-report-search" style=\{srOnly\}>Search reports<\/label>/);
  assert.match(toolbar, /maxWidth: 380/, 'desktop width ~320-400px, fluid below');
  const thead = pageSrc.slice(pageSrc.indexOf('<thead>'), pageSrc.indexOf('</thead>'));
  assert.doesNotMatch(thead, /<input/);
  const headerActions = pageSrc.slice(pageSrc.indexOf('AI Settings'), headerEnd);
  assert.doesNotMatch(headerActions, /tl-report-search/);
  assert.match(pageSrc, /const searchInputStyle = \{ \.\.\.ui\.input, padding: '8px 12px', fontSize: 13, minHeight: 36 \}/);
  assert.match(toolbar, /maxLength=\{REPORT_LIST_SEARCH_MAX_LENGTH\}/);
});

test('typing updates searchInput; Escape clears it', () => {
  assert.match(toolbar, /value=\{searchInput\}/);
  assert.match(toolbar, /onChange=\{\(e\) => setSearchInput\(e\.target\.value\)\}/);
  assert.match(toolbar, /onKeyDown=\{\(e\) => \{ if \(e\.key === 'Escape'\) setSearchInput\(''\); \}\}/);
});

test('URL is the single source of truth for search + page; the field is the only local search state', () => {
  assert.match(pageSrc, /const \{ search, page \} = useMemo\(\(\) => parseReportListUrlState\(searchParams\), \[searchParams\]\);/);
  assert.match(pageSrc, /const \[searchInput, setSearchInput\] = useState\(search\);/);
  assert.doesNotMatch(pageSrc, /useState\(initial/);
  assert.doesNotMatch(pageSrc, /const \[search, setSearch\]|const \[page, setPage\]/, 'no shadow copies of URL state that could fight the router');
  // Every URL write goes through one guarded, identity-stable writer (replace, not push).
  assert.match(pageSrc, /const setListUrl = useCallback\(\(next\) => \{\s*const params = buildReportListUrlSearchParams\(next\);\s*const router = routerRef\.current;\s*if \(params\.toString\(\) !== router\.searchParams\.toString\(\)\) router\.setSearchParams\(params, \{ replace: true \}\);\s*\}, \[\]\);/);
  assert.equal((pageSrc.match(/setSearchParams\(params/g) || []).length, 1);
});

test('requests are debounced and a changed term (including clearing) resets to page 1', () => {
  const debounce = pageSrc.slice(pageSrc.indexOf('const t = setTimeout(() => {'), pageSrc.indexOf('}, [searchInput, search, setListUrl]);'));
  assert.match(debounce, /const next = normalizeReportListSearch\(searchInput\);\s*if \(next !== search\) setListUrl\(\{ search: next, page: 1 \}\);/);
  assert.match(debounce, /\}, REPORT_LIST_SEARCH_DEBOUNCE_MS\);\s*return \(\) => clearTimeout\(t\);/);
  // load depends on the URL-derived term and page, never on the raw input.
  assert.match(pageSrc, /\}, \[search, page, setListUrl\]\);\s*useEffect\(\(\) => \{\s*load\(\)\.catch/);
  assert.doesNotMatch(pageSrc, /\}, \[searchInput, search, setListUrl\]\);[\s\S]*loaderRef\.current\.load/);
});

test('Back/Forward and shared links: the field follows the URL term; hand-typed URLs are canonicalised (fixed point, no loop)', () => {
  assert.match(pageSrc, /setSearchInput\(\(prev\) => \(normalizeReportListSearch\(prev\) === search \? prev : search\)\);\s*\}, \[search\]\);/);
  assert.match(pageSrc, /useEffect\(\(\) => \{\s*setListUrl\(\{ search, page \}\);\s*\}, \[search, page, setListUrl\]\);/);
});

test('every list request (initial, search, page, Refresh) goes through the single loader', () => {
  assert.match(pageSrc, /loaderRef\.current = createReportListLoader\(\{\s*pageSize: REPORT_LIST_PAGE_SIZE,\s*fetchPage: async \(params, signal\) => \(await api\.get\('\/threat-library\/reports', \{ params, signal \}\)\)\.data\s*\}\);/);
  assert.match(pageSrc, /const result = await loaderRef\.current\.load\(\{ search, page \}\);/);
  assert.equal((pageSrc.match(/api\.get\(/g) || []).length, 1, 'exactly one list request site');
  assert.doesNotMatch(pageSrc, /\.slice\(/, 'no client-side slicing of a larger result set');
  assert.doesNotMatch(pageSrc, /limit: 100/);
});

test('stale outcomes are ignored, clamped outcomes move to the last valid page and keep loading', () => {
  const load = pageSrc.slice(pageSrc.indexOf('const load = useCallback'), pageSrc.indexOf('}, [search, page, setListUrl]);'));
  assert.match(load, /if \(result\.kind === 'stale'\) return;/);
  assert.match(load, /if \(result\.kind === 'clamped'\) \{[\s\S]*?setTotal\(result\.total\);\s*setListUrl\(\{ search, page: result\.page \}\);\s*return;\s*\}/);
  assert.match(load, /if \(result\.kind === 'error'\) \{\s*setError\(result\.message\);\s*setItems\(\[\]\);\s*setTotal\(0\);/);
  assert.match(load, /setItems\(result\.items\);\s*setTotal\(result\.total\);\s*\}\s*setLoading\(false\);/);
  assert.match(pageSrc, /useEffect\(\(\) => \(\) => loaderRef\.current\?\.abort\(\), \[\]\);/, 'unmount aborts the in-flight request');
});

test('loading and error states: Loading row, role=alert error', () => {
  assert.match(pageSrc, /emptyState\.kind === 'loading' \? \(\s*<tr style=\{ui\.tr\}><td colSpan=\{8\} style=\{ui\.td\}>Loading/);
  assert.match(pageSrc, /\{error \? <div style=\{\{ \.\.\.ui\.error, marginBottom: 12 \}\} role="alert">\{error\}<\/div> : null\}/);
});

test('zero-result search shows the search-specific empty state; out-of-range pages never show it', () => {
  assert.match(pageSrc, /const emptyState = describeReportListEmptyState\(\{ loading, itemCount: items\.length, total, search, canWrite \}\);/);
  assert.match(pageSrc, /data-testid=\{`report-list-\$\{emptyState\.kind\}`\}/);
  assert.match(pageSrc, /\{emptyState\.message\}\{emptyState\.hint \? ` \$\{emptyState\.hint\}` : ''\}/);
  assert.doesNotMatch(pageSrc, /No reports yet\./);
});

test('Refresh re-runs load() with the active search and page; import/AI settings untouched', () => {
  assert.match(pageSrc, /<button type="button" style=\{ui\.btn\} onClick=\{\(\) => load\(\)\.catch\(\(\) => \{\}\)\}>Refresh<\/button>/);
  // load() closes over the current URL-derived search and page, so Refresh keeps both.
  assert.match(pageSrc, /loaderRef\.current\.load\(\{ search, page \}\)[\s\S]*?\}, \[search, page, setListUrl\]\);/);
  assert.match(pageSrc, /<Link to="\/threat-intelligence\/threat-library\/ai-settings"/);
  assert.match(pageSrc, /onClick=\{\(\) => setImportOpen\(true\)\}/);
  assert.match(pageSrc, /<ImportIntelligenceModal\s+open=\{importOpen\}\s+onClose=\{\(\) => setImportOpen\(false\)\}\s+onImported=\{onImported\}/);
});

test('URL carries ?search=&page= and pager clicks write the URL (replace, not push)', () => {
  assert.match(pageSrc, /const \[searchParams, setSearchParams\] = useSearchParams\(\);/);
  assert.match(pageSrc, /const goToPage = \(next\) => setListUrl\(\{ search, page: next \}\);/);
  assert.doesNotMatch(pageSrc, /navigate\(`\/threat-intelligence\/threat-library\?/, 'pager never pushes history entries');
});

test('footer: Showing A-B of N (filtered total), Previous / Page X of Y / Next with existing button styles', () => {
  assert.match(pageSrc, /const pagination = describeReportListPagination\(\{ page, total, pageSize: REPORT_LIST_PAGE_SIZE \}\);/);
  assert.match(footer, /formatReportListShowingLabel\(\{ from: pagination\.from, to: pagination\.to, total, search \}\)/);
  assert.match(footer, /\{loading \? ' \\u00b7 Updating\\u2026' : ''\}/);
  assert.match(footer, /disabled=\{!pagination\.hasPrevious \|\| loading\}\s*onClick=\{\(\) => goToPage\(Math\.max\(1, page - 1\)\)\}\s*>\s*Previous/);
  assert.match(footer, /<span style=\{\{ color: '#e2e8f0', fontWeight: 600 \}\}>\{pagination\.pageLabel\}<\/span>/);
  assert.match(footer, /disabled=\{!pagination\.hasNext \|\| loading\}\s*onClick=\{\(\) => goToPage\(page \+ 1\)\}\s*>\s*Next/);
  assert.match(pageSrc, /const pagerBtn = \{ \.\.\.ui\.btn, minHeight: 30, padding: '4px 10px', fontSize: 12 \}/);
  assert.match(footer, /flexWrap: 'wrap'[\s\S]*?justifyContent: 'space-between'/, 'wraps on narrow screens');
  // Footer is present for every non-empty result (filtered or not) so the layout does not jump; hidden only at zero.
  assert.equal((footer.match(/\{total > 0 \? \(/g) || []).length, 1);
  assert.doesNotMatch(footer, /!loading && total/);
});

test('row click navigation is preserved', () => {
  assert.match(pageSrc, /onClick=\{\(\) => navigate\(`\/threat-intelligence\/threat-library\/\$\{row\.id\}`\)\}/);
});

// Column contract. Two list-only removals, both keeping the DB/API/MCP/THIB
// fields and the detail page untouched:
// - `Published` (threat_reports.published_at) is never set by the URL/PDF
//   import pipeline — only THIB bundle imports can carry it — so the list showed
//   "—" for every report.
// - `Type` (threat_reports.report_type) is free text the AI synthesis may or
//   may not return (no enum, no normalisation), rendered raw ("threat_report",
//   "—"); it stays searchable server-side and humanised on the detail page.
const LIST_COLUMNS = ['Report', 'Source', 'TLP', 'Entities', 'Indicators', 'Matched', 'Status', 'Imported'];

test('report list columns: no Published/Type columns, Imported kept last, order fixed', () => {
  const thead = pageSrc.slice(pageSrc.indexOf('<thead>'), pageSrc.indexOf('</thead>'));
  const headers = [...thead.matchAll(/<th style=\{ui\.th\}>([^<]+)<\/th>/g)].map((m) => m[1]);
  assert.deepEqual(headers, LIST_COLUMNS);
  assert.ok(!headers.includes('Published'));
  assert.ok(!headers.includes('Type'));
  assert.equal(headers.at(-1), 'Imported');
});

test('report list body renders exactly one cell per header and no published_at / report_type cell', () => {
  const rowStart = pageSrc.indexOf('items.map((row) => (');
  const rowEnd = pageSrc.indexOf('</tbody>', rowStart);
  const row = pageSrc.slice(rowStart, rowEnd);
  const cells = row.match(/<td style=\{(?:ui\.td|\{ \.\.\.ui\.td[^}]*\})\}/g) || [];
  assert.equal(cells.length, LIST_COLUMNS.length, 'body cells must align with the header columns');
  assert.doesNotMatch(row, /published_at|report_type/);
  assert.doesNotMatch(pageSrc, /published_at|report_type/, 'list page no longer reads either field at all');
  // The Source cell still carries the source_type sub-line (url / pdf / thib).
  assert.match(row, /\{row\.source_type \|\| '—'\}/);
  // Imported column still renders created_at through the canonical formatter.
  assert.match(row, /<td style=\{ui\.td\}>\{row\.created_at \? formatUserDateTime\(row\.created_at\) : '—'\}<\/td>\s*<\/tr>/);
});

test('empty/loading rows span exactly the header column count', () => {
  const spans = [...pageSrc.matchAll(/colSpan=\{(\d+)\}/g)].map((m) => Number(m[1]));
  assert.equal(spans.length, 2);
  for (const span of spans) assert.equal(span, LIST_COLUMNS.length);
});

test('report type metadata survives outside the list: detail header + Overview humanise it, list search still covers it', () => {
  const reportPageSrc = readFileSync(path.join(here, 'ThreatLibraryReportPage.jsx'), 'utf8');
  const overviewSrc = readFileSync(path.join(here, 'reportOverview.js'), 'utf8');
  assert.match(reportPageSrc, /\{report\.report_type \? \(\s*<span[^>]*>\{humanizeEnum\(report\.report_type\)\}<\/span>/);
  assert.match(overviewSrc, /pushIf\(items, 'Report type', report\.report_type \? humanizeEnum\(report\.report_type\) : null\);/);
  // The list search request is untouched: the server matches report_type server-side.
  assert.match(pageSrc, /api\.get\('\/threat-library\/reports', \{ params, signal \}\)/);
});

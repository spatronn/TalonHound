/**
 * Source-level contract for the Threat Library report list: toolbar (search +
 * TLP / Source / Imported filters + sort menu), status tabs, debounce, single
 * loader (stale guard + clamp), URL state, Refresh semantics, footer pager and
 * the loading / empty / error states.
 * Complements reportList.test.js (pure helpers), reportListLoader.test.js
 * (request state machine) and reportListRow.test.js (row presentation).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const pageSrc = readFileSync(path.join(here, 'ThreatLibraryPage.jsx'), 'utf8');
const cssSrc = readFileSync(path.join(here, 'reportList.css'), 'utf8');

const pageBody = pageSrc.slice(pageSrc.indexOf('export default function ThreatLibraryPage'));
const headerEnd = pageBody.indexOf('Import Intelligence\n');
const tableStart = pageBody.indexOf('<table');
const toolbar = pageBody.slice(headerEnd, tableStart);
const footer = pageBody.slice(pageBody.indexOf('{total > 0 ? ('), pageBody.indexOf('<ImportIntelligenceModal'));
const rowSrc = pageSrc.slice(pageSrc.indexOf('function ReportRow('), pageSrc.indexOf('export default function ThreatLibraryPage'));

test('search input renders in the toolbar above the table, outside the header actions and the table header', () => {
  assert.ok(headerEnd > 0 && tableStart > headerEnd);
  assert.match(toolbar, /<input\s+id="tl-report-search"\s+type="search"/);
  assert.match(toolbar, /placeholder="Search reports, titles, sources, tags\.\.\."/);
  assert.match(toolbar, /<label htmlFor="tl-report-search" className="tl-lib-sr-only">Search reports<\/label>/);
  const thead = pageBody.slice(pageBody.indexOf('<thead>'), pageBody.indexOf('</thead>'));
  assert.doesNotMatch(thead, /<input/);
  const headerActions = pageBody.slice(pageBody.indexOf('AI Settings'), headerEnd);
  assert.doesNotMatch(headerActions, /tl-report-search/);
  assert.match(toolbar, /maxLength=\{REPORT_LIST_SEARCH_MAX_LENGTH\}/);
});

test('typing updates searchInput; Escape clears it', () => {
  assert.match(toolbar, /value=\{searchInput\}/);
  assert.match(toolbar, /onChange=\{\(e\) => setSearchInput\(e\.target\.value\)\}/);
  assert.match(toolbar, /onKeyDown=\{\(e\) => \{ if \(e\.key === 'Escape'\) setSearchInput\(''\); \}\}/);
});

test('toolbar filters are the real API filters (TLP / Source / Imported) plus the sort menu; status lives in the tabs', () => {
  assert.match(toolbar, /<FilterSelect id="tl-filter-tlp" label="TLP" value=\{tlp\} options=\{REPORT_LIST_TLP_OPTIONS\} onChange=\{\(v\) => changeFilter\('tlp', v\)\} \/>/);
  assert.match(toolbar, /<FilterSelect id="tl-filter-source" label="Source" value=\{source\} options=\{REPORT_LIST_SOURCE_OPTIONS\} onChange=\{\(v\) => changeFilter\('source', v\)\} \/>/);
  assert.match(toolbar, /<FilterSelect id="tl-filter-imported" label="Imported" value=\{imported\} options=\{REPORT_LIST_IMPORTED_OPTIONS\} onChange=\{\(v\) => changeFilter\('imported', v\)\} \/>/);
  assert.match(toolbar, /id="tl-report-sort"[\s\S]*?value=\{sortMenu\.value\}[\s\S]*?options=\{sortMenu\.options\}[\s\S]*?onChange=\{chooseSort\}/);
  // Exactly one status control (the tabs): no duplicate status <select> that could disagree.
  assert.doesNotMatch(toolbar, /tl-filter-status/);
  assert.match(toolbar, /REPORT_LIST_STATUS_TABS\.map\(\(tab\) =>/);
  assert.match(toolbar, /aria-pressed=\{status === tab\.value\}/);
  assert.match(toolbar, /onClick=\{\(\) => changeFilter\('status', tab\.value\)\}/);
  // Selects are named by their visible caption.
  assert.match(pageSrc, /aria-labelledby=\{`\$\{id\}-label`\}/);
});

test('status tab counts come from the API phase_counts (whole filtered set), never from the loaded rows', () => {
  assert.match(toolbar, /const count = phaseCounts \? phaseCounts\[tab\.countKey\] : null;/);
  assert.match(pageBody, /setPhaseCounts\(result\.phaseCounts\);/);
  assert.doesNotMatch(pageBody, /items\.filter\(/, 'no client-side counting or filtering of the page');
  // Unknown counts render no number rather than a guess.
  assert.match(toolbar, /\{count != null \? \(/);
});

test('every filter change (toolbar or tab) restarts at page 1 and keeps search + sort', () => {
  assert.match(pageBody, /const changeFilter = \(key, value\) => setListUrl\(\{ search, page: 1, pageSize, sort, order, \.\.\.filters, \[key\]: value \}\);/);
  assert.match(pageBody, /const clearFilters = \(\) => \{\s*setSearchInput\(''\);\s*setListUrl\(\{ search: '', page: 1, pageSize, sort, order \}\);\s*\};/);
  assert.match(pageBody, /const chooseSort = \(value\) => \{\s*const next = parseReportListSortMenuValue\(value\);\s*setListUrl\(\{ search, page: 1, pageSize, sort: next\.sort, order: next\.order, \.\.\.filters \}\);/);
});

test('URL is the single source of truth for search, page, size, sort and filters; the field is the only local search state', () => {
  assert.match(pageBody, /const \{ search, page, pageSize, sort, order, status, tlp, source, imported \} = useMemo\(\s*\(\) => parseReportListUrlState\(searchParams\),\s*\[searchParams\]\s*\);/);
  assert.match(pageBody, /const filters = useMemo\(\(\) => \(\{ status, tlp, source, imported \}\), \[status, tlp, source, imported\]\);/);
  assert.match(pageBody, /const \[searchInput, setSearchInput\] = useState\(search\);/);
  assert.doesNotMatch(pageBody, /const \[(search|page|pageSize|status|tlp|source|imported), set\w+\] = useState/, 'no shadow copies of URL state that could fight the router');
  // Every URL write goes through one guarded, identity-stable writer (replace, not push).
  assert.match(pageBody, /const setListUrl = useCallback\(\(next\) => \{\s*const params = buildReportListUrlSearchParams\(next\);\s*const router = routerRef\.current;\s*if \(params\.toString\(\) !== router\.searchParams\.toString\(\)\) router\.setSearchParams\(params, \{ replace: true \}\);\s*\}, \[\]\);/);
  assert.equal((pageSrc.match(/setSearchParams\(params/g) || []).length, 1);
});

test('requests are debounced; a changed term (including clearing) resets to page 1 and keeps the filters', () => {
  const debounce = pageBody.slice(pageBody.indexOf('const t = setTimeout(() => {'), pageBody.indexOf('}, [searchInput, search, pageSize, sort, order, filters, setListUrl]);'));
  assert.match(debounce, /const next = normalizeReportListSearch\(searchInput\);\s*if \(next !== search\) setListUrl\(\{ search: next, page: 1, pageSize, sort, order, \.\.\.filters \}\);/);
  assert.match(debounce, /\}, REPORT_LIST_SEARCH_DEBOUNCE_MS\);\s*return \(\) => clearTimeout\(t\);/);
  // load depends on the URL-derived state only, never on the raw input.
  assert.match(pageBody, /\}, \[search, page, pageSize, sort, order, filters, setListUrl\]\);\s*useEffect\(\(\) => \{\s*load\(\)\.catch/);
});

test('Back/Forward and shared links: the field follows the URL term; hand-typed URLs are canonicalised (fixed point, no loop)', () => {
  assert.match(pageBody, /setSearchInput\(\(prev\) => \(normalizeReportListSearch\(prev\) === search \? prev : search\)\);\s*\}, \[search\]\);/);
  assert.match(pageBody, /useEffect\(\(\) => \{\s*setListUrl\(\{ search, page, pageSize, sort, order, \.\.\.filters \}\);\s*\}, \[search, page, pageSize, sort, order, filters, setListUrl\]\);/);
});

test('every list request (initial, search, filter, page, Refresh) goes through the single loader', () => {
  assert.match(pageBody, /loaderRef\.current = createReportListLoader\(\{\s*pageSize: REPORT_LIST_PAGE_SIZE,\s*fetchPage: async \(params, signal\) => \(await api\.get\('\/threat-library\/reports', \{ params, signal \}\)\)\.data\s*\}\);/);
  assert.match(pageBody, /const result = await loaderRef\.current\.load\(\{ search, page, pageSize, sort, order, \.\.\.filters \}\);/);
  assert.equal((pageSrc.match(/api\.get\(/g) || []).length, 1, 'exactly one list request site');
  assert.doesNotMatch(pageSrc, /\.slice\(/, 'no client-side slicing of a larger result set');
  assert.doesNotMatch(pageSrc, /limit: 100/);
});

test('stale outcomes are ignored, clamped outcomes move to the last valid page and keep loading', () => {
  const load = pageBody.slice(pageBody.indexOf('const load = useCallback'), pageBody.indexOf('}, [search, page, pageSize, sort, order, filters, setListUrl]);'));
  assert.match(load, /if \(result\.kind === 'stale'\) return;/);
  assert.match(load, /if \(result\.kind === 'clamped'\) \{[\s\S]*?setTotal\(result\.total\);[\s\S]*?setListUrl\(\{ search, page: result\.page, pageSize, sort, order, \.\.\.filters \}\);\s*return;\s*\}/);
  assert.match(load, /if \(result\.kind === 'error'\) \{\s*setError\(result\.message\);\s*setItems\(\[\]\);\s*setTotal\(0\);\s*setPhaseCounts\(null\);/);
  assert.match(load, /setItems\(result\.items\);\s*setTotal\(result\.total\);\s*setPhaseCounts\(result\.phaseCounts\);\s*\}\s*setLoading\(false\);/);
  assert.match(pageBody, /useEffect\(\(\) => \(\) => loaderRef\.current\?\.abort\(\), \[\]\);/, 'unmount aborts the in-flight request');
});

test('loading / empty / error states: one placeholder row spanning all columns; errors are announced once and never shown as an empty library', () => {
  assert.match(pageBody, /const emptyState = describeReportListEmptyState\(\{\s*loading: loading && !showRows,\s*itemCount: items\.length,\s*total,\s*search,\s*canWrite,\s*error,\s*filters\s*\}\);/);
  assert.match(pageBody, /data-testid=\{`report-list-\$\{emptyState\.kind\}`\}/);
  assert.match(pageBody, /role=\{emptyState\.kind === 'error' \? 'alert' : undefined\}/);
  assert.equal((pageSrc.match(/role="alert"/g) || []).length, 0, 'no second, page-level error banner');
  assert.match(pageBody, /emptyState\.kind === 'no_match' \? \([\s\S]*?onClick=\{clearFilters\}>Clear filters</);
  assert.match(pageBody, /emptyState\.kind === 'error' \? \([\s\S]*?onClick=\{\(\) => load\(\)\.catch\(\(\) => \{\}\)\}>Try again</);
  // Rows on screen stay (dimmed) while the next request runs.
  assert.match(pageBody, /className=\{`tl-lib-table-wrap\$\{loading && showRows \? ' is-updating' : ''\}`\} aria-busy=\{loading\}/);
  assert.doesNotMatch(pageSrc, /No reports yet\./);
});

test('Refresh re-runs load() with the active state; AI Settings / Import Intelligence unchanged', () => {
  assert.match(pageBody, /<button type="button" style=\{ui\.btn\} onClick=\{\(\) => load\(\)\.catch\(\(\) => \{\}\)\}>\s*\{ListIcons\.refresh\}\s*Refresh\s*<\/button>/);
  assert.match(pageBody, /\{isAdmin \? \(\s*<Link to=\{`\$\{REPORT_PATH\}\/ai-settings`\}/);
  assert.match(pageBody, /\{canWrite \? \(\s*<button type="button" style=\{ui\.btnPrimary\} onClick=\{\(\) => setImportOpen\(true\)\}>/);
  assert.match(pageBody, /<ImportIntelligenceModal\s+open=\{importOpen\}\s+onClose=\{\(\) => setImportOpen\(false\)\}\s+onImported=\{onImported\}/);
  assert.match(pageSrc, /const REPORT_PATH = '\/threat-intelligence\/threat-library';/);
});

test('pager clicks write the URL (replace, not push); size change restarts at page 1; header sort cycles', () => {
  assert.match(pageBody, /const \[searchParams, setSearchParams\] = useSearchParams\(\);/);
  assert.match(pageBody, /const goToPage = \(next\) => setListUrl\(\{ search, page: next, pageSize, sort, order, \.\.\.filters \}\);/);
  assert.match(pageBody, /const changePageSize = \(next\) => setListUrl\(\{ search, page: 1, pageSize: next, sort, order, \.\.\.filters \}\);/);
  assert.match(pageBody, /const next = cycleReportListSort\(sort, order, column\);\s*setListUrl\(\{ search, page: 1, pageSize, sort: next\.sort, order: next\.order, \.\.\.filters \}\);/);
  assert.doesNotMatch(pageSrc, /navigate\(`\/threat-intelligence\/threat-library\?/, 'pager never pushes history entries');
});

test('footer: Showing A-B of N (filtered total), numbered pages with prev / next and the 25 / 50 size selector', () => {
  assert.match(pageBody, /const pagination = describeReportListPagination\(\{ page, total, pageSize \}\);/);
  assert.match(pageBody, /const pageItems = buildReportListPageItems\(pagination\.page, pagination\.totalPages\);/);
  assert.match(footer, /formatReportListShowingLabel\(\{ from: pagination\.from, to: pagination\.to, total, search, filtered \}\)/);
  assert.match(footer, /\{loading \? ' (?:\\u00b7|·) Updating(?:\\u2026|…)' : ''\}/);
  assert.match(footer, /aria-label="Previous page"\s+disabled=\{!pagination\.hasPrevious \|\| loading\}\s+onClick=\{\(\) => goToPage\(Math\.max\(1, page - 1\)\)\}/);
  assert.match(footer, /aria-label="Next page"\s+disabled=\{!pagination\.hasNext \|\| loading\}\s+onClick=\{\(\) => goToPage\(page \+ 1\)\}/);
  assert.match(footer, /aria-current=\{item === pagination\.page \? 'page' : undefined\}/);
  assert.match(footer, /<span className="tl-lib-sr-only">\{pagination\.pageLabel\}<\/span>/);
  assert.match(footer, /<label htmlFor="tl-report-page-size"[^>]*>\s*Rows per page\s*<select\s+id="tl-report-page-size"\s+value=\{pageSize\}\s+onChange=\{\(e\) => changePageSize\(Number\(e\.target\.value\)\)\}\s*>/);
  assert.match(footer, /\{REPORT_LIST_PAGE_SIZE_OPTIONS\.map\(\(n\) => \(\s*<option key=\{n\} value=\{n\}>\{n\}<\/option>\s*\)\)\}/);
  assert.ok(footer.indexOf('tl-report-page-size') < footer.indexOf('Previous page'));
  // Footer is present for every non-empty result so the layout does not jump; hidden only at zero.
  assert.equal((footer.match(/\{total > 0 \? \(/g) || []).length, 1);
});

test('row navigation: the title is a real link (keyboard / new tab) and the row click ignores inner links', () => {
  assert.match(rowSrc, /<Link to=\{`\$\{REPORT_PATH\}\/\$\{row\.id\}`\} className="tl-lib-report__title" title=\{title\}>\{title\}<\/Link>/);
  assert.match(rowSrc, /<tr className="tl-lib-row" onClick=\{\(e\) => onOpen\(e, row\)\}>/);
  assert.match(pageBody, /if \(e\.target instanceof Element && e\.target\.closest\('a, button, input, select, label'\)\) return;/);
  assert.match(pageBody, /navigate\(`\$\{REPORT_PATH\}\/\$\{row\.id\}`\);/);
});

test('source link: only an http(s) URL from describeReportSource, new tab with noopener', () => {
  assert.match(rowSrc, /\{source\.href \? \(\s*<a\s+href=\{source\.href\}\s+target="_blank"\s+rel="noopener noreferrer"/);
  assert.equal((rowSrc.match(/<a\s/g) || []).length, 1, 'the source icon is the only raw anchor in a row');
});

// Column contract. `Published` is the original report publication date
// (`published_at` / `published_date` via formatPublicationDate). `Imported`
// is created_at. They are never substituted for each other. `Type` stays off
// the list (free text; still on the detail page). Entities / Indicators /
// Matched IOCs are grouped under Intelligence but each stays sortable.
const LIST_COLUMNS = ['Report', 'Source', 'TLP', 'Intelligence', 'Status', 'Published', 'Imported'];

test('report list columns: Intelligence groups the three counters, Published immediately before Imported, Type absent', () => {
  const thead = pageBody.slice(pageBody.indexOf('<thead>'), pageBody.indexOf('</thead>'));
  const headers = [...thead.matchAll(/<(SortableTh label="([^"]+)"|IntelligenceTh)/g)].map((m) => m[2] || 'Intelligence');
  assert.deepEqual(headers, LIST_COLUMNS);
  assert.ok(!headers.includes('Type'));
  const intel = pageSrc.slice(pageSrc.indexOf('const INTEL_COLUMNS'), pageSrc.indexOf('function IntelligenceTh'));
  assert.deepEqual([...intel.matchAll(/column: '(\w+)'/g)].map((m) => m[1]), ['entities', 'indicators', 'matched']);
  assert.match(pageSrc, /aria-sort=\{reportListAriaSort\(sort, order, column\)\}/);
  assert.match(pageSrc, /aria-sort=\{active \? reportListAriaSort\(sort, order, active\.column\) : 'none'\}/);
  assert.equal((pageSrc.match(/<col className="tl-lib-col--/g) || []).length, LIST_COLUMNS.length);
});

test('report list body: one cell per column; Published from the publication date, Imported from created_at, counters from the API', () => {
  const cells = rowSrc.match(/<td[\s>]/g) || [];
  assert.equal(cells.length, LIST_COLUMNS.length, 'body cells must align with the header columns');
  assert.match(pageSrc, /import \{ formatPublicationDate, publicationDateTitle \} from '\.\/publicationDate\.js'/);
  assert.match(rowSrc, /\{formatPublicationDate\(row\) \|\| '—'\}/);
  assert.doesNotMatch(rowSrc, /formatPublicationDate\(row\) \|\| formatUserDateTime/);
  assert.doesNotMatch(rowSrc, /published_at/);
  assert.match(rowSrc, /const imported = describeReportImported\(row\);/);
  assert.doesNotMatch(rowSrc, /report_type/);
  assert.match(rowSrc, /\{describeReportIntelligence\(row\)\.map\(\(m\) => \(/);
  // No counting in the page: every number comes through the row module from canonical API fields.
  assert.doesNotMatch(rowSrc, /candidates/);
  assert.doesNotMatch(rowSrc, /matched_count|total_unique_indicator_count|entity_count/);
});

test('empty/loading rows span exactly the header column count', () => {
  assert.match(pageSrc, /const COLUMN_COUNT = 7;/);
  assert.equal(LIST_COLUMNS.length, 7);
  const spans = [...pageSrc.matchAll(/colSpan=\{(\w+)\}/g)].map((m) => m[1]);
  assert.equal(spans.length, 2);
  for (const span of spans) assert.equal(span, 'COLUMN_COUNT');
});

test('responsive contract: container queries on the section (not the viewport), contained table scroll, positioned scroller', () => {
  assert.match(pageBody, /<section style=\{ui\.section\} className="tl-lib">/);
  assert.match(cssSrc, /\.tl-lib \{\s*position: relative;\s*container-type: inline-size;\s*container-name: tl-lib;/);
  assert.match(cssSrc, /@container tl-lib \(max-width: 919px\) \{\s*\.tl-lib \.tl-lib-table-wrap \{\s*overflow-x: auto;/);
  // The scroller must be the containing block of the absolute sr-only helpers,
  // otherwise they escape it and widen the whole page on phones.
  assert.match(cssSrc, /\.tl-lib \.tl-lib-table-wrap \{[^}]*position: relative;[^}]*overflow: hidden;/);
  assert.match(cssSrc, /\.tl-lib \.tl-lib-table \{[^}]*table-layout: fixed;/);
  assert.match(pageSrc, /import '\.\/reportList\.css';/);
});

test('report type metadata survives outside the list: detail header + Overview humanise it; the list request shape is unchanged', () => {
  const reportPageSrc = readFileSync(path.join(here, 'ThreatLibraryReportPage.jsx'), 'utf8');
  const overviewSrc = readFileSync(path.join(here, 'reportOverview.js'), 'utf8');
  assert.match(reportPageSrc, /\{report\.report_type \? \(\s*<span[^>]*>\{humanizeEnum\(report\.report_type\)\}<\/span>/);
  assert.match(overviewSrc, /pushIf\(items, 'Report type', report\.report_type \? humanizeEnum\(report\.report_type\) : null\);/);
  assert.match(pageSrc, /api\.get\('\/threat-library\/reports', \{ params, signal \}\)/);
});

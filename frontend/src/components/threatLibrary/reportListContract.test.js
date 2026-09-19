/**
 * Source-level contract for the Threat Library report-list search: toolbar
 * placement, debounce, stale-request guard, URL state, Refresh semantics and
 * the search-specific empty state. Complements reportList.test.js (pure helpers).
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

test('search input renders above the table, outside the header actions and the table header', () => {
  assert.ok(headerEnd > 0 && tableStart > headerEnd);
  assert.match(toolbar, /<input\s+id="tl-report-search"\s+type="search"/);
  assert.match(toolbar, /placeholder="Search reports\.\.\."/);
  assert.match(toolbar, /<label htmlFor="tl-report-search" style=\{srOnly\}>Search reports<\/label>/);
  assert.match(toolbar, /maxWidth: 380/, 'desktop width ~320-400px, fluid below');
  // Not inside <thead>, not next to AI Settings / Refresh / Import Intelligence.
  const thead = pageSrc.slice(pageSrc.indexOf('<thead>'), pageSrc.indexOf('</thead>'));
  assert.doesNotMatch(thead, /<input/);
  const headerActions = pageSrc.slice(pageSrc.indexOf('AI Settings'), headerEnd);
  assert.doesNotMatch(headerActions, /tl-report-search/);
  // Existing input styling, bounded to the API max length.
  assert.match(pageSrc, /const searchInputStyle = \{ \.\.\.ui\.input, padding: '8px 12px', fontSize: 13, minHeight: 36 \}/);
  assert.match(toolbar, /maxLength=\{REPORT_LIST_SEARCH_MAX_LENGTH\}/);
});

test('typing updates searchInput; Escape clears it', () => {
  assert.match(toolbar, /value=\{searchInput\}/);
  assert.match(toolbar, /onChange=\{\(e\) => setSearchInput\(e\.target\.value\)\}/);
  assert.match(toolbar, /onKeyDown=\{\(e\) => \{ if \(e\.key === 'Escape'\) setSearchInput\(''\); \}\}/);
});

test('requests are debounced: the request-driving `search` state only changes after the timer', () => {
  assert.match(pageSrc, /const \[searchInput, setSearchInput\] = useState\(initial\.search\);\s*const \[search, setSearch\] = useState\(initial\.search\);/);
  const debounce = pageSrc.slice(pageSrc.indexOf('const t = setTimeout(() => {'), pageSrc.indexOf('}, [searchInput]);'));
  assert.match(debounce, /normalizeReportListSearch\(searchInput\)/);
  assert.match(debounce, /setSearch\(\(prev\) => \(prev === next \? prev : next\)\)/, 'unchanged term does not re-request');
  assert.match(debounce, /\}, REPORT_LIST_SEARCH_DEBOUNCE_MS\);\s*return \(\) => clearTimeout\(t\);/);
  // The load callback depends on the debounced term, never on the raw input.
  assert.match(pageSrc, /\}, \[search\]\);\s*useEffect\(\(\) => \{\s*load\(\)\.catch/);
  assert.doesNotMatch(pageSrc, /\}, \[searchInput, /);
});

test('list request sends the search param through the shared builder and no other params change', () => {
  assert.match(pageSrc, /const params = buildReportListQueryParams\(\{ search, limit: REPORT_LIST_PAGE_SIZE, offset: 0 \}\);/);
  assert.match(pageSrc, /api\.get\('\/threat-library\/reports', \{ params, signal: controller\.signal \}\)/);
  assert.doesNotMatch(pageSrc, /params: \{ limit: 100, offset: 0 \}/, 'old inline params replaced by the builder');
});

test('stale responses cannot overwrite newer results (sequence token + abort)', () => {
  assert.match(pageSrc, /const seq = \+\+requestSeqRef\.current;/);
  assert.match(pageSrc, /if \(abortRef\.current\) abortRef\.current\.abort\(\);\s*const controller = new AbortController\(\);/);
  assert.match(pageSrc, /if \(seq !== requestSeqRef\.current\) return;\s*setItems\(data\?\.items \|\| \[\]\);/);
  assert.match(pageSrc, /if \(err\?\.code === 'ERR_CANCELED' \|\| err\?\.name === 'CanceledError' \|\| err\?\.name === 'AbortError'\) return;/);
  assert.match(pageSrc, /if \(seq === requestSeqRef\.current\) setLoading\(false\);/);
});

test('loading and error states are unchanged: Loading row, role=alert error, items reset on failure', () => {
  assert.match(pageSrc, /emptyState\.kind === 'loading' \? \(\s*<tr style=\{ui\.tr\}><td colSpan=\{10\} style=\{ui\.td\}>Loading/);
  assert.match(pageSrc, /\{error \? <div style=\{\{ \.\.\.ui\.error, marginBottom: 12 \}\} role="alert">\{error\}<\/div> : null\}/);
  assert.match(pageSrc, /setError\(err\?\.response\?\.data\?\.message \|\| 'Failed to load Threat Library'\);\s*setItems\(\[\]\);\s*setTotal\(0\);/);
});

test('zero-result search shows the search-specific empty state, not the empty-library copy', () => {
  assert.match(pageSrc, /const emptyState = describeReportListEmptyState\(\{ loading, itemCount: items\.length, search, canWrite \}\);/);
  assert.match(pageSrc, /data-testid=\{`report-list-\$\{emptyState\.kind\}`\}/);
  assert.match(pageSrc, /\{emptyState\.message\}\{emptyState\.hint \? ` \$\{emptyState\.hint\}` : ''\}/);
  assert.doesNotMatch(pageSrc, /No reports yet\./, 'copy lives in the descriptor so both states are tested there');
});

test('Refresh re-runs load() with the active search preserved; import/AI settings untouched', () => {
  assert.match(pageSrc, /<button type="button" style=\{ui\.btn\} onClick=\{\(\) => load\(\)\.catch\(\(\) => \{\}\)\}>Refresh<\/button>/);
  // load() closes over the debounced `search` (its only dependency), so Refresh keeps the filter.
  assert.match(pageSrc, /\}, \[search\]\);/);
  assert.match(pageSrc, /<Link to="\/threat-intelligence\/threat-library\/ai-settings"/);
  assert.match(pageSrc, /onClick=\{\(\) => setImportOpen\(true\)\}/);
  assert.match(pageSrc, /<ImportIntelligenceModal\s+open=\{importOpen\}\s+onClose=\{\(\) => setImportOpen\(false\)\}\s+onImported=\{onImported\}/);
});

test('URL carries ?search= (replace, not push) and seeds the field on load', () => {
  assert.match(pageSrc, /const \[searchParams, setSearchParams\] = useSearchParams\(\);/);
  assert.match(pageSrc, /const initial = useMemo\(\(\) => parseReportListUrlState\(searchParams\), \[\]\);/);
  assert.match(pageSrc, /const next = buildReportListUrlSearchParams\(\{ search \}\);\s*if \(next\.toString\(\) !== searchParams\.toString\(\)\) \{\s*setSearchParams\(next, \{ replace: true \}\);/);
});

test('row click navigation and the showing counter are preserved; counter uses the filtered total', () => {
  assert.match(pageSrc, /onClick=\{\(\) => navigate\(`\/threat-intelligence\/threat-library\/\$\{row\.id\}`\)\}/);
  assert.match(pageSrc, /\{formatReportListShowingLabel\(\{ shown: items\.length, total, search \}\)\}/);
  assert.match(pageSrc, /setTotal\(Number\(data\?\.total \|\| 0\)\);/);
});

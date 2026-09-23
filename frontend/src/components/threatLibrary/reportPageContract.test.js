/**
 * Source-level contract for the redesigned report page: sections, header
 * actions, inert indicator values, hidden-empty metadata and unchanged
 * review / RBAC gates. Complements the pure-module tests (reportOverview,
 * reportTabs, reportDisplayLabels, candidateDetail).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const pageSrc = readFileSync(path.join(here, 'ThreatLibraryReportPage.jsx'), 'utf8');
const drawerSrc = readFileSync(path.join(here, 'IndicatorDetailDrawer.jsx'), 'utf8');
const partsSrc = readFileSync(path.join(here, 'reportPageParts.jsx'), 'utf8');
const mainSrc = readFileSync(path.join(here, '..', '..', 'main.jsx'), 'utf8');

test('page is split into Overview / Indicators / Entities / Source with the Overview default', () => {
  assert.match(pageSrc, /<ReportTabBar tabs=\{tabs\} active=\{view\} onChange=\{setView\} \/>/);
  for (const v of ['OVERVIEW', 'INDICATORS', 'ENTITIES', 'SOURCE']) {
    assert.match(pageSrc, new RegExp(`view === REPORT_VIEWS\\.${v} \\? \\(`), `panel for ${v}`);
  }
  assert.match(pageSrc, /useState\(\(\) => parseReportView\(searchParams\)\)/);
  assert.match(pageSrc, /withReportView\(serializeReviewTableUrlState\(/, 'section is carried next to the review-table params');
});

test('header: Finalize is the primary CTA, Export secondary, Delete lives in the overflow menu behind isAdmin', () => {
  assert.match(pageSrc, /\{canWrite && canFinalize\(report\) \? \([\s\S]*?style=\{ui\.btnPrimary\}[\s\S]*?Finalize report/);
  assert.match(pageSrc, /Export THIB/);
  assert.match(pageSrc, /isAdmin \? \{ id: 'delete', label: 'Delete report', danger: true[\s\S]*?removeReport\(\)/);
  assert.doesNotMatch(pageSrc, /style=\{ui\.btnDanger\}[\s\S]{0,200}Delete/, 'no standalone red Delete button');
  assert.match(pageSrc, /window\.confirm\('Delete this Threat Library report permanently\?'\)/, 'delete confirmation unchanged');
  assert.match(pageSrc, /if \(!isAdmin\) return;\s*const ok = window\.confirm/, 'delete stays admin-only');
});

test('indicator values render as inert text: never an anchor in the table or the drawer', () => {
  const table = pageSrc.slice(pageSrc.indexOf('<table className="tl-table"'), pageSrc.indexOf('</table>'));
  assert.doesNotMatch(table, /<a\b/, 'no anchors inside the indicator table');
  assert.doesNotMatch(table, /href=/);
  assert.match(table, /<span className="tl-value" data-testid="indicator-value">\{value \|\| '—'\}<\/span>/);
  assert.doesNotMatch(drawerSrc, /<a\b/, 'no anchors in the detail drawer');
  assert.doesNotMatch(drawerSrc, /href=/);
  // The only anchor on the page is the explicit "Open source" action, gated on http(s).
  const anchors = pageSrc.match(/<a\b/g) || [];
  assert.equal(anchors.length, 1);
  assert.match(pageSrc, /\{url && isOpenableSourceUrl\(url\) \? \(\s*<a\s+href=\{url\}\s+target="_blank"\s+rel="noopener noreferrer"/);
});

test('enum cells go through display labels; canonical values feed only comparisons and requests', () => {
  assert.match(pageSrc, /candidateTypeLabel\(c\.candidate_type\)/);
  assert.match(pageSrc, /assessmentLabel\(c\.assessment\)/);
  assert.match(pageSrc, /roleLabel\(c\.role\)/);
  assert.match(pageSrc, /reviewStatusLabel\(c\.review_status\)/);
  assert.match(pageSrc, /matchCellLabel\(c\)/);
  assert.doesNotMatch(pageSrc, /<td[^>]*>\{c\.candidate_type\}<\/td>/, 'raw candidate_type no longer rendered');
  assert.doesNotMatch(pageSrc, /<td[^>]*>\{c\.role \|\| '—'\}<\/td>/, 'raw role no longer rendered');
  assert.doesNotMatch(pageSrc, /<td[^>]*>\{c\.review_status \|\| '—'\}<\/td>/, 'raw review_status no longer rendered');
  // Request bodies still carry canonical values / ids only (eligibility-filtered, see selectionForAction).
  assert.match(pageSrc, /body\.candidate_ids = ids;/);
  assert.match(pageSrc, /const \{ ids, excluded \} = selectionForAction\(action, selectedRows\);/);
  assert.match(pageSrc, /candidate_ids: ids,\s*confirm: false/);
  assert.match(pageSrc, /candidate_ids: ids,\s*confirm: true/);
  assert.match(pageSrc, /c\.candidate_type === 'cidr'/, 'canonical comparison for the CIDR note');
});

test('overview metrics and report details come from the loaded rows, never hardcoded', () => {
  assert.match(pageSrc, /const metrics = useMemo\(\(\) => buildOverviewMetrics\(candidates, report\)/);
  assert.match(pageSrc, /\{metrics\.available \? \(/);
  for (const id of ['metric-candidates', 'metric-new', 'metric-existing', 'metric-needs-review', 'metric-progress']) {
    assert.match(pageSrc, new RegExp(`testId="${id}"|data-testid="${id}"`));
  }
  assert.match(pageSrc, /`\$\{metrics\.reviewed\}\/\$\{metrics\.total\}`/);
  assert.match(pageSrc, /className="tl-statstrip"/, 'compact strip, not KPI cards');
  assert.doesNotMatch(pageSrc, /className="tl-metrics"/);
  assert.match(pageSrc, /buildReportDetails\(report, \{/);
  assert.match(pageSrc, /<DetailList items=\{reportDetails\} testId="report-details" className="tl-dl--info" \/>/);
  assert.match(pageSrc, /const filterCounts = useMemo\(\(\) => buildReviewFilterCounts\(candidates\)/);
  assert.match(pageSrc, /\{filterCounts\[f\.id\] \?\? 0\}/);
  assert.doesNotMatch(pageSrc, /<Meta label="File name"/, 'empty file name / sha256 rows are gone');
  assert.doesNotMatch(pageSrc, /<Meta label="SHA-256"/);
});

test('review workflow gates are unchanged: canWrite for actions, showReview for the table, mutations only from the toolbar', () => {
  assert.match(pageSrc, /\{canWrite \? \(\s*<div className="tl-bulkbar"/);
  assert.match(pageSrc, /\{showReview \? \(/);
  assert.match(pageSrc, /\{showPreliminary \? \(\s*<PreliminaryIndicatorsCard/);
  assert.match(pageSrc, /async function runReview\(action\) \{\s*if \(!canWrite\) return;/);
  assert.match(pageSrc, /async function createIocs\(\) \{\s*if \(!canWrite \|\| !selected\.size\) return;/);
  // The toolbar renders the filter-aware descriptor: no hardcoded action buttons.
  assert.match(pageSrc, /className="tl-bulkbar"[\s\S]*?\{toolbar\.actions\.map\(\(a\) => \([\s\S]*?onClick=\{\(\) => runReview\(a\.id\)\.catch/);
  assert.match(pageSrc, /describeReviewToolbar\(\{ filter, selectedRows, busy: Boolean\(busy\) \}\)/);
  assert.doesNotMatch(pageSrc, /runReview\('(approve|context_only|ignore|create_iocs|approve_high_confidence_malicious)'\)/, 'no filter-blind action buttons');
  assert.match(pageSrc, /SourceUrlEditor[\s\S]*?canWrite=\{canWrite\}/);
  assert.match(pageSrc, /if \(!canWrite\) return;\s*setBusy\('export'\)/);
  assert.match(pageSrc, /if \(!canWrite\) return;\s*setBusy\('finalize'\)/);
});

test('one scroll model: no nested max-height table scroller, sticky header offset follows the bulk bar', () => {
  assert.doesNotMatch(pageSrc, /maxHeight: 'min\(70vh, 720px\)'/);
  assert.match(pageSrc, /'--tl-sticky-offset': `\$\{stickyOffset\}px`/);
  assert.match(pageSrc, /ref=\{bulkBarRef\}/);
});

test('entities are grouped by canonical type and only detailed when data exists', () => {
  assert.match(pageSrc, /const entityGroups = useMemo\(\(\) => groupEntitiesByType\(entities\)/);
  assert.match(pageSrc, /className="tl-entity-grid"/);
  assert.match(pageSrc, /data-entity-type=\{group\.type\}/);
  assert.match(pageSrc, /\{e\.description \? <div className="tl-entity-card__desc">/, 'description kept when present');
  assert.match(pageSrc, /\{e\.evidence_text \? <blockquote className="tl-quote">/, 'evidence kept when present');
  assert.match(pageSrc, /\{conf \? <span className="tl-entity-card__conf"/, 'confidence only when present');
  assert.doesNotMatch(pageSrc, /<th style=\{ui\.th\}>Confidence<\/th>\s*<th style=\{ui\.th\}>Evidence<\/th>/, 'no empty Confidence/Evidence entity table');
});

test('drawer is read-only: no review mutation controls, no review handler, no generic feedback', () => {
  assert.doesNotMatch(drawerSrc, /onReview|runReview|createIocs|api\.post/, 'drawer has no mutation path');
  assert.doesNotMatch(drawerSrc, /candidateActions|describeCandidateActions/);
  assert.doesNotMatch(drawerSrc, />\s*(Approve|Context only|Ignore|Create IOC)\s*</, 'no review buttons rendered');
  assert.doesNotMatch(drawerSrc, /data-testid="drawer-actions"/);
  const drawerButtons = drawerSrc.match(/aria-label="[^"]+"/g) || [];
  assert.deepEqual(
    drawerButtons.filter((a) => /Close details|Previous indicator|Next indicator/.test(a)).length,
    3,
    'the only controls are close, previous and next (plus copy)'
  );
  assert.match(pageSrc, /<IndicatorDetailDrawer\s+candidate=\{openCandidate\}\s+onClose=\{\(\) => setOpenCandidateId\(null\)\}\s+position=\{drawerPosition\}\s+onNavigate=\{navigateDrawer\}\s*\/>/);
  assert.doesNotMatch(pageSrc, /Review action applied\./, 'generic feedback replaced by action-specific text');
  assert.match(pageSrc, /describeReviewFeedback\(action, \{/);
  assert.match(pageSrc, /describeCreateIocFeedback\(\{/);
  // Status stays visible, read-only, in the body.
  assert.match(drawerSrc, /<Field label="Review">/);
  assert.match(drawerSrc, /<Field label="IOC result">/);
  assert.match(drawerSrc, /<Field label="Existing match">/);
});

test('drawer: previous / next walk the filtered set, row trigger says what it opens', () => {
  assert.match(pageSrc, /describeDrawerPosition\(filtered, openCandidateId, paged\.pageSize\)/);
  assert.match(pageSrc, /function navigateDrawer\(nextId\)[\s\S]*?setPage\(target\.page\);\s*setOpenCandidateId\(nextId\);/);
  assert.doesNotMatch(pageSrc.slice(pageSrc.indexOf('function navigateDrawer'), pageSrc.indexOf('function onRowClick')), /setSelected/, 'navigation keeps the selection');
  assert.match(pageSrc, /aria-label=\{`View details for \$\{value \|\| c\.id\}`\}[\s\S]*?aria-haspopup="dialog"/);
  assert.match(drawerSrc, /aria-label="Previous indicator"/);
  assert.match(drawerSrc, /aria-label="Next indicator"/);
  assert.match(drawerSrc, /disabled=\{position\.prevId == null\}/);
  assert.match(drawerSrc, /disabled=\{position\.nextId == null\}/);
  assert.match(drawerSrc, /e\.key === 'Escape'/);
  assert.match(drawerSrc, /aria-label="Close details"/);
});

test('source card: identity first, explicit open / copy, low-emphasis edit, no fabricated organisation', () => {
  assert.match(pageSrc, /className="tl-source-card"/);
  assert.match(pageSrc, /data-testid="source-identity"[\s\S]*?\{report\.source_name \|\| report\.source_file_name \|\| sourceTypeLabel\(report\.source_type\)/);
  assert.doesNotMatch(pageSrc, /ncsc|infoblox|socradar/i, 'no hardcoded domain → organisation mapping');
  assert.match(pageSrc, /<CopyUrlButton value=\{url\} \/>/);
  assert.match(pageSrc, /className="tl-ghost-btn"[\s\S]*?\{value \? 'Edit' : 'Add source URL'\}/);
  assert.match(pageSrc, /<details className="tl-artifacts"/);
});

test('finalize "Show Needs Review" lands on the Indicators section', () => {
  assert.match(pageSrc, /if \(ok\) \{\s*setView\(REPORT_VIEWS\.INDICATORS\);\s*changeFilter\('needs_review'\);/);
});

test('copy control reuses the shared clipboard helper and overflow menu reuses the shared menu item style', () => {
  assert.match(partsSrc, /import \{ IOC_COPY_FEEDBACK_MS, copyTextToClipboard \} from '\.\.\/\.\.\/lib\/iocCopyFeedback\.js'/);
  assert.match(partsSrc, /computeOverflowMenuPosition/);
  assert.match(partsSrc, /className=\{`br-menu-item\$\{item\.danger \? ' ioc-source-menu-item--danger' : ''\}`\}/);
});

test('Context Only != IOC candidate: promotion is a confirmed single-row override, mixed selections drop context rows', () => {
  assert.match(pageSrc, /if \(action === 'promote_to_ioc'\) \{\s*await promoteToIoc\(\);/);
  assert.match(pageSrc, /async function promoteToIoc\(\) \{\s*if \(!canWrite \|\| selectedRows\.length !== 1\) return;/);
  assert.match(pageSrc, /if \(!isContextOnlyCandidate\(row\)\) return;/);
  assert.match(pageSrc, /is classified as Context Only\. Promote it to an IOC\?/, 'confirmation names the transition');
  assert.match(pageSrc, /action: 'promote_to_ioc',\s*candidate_ids: \[row\.id\]/, 'exactly one id is sent');
  assert.match(pageSrc, /confirmLabel: 'Promote to IOC'/);
  assert.match(pageSrc, /const \{ ids, excluded \} = selectionForAction\('create_iocs', selectedRows\);/);
  assert.match(pageSrc, /excluded: excluded \+ \(Number\(data\?\.skipped_context_only\) \|\| 0\)/, 'feedback reports skipped context rows');
  assert.doesNotMatch(drawerSrc, /promote_to_ioc|promoteToIoc|Promote to IOC/, 'drawer stays read-only');
});

test('Create IOCs with nothing to create is informational: Close only, no OK, no mutation call', () => {
  const fn = pageSrc.slice(pageSrc.indexOf('async function createIocs()'), pageSrc.indexOf('async function promoteToIoc()'));
  assert.match(fn, /const noop = describeNoCreatableIocs\(summary\);\s*if \(noop\) \{/);
  assert.doesNotMatch(fn, /confirmLabel: 'OK'/, 'no OK action on a no-mutation modal');
  const noopBlock = fn.slice(fn.indexOf('if (noop) {'), fn.indexOf('const ok = await requestConfirm'));
  assert.match(noopBlock, /informational: true/);
  assert.match(noopBlock, /return;/);
  assert.doesNotMatch(noopBlock, /confirm: true/, 'no commit call on the informational path');
  assert.match(mainSrc, /\{state\.informational \? null : \(/, 'confirm host hides the confirm button');
});

test('IOC Result cell renders the effective outcome and links only via the backend public id', () => {
  assert.match(pageSrc, /const resultTone = promotionOutcomeTone\(iocResultOutcome\(c\)\);/);
  assert.match(pageSrc, /const resultHref = iocResultLink\(c\);/);
  assert.match(pageSrc, /\{resultHref \? \(\s*<Link to=\{resultHref\}[^>]*>View IOC<\/Link>/);
});

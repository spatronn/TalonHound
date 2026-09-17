/**
 * Report section tabs: URL state alongside the review-table params, dynamic
 * counts that never present a preliminary total as stable.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseReviewTableUrlState, serializeReviewTableUrlState } from './candidateReview.js';
import {
  DEFAULT_REPORT_VIEW,
  REPORT_VIEWS,
  buildReportTabs,
  parseReportView,
  withReportView
} from './reportTabs.js';

test('default section is Overview', () => {
  assert.equal(DEFAULT_REPORT_VIEW, 'overview');
  assert.equal(parseReportView(new URLSearchParams('')), 'overview');
  assert.equal(parseReportView(''), 'overview');
  assert.equal(parseReportView(new URLSearchParams('view=nonsense')), 'overview');
});

test('explicit view param selects the section', () => {
  assert.equal(parseReportView(new URLSearchParams('view=indicators')), 'indicators');
  assert.equal(parseReportView(new URLSearchParams('view=entities')), 'entities');
  assert.equal(parseReportView(new URLSearchParams('view=source')), 'source');
  assert.equal(parseReportView(new URLSearchParams('view=Source')), 'source');
});

test('pre-redesign review-table deep links land on Indicators', () => {
  assert.equal(parseReportView(new URLSearchParams('tab=needs_review')), 'indicators');
  assert.equal(parseReportView(new URLSearchParams('q=185.')), 'indicators');
  assert.equal(parseReportView(new URLSearchParams('page=2&pageSize=100')), 'indicators');
  // An explicit view still wins over table params.
  assert.equal(parseReportView(new URLSearchParams('tab=needs_review&view=overview')), 'overview');
});

test('withReportView carries the section next to the review-table params', () => {
  const table = serializeReviewTableUrlState({ tab: 'needs_review', q: 'abc', type: 'ip', result: 'all', page: 2, pageSize: 50 });
  const withView = withReportView(table, REPORT_VIEWS.INDICATORS);
  assert.equal(withView.get('view'), 'indicators');
  assert.equal(withView.get('tab'), 'needs_review');
  assert.equal(withView.get('q'), 'abc');
  assert.equal(withView.get('type'), 'ip');
  assert.equal(withView.get('page'), '2');
  // Round trip: the review table still reads its own state unchanged.
  const parsed = parseReviewTableUrlState(withView);
  assert.equal(parsed.tab, 'needs_review');
  assert.equal(parsed.q, 'abc');
  assert.equal(parsed.type, 'ip');
  assert.equal(parsed.page, 2);
  assert.equal(parseReportView(withView), 'indicators');
});

test('Overview stays implicit and a stale view param is replaced', () => {
  assert.equal(withReportView(new URLSearchParams(''), 'overview').toString(), '');
  assert.equal(withReportView(new URLSearchParams('view=source'), 'overview').toString(), '');
  assert.equal(withReportView(new URLSearchParams('view=source'), 'entities').get('view'), 'entities');
  assert.equal(withReportView(new URLSearchParams('view=source'), 'bogus').has('view'), false);
  assert.equal(withReportView(null, 'source').get('view'), 'source');
});

test('tab counts are dynamic and omitted while preliminary', () => {
  const stable = buildReportTabs({ indicatorCount: 25, indicatorCountStable: true, entityCount: 8 });
  assert.deepEqual(stable.map((t) => [t.id, t.label, t.count]), [
    ['overview', 'Overview', null],
    ['indicators', 'Indicators', 25],
    ['entities', 'Entities', 8],
    ['source', 'Source', null]
  ]);
  const preliminary = buildReportTabs({ indicatorCount: 51, indicatorCountStable: false, entityCount: 0 });
  assert.equal(preliminary[1].count, null);
  assert.equal(preliminary[2].count, 0);
  assert.equal(buildReportTabs({}).find((t) => t.id === 'entities').count, null);
});

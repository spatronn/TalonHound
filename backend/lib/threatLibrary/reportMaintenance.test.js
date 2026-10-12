import test from 'node:test';
import assert from 'node:assert/strict';
import { dismissPreconditions, parseArgs } from '../../scripts/threat-library-report-maintenance.js';

const pending = {
  report_id: 18651,
  lifecycle_status: 'discovered',
  inspection_status: 'pending',
  extraction_status: 'pending',
  discovery_method: 'auto'
};

test('dismiss preconditions: a pending source that produced nothing may be dismissed', () => {
  assert.deepEqual(dismissPreconditions({ source: pending, reportId: 18651, fileCount: 0, linkCount: 0 }), []);
});

test('dismiss preconditions: anything that already produced data, or another report, is refused', () => {
  assert.deepEqual(dismissPreconditions({ source: null, reportId: 1, fileCount: 0, linkCount: 0 }), ['source_not_found']);
  assert.deepEqual(dismissPreconditions({ source: pending, reportId: 1, fileCount: 0, linkCount: 0 }), ['source_belongs_to_another_report']);
  assert.deepEqual(dismissPreconditions({ source: pending, reportId: 18651, fileCount: 2, linkCount: 5 }), ['has_2_source_files', 'has_5_extracted_candidate_links']);
  assert.deepEqual(
    dismissPreconditions({ source: { ...pending, lifecycle_status: 'extracted', extraction_status: 'succeeded' }, reportId: 18651, fileCount: 0, linkCount: 0 }),
    ['lifecycle_extracted_not_dismissable', 'extraction_succeeded']
  );
  assert.deepEqual(dismissPreconditions({ source: { ...pending, lifecycle_status: 'dismissed' }, reportId: 18651, fileCount: 0, linkCount: 0 }), ['already_dismissed']);
});

test('arguments: dry-run unless --apply', () => {
  const a = parseArgs(['dismiss-source', '--report', 'r', '--source', 's']);
  assert.equal(a.apply, false);
  assert.equal(a.source, 's');
  assert.equal(parseArgs(['refresh-extraction', '--report', 'r', '--apply']).apply, true);
});

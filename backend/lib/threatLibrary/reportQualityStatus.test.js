import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateFinalizeObligations, FINALIZE_OBLIGATION_CODES as C, reportStatusAxes, uncoveredObligations } from './reportQualityStatus.js';

const clean = {
  firstPassRun: { id: 1, is_first_pass: true },
  latestRun: { id: 1, run_type: 'initial', operational_status: 'completed', contract_fingerprint: 'fp' },
  significantRegions: [],
  latestDiscovery: { status: 'completed' },
  sources: [],
  candidates: [],
  quality: { warnings: [] }
};
const codes = (s) => evaluateFinalizeObligations(s).unmet.map((o) => o.code);

test('a clean new report meets every obligation', () => {
  assert.deepEqual(evaluateFinalizeObligations(clean), { applies: true, unmet: [] });
});

test('a report without a first-pass run is historical: nothing applies, whatever is missing', () => {
  const r = evaluateFinalizeObligations({ ...clean, firstPassRun: null, latestRun: null, latestDiscovery: null, quality: null });
  assert.deepEqual(r, { applies: false, unmet: [] });
});

test('a degraded run is an explicit recorded state, not a blocker', () => {
  assert.deepEqual(codes({ ...clean, latestRun: { ...clean.latestRun, operational_status: 'degraded' } }), []);
});

test('each obligation fails on its own evidence', () => {
  assert.deepEqual(codes({ ...clean, latestRun: null }), [C.EXTRACTION_NOT_RECORDED]);
  assert.deepEqual(codes({ ...clean, significantRegions: [{ region_kind: 'div', observable_count: 3 }] }), [C.SOURCE_REGIONS_UNACCOUNTED]);
  assert.deepEqual(codes({ ...clean, latestDiscovery: null }), [C.DISCOVERY_INCOMPLETE]);
  assert.deepEqual(codes({ ...clean, latestDiscovery: { status: 'failed' } }), [C.DISCOVERY_INCOMPLETE]);
  assert.deepEqual(codes({ ...clean, latestDiscovery: { status: 'partial' } }), [C.DISCOVERY_INCOMPLETE]);
  assert.deepEqual(codes({ ...clean, sources: [{ lifecycle_status: 'dismissed', dismissal_reason: '  ' }] }), [C.DISMISSAL_WITHOUT_EVIDENCE]);
  assert.deepEqual(codes({ ...clean, quality: { warnings: [{ code: 'explicit_table_rows_dropped' }] } }), [C.CRITICAL_EXTRACTION_FAILURE]);
});

test('noise does not block: an ordinary warning, a dismissal with a reason, a region with no observables', () => {
  assert.deepEqual(codes({
    ...clean,
    quality: { warnings: [{ code: 'context_only_heavy' }, { code: 'source_region_observables_dropped' }] },
    sources: [{ lifecycle_status: 'dismissed', dismissal_reason: 'Belongs to another campaign.' }],
    significantRegions: [{ region_kind: 'div', observable_count: 0 }]
  }), []);
});

test('an exception covers only the obligation it was recorded for', () => {
  const unmet = [{ code: 'a' }, { code: 'b' }];
  assert.deepEqual(uncoveredObligations(unmet, [{ obligation_code: 'a' }]), [{ code: 'b' }]);
});

test('axes stay independent: finalized does not imply covered or fresh', () => {
  const axes = reportStatusAxes({
    ...clean,
    report: { finalized_at: '2026-11-04' },
    latestDiscovery: { status: 'failed' },
    significantRegions: [{ region_kind: 'div', observable_count: 2 }],
    currentFingerprint: 'other'
  });
  assert.equal(axes.finalized, true);
  assert.equal(axes.generation, 'first_pass_recorded');
  assert.equal(axes.operational_execution.status, 'completed');
  assert.equal(axes.document_coverage.status, 'regions_unaccounted');
  assert.equal(axes.package_discovery.status, 'discovery_incomplete');
  assert.equal(axes.contract_freshness.status, 'older_contract');
  assert.equal(axes.analyst_review.status, 'complete');
});

test('a historical report reads as not recorded, never as covered', () => {
  const axes = reportStatusAxes({
    report: { finalized_at: '2026-01-01' },
    firstPassRun: null,
    latestRun: { run_type: 'legacy_baseline', operational_status: 'completed', contract_fingerprint: 'old' },
    significantRegions: [],
    latestDiscovery: null,
    sources: [],
    candidates: [],
    quality: null,
    currentFingerprint: 'new'
  });
  assert.equal(axes.generation, 'historical');
  assert.equal(axes.finalized, true);
  assert.equal(axes.operational_execution.status, 'not_recorded');
  assert.equal(axes.document_coverage.status, 'not_recorded');
  assert.equal(axes.package_discovery.status, 'not_recorded');
  assert.equal(axes.contract_freshness.status, 'older_contract');
});

test('a dropped region holding only the report\'s own URL is a self-reference, not an unaccounted region', () => {
  const report = { source_url: 'https://www.vendor.example/blog/campaign-analysis/' };
  const citation = { region_kind: 'button', locator: 'button.copy_btn', observable_count: 1, sample_observables: ['https://www.vendor.example/blog/campaign-analysis/'] };
  assert.deepEqual(codes({ ...clean, report, significantRegions: [citation] }), []);
  assert.equal(reportStatusAxes({ ...clean, report, significantRegions: [citation] }).document_coverage.status, 'accounted');
  // Same page written without scheme / www / trailing slash / fragment is still the page itself.
  assert.deepEqual(codes({ ...clean, report, significantRegions: [{ ...citation, sample_observables: ['vendor.example/blog/campaign-analysis#cite'] }] }), []);
  // Any other value in the region keeps the obligation.
  const mixed = { ...citation, observable_count: 2, sample_observables: [citation.sample_observables[0], 'evil-host.example.net'] };
  assert.deepEqual(codes({ ...clean, report, significantRegions: [mixed] }), [C.SOURCE_REGIONS_UNACCOUNTED]);
  // Another page of the same site is not the report itself.
  assert.deepEqual(codes({ ...clean, report, significantRegions: [{ ...citation, sample_observables: ['https://www.vendor.example/blog/other-post/'] }] }), [C.SOURCE_REGIONS_UNACCOUNTED]);
  // More values than samples: unsampled values may be anything.
  assert.deepEqual(codes({ ...clean, report, significantRegions: [{ ...citation, observable_count: 25 }] }), [C.SOURCE_REGIONS_UNACCOUNTED]);
  // Without samples or a known source URL nothing is excused.
  assert.deepEqual(codes({ ...clean, report, significantRegions: [{ ...citation, sample_observables: [] }] }), [C.SOURCE_REGIONS_UNACCOUNTED]);
  assert.deepEqual(codes({ ...clean, report: { source_url: null }, significantRegions: [citation] }), [C.SOURCE_REGIONS_UNACCOUNTED]);
});

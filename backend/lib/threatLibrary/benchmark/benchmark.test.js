/**
 * Golden-report benchmark gate.
 *
 * Every committed case runs through the deterministic extraction stage. A case
 * that is not a recorded known failure must match its ground truth exactly,
 * and the whole run must match baseline.json: an unexpected Indicator
 * membership change in either direction fails (a stale baseline would hide the
 * next regression). After a REVIEWED change, refresh the baseline with
 *   npm run benchmark:threat-library -- --write-baseline
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  compareWithBaseline,
  loadBenchmarkCases,
  readBaseline,
  runBenchmark
} from './benchmarkRunner.js';
import { knownFailureFor } from './knownFailures.js';

// Public cases only: real-report labels are scored in realReports.test.js.
const cases = loadBenchmarkCases({ privateDir: null, sourceDir: null });
const run = runBenchmark({ cases });
const byId = new Map(run.results.map((r) => [r.id, r]));

test('committed cases load, validate and include fixtures, controls and layout variants', () => {
  const ids = cases.map((c) => c.id);
  assert.ok(ids.includes('pdf-pivotc2-socradar'));
  assert.ok(ids.includes('pdf-kimsuky-360-appendix'));
  assert.ok(ids.filter((id) => id.startsWith('control-')).length >= 4);
  assert.ok(ids.filter((id) => id.startsWith('layout/')).length >= 30);
  for (const c of cases) assert.ok(c.ground_truth.provenance.method, `${c.id} provenance`);
});

test('every case that is not a recorded known failure matches its ground truth exactly', () => {
  const wrong = run.results
    .filter((r) => !knownFailureFor(r.id))
    .filter((r) => r.metrics.indicators.fp !== 0 || r.metrics.indicators.fn !== 0)
    .map((r) => ({
      id: r.id,
      false_negatives: r.metrics.indicators.false_negatives.map((x) => x.id),
      false_positives: r.metrics.indicators.false_positives.map((x) => x.id)
    }));
  assert.deepEqual(wrong, []);
});

test('known-clean controls: no legitimate, contextual or narrative observable becomes an Indicator', () => {
  for (const r of run.results.filter((x) => x.id.startsWith('control-'))) {
    const m = r.metrics;
    assert.deepEqual(m.legitimate_exclusion.promoted, [], `${r.id} legitimate`);
    assert.deepEqual(m.non_indicators.promoted, [], `${r.id} non-indicators`);
    assert.deepEqual(m.context_only.wrong, [], `${r.id} context only`);
    assert.deepEqual(m.unsupported_indicators, [], `${r.id} unsupported`);
    assert.equal(m.sections.correct, m.sections.checked, `${r.id} sections`);
  }
});

test('verified PDF fixtures keep their publisher sets and section structure', () => {
  for (const id of ['pdf-pivotc2-socradar', 'pdf-kimsuky-360-appendix']) {
    const m = byId.get(id).metrics;
    assert.equal(m.indicators.recall, 1, `${id} recall`);
    assert.equal(m.indicators.precision, 1, `${id} precision`);
    assert.equal(m.sections.correct, m.sections.checked, `${id} sections`);
    assert.equal(m.assertions.correct, m.assertions.checked, `${id} assertions`);
  }
});

test('no unexpected Indicator membership change against baseline.json', () => {
  const baseline = readBaseline();
  assert.ok(baseline, 'baseline.json is missing — run npm run benchmark:threat-library -- --write-baseline');
  const cmp = compareWithBaseline(run, baseline, new Map(cases.map((c) => [c.id, c])));
  assert.deepEqual(
    { changes: cmp.changes, new_cases: cmp.new_cases, missing_cases: cmp.missing_cases },
    { changes: [], new_cases: [], missing_cases: [] },
    'benchmark membership differs from baseline.json: review the change (regressions are new FN / FP), ' +
      'then refresh with `npm run benchmark:threat-library -- --write-baseline`'
  );
});

test('quality detector: no warning on exact cases, every failing case flagged', () => {
  const q = run.aggregate.quality;
  const flaggedExact = run.results
    .filter((r) => r.metrics.indicators.fp === 0 && r.metrics.indicators.fn === 0)
    .filter((r) => r.quality.counts.high + r.quality.counts.warning > 0)
    .map((r) => ({ id: r.id, codes: r.quality.warnings.map((w) => w.code) }));
  assert.deepEqual(flaggedExact, [], 'false quality warnings on cases that match ground truth');
  const silentFailures = run.results
    .filter((r) => r.metrics.indicators.fp !== 0 || r.metrics.indicators.fn !== 0)
    .filter((r) => r.quality.counts.high + r.quality.counts.warning === 0)
    .map((r) => r.id);
  assert.deepEqual(silentFailures, [], 'failing cases the detector does not flag');
  assert.equal(q.exact_cases_flagged, 0);
  assert.equal(q.failing_cases_flagged, q.failing_cases);
});

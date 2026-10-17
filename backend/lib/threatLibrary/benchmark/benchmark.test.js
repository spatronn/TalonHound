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
import { groundTruthIdentity } from './benchmarkMetrics.js';

// The gate measures the production scope engine (section-tree owns Indicator
// membership); `legacy` is an emergency rollback and is not benchmarked here.
process.env.THREAT_LIBRARY_SCOPE_ENGINE = process.env.THREAT_LIBRARY_SCOPE_ENGINE || 'section_tree';

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

test('six-report golden corpus: exact publisher sets and the audited failure classes stay fixed', () => {
  const golden = [
    'golden-unit42-ai-enabled-malware',
    'golden-checkpoint-mois-cybercrime',
    'golden-huntress-muddywater-chain',
    'golden-levelblue-blind-eagle',
    'golden-elastic-apex-accelerator',
    'golden-microsoft-needymantis'
  ];
  for (const id of golden) {
    const m = byId.get(id)?.metrics;
    assert.ok(m, `${id} present`);
    assert.equal(m.indicators.fp, 0, `${id} false positives: ${m.indicators.false_positives.map((x) => x.id).join(' ')}`);
    assert.equal(m.indicators.fn, 0, `${id} false negatives: ${m.indicators.false_negatives.map((x) => x.id).join(' ')}`);
    // Legitimate binaries, thumbprints, technical identifiers, crypto constants never promoted.
    assert.deepEqual(m.legitimate_exclusion.promoted, [], `${id} legitimate`);
    assert.deepEqual(m.non_indicators.promoted, [], `${id} non-indicators`);
    // Reference / source / narrative context stays Context Only.
    assert.deepEqual(m.context_only.wrong, [], `${id} context only`);
    assert.equal(m.sections.correct, m.sections.checked, `${id} sections`);
    assert.equal(m.assertions.correct, m.assertions.checked, `${id} assertions`);
  }
  assert.equal(golden.reduce((n, id) => n + byId.get(id).metrics.indicators.expected, 0), 65, 'independent publisher Indicator total');
});

test('Unit 42 PPI key-value IOC records stay inside the appendix across H3 operation headings (tl-zones-v13)', () => {
  const m = byId.get('golden-unit42-ppi-untracked-nightmares')?.metrics;
  assert.ok(m, 'golden-unit42-ppi-untracked-nightmares present');
  assert.equal(m.indicators.expected, 330, 'independent publisher Indicator total');
  assert.equal(m.indicators.fn, 0, `false negatives: ${m.indicators.false_negatives.map((x) => x.id).join(' ')}`);
  assert.equal(m.indicators.fp, 0, `false positives: ${m.indicators.false_positives.map((x) => x.id).join(' ')}`);
  assert.deepEqual(m.non_indicators.promoted, [], 'record file names never promoted');
  assert.deepEqual(m.context_only.wrong, [], 'context only');
  assert.equal(m.sections.correct, m.sections.checked, 'sections');
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

/**
 * Warnings that are review prompts by design and fire on correct extractions:
 * delegated authority (every formal IOC section empty) always asks for review.
 */
const REVIEW_PROMPT_CODES = new Set(['delegated_authority_applied']);

/**
 * A warning is a false alarm on an exact case unless it is a review prompt or
 * every value it lists is one the ground truth records as genuinely ambiguous
 * (publisher evidence supports either reading, e.g. an IOC row the publisher
 * says now serves legitimate services).
 * @param {object} r benchmark result
 */
function falseAlarmWarnings(r) {
  const c = cases.find((x) => x.id === r.id);
  const ambiguous = new Set((c?.ground_truth?.ambiguous || []).map(groundTruthIdentity));
  return r.quality.warnings
    .filter((w) => w.severity === 'warning' || w.severity === 'high')
    .filter((w) => !REVIEW_PROMPT_CODES.has(w.code))
    .filter((w) => !(Array.isArray(w.candidates) && w.candidates.length > 0 && w.candidates.every((id) => ambiguous.has(id))));
}

test('quality detector: no warning on exact cases, every failing case flagged', () => {
  const q = run.aggregate.quality;
  const flaggedExact = run.results
    .filter((r) => r.metrics.indicators.fp === 0 && r.metrics.indicators.fn === 0)
    .filter((r) => falseAlarmWarnings(r).length > 0)
    .map((r) => ({ id: r.id, codes: falseAlarmWarnings(r).map((w) => w.code) }));
  assert.deepEqual(flaggedExact, [], 'false quality warnings on cases that match ground truth');
  const silentFailures = run.results
    .filter((r) => r.metrics.indicators.fp !== 0 || r.metrics.indicators.fn !== 0)
    .filter((r) => r.quality.counts.high + r.quality.counts.warning === 0)
    .map((r) => r.id);
  assert.deepEqual(silentFailures, [], 'failing cases the detector does not flag');
  // Aggregate exact_cases_flagged also counts review prompts / ambiguous-only
  // warnings; the false-alarm check above is the gate.
  assert.ok(q.exact_cases_flagged >= flaggedExact.length);
  assert.equal(q.failing_cases_flagged, q.failing_cases);
});

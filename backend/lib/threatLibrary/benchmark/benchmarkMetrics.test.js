/**
 * Benchmark metric calculation: extraction vs membership failures, context
 * only / legitimate / non-indicator categories, ai_dependent separation,
 * assertion and section scoring, aggregation and case validation.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  aggregateBenchmark,
  groundTruthIdentity,
  scoreBenchmarkCase,
  scoreSections,
  zoneClass
} from './benchmarkMetrics.js';
import { compareWithBaseline, validateBenchmarkCase } from './benchmarkRunner.js';

const occ = (zone, asserted, kind = asserted ? 'standalone_indicator_row' : 'narrative_mention') => ({
  block_id: 'b1',
  zone,
  asserted,
  occurrence_kind: kind,
  row_shape: asserted,
  structural_row: false
});

/** Minimal extracted candidate in the shape candidateExtraction produces. */
function cand(type, value, opts = {}) {
  return {
    candidate_type: type,
    normalized_value: value,
    original_value: value,
    is_ioc: opts.is_ioc ?? true,
    assessment: opts.assessment || 'malicious',
    match_state: opts.match_state,
    role: 'malicious_infrastructure',
    source_assertion: opts.source_assertion || 'explicit_ioc',
    policy_decision: opts.policy_decision || 'explicit_report_assertion',
    document_has_authoritative_scope: opts.modeA ?? true,
    ai_needed: opts.ai_needed === true,
    occurrences: opts.occurrences || [occ('explicit_ioc_section', true)]
  };
}

const narrative = (type, value, extra = {}) =>
  cand(type, value, {
    source_assertion: 'body_mention',
    policy_decision: 'ai_needed_prose_sample_hash',
    assessment: 'unknown',
    ai_needed: true,
    occurrences: [occ('report_body', false)],
    ...extra
  });

const contextOnly = (type, value) =>
  cand(type, value, {
    assessment: 'context_only',
    match_state: 'context_only',
    source_assertion: 'reference_only',
    policy_decision: 'context_only_negative_zone',
    occurrences: [{ ...occ('reference_section', false), occurrence_kind: 'reference' }]
  });

const H1 = 'a'.repeat(32);
const H2 = 'b'.repeat(32);
const H3 = 'c'.repeat(32);

test('ground truth identities use the extractor normalizer (case, defang)', () => {
  assert.equal(groundTruthIdentity({ type: 'md5', value: H1.toUpperCase() }), `md5:${H1}`);
  assert.equal(groundTruthIdentity({ type: 'domain', value: 'Evil-C2[.]com' }), 'domain:evil-c2.com');
  assert.equal(
    groundTruthIdentity({ type: 'url', value: 'http[:]//217[.]60[.]36[.]94/unicorn/mort[.]php' }),
    'url:http://217.60.36.94/unicorn/mort.php'
  );
});

test('extraction failures and membership failures are separated', () => {
  const m = scoreBenchmarkCase({
    groundTruth: {
      indicators: [
        { type: 'md5', value: H1, assertion: 'explicit' },
        { type: 'md5', value: H2, assertion: 'explicit_ioc' },
        { type: 'md5', value: H3 }
      ]
    },
    candidates: [cand('md5', H1), narrative('md5', H2)]
  });
  assert.equal(m.indicators.tp, 1);
  assert.equal(m.indicators.fn, 2);
  assert.equal(m.indicators.fn_not_extracted, 1, 'H3 never became a candidate');
  assert.equal(m.indicators.fn_not_member, 1, 'H2 was extracted but is not an Indicator');
  assert.deepEqual(m.candidate_extraction.not_extracted, [`md5:${H3}`]);
  const h2 = m.indicators.false_negatives.find((x) => x.id === `md5:${H2}`);
  assert.equal(h2.extracted, true);
  assert.equal(h2.policy_decision, 'ai_needed_prose_sample_hash');
  assert.equal(m.indicators.precision, 1);
  assert.equal(m.indicators.recall, 0.3333);
  assert.equal(m.assertions.checked, 2);
  assert.equal(m.assertions.correct, 1, 'explicit class matches H1; H2 is body_mention');
});

test('false positives are attributed to their ground-truth category', () => {
  const m = scoreBenchmarkCase({
    groundTruth: {
      indicators: [{ type: 'domain', value: 'evil.example' }],
      excluded_legitimate: [{ type: 'url', value: 'https://graph.microsoft.com/v1.0/organization' }],
      not_indicators: [{ type: 'md5', value: H2 }]
    },
    candidates: [
      cand('domain', 'evil.example'),
      cand('url', 'https://graph.microsoft.com/v1.0/organization', { source_assertion: 'explicit_c2' }),
      cand('md5', H2),
      cand('ip', '198.51.100.9')
    ]
  });
  assert.equal(m.indicators.fp, 3);
  const by = Object.fromEntries(m.indicators.false_positives.map((x) => [x.id, x.labeled_as]));
  assert.equal(by['url:https://graph.microsoft.com/v1.0/organization'], 'excluded_legitimate');
  assert.equal(by[`md5:${H2}`], 'not_indicators');
  assert.equal(by['ip:198.51.100.9'], 'unlabeled');
  assert.deepEqual(m.legitimate_exclusion.promoted, ['url:https://graph.microsoft.com/v1.0/organization']);
  assert.equal(m.legitimate_exclusion.accuracy, 0);
  assert.deepEqual(m.non_indicators.promoted, [`md5:${H2}`]);
});

test('context-only expectations distinguish Indicator, missing and pending rows', () => {
  const m = scoreBenchmarkCase({
    groundTruth: {
      context_only: [
        { type: 'url', value: 'https://ref.example/a' },
        { type: 'url', value: 'https://ref.example/b' },
        { type: 'url', value: 'https://ref.example/c' },
        { type: 'url', value: 'https://ref.example/d' }
      ]
    },
    candidates: [
      contextOnly('url', 'https://ref.example/a'),
      cand('url', 'https://ref.example/b'),
      narrative('url', 'https://ref.example/c')
    ]
  });
  assert.equal(m.context_only.correct, 1);
  const states = Object.fromEntries(m.context_only.wrong.map((x) => [x.id, x.state]));
  assert.equal(states['url:https://ref.example/b'], 'indicator');
  assert.equal(states['url:https://ref.example/c'], 'non_member_not_context_only');
  assert.equal(states['url:https://ref.example/d'], 'not_extracted');
});

test('ai_dependent entries are reported apart and excluded from deterministic precision', () => {
  const m = scoreBenchmarkCase({
    groundTruth: {
      indicators: [{ type: 'domain', value: 'c2-update.info' }],
      context_only: [{ type: 'url', value: 'https://learn.microsoft.com/x', ai_dependent: true }]
    },
    candidates: [
      cand('domain', 'c2-update.info', { modeA: false, source_assertion: 'body_mention', occurrences: [occ('report_body', false)] }),
      narrative('url', 'https://learn.microsoft.com/x', { modeA: false })
    ]
  });
  assert.equal(m.indicators.tp, 1);
  assert.equal(m.indicators.fp, 0, 'the MODE B pending URL is the model’s decision, not a deterministic FP');
  assert.equal(m.ai_dependent.length, 1);
  assert.equal(m.ai_dependent[0].deterministic_state.member, true);
  assert.equal(m.ai_dependent[0].deterministic_state.ai_needed, true);
});

test('unsupported Indicators: a member whose value is absent from the source text', () => {
  const m = scoreBenchmarkCase({
    groundTruth: { indicators: [{ type: 'domain', value: 'evil.example' }] },
    candidates: [cand('domain', 'evil.example'), cand('domain', 'invented.example')],
    blocks: [{ id: 'b1', type: 'paragraph', text: 'C2: evil[.]example', zone: 'explicit_ioc_section' }]
  });
  assert.deepEqual(m.unsupported_indicators, ['domain:invented.example']);
});

test('section scoring reads zone classes until the next heading (or until)', () => {
  const blocks = [
    { id: 'h1', type: 'heading', text: 'Indicators of compromise', zone: 'explicit_ioc_section' },
    { id: 'h2', type: 'heading', text: 'Network', zone: 'explicit_ioc_section' },
    { id: 'r1', type: 'list_item', text: 'evil.example', zone: 'explicit_ioc_section' },
    { id: 'pe', type: 'paragraph', text: 'page 2', zone: 'header_footer', layout: 'page_edge' },
    { id: 'r2', type: 'list_item', text: '198.51.100.1', zone: 'explicit_ioc_section' },
    { id: 'h3', type: 'heading', text: 'Samples', zone: 'report_body' },
    { id: 't1', type: 'table', text: 'f | h', zone: 'report_body' },
    { id: 'h4', type: 'heading', text: 'References', zone: 'reference_section' },
    { id: 'x1', type: 'list_item', text: 'https://ref.example/', zone: 'reference_section' }
  ];
  const s = scoreSections(blocks, [
    { heading: 'Network', expected: 'authoritative' },
    { heading: 'Samples', expected: 'authoritative' },
    { heading: 'References', expected: 'excluded' },
    { heading: 'Missing heading', expected: 'narrative' }
  ]);
  assert.equal(s.checked, 4);
  assert.equal(s.correct, 2);
  assert.equal(s.blocks_checked, 4, 'page-edge chrome is skipped');
  assert.deepEqual(s.mismatches.map((x) => x.heading), ['Samples', 'Missing heading']);
  assert.equal(s.mismatches[1].reason, 'heading_not_found');
  assert.equal(zoneClass('c2_section'), 'authoritative');
  assert.equal(zoneClass('vendor_about'), 'excluded');
  assert.equal(zoneClass('code'), 'narrative');
  assert.throws(() => scoreSections(blocks, [{ heading: 'Network', expected: 'malicious' }]), /unknown section class/);
});

test('aggregate is micro-averaged over cases', () => {
  const a = scoreBenchmarkCase({
    groundTruth: { indicators: [{ type: 'md5', value: H1 }, { type: 'md5', value: H2 }] },
    candidates: [cand('md5', H1), cand('md5', H2)]
  });
  const b = scoreBenchmarkCase({
    groundTruth: { indicators: [{ type: 'md5', value: H3 }] },
    candidates: [narrative('md5', H3), cand('ip', '198.51.100.2')]
  });
  const agg = aggregateBenchmark([
    { id: 'a', metrics: a, elapsed_ms: 2 },
    { id: 'b', metrics: b, elapsed_ms: 3 }
  ]);
  assert.equal(agg.cases, 2);
  assert.equal(agg.cases_exact, 1);
  assert.deepEqual(
    { tp: agg.indicators.tp, fp: agg.indicators.fp, fn: agg.indicators.fn },
    { tp: 2, fp: 1, fn: 1 }
  );
  assert.equal(agg.indicators.precision, 0.6667);
  assert.equal(agg.indicators.recall, 0.6667);
  assert.equal(agg.elapsed_ms, 5);
});

test('case validation requires provenance and rejects conflicting labels', () => {
  const ok = {
    id: 'case-ok',
    source: { kind: 'html_file', path: 'x.html' },
    ground_truth: { provenance: { method: 'publisher appendix', verified_by: 'analyst' }, indicators: [] }
  };
  assert.doesNotThrow(() => validateBenchmarkCase(ok));
  assert.throws(
    () => validateBenchmarkCase({ ...ok, ground_truth: { indicators: [] } }),
    /independently verified/
  );
  assert.throws(
    () => validateBenchmarkCase({
      ...ok,
      ground_truth: {
        ...ok.ground_truth,
        indicators: [{ type: 'md5', value: H1 }],
        not_indicators: [{ type: 'md5', value: H1.toUpperCase() }]
      }
    }),
    /labeled both indicators and not_indicators/
  );
  assert.throws(() => validateBenchmarkCase({ ...ok, source: { kind: 'prod_db' } }), /source\.kind/);
});

test('baseline comparison classifies membership changes against ground truth', () => {
  const run = {
    results: [
      { id: 'c1', metrics: { members: [`md5:${H1}`, 'ip:198.51.100.3'] } },
      { id: 'c2', metrics: { members: [`md5:${H2}`] } },
      { id: 'c3', metrics: { members: [] } }
    ]
  };
  const baseline = {
    cases: {
      c1: { members: [`md5:${H1}`, `md5:${H3}`] },
      c2: { members: [`md5:${H2}`] },
      gone: { members: [] }
    }
  };
  const caseById = {
    c1: { ground_truth: { indicators: [{ type: 'md5', value: H1 }, { type: 'md5', value: H3 }] } },
    c2: { ground_truth: { indicators: [{ type: 'md5', value: H2 }] } }
  };
  const cmp = compareWithBaseline(run, baseline, caseById);
  assert.equal(cmp.unchanged, false);
  assert.deepEqual(cmp.new_cases, ['c3']);
  assert.deepEqual(cmp.missing_cases, ['gone']);
  assert.equal(cmp.changes.length, 1);
  assert.deepEqual(
    cmp.changes[0].regressions.map((r) => `${r.kind}:${r.id}`).sort(),
    [`new_false_negative:md5:${H3}`, 'new_false_positive:ip:198.51.100.3']
  );
  assert.equal(cmp.regression_count, 2);
});

test('a value extracted under another type is a typing failure, not a missing extraction', () => {
  const m = scoreBenchmarkCase({
    groundTruth: {
      indicators: [
        { type: 'domain', value: 'loader.cfg.example' },
        { type: 'md5', value: H1 },
        { type: 'md5', value: H2 }
      ]
    },
    candidates: [
      { ...cand('technical_artifact', 'loader.cfg.example'), is_ioc: false, assessment: 'context_only', match_state: 'context_only', source_assertion: 'non_ioc' },
      narrative('md5', H1)
    ]
  });
  assert.equal(m.indicators.fn, 3);
  assert.equal(m.indicators.fn_mistyped, 1);
  assert.equal(m.indicators.fn_not_extracted, 1, `md5:${H2} is genuinely absent`);
  assert.equal(m.indicators.fn_not_member, 1);
  const mistyped = m.indicators.false_negatives.find((x) => x.id === 'domain:loader.cfg.example');
  assert.equal(mistyped.extracted, false);
  assert.equal(mistyped.mistyped_as, 'technical_artifact');
  assert.deepEqual(m.candidate_extraction.mistyped, [{ id: 'domain:loader.cfg.example', extracted_as: 'technical_artifact' }]);
  const agg = aggregateBenchmark([{ id: 'x', metrics: m }]);
  assert.deepEqual(
    [agg.indicators.fn_not_extracted, agg.indicators.fn_mistyped, agg.indicators.fn_not_member],
    [1, 1, 1]
  );
});

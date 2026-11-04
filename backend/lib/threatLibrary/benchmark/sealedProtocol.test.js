import test from 'node:test';
import assert from 'node:assert/strict';
import { buildLabelingPacket, drawStratifiedSample, labelAgreement, sealedCaseProblems, sealedSetReadiness } from './sealedProtocol.js';

const FP = 'abc123';
const population = [
  ...Array.from({ length: 10 }, (_, i) => ({ id: `a${i}`, publisher: 'Publisher A', format: 'html', package_announced: true })),
  ...Array.from({ length: 10 }, (_, i) => ({ id: `b${i}`, publisher: 'Publisher B', format: 'pdf', package_announced: false })),
  { id: 'c0', publisher: 'Publisher C', format: 'html', package_announced: false }
];

const valid = (over = {}) => ({
  id: 'sealed-a',
  sampling: { method: 'seeded_stratified_round_robin', drawn_at: '2026-11-05' },
  contract_fingerprint: FP,
  ground_truth: {
    provenance: { method: 'independent_human_review_of_publisher_source', verified_by: 'Reviewer', verified_at: '2026-11-06', coverage_note: 'Whole article and its CSV.' },
    indicators: [{ type: 'domain', value: 'evil.net', role: 'command_and_control', evidence: 'IOC table, row 2' }],
    context_only: [{ type: 'domain', value: 'victim.org', role: 'victim', evidence: 'Paragraph 4' }],
    ambiguous: [],
    linked_packages: []
  },
  ...over
});

test('a draw is repeatable from its seed and reaches every stratum first', () => {
  const opts = { seed: 'batch-1', size: 5, contract_fingerprint: FP, drawn_at: '2026-11-05' };
  const a = drawStratifiedSample(population, opts);
  const b = drawStratifiedSample(population, opts);
  assert.deepEqual(a, b);
  assert.notDeepEqual(a.reports.map((r) => r.id), drawStratifiedSample(population, { ...opts, seed: 'batch-2' }).reports.map((r) => r.id));
  assert.equal(a.reports.length, 5);
  assert.equal(new Set(a.reports.slice(0, 3).map((r) => r.publisher)).size, 3, 'each publisher before any second report');
  assert.equal(a.contract_fingerprint, FP);
});

test('at least a fifth of the sample goes to a second labeler', () => {
  const m = drawStratifiedSample(population, { seed: 's', size: 20, contract_fingerprint: FP });
  assert.ok(m.reports.filter((r) => r.second_labeler).length >= 4);
});

test('a draw needs a recorded seed and a frozen contract', () => {
  assert.throws(() => drawStratifiedSample(population, { size: 2, contract_fingerprint: FP }), /seed/);
  assert.throws(() => drawStratifiedSample(population, { seed: 's', size: 2 }), /fingerprint/);
});

test('a labeling packet starts empty: nothing in it comes from extraction', () => {
  const m = drawStratifiedSample(population, { seed: 's', size: 1, contract_fingerprint: FP });
  const p = buildLabelingPacket(m.reports[0], m);
  assert.deepEqual(p.ground_truth.indicators, []);
  assert.deepEqual(p.ground_truth.context_only, []);
  assert.deepEqual(p.ground_truth.linked_packages, []);
  assert.equal(p.ground_truth.provenance.verified_by, '');
  assert.equal(p.contract_fingerprint, FP);
  assert.ok(sealedCaseProblems(p).length > 0, 'an unfilled packet cannot count');
});

test('a complete independent case counts', () => {
  assert.deepEqual(sealedCaseProblems(valid(), { contract_fingerprint: FP }), []);
});

test('labels derived from TalonHound are refused, whatever they are called', () => {
  for (const method of ['approved IOC rows', 'talonhound export', 'extractor output reviewed', 'replay of candidates', 'AI-assisted labeling', 'model output']) {
    const c = valid();
    c.ground_truth.provenance.method = method;
    assert.ok(sealedCaseProblems(c).some((p) => /must not derive/.test(p)), method);
  }
});

test('every label needs evidence and a role; every case needs frozen code and coverage', () => {
  const noEvidence = valid();
  delete noEvidence.ground_truth.indicators[0].evidence;
  assert.ok(sealedCaseProblems(noEvidence).some((p) => /evidence/.test(p)));
  const noRole = valid();
  noRole.ground_truth.indicators[0].role = 'bad';
  assert.ok(sealedCaseProblems(noRole).some((p) => /role/.test(p)));
  assert.ok(sealedCaseProblems(valid(), { contract_fingerprint: 'other' }).some((p) => /different contract/.test(p)));
  const noPackages = valid();
  delete noPackages.ground_truth.linked_packages;
  assert.ok(sealedCaseProblems(noPackages).some((p) => /linked_packages/.test(p)));
});

test('agreement names every disagreement', () => {
  const a = { indicators: [{ type: 'domain', value: 'one.net' }, { type: 'domain', value: 'two.net' }] };
  const b = { indicators: [{ type: 'domain', value: 'ONE.net' }], context_only: [{ type: 'domain', value: 'two.net' }] };
  const r = labelAgreement(a, b);
  assert.equal(r.agreement, 0.5);
  assert.deepEqual(r.disagreements, [{ identity: 'domain:two.net', first: 'indicator', second: 'context_only' }]);
});

test('readiness stays false until there are enough valid cases and second labelers', () => {
  const opts = { min_reports: 2, contract_fingerprint: FP };
  assert.equal(sealedSetReadiness([], opts).ready, false);
  const single = sealedSetReadiness([valid()], opts);
  assert.equal(single.ready, false);
  assert.ok(single.blockers.some((b) => /1 of 2/.test(b)));
  const noSecond = sealedSetReadiness([valid({ id: 'x' }), valid({ id: 'y' })], opts);
  assert.ok(noSecond.blockers.some((b) => /second labeler/.test(b)));
  const seconded = valid({ id: 'z' });
  seconded.ground_truth.provenance.second_labeler = 'Other reviewer';
  assert.equal(sealedSetReadiness([valid({ id: 'x' }), seconded], opts).ready, true);
});

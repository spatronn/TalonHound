/**
 * The evaluation gate must run for real: an empty corpus, a skipped suite or a
 * stale baseline fails here instead of passing silently.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildScorecard, formatScorecard, SEALED_MIN_REPORTS } from './scorecard.js';
import { extractorVersions, loadBenchmarkCases, readBaseline } from './benchmarkRunner.js';
import { contractFingerprint, extractionContractBundle } from '../contractBundle.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = process.env.THREAT_LIBRARY_SCOPE_ENGINE || 'section_tree';

const card = buildScorecard();

test('the benchmark actually loads its fixtures: no silent empty corpus', () => {
  assert.ok(card.tiers.development.cases >= 40, `development cases: ${card.tiers.development.cases}`);
  assert.ok(card.tiers.regression.cases >= 40, `regression cases: ${card.tiers.regression.cases}`);
  assert.ok(card.tiers.held_out.cases >= 12, `held-out cases: ${card.tiers.held_out.cases}`);
  assert.ok(card.tiers.regression.tp > 500, 'regression tier scored real identities');
});

test('baseline.json names the current extraction contract: a bump must refresh it', () => {
  const baseline = readBaseline();
  assert.deepEqual(baseline.versions, extractorVersions(), 'run npm run benchmark:threat-library -- --write-baseline after reviewing the diff');
});

test('first-pass accuracy is never claimed without enough sealed labels', () => {
  const sealed = card.tiers.sealed.cases;
  assert.equal(card.first_pass_accuracy.validated, sealed >= SEALED_MIN_REPORTS);
  if (sealed < SEALED_MIN_REPORTS) {
    assert.equal(card.first_pass_accuracy.status, 'not_yet_validated');
    assert.match(formatScorecard(card), /First-pass accuracy: not_yet_validated/);
  }
  assert.equal(card.linked_package_coverage.validated, false);
});

test('regression and held-out tiers stay exact and state their limitation', () => {
  for (const tier of ['development', 'regression', 'held_out']) {
    const t = card.tiers[tier];
    assert.ok(t.limitation.length > 0);
    assert.deepEqual(t.failures, [], `${tier} failures`);
  }
});

test('no labelled case loses a token without a disposition', () => {
  for (const tier of ['development', 'regression', 'held_out']) {
    assert.equal(card.tiers[tier].undispositioned_tokens, 0, `${tier}: silent evidence loss`);
  }
});

test('provenance: every occurrence names its section; offsets cover nearly all', () => {
  for (const tier of ['development', 'regression', 'held_out']) {
    const t = card.tiers[tier];
    assert.equal(t.provenance_section_path, 1, `${tier}: section paths`);
    assert.ok(t.provenance_char_offsets >= 0.9, `${tier}: char offsets ${t.provenance_char_offsets}`);
  }
});

test('the contract fingerprint moves when any contract constant moves', () => {
  const bundle = extractionContractBundle();
  assert.notEqual(contractFingerprint(bundle), contractFingerprint({ ...bundle, candidates: 'changed' }));
  assert.equal(contractFingerprint(bundle), contractFingerprint(Object.fromEntries(Object.entries(bundle).reverse())));
});

test('real-report labels are present even when their private sources are not', () => {
  const withStore = loadBenchmarkCases({ privateDir: null, sourceDir: null });
  assert.ok(withStore.length > 0);
});

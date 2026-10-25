/**
 * Held-out evaluation workflow tests.
 * Does not invent labeled cases; verifies empty corpus behaviour and failure-stage mapping.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { discoverHeldOutCases, evaluateHeldOutCorpus, HELD_OUT_CASES_DIR } from './evaluateHeldOut.js';
import { classifyFailureStage, FAILURE_STAGES, annotateFalseNegativesWithStages } from './failureStage.js';
import { BENCHMARK_CASES_DIR } from '../benchmarkRunner.js';

test('held-out discovery never fabricates metrics; empty corpora stay null', () => {
  assert.ok(fs.existsSync(HELD_OUT_CASES_DIR));
  const d = discoverHeldOutCases();
  assert.notEqual(d.held_out_cases_dir, BENCHMARK_CASES_DIR);
  // Guard: committed held-out cases must not reuse regression case ids.
  const regressionIds = new Set(
    fs
      .readdirSync(BENCHMARK_CASES_DIR)
      .filter((f) => f.endsWith('.json') && !f.startsWith('known-'))
      .map((f) => f.replace(/\.json$/, ''))
  );
  for (const item of d.labeled) {
    assert.ok(!regressionIds.has(item.definition.id), `${item.definition.id} collides with regression`);
    assert.ok(
      item.definition.dataset_split === 'held_out_pilot' || (item.definition.tags || []).includes('held_out'),
      `${item.definition.id} missing held_out marker`
    );
  }
  const score = evaluateHeldOutCorpus();
  assert.equal(score.labeled_cases, d.labeled_cases);
  if (score.labeled_cases === 0) {
    assert.equal(score.available_cases, 0);
    assert.equal(score.aggregate.tp, null);
    assert.match(score.aggregate.note || '', /No independently labeled/);
  } else {
    assert.equal(typeof score.aggregate.tp, 'number');
    assert.equal(typeof score.aggregate.fp, 'number');
    assert.equal(typeof score.aggregate.fn, 'number');
    assert.ok(score.available_cases > 0);
  }
});

test('failure-stage classifier separates extraction vs membership vs AI vs analyst', () => {
  assert.equal(classifyFailureStage({ extracted: false }).stage, FAILURE_STAGES.NOT_EXTRACTED);
  assert.equal(
    classifyFailureStage({ extracted: false, mistyped_as: 'file' }).stage,
    FAILURE_STAGES.MISTYPED
  );
  assert.equal(
    classifyFailureStage(
      { extracted: true, member: false, policy_decision: 'context_only_narrative_with_authoritative_scope' },
      null
    ).stage,
    FAILURE_STAGES.CONTEXT_ONLY_POLICY
  );
  assert.equal(
    classifyFailureStage(
      { extracted: true, member: false },
      { ai_classification: { applied: true, assessment: 'context_only' } }
    ).stage,
    FAILURE_STAGES.AI_DEMOTION
  );
  assert.equal(
    classifyFailureStage({ extracted: true, member: false }, { review_status: 'context_only' }).stage,
    FAILURE_STAGES.ANALYST_EXCLUSION
  );
});

test('annotateFalseNegativesWithStages aggregates counts', () => {
  const out = annotateFalseNegativesWithStages({
    tp: 1,
    fp: 0,
    fn: 2,
    false_negatives: [
      { id: 'domain:a.example', extracted: false },
      { id: 'domain:b.example', extracted: true, member: false, policy_decision: 'context_only_narrative_with_authoritative_scope' }
    ]
  });
  assert.equal(out.failure_stages[FAILURE_STAGES.NOT_EXTRACTED], 1);
  assert.equal(out.failure_stages[FAILURE_STAGES.CONTEXT_ONLY_POLICY], 1);
});

test('exploratory files in cases/ are skipped, not scored', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-heldout-'));
  const casesDir = path.join(tmp, 'cases');
  const unlabeledDir = path.join(tmp, 'unlabeled');
  fs.mkdirSync(casesDir);
  fs.mkdirSync(unlabeledDir);
  fs.writeFileSync(
    path.join(casesDir, 'exploratory.json'),
    JSON.stringify({
      id: 'exploratory-demo',
      evaluation: 'exploratory',
      ground_truth: { provenance: { method: 'none', verified_by: 'n/a' } }
    })
  );
  fs.writeFileSync(path.join(unlabeledDir, 'note.json'), JSON.stringify({ id: 'u1', note: 'unlabeled' }));
  const d = discoverHeldOutCases({ casesDir, unlabeledDir });
  assert.equal(d.labeled_cases, 0);
  assert.equal(d.unlabeled_cases, 1);
  assert.ok(d.skipped.some((s) => s.reason.includes('exploratory')));
});

#!/usr/bin/env node
/**
 * Score the held-out Threat Library evaluation corpus.
 *
 * Never invents labels. When no independently labeled cases exist, prints an
 * empty scorecard (metrics null) and exits 0.
 *
 * Usage (from backend container / Node 24):
 *   node scripts/threat-library-held-out.js
 *   node scripts/threat-library-held-out.js --json
 */
import { evaluateHeldOutCorpus } from '../lib/threatLibrary/benchmark/heldOut/evaluateHeldOut.js';

const json = process.argv.includes('--json');
const score = evaluateHeldOutCorpus();
if (json) {
  process.stdout.write(`${JSON.stringify(score, null, 2)}\n`);
} else {
  console.log(`Held-out evaluation ${score.version}`);
  console.log(`  labeled cases:     ${score.labeled_cases}`);
  console.log(`  available cases:   ${score.available_cases}`);
  console.log(`  unlabeled cases:   ${score.unlabeled_cases}`);
  console.log(`  exact cases:       ${score.exact_cases}`);
  if (score.aggregate.note) console.log(`  ${score.aggregate.note}`);
  else {
    console.log(`  TP/FP/FN:          ${score.aggregate.tp}/${score.aggregate.fp}/${score.aggregate.fn}`);
    console.log(`  precision/recall:  ${score.aggregate.precision}/${score.aggregate.recall}`);
    console.log(`  F1:                ${score.aggregate.f1}`);
    if (score.aggregate.failure_stages) {
      console.log(`  failure stages:    ${JSON.stringify(score.aggregate.failure_stages)}`);
    }
  }
}
process.exit(0);

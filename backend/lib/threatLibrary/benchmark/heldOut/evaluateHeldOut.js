/**
 * Held-out evaluation workflow (pure scoring + discovery).
 *
 * Scans heldOut/cases for independently labeled fixtures and heldOut/unlabeled
 * for exploratory inputs. Never invents labels. When zero labeled cases exist,
 * returns an empty scorecard with explicit coverage counts.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  runBenchmarkCase,
  validateBenchmarkCase,
  caseSourceAvailable,
  BENCHMARK_CASES_DIR
} from '../benchmarkRunner.js';
import { annotateFalseNegativesWithStages } from './failureStage.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const HELD_OUT_CASES_DIR = path.join(here, 'cases');
export const HELD_OUT_UNLABELED_DIR = path.join(here, 'unlabeled');
export const HELD_OUT_EVALUATION_VERSION = 'tl-held-out-eval-v1';

function listJsonFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((n) => n.endsWith('.json'))
    .map((n) => path.join(dir, n))
    .sort();
}

/**
 * Load labeled held-out cases. Invalid / unlabeled exploratory files are skipped
 * with a recorded reason (never scored as accuracy).
 */
export function discoverHeldOutCases({ casesDir = HELD_OUT_CASES_DIR, unlabeledDir = HELD_OUT_UNLABELED_DIR } = {}) {
  const labeled = [];
  const skipped = [];
  for (const file of listJsonFiles(casesDir)) {
    let raw;
    try {
      raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
      skipped.push({ path: file, reason: `json_parse:${err.message}` });
      continue;
    }
    if (raw?.evaluation === 'exploratory' || raw?.ground_truth?.provenance?.method === 'none') {
      skipped.push({ path: file, reason: 'exploratory_or_unlabeled_in_cases_dir' });
      continue;
    }
    try {
      validateBenchmarkCase(raw, file);
      labeled.push({ path: file, definition: raw });
    } catch (err) {
      skipped.push({ path: file, reason: String(err.message || err).slice(0, 240) });
    }
  }
  const unlabeled = listJsonFiles(unlabeledDir).map((p) => ({ path: p, evaluation: 'exploratory' }));
  return {
    version: HELD_OUT_EVALUATION_VERSION,
    labeled_cases: labeled.length,
    unlabeled_cases: unlabeled.length,
    skipped,
    labeled,
    unlabeled,
    // Guardrail: held-out must not silently reuse the regression cases dir.
    regression_cases_dir: BENCHMARK_CASES_DIR,
    held_out_cases_dir: casesDir
  };
}

/**
 * Score one already-validated held-out case definition through the golden
 * benchmark extraction path.
 * @param {object} definition validated benchmark case
 */
export function scoreHeldOutCase(definition) {
  if (!caseSourceAvailable(definition)) {
    return {
      id: definition.id,
      available: false,
      reason: 'source_unavailable'
    };
  }
  const ran = runBenchmarkCase(definition);
  const indicators = annotateFalseNegativesWithStages(ran.metrics.indicators, new Map());
  return {
    id: definition.id,
    available: true,
    exact: indicators.fp === 0 && indicators.fn === 0,
    indicators,
    candidate_extraction: ran.metrics.candidate_extraction,
    quality_warning_codes: (ran.quality?.warnings || []).map((w) => w.code).sort(),
    publisher: definition.publisher || definition.meta?.publisher || null,
    tags: definition.tags || []
  };
}

/**
 * Aggregate held-out scorecard. Safe when labeled_cases === 0.
 */
export function evaluateHeldOutCorpus(opts = {}) {
  const discovery = discoverHeldOutCases(opts);
  const results = [];
  for (const item of discovery.labeled) {
    results.push(scoreHeldOutCase(item.definition));
  }
  const available = results.filter((r) => r.available);
  const unavailable = results.filter((r) => !r.available);
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let exact = 0;
  const failureStages = {};
  const reportsWithFn = [];
  const reportsWithFp = [];
  for (const r of available) {
    tp += r.indicators.tp;
    fp += r.indicators.fp;
    fn += r.indicators.fn;
    if (r.exact) exact += 1;
    if (r.indicators.fn > 0) reportsWithFn.push(r.id);
    if (r.indicators.fp > 0) reportsWithFp.push(r.id);
    for (const [stage, n] of Object.entries(r.indicators.failure_stages || {})) {
      failureStages[stage] = (failureStages[stage] || 0) + n;
    }
  }
  const precision = tp + fp > 0 ? Math.round((tp / (tp + fp)) * 10000) / 10000 : null;
  const recall = tp + fn > 0 ? Math.round((tp / (tp + fn)) * 10000) / 10000 : null;
  const f1 =
    precision != null && recall != null && precision + recall > 0
      ? Math.round(((2 * precision * recall) / (precision + recall)) * 10000) / 10000
      : null;

  return {
    version: HELD_OUT_EVALUATION_VERSION,
    labeled_cases: discovery.labeled_cases,
    unlabeled_cases: discovery.unlabeled_cases,
    available_cases: available.length,
    unavailable_cases: unavailable.length,
    skipped: discovery.skipped,
    exact_cases: exact,
    reports_with_missing_publisher_ioc: reportsWithFn,
    reports_with_false_positive_indicator: reportsWithFp,
    aggregate:
      available.length === 0
        ? {
            note: 'No independently labeled held-out cases are present. Metrics are not computed.',
            tp: null,
            fp: null,
            fn: null,
            precision: null,
            recall: null,
            f1: null
          }
        : { tp, fp, fn, precision, recall, f1, failure_stages: failureStages },
    cases: results
  };
}

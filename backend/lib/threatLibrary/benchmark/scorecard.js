/**
 * Threat Library evaluation scorecard.
 *
 * One report over every dataset tier, with each tier's limits stated. Precision
 * and recall are only ever computed against labels written independently of
 * TalonHound output. Approved Indicators are never used as ground truth.
 *
 * Tiers:
 *   development  synthetic controls and metamorphic layouts: structure checks
 *   regression   real-report excerpts labelled after an audit, in the same
 *                change as the fix they drove: they prove a past fix holds, and
 *                say nothing about unseen reports
 *   held_out     real extracts and synthetic cases not used to write the rules
 *                they first scored. Small, and partly contaminated (see CORPUS.md)
 *   sealed       sampled at import and labelled before any fix. The only tier
 *                that measures first-pass quality. `validated: false` until it
 *                holds independently labelled reports
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { contractFingerprint, extractionContractBundle } from '../contractBundle.js';
import { loadBenchmarkCases, loadCaseDirectory, materializeCase, runBenchmarkCase } from './benchmarkRunner.js';
import { extractReportCandidates } from '../extractionStages.js';
import { buildCandidateEvidenceRecord } from '../evidencePolicy.js';
import { buildObservableDispositions } from '../observableDispositions.js';
import { HELD_OUT_CASES_DIR } from './heldOut/evaluateHeldOut.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const SEALED_CASES_DIR = path.join(here, 'sealed', 'cases');
export const SCORECARD_VERSION = 'tl-scorecard-v1';

/** A sealed score below this many reports is reported, never treated as validated. */
export const SEALED_MIN_REPORTS = 30;

export const TIER_LIMITS = Object.freeze({
  development: 'Synthetic. Checks structure handling; not an accuracy measure.',
  regression: 'Labelled with the fix they drove. Proves past fixes hold; does not predict unseen reports.',
  held_out: 'Small and partly contaminated; see heldOut/CORPUS.md. Indicative only.',
  sealed: 'First-pass measure. Valid only with independent labels sampled before any fix.'
});

function ratio(n, d) {
  return d > 0 ? Number((n / d).toFixed(4)) : null;
}

/** Tier of a regression-corpus case from its id. */
export function caseTier(c) {
  const id = String(c?.id || '');
  if (id.startsWith('golden-') || id.startsWith('pdf-')) return 'regression';
  return 'development';
}

/**
 * Evidence accounting of one case, independent of its labels: tokens nothing
 * accounted for, and how many occurrences carry exact locators.
 * @param {object} c case definition
 */
export function caseEvidenceAccounting(c) {
  const { report, document } = materializeCase(c);
  const r = extractReportCandidates(report, document);
  const rows = r.candidates.map((x) => ({ ...x, evidence: buildCandidateEvidenceRecord(x) }));
  const disp = buildObservableDispositions({ candidates: rows, tokenLog: r.tokenLog, blocks: r.annotated?.blocks || [] });
  let occurrences = 0;
  let withSection = 0;
  let withOffset = 0;
  for (const row of rows) {
    if (row.is_ioc === false) continue;
    for (const o of row.evidence.occurrences || []) {
      occurrences += 1;
      if (Array.isArray(o.section_path)) withSection += 1;
      if (Number.isInteger(o.char_start)) withOffset += 1;
    }
  }
  return {
    undispositioned_tokens: disp.counts.undispositioned,
    needs_review: disp.counts.needs_review || 0,
    occurrences,
    with_section_path: withSection,
    with_char_offsets: withOffset
  };
}

function scoreTier(cases, tier) {
  const out = {
    tier,
    limitation: TIER_LIMITS[tier],
    cases: cases.length,
    exact: 0,
    tp: 0,
    fp: 0,
    fn: 0,
    fn_not_extracted: 0,
    fn_mistyped: 0,
    fn_not_member: 0,
    fn_with_review_path: 0,
    context_only_checked: 0,
    context_only_correct: 0,
    candidate_recall_checked: 0,
    candidate_recall_found: 0,
    undispositioned_tokens: 0,
    needs_review: 0,
    occurrences: 0,
    with_section_path: 0,
    with_char_offsets: 0,
    publishers: {},
    failures: []
  };
  for (const c of cases) {
    const r = runBenchmarkCase(c);
    const m = r.metrics.indicators;
    out.tp += m.tp;
    out.fp += m.fp;
    out.fn += m.fn;
    out.fn_not_extracted += m.fn_not_extracted || 0;
    out.fn_mistyped += m.fn_mistyped || 0;
    out.fn_not_member += m.fn_not_member || 0;
    out.fn_with_review_path += m.fn_needs_review || 0;
    out.context_only_checked += r.metrics.context_only?.checked ?? 0;
    out.context_only_correct += r.metrics.context_only?.correct ?? 0;
    out.candidate_recall_checked += m.expected;
    out.candidate_recall_found += m.expected - (m.fn_not_extracted || 0);
    if (!m.fp && !m.fn) out.exact += 1;
    else out.failures.push({ id: c.id, fp: m.fp, fn: m.fn });
    const publisher = c.publisher || 'synthetic_or_unlabelled';
    out.publishers[publisher] = (out.publishers[publisher] || 0) + 1;
    const a = caseEvidenceAccounting(c);
    out.undispositioned_tokens += a.undispositioned_tokens;
    out.needs_review += a.needs_review;
    out.occurrences += a.occurrences;
    out.with_section_path += a.with_section_path;
    out.with_char_offsets += a.with_char_offsets;
  }
  out.precision = ratio(out.tp, out.tp + out.fp);
  out.recall = ratio(out.tp, out.tp + out.fn);
  out.f1 = out.precision != null && out.recall != null && out.precision + out.recall > 0
    ? Number(((2 * out.precision * out.recall) / (out.precision + out.recall)).toFixed(4))
    : null;
  out.report_exact_match = ratio(out.exact, out.cases);
  out.candidate_type_accuracy = ratio(out.tp + out.fn_not_member, out.tp + out.fn_not_member + out.fn_mistyped);
  out.classification_accuracy = ratio(out.context_only_correct, out.context_only_checked);
  out.candidate_discovery_recall = ratio(out.candidate_recall_found, out.candidate_recall_checked);
  out.provenance_section_path = ratio(out.with_section_path, out.occurrences);
  out.provenance_char_offsets = ratio(out.with_char_offsets, out.occurrences);
  return out;
}

/** @returns {object} the full scorecard (no database, network or model) */
export function buildScorecard() {
  const corpus = loadBenchmarkCases({ privateDir: null, sourceDir: null });
  const development = corpus.filter((c) => caseTier(c) === 'development');
  const regression = corpus.filter((c) => caseTier(c) === 'regression');
  const heldOut = loadCaseDirectory(HELD_OUT_CASES_DIR).filter((c) => c.ground_truth?.indicators && c.evaluation !== 'exploratory')
    .map((c) => ({ ...c, __dir: c.__dir || HELD_OUT_CASES_DIR }));
  const sealed = loadCaseDirectory(SEALED_CASES_DIR).map((c) => ({ ...c, __dir: c.__dir || SEALED_CASES_DIR }));
  const sealedTier = scoreTier(sealed, 'sealed');
  const validated = sealed.length >= SEALED_MIN_REPORTS;
  return {
    version: SCORECARD_VERSION,
    contract_bundle: extractionContractBundle(),
    contract_fingerprint: contractFingerprint(),
    first_pass_accuracy: {
      validated,
      status: validated ? 'validated_by_sealed_labels' : 'not_yet_validated',
      sealed_reports: sealed.length,
      required_reports: SEALED_MIN_REPORTS,
      note: validated
        ? 'Sealed labels were sampled at import and labelled before any fix.'
        : 'No first-pass accuracy claim is possible yet. Regression and held-out figures below do not measure unseen reports.'
    },
    linked_package_coverage: {
      validated: false,
      status: 'not_yet_validated',
      note: 'Requires labels that list each report\'s publisher package. No labelled set exists yet.'
    },
    tiers: {
      development: scoreTier(development, 'development'),
      regression: scoreTier(regression, 'regression'),
      held_out: scoreTier(heldOut, 'held_out'),
      sealed: sealedTier
    }
  };
}

/** Human summary of a scorecard. */
export function formatScorecard(card) {
  const lines = [`Scorecard ${card.version}  contract ${card.contract_fingerprint}`];
  lines.push(`First-pass accuracy: ${card.first_pass_accuracy.status} (${card.first_pass_accuracy.sealed_reports}/${card.first_pass_accuracy.required_reports} sealed reports)`);
  lines.push(`Linked package coverage: ${card.linked_package_coverage.status}`);
  for (const t of Object.values(card.tiers)) {
    lines.push(`\n[${t.tier}] ${t.limitation}`);
    if (!t.cases) {
      lines.push('  no cases');
      continue;
    }
    lines.push(`  cases ${t.cases}  exact ${t.exact}  P ${t.precision}  R ${t.recall}  F1 ${t.f1}`);
    lines.push(`  fn not_extracted ${t.fn_not_extracted}  mistyped ${t.fn_mistyped}  not_member ${t.fn_not_member}  with_review_path ${t.fn_with_review_path}`);
    lines.push(`  type_accuracy ${t.candidate_type_accuracy}  classification_accuracy ${t.classification_accuracy}  discovery_recall ${t.candidate_discovery_recall}`);
    lines.push(`  needs_review ${t.needs_review}  undispositioned_tokens ${t.undispositioned_tokens}`);
    lines.push(`  provenance: section_path ${t.provenance_section_path}  char_offsets ${t.provenance_char_offsets}`);
  }
  return lines.join('\n');
}

export function sealedDirectoryExists() {
  return fs.existsSync(SEALED_CASES_DIR);
}

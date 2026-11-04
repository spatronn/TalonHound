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
import { compareWithBaseline, loadBenchmarkCases, loadCaseDirectory, materializeCase, readBaseline, runBenchmark, runBenchmarkCase } from './benchmarkRunner.js';
import { extractReportCandidates } from '../extractionStages.js';
import { buildCandidateEvidenceRecord } from '../evidencePolicy.js';
import { buildObservableDispositions } from '../observableDispositions.js';
import { HELD_OUT_CASES_DIR } from './heldOut/evaluateHeldOut.js';
import { sealedSetReadiness } from './sealedProtocol.js';
import { discoverIocSourcesFromBlocks } from '../iocSources/discover.js';
import { canonicalizeReportUrl } from '../importIdentity.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const SEALED_CASES_DIR = path.join(here, 'sealed', 'cases');
export const SCORECARD_VERSION = 'tl-scorecard-v2';

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

/**
 * Whether discovery reaches the packages a label says the report points to. Reads the
 * labelled URLs only; a case without `ground_truth.linked_packages` scores nothing.
 * @param {{ ground_truth?: { linked_packages?: Array<{ url: string, expected_identities?: string[] }> } }} c
 * @param {{ blocks?: object[] }} document
 * @param {string|null} [reportUrl]
 */
export function scoreLinkedPackages(c, document, reportUrl = null) {
  const labelled = c?.ground_truth?.linked_packages || [];
  if (!labelled.length) return { labelled: 0, discovered: 0, identities_labelled: 0, missed: [] };
  const found = new Set(discoverIocSourcesFromBlocks(document?.blocks || [], { reportUrl }).map((d) => d.canonical_url));
  const missed = labelled.filter((p) => !found.has(canonicalizeReportUrl(p.url)));
  return {
    labelled: labelled.length,
    discovered: labelled.length - missed.length,
    identities_labelled: labelled.reduce((n, p) => n + (p.expected_identities || []).length, 0),
    missed: missed.map((p) => p.url)
  };
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1)];
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
    review_path_cases: [],
    failures: [],
    linked_packages_labelled: 0,
    linked_packages_discovered: 0,
    linked_identities_labelled: 0,
    linked_packages_missed: []
  };
  const reviewPerCase = [];
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
    out.context_only_checked += r.metrics.context_only?.expected ?? 0;
    out.context_only_correct += r.metrics.context_only?.correct ?? 0;
    out.candidate_recall_checked += m.expected;
    out.candidate_recall_found += m.expected - (m.fn_not_extracted || 0);
    if (!m.fp && !m.fn) out.exact += 1;
    // A value that reached review is visible and is reported, not a silent failure.
    else if (!m.fp && m.fn === (m.fn_needs_review || 0)) out.review_path_cases.push({ id: c.id, fn: m.fn });
    else out.failures.push({ id: c.id, fp: m.fp, fn: m.fn, fn_needs_review: m.fn_needs_review || 0 });
    const publisher = c.publisher || 'synthetic_or_unlabelled';
    out.publishers[publisher] = (out.publishers[publisher] || 0) + 1;
    const a = caseEvidenceAccounting(c);
    out.undispositioned_tokens += a.undispositioned_tokens;
    out.needs_review += a.needs_review;
    reviewPerCase.push(a.needs_review);
    if (c.ground_truth?.linked_packages?.length) {
      const { report, document } = materializeCase(c);
      const lp = scoreLinkedPackages(c, document, report?.source_url || null);
      out.linked_packages_labelled += lp.labelled;
      out.linked_packages_discovered += lp.discovered;
      out.linked_identities_labelled += lp.identities_labelled;
      out.linked_packages_missed.push(...lp.missed);
    }
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
  // Case labels list what the document itself asserts, so recall is document-only coverage.
  out.document_only_ioc_coverage = out.recall;
  out.linked_package_discovery_recall = ratio(out.linked_packages_discovered, out.linked_packages_labelled);
  const reviewSorted = [...reviewPerCase].sort((x, y) => x - y);
  out.unresolved_review_volume = {
    total: out.needs_review,
    median_per_report: percentile(reviewSorted, 0.5),
    p90_per_report: percentile(reviewSorted, 0.9),
    max_per_report: reviewSorted.length ? reviewSorted[reviewSorted.length - 1] : 0
  };
  out.silent_evidence_loss = out.undispositioned_tokens;
  const expected = out.tp + out.fn;
  out.per_stage_failure_rates = {
    candidate_discovery: ratio(out.fn_not_extracted, expected),
    type_resolution: ratio(out.fn_mistyped, expected),
    membership_decision: ratio(out.fn_not_member, expected),
    reached_review_only: ratio(out.fn_with_review_path, expected)
  };
  out.candidate_type_accuracy = ratio(out.tp + out.fn_not_member, out.tp + out.fn_not_member + out.fn_mistyped);
  out.classification_accuracy = ratio(out.context_only_correct, out.context_only_checked);
  out.candidate_discovery_recall = ratio(out.candidate_recall_found, out.candidate_recall_checked);
  out.provenance_section_path = ratio(out.with_section_path, out.occurrences);
  out.provenance_char_offsets = ratio(out.with_char_offsets, out.occurrences);
  return out;
}

/**
 * Scoring real reports needs their private source store, which CI does not have. That
 * is "not evaluated", stated as such, and never a pass.
 */
function privateSourceScoring() {
  const dir = process.env.TL_BENCHMARK_SOURCE_DIR || null;
  return dir
    ? { status: 'evaluated_with_private_store', source_dir_configured: true }
    : { status: 'not_evaluated', source_dir_configured: false, note: 'Set TL_BENCHMARK_SOURCE_DIR to score the real-report labels. This run says nothing about them.' };
}

/** What the current contract changes against the committed baseline. */
function contractComparison() {
  const baseline = readBaseline();
  const diff = compareWithBaseline(runBenchmark({ privateDir: null, sourceDir: null }), baseline);
  return {
    baseline_versions: baseline.versions,
    regressions: diff.changes.flatMap((c) => c.regressions.map((r) => ({ case: c.case, ...r }))),
    improvements: diff.changes.flatMap((c) => c.improvements.map((r) => ({ case: c.case, ...r }))),
    cases_changed: diff.changes.length,
    new_cases: diff.new_cases.length,
    missing_cases: diff.missing_cases.length
  };
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
  const validated = sealedSetReadiness(sealed, { min_reports: SEALED_MIN_REPORTS, contract_fingerprint: contractFingerprint() }).ready;
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
      validated: validated && sealedTier.linked_packages_labelled > 0,
      status: validated && sealedTier.linked_packages_labelled > 0 ? 'validated_by_sealed_labels' : 'not_yet_validated',
      labelled_packages: sealedTier.linked_packages_labelled,
      discovery_recall: sealedTier.linked_package_discovery_recall,
      note: 'Counts sealed labels that list a report\'s publisher package. Measures discovery; extraction from a pack needs its fetched files.'
    },
    private_source_scoring: privateSourceScoring(),
    sealed_readiness: sealedSetReadiness(sealed, { min_reports: SEALED_MIN_REPORTS, contract_fingerprint: contractFingerprint() }),
    contract_comparison: contractComparison(),
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
  lines.push(`Linked package coverage: ${card.linked_package_coverage.status} (${card.linked_package_coverage.labelled_packages} labelled)`);
  lines.push(`Private source scoring: ${card.private_source_scoring.status}`);
  if (card.sealed_readiness.blockers.length) lines.push(`Sealed set blockers: ${card.sealed_readiness.blockers.join('; ')}`);
  lines.push(`Against baseline: ${card.contract_comparison.regressions.length} regressions, ${card.contract_comparison.improvements.length} improvements`);
  for (const t of Object.values(card.tiers)) {
    lines.push(`\n[${t.tier}] ${t.limitation}`);
    if (!t.cases) {
      lines.push('  no cases');
      continue;
    }
    lines.push(`  cases ${t.cases}  exact ${t.exact}  P ${t.precision}  R ${t.recall}  F1 ${t.f1}`);
    lines.push(`  fn not_extracted ${t.fn_not_extracted}  mistyped ${t.fn_mistyped}  not_member ${t.fn_not_member}  with_review_path ${t.fn_with_review_path}`);
    lines.push(`  type_accuracy ${t.candidate_type_accuracy}  classification_accuracy ${t.classification_accuracy}  discovery_recall ${t.candidate_discovery_recall}`);
    lines.push(`  needs_review ${t.needs_review}  median ${t.unresolved_review_volume.median_per_report}  p90 ${t.unresolved_review_volume.p90_per_report}  max ${t.unresolved_review_volume.max_per_report}  silent_evidence_loss ${t.silent_evidence_loss}`);
    lines.push(`  document_only_coverage ${t.document_only_ioc_coverage}  linked_discovery ${t.linked_package_discovery_recall ?? 'no labels'}`);
    lines.push(`  stage failure rates: ${JSON.stringify(t.per_stage_failure_rates)}`);
    lines.push(`  provenance: section_path ${t.provenance_section_path}  char_offsets ${t.provenance_char_offsets}`);
  }
  return lines.join('\n');
}

export function sealedDirectoryExists() {
  return fs.existsSync(SEALED_CASES_DIR);
}

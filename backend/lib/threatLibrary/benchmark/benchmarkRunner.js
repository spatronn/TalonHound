/**
 * Threat Library golden-report benchmark runner.
 *
 * Runs the deterministic extraction stage the pipeline and Refresh extraction
 * use (extractionStages.extractReportCandidates) on frozen fixtures and scores
 * the result against independently labeled ground truth. It never calls a
 * model, never touches a database and never reads production classifications:
 * stored TalonHound output is not ground truth.
 *
 * Case sources:
 *   html_file   retained / synthetic HTML (path relative to the case file)
 *   pdf_items   pdf.js text items (the existing fixture format) → pdfLayout
 *   canonical   a stored canonical document JSON
 *   layout_variant  generated metamorphic variant (layoutVariants.js)
 *
 * Committed cases live in ./cases. Private cases (retained publisher HTML that
 * must not be committed) use the same format in TL_BENCHMARK_PRIVATE_DIR.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractReportCandidates } from '../extractionStages.js';
import { extractCanonicalDocumentFromHtml, THREAT_LIBRARY_HTML_EXTRACTOR_VERSION } from '../extract/extractHtml.js';
import { pagesToBlocks, PDF_LAYOUT_VERSION } from '../pdfLayout.js';
import { createCanonicalDocument } from '../canonicalDocument.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from '../candidateExtraction.js';
import { THREAT_LIBRARY_DOCUMENT_ZONES_VERSION } from '../documentZones.js';
import { TABLE_SEMANTICS_VERSION } from '../tableSemantics.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION } from '../observableTypeResolver.js';
import {
  BENCHMARK_METRICS_VERSION,
  GROUND_TRUTH_CATEGORIES,
  aggregateBenchmark,
  groundTruthIdentity,
  scoreBenchmarkCase
} from './benchmarkMetrics.js';
import { buildLayoutVariant, layoutVariantGroundTruth, listLayoutVariantIds } from './layoutVariants.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const BENCHMARK_CASES_DIR = path.join(here, 'cases');
export const BENCHMARK_BASELINE_PATH = path.join(here, 'baseline.json');

const CASE_KINDS = new Set(['html_file', 'pdf_items', 'canonical', 'layout_variant']);

/** Extractor contract versions a benchmark run was produced under. */
export function extractorVersions() {
  return {
    candidates: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
    zones: THREAT_LIBRARY_DOCUMENT_ZONES_VERSION,
    tables: TABLE_SEMANTICS_VERSION,
    type_resolver: OBSERVABLE_TYPE_RESOLVER_VERSION,
    html: THREAT_LIBRARY_HTML_EXTRACTOR_VERSION,
    pdf: PDF_LAYOUT_VERSION,
    metrics: BENCHMARK_METRICS_VERSION
  };
}

/**
 * Structural validation of a case definition (fails loudly on a bad fixture).
 * @param {object} c
 * @param {string} [origin]
 */
export function validateBenchmarkCase(c, origin = 'case') {
  const problems = [];
  if (!c || typeof c !== 'object') problems.push('not an object');
  else {
    if (!/^[a-z0-9][a-z0-9._/-]{2,120}$/.test(String(c.id || ''))) problems.push('id must be a lowercase slug');
    if (!CASE_KINDS.has(c.source?.kind)) problems.push(`source.kind must be one of ${[...CASE_KINDS].join(', ')}`);
    const gt = c.ground_truth;
    if (!gt || typeof gt !== 'object') problems.push('ground_truth is required');
    else {
      if (!gt.provenance?.method || !gt.provenance?.verified_by) {
        problems.push('ground_truth.provenance.method and verified_by are required (ground truth must be independently verified)');
      }
      for (const key of GROUND_TRUTH_CATEGORIES) {
        if (gt[key] != null && !Array.isArray(gt[key])) problems.push(`ground_truth.${key} must be an array`);
        for (const e of gt[key] || []) {
          if (!e?.type || !e?.value) problems.push(`ground_truth.${key}: every entry needs type and value`);
        }
      }
      const seen = new Map();
      for (const key of GROUND_TRUTH_CATEGORIES) {
        for (const e of gt[key] || []) {
          const id = groundTruthIdentity(e);
          if (seen.has(id) && seen.get(id) !== key) problems.push(`${id} is labeled both ${seen.get(id)} and ${key}`);
          seen.set(id, key);
        }
      }
    }
  }
  if (problems.length) throw new Error(`invalid benchmark case ${origin}: ${problems.join('; ')}`);
  return c;
}

/**
 * Case definitions from a directory (*.json, one case per file).
 * @param {string} dir
 */
export function loadCaseDirectory(dir) {
  if (!dir || !fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => {
      const file = path.join(dir, f);
      const c = validateBenchmarkCase(JSON.parse(fs.readFileSync(file, 'utf8')), file);
      return { ...c, __dir: dir };
    });
}

/** Generated metamorphic cases (one per layout variant). */
export function layoutVariantCases() {
  const groundTruth = layoutVariantGroundTruth();
  return listLayoutVariantIds().map((variant) => ({
    id: `layout/${variant}`,
    title: buildLayoutVariant(variant).description,
    publisher: 'synthetic',
    format: variant.startsWith('pdf_') ? 'pdf' : 'html',
    tags: ['metamorphic', 'layout_variant'],
    source: { kind: 'layout_variant', variant },
    ground_truth: groundTruth
  }));
}

/**
 * Every benchmark case: committed fixtures, generated layout variants and (when
 * configured) private cases.
 * @param {{ privateDir?: string|null, includeLayoutVariants?: boolean }} [opts]
 */
export function loadBenchmarkCases(opts = {}) {
  const privateDir = opts.privateDir === undefined ? process.env.TL_BENCHMARK_PRIVATE_DIR || null : opts.privateDir;
  const cases = [
    ...loadCaseDirectory(BENCHMARK_CASES_DIR),
    ...(opts.includeLayoutVariants === false ? [] : layoutVariantCases()),
    ...loadCaseDirectory(privateDir).map((c) => ({ ...c, private: true }))
  ];
  const ids = new Set();
  for (const c of cases) {
    if (ids.has(c.id)) throw new Error(`duplicate benchmark case id: ${c.id}`);
    ids.add(c.id);
  }
  return cases;
}

/**
 * Canonical document + report context for a case.
 * @param {object} c
 */
export function materializeCase(c) {
  const src = c.source || {};
  const resolve = (p) => path.resolve(c.__dir || BENCHMARK_CASES_DIR, p);
  if (src.kind === 'layout_variant') {
    const v = buildLayoutVariant(src.variant);
    return { document: v.document, report: { source_type: v.format === 'pdf' ? 'pdf' : 'url', source_url: v.sourceUrl } };
  }
  if (src.kind === 'html_file') {
    const html = fs.readFileSync(resolve(src.path), 'utf8');
    const url = src.url || 'https://benchmark.example/report/';
    const r = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
    if (!r.ok) throw new Error(`benchmark case ${c.id}: HTML extraction failed (${r.code})`);
    return { document: r.document, report: { source_type: 'url', source_url: url, published_at: c.published_at || null } };
  }
  if (src.kind === 'pdf_items') {
    const raw = JSON.parse(fs.readFileSync(resolve(src.path), 'utf8'));
    const pages = Array.isArray(raw) ? raw : raw[src.pages_key || 'pages'];
    const { blocks } = pagesToBlocks(pages);
    const document = createCanonicalDocument({
      title: c.title || c.id,
      language: c.language || null,
      blocks,
      meta: { extractor: PDF_LAYOUT_VERSION, adapter: 'pdf' }
    });
    return { document, report: { source_type: 'pdf', source_url: null, published_at: c.published_at || null } };
  }
  const document = JSON.parse(fs.readFileSync(resolve(src.path), 'utf8'));
  return { document, report: { source_type: c.format === 'pdf' ? 'pdf' : 'url', source_url: src.url || null } };
}

/**
 * Run one case through the deterministic extraction stage and score it.
 * @param {object} c
 */
export function runBenchmarkCase(c) {
  const { document, report } = materializeCase(c);
  const started = process.hrtime.bigint();
  const extracted = extractReportCandidates(report, document);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const blocks = extracted.annotated?.blocks || [];
  const metrics = scoreBenchmarkCase({ groundTruth: c.ground_truth, candidates: extracted.candidates, blocks });
  return {
    id: c.id,
    title: c.title || null,
    format: c.format || null,
    tags: c.tags || [],
    private: c.private === true,
    elapsed_ms: Math.round(elapsedMs * 10) / 10,
    metrics,
    quality: extracted.diagnostics?.quality || null
  };
}

/**
 * @param {{ cases?: object[], privateDir?: string|null, filter?: (c: object) => boolean }} [opts]
 */
export function runBenchmark(opts = {}) {
  const cases = (opts.cases || loadBenchmarkCases({ privateDir: opts.privateDir })).filter(opts.filter || (() => true));
  const results = cases.map((c) => runBenchmarkCase(c));
  return { versions: extractorVersions(), aggregate: aggregateBenchmark(results), results };
}

/**
 * Baseline record of a run: per-case members + headline metrics. Timing and
 * timestamps are left out so the file only changes when behaviour changes.
 * @param {ReturnType<typeof runBenchmark>} run
 */
export function baselineFromRun(run) {
  const cases = {};
  for (const r of run.results.filter((x) => !x.private)) {
    const m = r.metrics;
    cases[r.id] = {
      members: m.members,
      tp: m.indicators.tp,
      fp: m.indicators.fp,
      fn: m.indicators.fn,
      fn_not_extracted: m.indicators.fn_not_extracted,
      fn_not_member: m.indicators.fn_not_member,
      sections_correct: m.sections.correct,
      sections_checked: m.sections.checked,
      assertions_correct: m.assertions.correct,
      assertions_checked: m.assertions.checked,
      ...(r.quality ? { warning_codes: [...new Set((r.quality.warnings || []).map((w) => w.code))].sort() } : {})
    };
  }
  const { elapsed_ms: _ignored, ...aggregate } = aggregateBenchmark(run.results.filter((x) => !x.private));
  return { versions: run.versions, aggregate, cases };
}

/**
 * Unexpected Indicator membership changes against a stored baseline. A change
 * toward ground truth is an improvement, away from it a regression; both are
 * reported (a stale baseline hides future regressions).
 * @param {ReturnType<typeof runBenchmark>} run
 * @param {{ cases?: Record<string, { members: string[] }> }|null} baseline
 * @param {Map<string, object>|Record<string, object>} [caseById] ground truth lookup
 */
export function compareWithBaseline(run, baseline, caseById = {}) {
  const lookup = caseById instanceof Map ? caseById : new Map(Object.entries(caseById));
  const base = baseline?.cases || {};
  const changes = [];
  const newCases = [];
  const current = new Set();
  for (const r of run.results.filter((x) => !x.private)) {
    current.add(r.id);
    const prior = base[r.id];
    if (!prior) {
      newCases.push(r.id);
      continue;
    }
    const before = new Set(prior.members || []);
    const after = new Set(r.metrics.members);
    const added = [...after].filter((id) => !before.has(id)).sort();
    const removed = [...before].filter((id) => !after.has(id)).sort();
    const priorCodes = prior.warning_codes || null;
    const codes = r.quality ? [...new Set((r.quality.warnings || []).map((w) => w.code))].sort() : null;
    const warningsChanged = priorCodes != null && codes != null && priorCodes.join(',') !== codes.join(',');
    if (!added.length && !removed.length && !warningsChanged) continue;
    const expected = new Set((lookup.get(r.id)?.ground_truth?.indicators || []).map(groundTruthIdentity));
    changes.push({
      case: r.id,
      added_members: added,
      removed_members: removed,
      regressions: [
        ...removed.filter((id) => expected.has(id)).map((id) => ({ id, kind: 'new_false_negative' })),
        ...added.filter((id) => !expected.has(id)).map((id) => ({ id, kind: 'new_false_positive' }))
      ],
      improvements: [
        ...added.filter((id) => expected.has(id)).map((id) => ({ id, kind: 'fixed_false_negative' })),
        ...removed.filter((id) => !expected.has(id)).map((id) => ({ id, kind: 'fixed_false_positive' }))
      ],
      ...(warningsChanged ? { warning_codes_before: priorCodes, warning_codes_after: codes } : {})
    });
  }
  const missingCases = Object.keys(base).filter((id) => !current.has(id)).sort();
  return {
    changes,
    new_cases: newCases.sort(),
    missing_cases: missingCases,
    regression_count: changes.reduce((n, c) => n + c.regressions.length, 0),
    improvement_count: changes.reduce((n, c) => n + c.improvements.length, 0),
    unchanged: changes.length === 0 && newCases.length === 0 && missingCases.length === 0
  };
}

export function readBaseline(file = BENCHMARK_BASELINE_PATH) {
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

export function writeBaseline(run, file = BENCHMARK_BASELINE_PATH) {
  fs.writeFileSync(file, `${JSON.stringify(baselineFromRun(run), null, 2)}\n`);
}

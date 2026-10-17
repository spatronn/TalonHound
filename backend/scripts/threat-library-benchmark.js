#!/usr/bin/env node
/**
 * Threat Library golden-report benchmark (deterministic extraction only).
 *
 * Runs every benchmark case (lib/threatLibrary/benchmark/cases, generated
 * layout variants, and TL_BENCHMARK_PRIVATE_DIR when set) through the same
 * extraction stage the pipeline uses and prints precision / recall, candidate
 * extraction vs membership failures, section and assertion accuracy, quality
 * warnings and the change against the committed baseline. No database, no
 * model, no network.
 *
 *   node scripts/threat-library-benchmark.js                 table + baseline diff
 *   node scripts/threat-library-benchmark.js --json          full JSON report
 *   node scripts/threat-library-benchmark.js --case <prefix> only matching case ids
 *   node scripts/threat-library-benchmark.js --private-dir <dir>
 *   node scripts/threat-library-benchmark.js --write-baseline
 *       rewrite lib/threatLibrary/benchmark/baseline.json after a REVIEWED change
 *
 * Exit status: 1 when the run regresses against the baseline (new false
 * negative / false positive), else 0.
 */

import {
  compareWithBaseline,
  loadBenchmarkCases,
  readBaseline,
  runBenchmark,
  writeBaseline
} from '../lib/threatLibrary/benchmark/benchmarkRunner.js';
import { knownFailureFor } from '../lib/threatLibrary/benchmark/knownFailures.js';

// Benchmark the production scope engine unless one is chosen explicitly
// (THREAT_LIBRARY_SCOPE_ENGINE=legacy measures the emergency rollback).
process.env.THREAT_LIBRARY_SCOPE_ENGINE = process.env.THREAT_LIBRARY_SCOPE_ENGINE || 'section_tree';

function parseArgs(argv) {
  const args = { json: false, writeBaseline: false, casePrefix: null, privateDir: undefined, sourceDir: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--write-baseline') args.writeBaseline = true;
    else if (a === '--case') args.casePrefix = argv[++i] || null;
    else if (a === '--private-dir') args.privateDir = argv[++i] || null;
    else if (a === '--source-dir') args.sourceDir = argv[++i] || null;
    else if (a === '--help' || a === '-h') args.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

const pct = (v) => (v == null ? '   —  ' : `${(v * 100).toFixed(1).padStart(5)}%`);

function printTable(run, comparison) {
  const a = run.aggregate;
  console.log(`Threat Library benchmark — ${a.cases} cases (${a.cases_exact} exact)`);
  console.log(`versions: ${Object.entries(run.versions).map(([k, v]) => `${k}=${v}`).join(' ')}`);
  console.log(
    `Indicators: precision ${pct(a.indicators.precision)}  recall ${pct(a.indicators.recall)}  F1 ${pct(a.indicators.f1)}  ` +
      `TP ${a.indicators.tp}  FP ${a.indicators.fp}  FN ${a.indicators.fn} ` +
      `(not extracted ${a.indicators.fn_not_extracted}, wrong type ${a.indicators.fn_mistyped}, extracted but not member ${a.indicators.fn_not_member})`
  );
  console.log(
    `candidate extraction recall ${pct(a.candidate_extraction_recall)}  context-only ${pct(a.context_only_accuracy)}  ` +
      `legitimate exclusion ${pct(a.legitimate_exclusion_accuracy)}  assertions ${pct(a.assertion_accuracy)}  ` +
      `sections ${pct(a.section_accuracy)}  unsupported ${a.unsupported_indicators}  extraction ${a.elapsed_ms.toFixed(1)} ms`
  );
  if (a.quality) {
    console.log(
      `quality warnings: high ${a.quality.high}  warning ${a.quality.warning}  info ${a.quality.info}  ` +
        `(cases with warning+: ${a.quality.cases_flagged}; exact cases flagged: ${a.quality.exact_cases_flagged})`
    );
  }
  console.log('');
  for (const r of run.results) {
    const m = r.metrics.indicators;
    const exact = m.fp === 0 && m.fn === 0;
    const known = knownFailureFor(r.id);
    const codes = r.quality ? [...new Set((r.quality.warnings || []).filter((w) => w.severity !== 'info').map((w) => w.code))] : [];
    console.log(
      `${exact ? 'ok  ' : 'FAIL'} ${r.id.padEnd(58)} ${String(m.tp).padStart(3)}/${String(m.expected).padEnd(3)} ` +
        `fp ${String(m.fp).padStart(2)} fn ${String(m.fn).padStart(2)}` +
        `${m.fn ? ` (x${m.fn_not_extracted}/t${m.fn_mistyped}/m${m.fn_not_member})` : ''}` +
        `${codes.length ? `  ⚠ ${codes.join(',')}` : ''}` +
        `${known ? `  [known: ${known.cause}]` : ''}`
    );
  }
  if (run.unavailable?.length) {
    console.log(`\nunavailable (source not in the private store, not scored): ${run.unavailable.join(', ')}`);
  }
  console.log('');
  if (!comparison) {
    console.log('No baseline found (run with --write-baseline after review).');
    return;
  }
  if (comparison.unchanged) {
    console.log('Baseline: no Indicator membership change.');
    return;
  }
  console.log(
    `Baseline: ${comparison.changes.length} changed case(s), ${comparison.regression_count} regression(s), ` +
      `${comparison.improvement_count} improvement(s); new cases ${comparison.new_cases.length}, missing ${comparison.missing_cases.length}`
  );
  for (const c of comparison.changes) {
    console.log(`  ${c.case}: +${c.added_members.length} -${c.removed_members.length}`);
    for (const x of c.regressions) console.log(`    REGRESSION ${x.kind} ${x.id}`);
    for (const x of c.improvements) console.log(`    improvement ${x.kind} ${x.id}`);
    if (c.warning_codes_before) console.log(`    warnings ${c.warning_codes_before.join(',') || '∅'} → ${c.warning_codes_after.join(',') || '∅'}`);
  }
  for (const id of comparison.new_cases) console.log(`  new case ${id}`);
  for (const id of comparison.missing_cases) console.log(`  missing case ${id}`);
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  console.log('usage: node scripts/threat-library-benchmark.js [--json] [--case <prefix>] [--private-dir <dir>] [--source-dir <private source store>] [--write-baseline]');
  process.exit(0);
}
const cases = loadBenchmarkCases({ privateDir: args.privateDir, sourceDir: args.sourceDir });
const selected = args.casePrefix ? cases.filter((c) => c.id.startsWith(args.casePrefix)) : cases;
const run = runBenchmark({ cases: selected });
const baseline = args.casePrefix ? null : readBaseline();
const comparison = baseline ? compareWithBaseline(run, baseline, new Map(selected.map((c) => [c.id, c]))) : null;

if (args.writeBaseline) {
  if (args.casePrefix) throw new Error('--write-baseline needs the full case set (drop --case)');
  writeBaseline(run);
}
if (args.json) {
  console.log(JSON.stringify({ ...run, baseline_comparison: comparison }, null, 2));
} else {
  printTable(run, comparison);
  if (args.writeBaseline) console.log('\nbaseline.json written.');
}
process.exitCode = comparison && comparison.regression_count > 0 && !args.writeBaseline ? 1 : 0;

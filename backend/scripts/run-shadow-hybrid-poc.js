#!/usr/bin/env node
/**
 * Shadow Hybrid IOC Extraction PoC CLI.
 *
 * Examples (run inside the backend container or on a host with NODE path set):
 *   node scripts/run-shadow-hybrid-poc.js --out /tmp/shadow-hybrid-poc/report.json
 *   node scripts/run-shadow-hybrid-poc.js --qwen --qwen-mode selective --out /tmp/shadow-hybrid-poc/report-qwen.json
 *   node scripts/run-shadow-hybrid-poc.js --qwen --qwen-mode full --ids shadow-unit42-blinder-tunnel
 *
 * Never writes to PostgreSQL. Never refreshes production reports.
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runShadowHybridPoc, writeReport } from '../lib/threatLibrary/experiments/shadowHybrid/runShadowHybrid.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(here, '..');

function parseArgs(argv) {
  const opts = {
    runQwen: false,
    qwenMode: 'selective',
    includeControls: true,
    out: path.join('/tmp/shadow-hybrid-poc', `report-${Date.now()}.json`),
    ids: null,
    abortIfBusy: true,
    maxChunks: null
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--qwen') opts.runQwen = true;
    else if (a === '--no-qwen') opts.runQwen = false;
    else if (a === '--qwen-mode') opts.qwenMode = argv[++i];
    else if (a === '--out') opts.out = argv[++i];
    else if (a === '--ids') opts.ids = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--no-controls') opts.includeControls = false;
    else if (a === '--allow-busy') opts.abortIfBusy = false;
    else if (a === '--max-chunks') opts.maxChunks = Number(argv[++i]);
    else if (a === '--ollama') opts.ollamaBaseUrl = argv[++i];
    else if (a === '--model') opts.ollamaModel = argv[++i];
    else if (a === '--help' || a === '-h') opts.help = true;
  }
  return opts;
}

function printMatrix(report) {
  const agg = report.aggregate?.approaches || {};
  console.log('\n=== Aggregate membership metrics ===');
  console.log(
    'Approach'.padEnd(36),
    'TP'.padStart(5),
    'FP'.padStart(5),
    'FN'.padStart(5),
    'Prec'.padStart(8),
    'Rec'.padStart(8),
    'F1'.padStart(8)
  );
  for (const [name, s] of Object.entries(agg)) {
    console.log(
      name.padEnd(36),
      String(s.tp).padStart(5),
      String(s.fp).padStart(5),
      String(s.fn).padStart(5),
      String(s.precision ?? '—').padStart(8),
      String(s.recall ?? '—').padStart(8),
      String(s.f1 ?? '—').padStart(8)
    );
  }
  console.log('\nSelective triggers:', JSON.stringify(report.aggregate?.selective || {}));
  console.log('Failure isolation OK:', report.failure_isolation_ok);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log(`Usage: node scripts/run-shadow-hybrid-poc.js [options]
  --qwen                Enable independent Qwen discovery (default off)
  --qwen-mode MODE      selective | full | appendix_window
  --ids id1,id2         Restrict to case ids
  --no-controls         Skip control-* / pdf-* cases
  --out PATH            Write JSON report
  --ollama URL          Ollama base URL
  --model NAME          Model name
  --allow-busy          Do not abort when Ollama already has a loaded model
  --max-chunks N        Cap Qwen chunks per report`);
    process.exit(0);
  }

  console.log(`[shadow-hybrid] backendRoot=${backendRoot}`);
  console.log(`[shadow-hybrid] runQwen=${opts.runQwen} mode=${opts.qwenMode} out=${opts.out}`);

  const report = await runShadowHybridPoc({
    backendRoot,
    runQwen: opts.runQwen,
    qwenMode: opts.qwenMode,
    includeControls: opts.includeControls,
    ids: opts.ids,
    out: opts.out,
    ollamaBaseUrl: opts.ollamaBaseUrl,
    ollamaModel: opts.ollamaModel,
    abortIfBusy: opts.abortIfBusy,
    maxChunks: opts.maxChunks,
    onCase: (r) => {
      const d = r.scores?.membership?.deterministic;
      const t = r.scores?.membership?.section_tree;
      console.log(
        `[case] ${r.id} det F1=${d?.f1} tree F1=${t?.f1} qwen=${r.qwen_proposal_count} skip=${r.qwen_skipped || '-'} trig=${r.selective?.would_trigger}`
      );
    }
  });

  writeReport(report, opts.out);
  printMatrix(report);
  console.log(`\nWrote ${opts.out}`);
  console.log(`Scored ${report.results.length} cases; skipped ${report.skipped.length}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

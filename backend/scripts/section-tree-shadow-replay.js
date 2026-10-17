#!/usr/bin/env node
/**
 * Offline / read-only section-tree shadow replay.
 *
 * Modes:
 *   --fixtures     score golden + control + pdf + shadow-blinder cases
 *   --db-export DIR  read canonical JSON files exported from production
 *   --ids a,b      restrict fixture case ids
 *
 * Never writes to PostgreSQL. Never refreshes reports.
 *
 *   node scripts/section-tree-shadow-replay.js --fixtures --out /tmp/st-replay.json
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractReportCandidates } from '../lib/threatLibrary/extractionStages.js';
import {
  annotateSectionTree,
  previewMembershipAdditive,
  candidateMemberKeySet,
  compareMembershipSets,
  evaluateSectionTreeShadow
} from '../lib/threatLibrary/sectionTree/index.js';
import { loadCaseDefinition, loadCaseDocument, listCaseFiles, selectCaseFiles, defaultCaseDirs, SHADOW_CASES_DIR } from '../lib/threatLibrary/experiments/shadowHybrid/loadCases.js';
import { gtIdentities, scoreSet } from '../lib/threatLibrary/experiments/shadowHybrid/scoring.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(here, '..');

function parseArgs(argv) {
  const opts = { fixtures: false, out: null, ids: null, dbExport: null, fullRezone: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--fixtures') opts.fixtures = true;
    else if (a === '--out') opts.out = argv[++i];
    else if (a === '--ids') opts.ids = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--db-export') opts.dbExport = argv[++i];
    else if (a === '--full-rezone') opts.fullRezone = true;
    else if (a === '--help' || a === '-h') opts.help = true;
  }
  return opts;
}

function runFixtureCase(caseFile) {
  const caseDef = loadCaseDefinition(caseFile);
  const document = loadCaseDocument(caseDef, caseFile);
  const expected = gtIdentities(caseDef.ground_truth?.indicators || []);
  const det = extractReportCandidates(
    {
      id: caseDef.id,
      source_type: caseDef.format === 'pdf' ? 'pdf' : 'url',
      source_url: caseDef.source_reference?.url || null,
      title: caseDef.title || caseDef.id
    },
    document
  );
  const detKeys = candidateMemberKeySet(det.candidates);
  const tree = annotateSectionTree(document);
  const preview = previewMembershipAdditive(document, det.candidates, { tree });
  const cmp = compareMembershipSets(detKeys, preview.memberKeys);
  const detScore = scoreSet(detKeys, expected);
  const treeScore = scoreSet(preview.memberKeys, expected);
  const shadow = evaluateSectionTreeShadow(document, det.candidates, { fullRezone: false });

  return {
    id: caseDef.id,
    title: caseDef.title || caseDef.id,
    expected_count: expected.size,
    deterministic: detScore,
    section_tree_additive: treeScore,
    comparison: cmp,
    shadow_ok: shadow.ok === true,
    quality_status: det.diagnostics?.quality?.status || null,
    quality_codes: (det.diagnostics?.quality?.codes || det.diagnostics?.quality?.warnings || [])
      .map((w) => (typeof w === 'string' ? w : w.code))
      .filter(Boolean),
    tree_only_correct: [...preview.memberKeys].filter((k) => expected.has(k) && !detKeys.has(k)),
    det_fp: detScore.fp_list,
    tree_fp: treeScore.fp_list
  };
}

function aggregate(results) {
  const sum = (pick) => {
    let tp = 0;
    let fp = 0;
    let fn = 0;
    for (const r of results) {
      const s = pick(r);
      tp += s.tp;
      fp += s.fp;
      fn += s.fn;
    }
    const precision = tp + fp > 0 ? tp / (tp + fp) : null;
    const recall = tp + fn > 0 ? tp / (tp + fn) : null;
    const f1 = precision != null && recall != null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null;
    const round = (x) => (x == null ? null : Math.round(x * 10000) / 10000);
    return { tp, fp, fn, precision: round(precision), recall: round(recall), f1: round(f1) };
  };
  return {
    deterministic: sum((r) => r.deterministic),
    section_tree_additive: sum((r) => r.section_tree_additive),
    reports_with_additions: results.filter((r) => r.comparison.additions_total > 0).length,
    reports_with_removals: results.filter((r) => r.comparison.removals_total > 0).length,
    reports_unchanged: results.filter((r) => r.comparison.equal).length
  };
}

function runDbExportDir(dir) {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  const results = [];
  for (const name of files) {
    const p = path.join(dir, name);
    let payload;
    try {
      payload = JSON.parse(fs.readFileSync(p, 'utf8'));
    } catch (err) {
      results.push({ id: name, skipped: true, reason: String(err.message || err) });
      continue;
    }
    const document = payload.canonical_document || payload.document || payload;
    const reportMeta = payload.report || {};
    const id = reportMeta.public_id || reportMeta.id || path.basename(name, '.json');
    try {
      const det = extractReportCandidates(
        {
          id,
          source_type: reportMeta.source_type || 'url',
          source_url: reportMeta.source_url || null,
          title: reportMeta.title || id
        },
        document
      );
      const shadow = evaluateSectionTreeShadow(document, det.candidates, { fullRezone: false });
      const cmp = shadow.ok ? shadow.additive : null;
      results.push({
        id,
        title: reportMeta.title || id,
        source_url: reportMeta.source_url || null,
        comparison: cmp,
        shadow_ok: shadow.ok === true,
        shadow_error: shadow.ok ? null : shadow.error,
        quality_status: det.diagnostics?.quality?.status || null,
        additions: cmp?.additions || [],
        removals: cmp?.removals || []
      });
    } catch (err) {
      results.push({ id, skipped: true, reason: String(err.message || err) });
    }
  }
  return results;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || (!opts.fixtures && !opts.dbExport)) {
    console.log(`Usage:
  node scripts/section-tree-shadow-replay.js --fixtures [--ids id1,id2] [--out path]
  node scripts/section-tree-shadow-replay.js --db-export DIR [--out path]`);
    process.exit(opts.help ? 0 : 1);
  }

  let report;
  if (opts.fixtures) {
    const dirs = defaultCaseDirs(backendRoot);
    // Ensure shadow cases dir is included even if path differs in container.
    if (!dirs.includes(SHADOW_CASES_DIR)) dirs.push(SHADOW_CASES_DIR);
    const files = selectCaseFiles(listCaseFiles(dirs), {
      includeControls: true,
      ids: opts.ids || null
    });
    const results = [];
    for (const f of files) {
      try {
        const def = loadCaseDefinition(f);
        if (!['canonical', 'canonical_abs', 'canonical_inline', 'html_file', 'pdf_items'].includes(def.source?.kind)) {
          results.push({ id: def.id, skipped: true, reason: `unsupported_source:${def.source?.kind}` });
          continue;
        }
        const r = runFixtureCase(f);
        results.push(r);
        console.log(
          `[case] ${r.id} det F1=${r.deterministic.f1} tree F1=${r.section_tree_additive.f1} +${r.comparison.additions_total}/-${r.comparison.removals_total}`
        );
      } catch (err) {
        results.push({ id: path.basename(f), skipped: true, reason: String(err.message || err) });
        console.log(`[skip] ${path.basename(f)}: ${err.message || err}`);
      }
    }
    const scored = results.filter((r) => !r.skipped);
    report = {
      mode: 'fixtures',
      generated_at: new Date().toISOString(),
      aggregate: aggregate(scored),
      results: scored,
      skipped: results.filter((r) => r.skipped)
    };
  } else {
    const results = runDbExportDir(opts.dbExport);
    const scored = results.filter((r) => !r.skipped);
    report = {
      mode: 'db_export',
      generated_at: new Date().toISOString(),
      summary: {
        total: scored.length,
        unchanged: scored.filter((r) => r.comparison?.equal).length,
        with_additions: scored.filter((r) => (r.comparison?.additions_total || 0) > 0).length,
        with_removals: scored.filter((r) => (r.comparison?.removals_total || 0) > 0).length,
        shadow_errors: scored.filter((r) => r.shadow_ok === false).length
      },
      results: scored,
      skipped: results.filter((r) => r.skipped)
    };
  }

  const text = JSON.stringify(report, null, 2);
  if (opts.out) {
    fs.mkdirSync(path.dirname(opts.out), { recursive: true });
    fs.writeFileSync(opts.out, text);
    console.log(`Wrote ${opts.out}`);
  }
  if (report.aggregate) {
    console.log('\nAggregate:', JSON.stringify(report.aggregate, null, 2));
  } else {
    console.log('\nSummary:', JSON.stringify(report.summary, null, 2));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

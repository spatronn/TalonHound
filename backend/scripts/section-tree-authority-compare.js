#!/usr/bin/env node
/**
 * Offline compare: legacy vs section_tree authoritative membership.
 *
 *   THREAT_LIBRARY_SCOPE_ENGINE=legacy node scripts/section-tree-authority-compare.js --fixtures
 *   node scripts/section-tree-authority-compare.js --db-export DIR --out /tmp/cmp.json
 *
 * Never writes to PostgreSQL.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractReportCandidates } from '../lib/threatLibrary/extractionStages.js';
import {
  candidateMemberKeySet,
  compareMembershipSets,
  SCOPE_ENGINE_LEGACY,
  SCOPE_ENGINE_SECTION_TREE
} from '../lib/threatLibrary/sectionTree/index.js';
import {
  loadCaseDefinition,
  loadCaseDocument,
  listCaseFiles,
  selectCaseFiles,
  defaultCaseDirs,
  SHADOW_CASES_DIR
} from '../lib/threatLibrary/experiments/shadowHybrid/loadCases.js';
import { gtIdentities, scoreSet } from '../lib/threatLibrary/experiments/shadowHybrid/scoring.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(here, '..');

function parseArgs(argv) {
  const opts = { fixtures: false, out: null, ids: null, dbExport: null };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--fixtures') opts.fixtures = true;
    else if (a === '--out') opts.out = argv[++i];
    else if (a === '--ids') opts.ids = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--db-export') opts.dbExport = argv[++i];
  }
  return opts;
}

function extractWithEngine(report, document, engine) {
  const prev = process.env.THREAT_LIBRARY_SCOPE_ENGINE;
  process.env.THREAT_LIBRARY_SCOPE_ENGINE = engine;
  try {
    return extractReportCandidates(report, document);
  } finally {
    if (prev === undefined) delete process.env.THREAT_LIBRARY_SCOPE_ENGINE;
    else process.env.THREAT_LIBRARY_SCOPE_ENGINE = prev;
  }
}

function runCase(document, reportMeta, expected = null) {
  const report = {
    id: reportMeta.id || reportMeta.public_id || 'case',
    source_type: reportMeta.source_type || 'url',
    source_url: reportMeta.source_url || null,
    title: reportMeta.title || reportMeta.id
  };
  const legacy = extractWithEngine(report, document, SCOPE_ENGINE_LEGACY);
  const tree = extractWithEngine(report, document, SCOPE_ENGINE_SECTION_TREE);
  const legacyKeys = candidateMemberKeySet(legacy.candidates);
  const treeKeys = candidateMemberKeySet(tree.candidates);
  const cmp = compareMembershipSets(legacyKeys, treeKeys);
  const out = {
    id: report.id,
    title: report.title,
    comparison: cmp,
    legacy_engine: legacy.diagnostics?.scope_engine || null,
    tree_engine: tree.diagnostics?.scope_engine || null,
    legacy_keys: [...legacyKeys].sort(),
    tree_keys: [...treeKeys].sort()
  };
  if (expected) {
    out.legacy_score = scoreSet(legacyKeys, expected);
    out.tree_score = scoreSet(treeKeys, expected);
  }
  return out;
}

const opts = parseArgs(process.argv.slice(2));
const results = [];

if (opts.fixtures) {
  const dirs = defaultCaseDirs(backendRoot);
  if (!dirs.includes(SHADOW_CASES_DIR)) dirs.push(SHADOW_CASES_DIR);
  const files = selectCaseFiles(listCaseFiles(dirs), { includeControls: true, ids: opts.ids || null });
  for (const f of files) {
    try {
      const def = loadCaseDefinition(f);
      const document = loadCaseDocument(def, f);
      const expected = gtIdentities(def.ground_truth?.indicators || []);
      const r = runCase(document, { id: def.id, title: def.title, source_type: def.format === 'pdf' ? 'pdf' : 'url' }, expected);
      results.push(r);
      console.log(
        `[case] ${r.id} legacy F1=${r.legacy_score.f1} tree F1=${r.tree_score.f1} +${r.comparison.additions_total}/-${r.comparison.removals_total}`
      );
    } catch (err) {
      results.push({ id: path.basename(f), skipped: true, reason: String(err.message || err) });
      console.log(`[skip] ${path.basename(f)}: ${err.message || err}`);
    }
  }
} else if (opts.dbExport) {
  for (const name of fs.readdirSync(opts.dbExport).filter((f) => f.endsWith('.json')).sort()) {
    const payload = JSON.parse(fs.readFileSync(path.join(opts.dbExport, name), 'utf8'));
    const document = payload.canonical_document || payload.document || payload;
    const reportMeta = payload.report || { id: path.basename(name, '.json') };
    try {
      results.push(runCase(document, reportMeta));
    } catch (err) {
      results.push({ id: reportMeta.id || name, skipped: true, reason: String(err.message || err) });
    }
  }
} else {
  console.error('Usage: --fixtures | --db-export DIR [--out path]');
  process.exit(1);
}

const scored = results.filter((r) => !r.skipped);
const summary = {
  total: scored.length,
  unchanged: scored.filter((r) => r.comparison?.equal).length,
  with_additions: scored.filter((r) => (r.comparison?.additions_total || 0) > 0).length,
  with_removals: scored.filter((r) => (r.comparison?.removals_total || 0) > 0).length,
  tree_f1_regressions: scored.filter(
    (r) => r.legacy_score && r.tree_score && r.tree_score.f1 < r.legacy_score.f1
  ).map((r) => r.id)
};

const report = { generated_at: new Date().toISOString(), summary, results };
if (opts.out) fs.writeFileSync(opts.out, JSON.stringify(report, null, 2));
console.log('Summary:', JSON.stringify(summary, null, 2));

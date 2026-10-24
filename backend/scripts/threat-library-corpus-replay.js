#!/usr/bin/env node
/**
 * Offline corpus replay of Threat Library extraction (no database, no model,
 * no network).
 *
 *   node scripts/threat-library-corpus-replay.js <snapshot.jsonl[.gz]> [--out <file>] [--ids 1,2,3]
 *   node scripts/threat-library-corpus-replay.js --diff <before.json> <after.json>
 *
 * The snapshot is a PRIVATE export (JSON lines) of stored reports: each line
 * `{ report, rows, ioc_sources }` with the report's canonical_document and its
 * persisted candidate rows. It holds publisher content and must stay outside
 * the repository.
 *
 * For every report the replay runs the same computation a Refresh extraction
 * runs (extractionRefresh.computeExtractionRefresh: deterministic extraction
 * of the stored document + replay of the stored model decisions + analyst
 * state preservation) against a stub pool that matches nothing, then records
 * the original-document Indicator identities and the extraction-quality codes.
 * IOC catalog matching is skipped; it never changes Indicator membership.
 *
 * `--diff` compares two replay outputs (e.g. before / after an extractor
 * change) and lists every report whose Indicator set changed.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';
import { computeExtractionRefresh } from '../lib/threatLibrary/extractionRefresh.js';
import { buildCandidateEvidenceRecord } from '../lib/threatLibrary/evidencePolicy.js';
import { isReportIndicatorMember } from '../lib/threatLibrary/indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from '../lib/threatLibrary/candidateExtraction.js';
import { loadRealReportLabels } from '../lib/threatLibrary/benchmark/benchmarkRunner.js';
import { groundTruthIdentity } from '../lib/threatLibrary/benchmark/benchmarkMetrics.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = process.env.THREAT_LIBRARY_SCOPE_ENGINE || 'section_tree';

const STUB_POOL = Object.freeze({ query: async () => ({ rows: [], rowCount: 0 }) });

const identity = (c) => `${c.candidate_type}:${c.normalized_value}`;

/** Persisted shape of a refreshed candidate (what the read path evaluates). */
function persistedShape(c) {
  return {
    ...c,
    has_original_document_occurrence: c.has_original_document_occurrence !== false,
    review_status: c.review_status || 'pending',
    evidence: Array.isArray(c.occurrences) || !c.evidence ? buildCandidateEvidenceRecord(c) : c.evidence
  };
}

export function readSnapshot(file) {
  let raw = fs.readFileSync(file);
  if (file.endsWith('.gz')) raw = zlib.gunzipSync(raw);
  return raw
    .toString('utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

export async function replayEntry(entry) {
  const { report, rows } = entry;
  const document = report.canonical_document;
  const refreshed = await computeExtractionRefresh(STUB_POOL, { report, document, previousRows: rows });
  const members = refreshed.candidates.filter((c) => isReportIndicatorMember(persistedShape(c))).map(identity).sort();
  const stored = rows.filter((r) => isReportIndicatorMember(r)).map(identity).sort();
  const quality = refreshed.diagnostics?.quality || null;
  return {
    id: report.id,
    public_id: report.public_id,
    status: report.import_status,
    members,
    stored_members: stored,
    candidates: refreshed.candidates.length,
    quality: quality
      ? { status: quality.status, mode: quality.mode, codes: (quality.warnings || []).map((w) => w.code).sort() }
      : null
  };
}

/**
 * Score replayed membership against the committed real-report labels whose
 * source.talonhound_report_id names a replayed report (independent publisher
 * ground truth; ambiguous entries are reported, never scored).
 */
export function scoreAgainstLabels(reports) {
  const byPublicId = new Map(reports.filter((r) => !r.error).map((r) => [r.public_id, r]));
  const rows = [];
  const total = { tp: 0, fn: 0, fp: 0, ambiguous: 0, exact: 0, reports: 0 };
  for (const label of loadRealReportLabels()) {
    const r = byPublicId.get(label.source?.talonhound_report_id);
    if (!r) continue;
    const gt = label.ground_truth;
    const expected = new Set(gt.indicators.map(groundTruthIdentity));
    const ambiguous = new Set((gt.ambiguous || []).map(groundTruthIdentity));
    const members = new Set(r.members);
    const tp = [...expected].filter((i) => members.has(i));
    const fn = [...expected].filter((i) => !members.has(i));
    const fp = [...members].filter((i) => !expected.has(i) && !ambiguous.has(i));
    const amb = [...ambiguous].map((i) => `${i} => ${members.has(i) ? 'member' : 'non-member'}`);
    rows.push({ label: label.id, report: r.id, expected: expected.size, tp: tp.length, fn, fp, ambiguous: amb });
    total.tp += tp.length;
    total.fn += fn.length;
    total.fp += fp.length;
    total.ambiguous += ambiguous.size;
    total.reports += 1;
    if (!fn.length && !fp.length) total.exact += 1;
  }
  total.precision = total.tp + total.fp ? Number((total.tp / (total.tp + total.fp)).toFixed(4)) : null;
  total.recall = total.tp + total.fn ? Number((total.tp / (total.tp + total.fn)).toFixed(4)) : null;
  for (const row of rows) {
    if (!row.fn.length && !row.fp.length && !row.ambiguous.length) continue;
    console.log(`${row.label} (${row.report}): expected ${row.expected} TP ${row.tp} FN ${row.fn.length} FP ${row.fp.length}`);
    for (const i of row.fn) console.log(`  FN ${i}`);
    for (const i of row.fp) console.log(`  FP ${i}`);
    for (const i of row.ambiguous) console.log(`  ambiguous ${i}`);
  }
  console.log(`labels scored: ${total.reports}; TP ${total.tp} FN ${total.fn} FP ${total.fp} ambiguous ${total.ambiguous}; exact ${total.exact}/${total.reports}; P ${total.precision} R ${total.recall}`);
  return { total, rows };
}

function diff(beforeFile, afterFile) {
  const before = new Map(JSON.parse(fs.readFileSync(beforeFile, 'utf8')).reports.map((r) => [r.id, r]));
  const after = JSON.parse(fs.readFileSync(afterFile, 'utf8')).reports;
  let changed = 0;
  for (const a of after) {
    const b = before.get(a.id);
    if (!b) continue;
    const bs = new Set(b.members);
    const as = new Set(a.members);
    const added = a.members.filter((m) => !bs.has(m));
    const removed = b.members.filter((m) => !as.has(m));
    const qb = (b.quality?.codes || []).join(',');
    const qa = (a.quality?.codes || []).join(',');
    if (!added.length && !removed.length && qb === qa) continue;
    changed += 1;
    console.log(`report ${a.id} (${a.status}): indicators ${b.members.length} -> ${a.members.length}`);
    for (const m of added) console.log(`  + ${m}`);
    for (const m of removed) console.log(`  - ${m}`);
    if (qb !== qa) console.log(`  quality [${qb}] -> [${qa}]`);
  }
  console.log(`${changed} of ${after.length} reports changed`);
}

async function main() {
  const args = process.argv.slice(2);
  if (args[0] === '--diff') return diff(args[1], args[2]);
  const file = args[0];
  if (!file) {
    console.log('usage: threat-library-corpus-replay.js <snapshot.jsonl[.gz]> [--out file] [--ids 1,2] | --diff <before> <after>');
    return;
  }
  const opt = (name) => {
    const i = args.indexOf(`--${name}`);
    return i >= 0 ? args[i + 1] : null;
  };
  const ids = opt('ids') ? new Set(opt('ids').split(',').map(Number)) : null;
  const reports = [];
  for (const entry of readSnapshot(file)) {
    if (ids && !ids.has(Number(entry.report.id))) continue;
    try {
      reports.push(await replayEntry(entry));
    } catch (err) {
      reports.push({ id: entry.report.id, error: err.message });
    }
  }
  const out = { extractor: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, reports };
  if (args.includes('--labels')) out.scores = scoreAgainstLabels(reports);
  const target = opt('out');
  if (target) fs.writeFileSync(target, JSON.stringify(out, null, 1));
  const errors = reports.filter((r) => r.error);
  const drift = reports.filter((r) => !r.error && r.members.join('|') !== r.stored_members.join('|'));
  console.log(`replayed ${reports.length} reports (${out.extractor}); errors ${errors.length}; replay != stored membership: ${drift.length}`);
  for (const e of errors) console.log(`  error ${e.id}: ${e.error}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  await main();
}

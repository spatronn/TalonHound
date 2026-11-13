/**
 * Capture first-pass review snapshots for unseen-first-pass-10.
 * Reads import-ledger.json; expects captures to be written by coordinator
 * after MCP get_review dumps are saved as first-pass-captures/<id>.json
 *
 * This helper only summarizes existing capture files + packets for scoring.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const ledger = JSON.parse(fs.readFileSync(path.join(ROOT, 'import-ledger.json'), 'utf8'));
const CAP = path.join(ROOT, 'first-pass-captures');
const PKT = path.join(ROOT, 'packets');

function keyOf(t, v) {
  return `${String(t || '').toLowerCase()}:${String(v || '').toLowerCase()}`;
}

function normalizeRoleMembership(c) {
  // First-pass "indicators" ≈ membership indicators / creatable / pending_actionable that look like IOC
  const membership = c.membership || c.indicator_membership || c.bucket || null;
  const decision = c.review_decision || c.review_status || c.assessment || null;
  const isIndicator =
    membership === 'indicators' ||
    membership === 'indicator' ||
    c.is_ioc === true ||
    c.in_indicators === true ||
    decision === 'approved' ||
    (Array.isArray(c.tags) && c.tags.includes('indicator'));
  const isContext =
    membership === 'context_only' ||
    membership === 'linked_only' ||
    decision === 'context_only' ||
    c.is_ioc === false;
  return { isIndicator, isContext, membership, decision };
}

const rows = [];
for (const imp of ledger.imports) {
  const capPath = path.join(CAP, `${imp.id}.json`);
  const pktPath = path.join(PKT, `unseen-${imp.id}.json`);
  const row = {
    id: imp.id,
    report_id: imp.report_id,
    has_capture: fs.existsSync(capPath),
    has_packet: fs.existsSync(pktPath)
  };
  if (!row.has_capture || !row.has_packet) {
    rows.push({ ...row, status: 'incomplete' });
    continue;
  }
  const cap = JSON.parse(fs.readFileSync(capPath, 'utf8'));
  const pkt = JSON.parse(fs.readFileSync(pktPath, 'utf8'));
  const gtInd = new Map((pkt.ground_truth?.indicators || []).map((x) => [keyOf(x.type, x.value), x]));
  const gtCtx = new Map((pkt.ground_truth?.context_only || []).map((x) => [keyOf(x.type, x.value), x]));
  const candidates = cap.candidates || cap.items || cap.review?.candidates || [];
  const fpInd = new Set();
  const fpCtx = new Set();
  const fpAll = new Map();
  for (const c of candidates) {
    const type = c.type || c.candidate_type || c.observable_type;
    const value = c.value || c.normalized_value || c.normalized;
    if (!type || !value) continue;
    const k = keyOf(type, value);
    fpAll.set(k, c);
    const m = normalizeRoleMembership(c);
    if (m.isIndicator) fpInd.add(k);
    else if (m.isContext) fpCtx.add(k);
  }

  let tp = 0;
  let fn = 0;
  const fnList = [];
  for (const [k, g] of gtInd) {
    if (fpInd.has(k)) tp += 1;
    else {
      fn += 1;
      fnList.push({ ...g, key: k, seen_as_context: fpCtx.has(k), seen_at_all: fpAll.has(k) });
    }
  }
  let fp = 0;
  const fpList = [];
  for (const k of fpInd) {
    if (!gtInd.has(k)) {
      fp += 1;
      const c = fpAll.get(k);
      fpList.push({
        type: c.type || c.candidate_type,
        value: c.value || c.normalized_value || c.normalized,
        key: k,
        labeled_context: gtCtx.has(k)
      });
    }
  }

  // Evidence-classification errors: GT context but first-pass indicator, or GT indicator but context-only
  const classErrors = [];
  for (const [k, g] of gtCtx) {
    if (fpInd.has(k)) classErrors.push({ kind: 'context_as_indicator', key: k, gt: g });
  }
  for (const [k, g] of gtInd) {
    if (!fpInd.has(k) && fpCtx.has(k)) classErrors.push({ kind: 'indicator_as_context', key: k, gt: g });
  }

  const precision = tp + fp === 0 ? null : tp / (tp + fp);
  const recall = tp + fn === 0 ? null : tp / (tp + fn);
  rows.push({
    ...row,
    status: 'scored',
    counts: {
      gt_indicators: gtInd.size,
      gt_context_only: gtCtx.size,
      gt_ambiguous: (pkt.ground_truth?.ambiguous || []).length,
      fp_candidates: candidates.length,
      fp_indicators: fpInd.size,
      tp,
      fp,
      fn,
      evidence_classification_errors: classErrors.length
    },
    precision,
    recall,
    fn_sample: fnList.slice(0, 25),
    fp_sample: fpList.slice(0, 25),
    class_error_sample: classErrors.slice(0, 25)
  });
}

const out = {
  generated_at: new Date().toISOString(),
  experiment: ledger.experiment,
  reports: rows,
  aggregate: rows
    .filter((r) => r.status === 'scored')
    .reduce(
      (a, r) => {
        a.tp += r.counts.tp;
        a.fp += r.counts.fp;
        a.fn += r.counts.fn;
        a.class_errors += r.counts.evidence_classification_errors;
        a.reports += 1;
        return a;
      },
      { reports: 0, tp: 0, fp: 0, fn: 0, class_errors: 0 }
    )
};
if (out.aggregate.tp + out.aggregate.fp > 0) {
  out.aggregate.ioc_precision = out.aggregate.tp / (out.aggregate.tp + out.aggregate.fp);
}
if (out.aggregate.tp + out.aggregate.fn > 0) {
  out.aggregate.discovery_recall = out.aggregate.tp / (out.aggregate.tp + out.aggregate.fn);
}

fs.writeFileSync(path.join(ROOT, 'score-summary.json'), JSON.stringify(out, null, 2) + '\n');
console.log(JSON.stringify(out.aggregate, null, 2));
console.log(
  'incomplete',
  rows.filter((r) => r.status !== 'scored').map((r) => r.id)
);

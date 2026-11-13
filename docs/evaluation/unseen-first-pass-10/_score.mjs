/**
 * Score frozen first-pass captures against source-only packets.
 *
 * Writes:
 *   score-summary.json              — strict string keys (original scorecard semantics)
 *   score-summary.equivalence.json  — scoring-only URL host/path + trailing-slash fold
 *
 * Does not modify captures, packets, or production IOC identities.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const ledger = JSON.parse(fs.readFileSync(path.join(ROOT, 'import-ledger.json'), 'utf8'));

function refang(v) {
  return String(v || '')
    .replace(/\[\.\]/g, '.')
    .replace(/^hxxps:\/\//i, 'https://')
    .replace(/^hxxp:\/\//i, 'http://');
}

function keyOf(t, v) {
  return `${String(t || '').toLowerCase()}:${String(v || '').toLowerCase()}`;
}

/**
 * Scoring-only URL identity aligned with production foldSchemeLess / hostPath
 * folding: scheme optional, host lower-cased, trailing slash on path-less or
 * path-ending URLs folded. Does not rewrite stored candidate values.
 */
function urlEquivalenceKey(type, value) {
  const t = String(type || '').toLowerCase();
  const v = refang(value);
  if (t !== 'url') return keyOf(t, v);
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : `https://${v}`;
    const u = new URL(withScheme);
    let p = u.pathname || '/';
    if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
    const pathPart = p === '/' ? '' : p;
    return `url~${u.hostname.toLowerCase()}${pathPart}${u.search || ''}`.toLowerCase();
  } catch {
    return keyOf('url', v);
  }
}

function scoreAll(keyFn, mode) {
  const rows = [];
  for (const imp of ledger.imports) {
    const capPath = path.join(ROOT, 'first-pass-captures', `${imp.id}.json`);
    const pktPath = path.join(ROOT, 'packets', `unseen-${imp.id}.json`);
    if (!fs.existsSync(capPath) || !fs.existsSync(pktPath)) {
      rows.push({ id: imp.id, status: 'incomplete', report_id: imp.report_id });
      continue;
    }
    const cap = JSON.parse(fs.readFileSync(capPath, 'utf8'));
    const pkt = JSON.parse(fs.readFileSync(pktPath, 'utf8'));
    const gtInd = new Map((pkt.ground_truth.indicators || []).map((x) => [keyFn(x.type, refang(x.value)), x]));
    const gtCtx = new Map((pkt.ground_truth.context_only || []).map((x) => [keyFn(x.type, refang(x.value)), x]));
    const cands = cap.candidates?.items || cap.candidates || [];
    const fpInd = new Set();
    const fpCtx = new Set();
    const fpAll = new Map();
    for (const c of cands) {
      const type = c.type || c.candidate_type;
      const value = refang(c.normalized_value || c.value);
      if (!type || !value) continue;
      const k = keyFn(type, value);
      fpAll.set(k, c);
      if (c.indicator_membership === true) fpInd.add(k);
      else if (c.is_ioc === false || c.assessment === 'context_only' || c.match_state === 'context_only') fpCtx.add(k);
    }
    let tp = 0;
    let fn = 0;
    let fp = 0;
    const fnList = [];
    const fpList = [];
    const classErrors = [];
    for (const [k, g] of gtInd) {
      if (fpInd.has(k)) tp += 1;
      else {
        fn += 1;
        fnList.push({
          key: k,
          type: g.type,
          value: g.value,
          seen_as_context: fpCtx.has(k),
          seen_at_all: fpAll.has(k)
        });
      }
    }
    for (const k of fpInd) {
      if (!gtInd.has(k)) {
        fp += 1;
        const c = fpAll.get(k);
        fpList.push({
          key: k,
          type: c.type || c.candidate_type,
          value: c.normalized_value || c.value,
          labeled_context: gtCtx.has(k),
          assessment: c.assessment,
          role: c.role
        });
      }
    }
    for (const [k] of gtCtx) {
      if (fpInd.has(k)) classErrors.push({ kind: 'context_as_indicator', key: k });
    }
    for (const [k] of gtInd) {
      if (!fpInd.has(k) && fpCtx.has(k)) classErrors.push({ kind: 'indicator_as_context', key: k });
    }
    rows.push({
      id: imp.id,
      status: 'scored',
      report_id: imp.report_id,
      scoring_mode: mode,
      generation: cap.counts?.status_axes?.generation || null,
      contract_freshness: cap.counts?.status_axes?.contract_freshness || null,
      counts: {
        gt_indicators: gtInd.size,
        gt_context: gtCtx.size,
        gt_ambiguous: (pkt.ground_truth.ambiguous || []).length,
        fp_all: Array.isArray(cands) ? cands.length : 0,
        fp_indicators: fpInd.size,
        fp_context: fpCtx.size,
        tp,
        fp,
        fn,
        class_errors: classErrors.length
      },
      precision: tp + fp ? tp / (tp + fp) : null,
      recall: tp + fn ? tp / (tp + fn) : null,
      fn_sample: fnList.slice(0, 20),
      fp_sample: fpList.slice(0, 20),
      class_error_sample: classErrors.slice(0, 20)
    });
  }
  const scored = rows.filter((r) => r.status === 'scored');
  const aggregate = scored.reduce(
    (a, r) => {
      a.tp += r.counts.tp;
      a.fp += r.counts.fp;
      a.fn += r.counts.fn;
      a.class_errors += r.counts.class_errors;
      a.reports += 1;
      return a;
    },
    { reports: 0, tp: 0, fp: 0, fn: 0, class_errors: 0 }
  );
  aggregate.ioc_precision = aggregate.tp + aggregate.fp ? aggregate.tp / (aggregate.tp + aggregate.fp) : null;
  aggregate.discovery_recall = aggregate.tp + aggregate.fn ? aggregate.tp / (aggregate.tp + aggregate.fn) : null;
  return { aggregate, reports: rows };
}

const generated_at = new Date().toISOString();
const strict = scoreAll((t, v) => keyOf(t, v), 'strict');
const equivalence = scoreAll(urlEquivalenceKey, 'equivalence_hostpath_trailingslash');

const strictOut = {
  generated_at,
  experiment: ledger.experiment,
  scoring_mode: 'strict',
  note: 'Original scorecard semantics. Preserved separately from equivalence-aware metrics.',
  aggregate: strict.aggregate,
  reports: strict.reports
};
const equivOut = {
  generated_at,
  experiment: ledger.experiment,
  scoring_mode: 'equivalence_hostpath_trailingslash',
  note: 'Scoring-only. Scheme-optional host/path identity + trailing-slash fold. Does not change stored IOC identities or frozen captures.',
  aggregate: equivalence.aggregate,
  reports: equivalence.reports,
  compared_to_strict: {
    tp_delta: equivalence.aggregate.tp - strict.aggregate.tp,
    fp_delta: equivalence.aggregate.fp - strict.aggregate.fp,
    fn_delta: equivalence.aggregate.fn - strict.aggregate.fn,
    precision_delta:
      (equivalence.aggregate.ioc_precision ?? 0) - (strict.aggregate.ioc_precision ?? 0),
    recall_delta:
      (equivalence.aggregate.discovery_recall ?? 0) - (strict.aggregate.discovery_recall ?? 0)
  }
};

fs.writeFileSync(path.join(ROOT, 'score-summary.json'), JSON.stringify(strictOut, null, 2) + '\n');
fs.writeFileSync(path.join(ROOT, 'score-summary.equivalence.json'), JSON.stringify(equivOut, null, 2) + '\n');

console.log('strict', JSON.stringify(strictOut.aggregate, null, 2));
console.log('equivalence', JSON.stringify(equivOut.aggregate, null, 2));
console.log('delta', equivOut.compared_to_strict);

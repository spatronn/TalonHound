import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const EXP = path.join(ROOT, '..');

function refang(v) {
  return String(v || '')
    .replace(/\[\.\]/g, '.')
    .replace(/^hxxps:\/\//i, 'https://')
    .replace(/^hxxp:\/\//i, 'http://');
}
function keyOf(t, v) {
  return `${String(t || '').toLowerCase()}:${String(v || '').toLowerCase()}`;
}
function urlEquivalenceKey(type, value) {
  const t = String(type || '').toLowerCase();
  let v = refang(value);
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

const ledger = JSON.parse(fs.readFileSync(path.join(EXP, 'import-ledger.json'), 'utf8'));
const original = JSON.parse(fs.readFileSync(path.join(EXP, 'score-summary.json'), 'utf8'));

const DISP = {
  'msft-gsocket|domain:gsocket.io': { verdict: 'gt_error', note: 'Publisher IOC table lists Domain gsocket.io as Indicator; GT demoted to legitimate_service.' },
  'msft-gsocket|domain:cdn.gsocket.io': { verdict: 'gt_error', note: 'Publisher IOC table Domain row.' },
  'msft-gsocket|domain:gsgg.b-cdn.net': { verdict: 'gt_error', note: 'Publisher IOC table Domain row.' },
  'rf-markirat|sha256:3b172281f65ceaee280ae810edb6fd39a1ecd25649f929f246c0405df94f4c89': { verdict: 'gt_omission', note: 'Hash present in retained RF HTML; missing from GT indicators.' },
  'rf-markirat|domain:yemplayer.zip': { verdict: 'pipeline_defect', note: 'Source shows filename YEMPlayer.zip; typed as domain.' },
  'rf-markirat|domain:pis2rayvpn.zip': { verdict: 'pipeline_defect', note: 'Source shows filename Pis2rayVPN.zip; typed as domain.' },
  'trend-installfix|domain:download-version.1-5-8.com': { verdict: 'intentional_policy', note: 'MODE A + empty authoritative + pending linked pack; body_mention non-member by contract.' },
  'trend-installfix|url:https://download-version.1-5-8.com/claude.msixbundle': { verdict: 'intentional_policy', note: 'MODE A body_mention; pack pending.' },
  'trend-installfix|domain:oakenfjrod.ru': { verdict: 'intentional_policy', note: 'MODE A body_mention; pack pending.' },
  'trend-installfix|sha1:811fbf0ff6b6acabe4b545e493ec0dd0178a0302': { verdict: 'intentional_policy', note: 'MODE A body_mention; pack pending.' },
  'trend-installfix|sha256:2f04ba77bb841111036b979fc0dab7fcbae99749718ae1dd6fd348d4495b5f74': { verdict: 'intentional_policy', note: 'MODE A body_mention; pack pending.' },
  'trend-installfix|ip:77.91.97.244': { verdict: 'gt_dispute', note: 'Publisher shows failed SYN attempts; GT indicator vs pipeline context_only.' },
  'trend-kongtuke|url:http://foodgefy.com/6o0jk.js': { verdict: 'intentional_policy', note: 'MODE A narrative non-member; pack pending. Sibling body URLs inconsistently members.' },
  'trend-kongtuke|ip:162.33.178.171': { verdict: 'intentional_policy', note: 'MODE A + pack pending.' },
  'trend-kongtuke|ip:45.61.138.224': { verdict: 'intentional_policy', note: 'MODE A + pack pending.' },
  'trend-kongtuke|url:http://45.61.138.224/n': { verdict: 'intentional_policy', note: 'MODE A + pack pending.' },
  'trend-kongtuke|ip:158.247.252.178': { verdict: 'intentional_policy', note: 'MODE A + pack pending.' },
  'trend-kongtuke|ip:170.168.103.208': { verdict: 'intentional_policy', note: 'MODE A + pack pending.' },
  'trend-teampcp|url:https://litter.catbox.moe/iqesmbhukgd2c7hq.sh': { verdict: 'intentional_policy', note: 'MODE A narrative; pack pending.' },
  'groupib-ghost-stadium|url:https://fifa-tickets.vip/tickets_shop': { verdict: 'url_serialization', note: 'Publisher table scheme-less; GT added https://.' },
  'groupib-ghost-stadium|url:https://fifa-tickets.vip/authorize.html': { verdict: 'url_serialization', note: 'Scheme-less vs https GT.' },
  'groupib-ghost-stadium|url:https://fifa-tickets.vip/pay/fwc20260418a3230f12ac': { verdict: 'url_serialization', note: 'Scheme-less vs https GT.' },
  'groupib-ghost-stadium|url:fifa-tickets.vip/tickets_shop': { verdict: 'url_serialization', note: 'Paired FP for scheme-less member.' },
  'groupib-ghost-stadium|url:fifa-tickets.vip/authorize.html': { verdict: 'url_serialization', note: 'Paired FP for scheme-less member.' },
  'groupib-ghost-stadium|url:fifa-tickets.vip/pay/fwc20260418a3230f12ac': { verdict: 'url_serialization', note: 'Paired FP for scheme-less member.' },
  'groupib-ghost-stadium|sha1:3b8bb7631b39f455d31544b55ba97b49ab1888c1': { verdict: 'gt_omission_plus_role_defect', note: 'Publisher IOC SSL fingerprint; GT omitted; role=malware_sample wrong.' },
  'groupib-ghost-stadium|sha1:84ecdca915f1af822ccc8a04479f5179104f353c': { verdict: 'gt_omission_plus_role_defect', note: 'SSL fingerprint in publisher table.' },
  'groupib-ghost-stadium|sha1:9bd164dd3f50d196c7dff4f6c1b0f1345ac96d9a': { verdict: 'gt_omission_plus_role_defect', note: 'SSL fingerprint in publisher table.' },
  'groupib-ghost-stadium|url:www.billplz.com/bills/6e88393d1b82ede9': { verdict: 'gt_dispute', note: 'Publisher IOC-3 Example bill; GT context_only.' },
  'groupib-ghost-stadium|domain:testnet.chainugo.com': { verdict: 'gt_dispute', note: 'Publisher IOC-1 Crypto gateway; GT context_only.' },
  'groupib-ghost-stadium|domain:billplz.com': { verdict: 'gt_dispute', note: 'Publisher IOC-3 Payment gateway abused; GT context_only.' },
  'google-tag-apt42|url:https://visioneditor.loseyourip.com': { verdict: 'url_serialization', note: 'Trailing-slash mismatch.' },
  'google-tag-apt42|url:https://visioneditor.loseyourip.com/': { verdict: 'url_serialization', note: 'Paired FP.' }
};

function scoreMode(mode) {
  const keyFn = mode === 'strict' ? (t, v) => keyOf(t, refang(v)) : urlEquivalenceKey;
  const rows = [];
  let TP = 0;
  let FP = 0;
  let FN = 0;
  for (const imp of ledger.imports) {
    const cap = JSON.parse(fs.readFileSync(path.join(EXP, 'first-pass-captures', `${imp.id}.json`), 'utf8'));
    const pkt = JSON.parse(fs.readFileSync(path.join(EXP, 'packets', `unseen-${imp.id}.json`), 'utf8'));
    const gtInd = pkt.ground_truth.indicators || [];
    const members = (cap.candidates?.items || []).filter((c) => c.indicator_membership === true);
    const gtKeys = new Map(gtInd.map((g) => [keyFn(g.type, g.value), g]));
    const fpKeys = new Map();
    for (const c of members) {
      const t = c.type || c.candidate_type;
      const v = refang(c.normalized_value || c.value);
      fpKeys.set(keyFn(t, v), c);
    }
    let tp = 0;
    let fp = 0;
    let fn = 0;
    for (const [k] of gtKeys) {
      if (fpKeys.has(k)) tp += 1;
      else fn += 1;
    }
    for (const [k] of fpKeys) {
      if (!gtKeys.has(k)) fp += 1;
    }
    TP += tp;
    FP += fp;
    FN += fn;
    rows.push({
      id: imp.id,
      tp,
      fp,
      fn,
      precision: tp + fp ? tp / (tp + fp) : null,
      recall: tp + fn ? tp / (tp + fn) : null
    });
  }
  return {
    mode,
    aggregate: {
      tp: TP,
      fp: FP,
      fn: FN,
      ioc_precision: TP + FP ? TP / (TP + FP) : null,
      discovery_recall: TP + FN ? TP / (TP + FN) : null
    },
    reports: rows
  };
}

const dispositions = [];
for (const r of original.reports) {
  if (r.status !== 'scored') continue;
  for (const x of r.fn_sample || []) {
    const id = `${r.id}|${x.key}`;
    dispositions.push({
      report: r.id,
      kind: 'FN',
      key: x.key,
      ...(DISP[id] || { verdict: 'unreviewed', note: '' }),
      seen_at_all: x.seen_at_all,
      seen_as_context: x.seen_as_context
    });
  }
  for (const x of r.fp_sample || []) {
    const id = `${r.id}|${x.key}`;
    dispositions.push({
      report: r.id,
      kind: 'FP',
      key: x.key,
      ...(DISP[id] || { verdict: 'unreviewed', note: '' }),
      labeled_context: x.labeled_context
    });
  }
}

const strict = scoreMode('strict');
const equivalence = scoreMode('equivalence_hostpath_trailingslash');

let tp = original.aggregate.tp;
let fp = original.aggregate.fp;
let fn = original.aggregate.fn;
for (const d of dispositions) {
  if (d.kind === 'FN' && d.verdict === 'url_serialization') {
    fn -= 1;
    tp += 1;
  } else if (d.kind === 'FP' && d.verdict === 'url_serialization') {
    fp -= 1;
  } else if (d.kind === 'FN' && d.verdict === 'intentional_policy') {
    fn -= 1;
  } else if (d.kind === 'FN' && d.verdict === 'gt_dispute') {
    fn -= 1;
  } else if (d.kind === 'FP' && d.verdict === 'gt_error') {
    fp -= 1;
    tp += 1;
  } else if (d.kind === 'FP' && (d.verdict === 'gt_omission' || d.verdict === 'gt_omission_plus_role_defect')) {
    fp -= 1;
    tp += 1;
  } else if (d.kind === 'FP' && d.verdict === 'gt_dispute') {
    fp -= 1;
  }
}

const count = (kind, verdicts) =>
  dispositions.filter((d) => d.kind === kind && verdicts.includes(d.verdict)).length;

const summary = {
  generated_at: new Date().toISOString(),
  experiment: ledger.experiment,
  original_preserved: {
    path: 'docs/evaluation/unseen-first-pass-10/score-summary.json',
    aggregate: original.aggregate
  },
  strict_rescore: strict.aggregate,
  equivalence_aware_rescore: equivalence.aggregate,
  disposition_counts: {
    FN_total: dispositions.filter((d) => d.kind === 'FN').length,
    FP_total: dispositions.filter((d) => d.kind === 'FP').length,
    FN_intentional_policy: count('FN', ['intentional_policy']),
    FN_url_serialization: count('FN', ['url_serialization']),
    FN_gt_dispute: count('FN', ['gt_dispute']),
    FN_pipeline_defect: count('FN', ['pipeline_defect']),
    FP_pipeline_defect: count('FP', ['pipeline_defect']),
    FP_gt_error: count('FP', ['gt_error']),
    FP_gt_omission: count('FP', ['gt_omission', 'gt_omission_plus_role_defect']),
    FP_gt_dispute: count('FP', ['gt_dispute']),
    FP_url_serialization: count('FP', ['url_serialization'])
  },
  verified_provisional: {
    note: 'Excludes intentional MODE A pack-deferred FNs; converts publisher-inventory GT errors/omissions to TP; drops URL serialization pairs and dual-use GT disputes from error counts. SSL fingerprint role defects remain qualitative.',
    tp,
    fp,
    fn,
    ioc_precision: tp + fp ? tp / (tp + fp) : null,
    discovery_recall: tp + fn ? tp / (tp + fn) : null,
    remaining_verified_fp: dispositions
      .filter((d) => d.kind === 'FP' && d.verdict === 'pipeline_defect')
      .map((d) => `${d.report}|${d.key}`),
    remaining_verified_fn: dispositions
      .filter((d) => d.kind === 'FN' && d.verdict === 'pipeline_defect')
      .map((d) => `${d.report}|${d.key}`)
  }
};

fs.writeFileSync(path.join(ROOT, 'fp-fn-disposition-v1.json'), JSON.stringify({ generated_at: summary.generated_at, items: dispositions }, null, 2) + '\n');
fs.writeFileSync(path.join(ROOT, 'score-summary.equivalence-v1.json'), JSON.stringify({ generated_at: summary.generated_at, ...equivalence }, null, 2) + '\n');
fs.writeFileSync(path.join(ROOT, 'score-summary.verified-provisional-v1.json'), JSON.stringify(summary, null, 2) + '\n');
console.log(JSON.stringify(summary, null, 2));

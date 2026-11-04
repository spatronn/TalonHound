/**
 * First-pass evaluation protocol: sample, label packet, validation and agreement.
 *
 * The sealed tier is the only measure of first-pass quality, so its rules live in code.
 * A case counts only if it was sampled before scoring, labelled from the publisher's
 * source against a frozen contract, and carries evidence for every label. Nothing here
 * reads extractor output, approved Indicators or IOC rows.
 */

import crypto from 'node:crypto';

export const SEALED_PROTOCOL_VERSION = 'tl-sealed-protocol-v1';

/** Share of cases that need an independent second labeler. */
export const SECOND_LABELER_SHARE = 0.2;

/** Provenance methods that are derived from TalonHound and so cannot be ground truth. */
const DERIVED_METHOD_RE = /\b(?:talonhound|approved|extractor|candidate|membership|replay|output|model|ai[-_ ]?assisted|auto)\b/i;

export const LABEL_ROLES = Object.freeze([
  'command_and_control', 'malware_download', 'phishing', 'malware_sample', 'staging', 'exfiltration',
  'victim', 'legitimate_service', 'reference', 'placeholder', 'other'
]);

/** Seeded, so a draw can be repeated and audited. */
function seededRank(seed, id) {
  return crypto.createHash('sha256').update(`${seed}\0${id}`).digest('hex');
}

/**
 * Draw a stratified sample: every stratum (publisher, format, whether a package is
 * announced) is represented before any stratum gets a second report.
 * @param {Array<{ id: string, url?: string, publisher: string, format: string, package_announced?: boolean }>} reports
 * @param {{ seed: string, size: number, drawn_at?: string, contract_fingerprint: string }} opts
 */
export function drawStratifiedSample(reports, opts) {
  if (!opts?.seed) throw new Error('a recorded seed is required');
  if (!opts?.contract_fingerprint) throw new Error('the frozen contract fingerprint is required');
  if (!Number.isInteger(opts.size) || opts.size < 1) throw new Error('size must be a positive integer');
  const strata = new Map();
  for (const r of reports) {
    const key = `${r.publisher}|${r.format}|${r.package_announced ? 'package' : 'no_package'}`;
    if (!strata.has(key)) strata.set(key, []);
    strata.get(key).push(r);
  }
  for (const list of strata.values()) list.sort((a, b) => seededRank(opts.seed, a.id).localeCompare(seededRank(opts.seed, b.id)));
  const order = [...strata.keys()].sort((a, b) => seededRank(opts.seed, a).localeCompare(seededRank(opts.seed, b)));
  const picked = [];
  for (let round = 0; picked.length < opts.size; round += 1) {
    let any = false;
    for (const key of order) {
      const r = strata.get(key)[round];
      if (!r) continue;
      any = true;
      if (picked.length < opts.size) picked.push({ ...r, stratum: key });
    }
    if (!any) break;
  }
  const secondCount = Math.ceil(picked.length * SECOND_LABELER_SHARE);
  const second = new Set([...picked].sort((a, b) => seededRank(`${opts.seed}:second`, a.id).localeCompare(seededRank(`${opts.seed}:second`, b.id))).slice(0, secondCount).map((r) => r.id));
  return {
    protocol: SEALED_PROTOCOL_VERSION,
    method: 'seeded_stratified_round_robin',
    seed: opts.seed,
    drawn_at: opts.drawn_at || new Date().toISOString(),
    contract_fingerprint: opts.contract_fingerprint,
    population: reports.length,
    strata: Object.fromEntries(order.map((k) => [k, strata.get(k).length])),
    second_labeler_share: SECOND_LABELER_SHARE,
    reports: picked.map((r) => ({ ...r, second_labeler: second.has(r.id) }))
  };
}

/** The empty case a labeler fills in, from the publisher's source only. */
export function buildLabelingPacket(entry, manifest) {
  return {
    id: `sealed-${String(entry.id).toLowerCase().replace(/[^a-z0-9._-]+/g, '-')}`,
    title: entry.title || '',
    publisher: entry.publisher,
    format: entry.format,
    sampling: { method: manifest.method, seed: manifest.seed, drawn_at: manifest.drawn_at, stratum: entry.stratum },
    contract_fingerprint: manifest.contract_fingerprint,
    source: { kind: 'private_source', url: entry.url || null, reference: entry.url || null, format: entry.format, sha256: '' },
    ground_truth: {
      provenance: { method: 'independent_human_review_of_publisher_source', verified_by: '', verified_at: '', coverage_note: '', second_labeler: null, disagreement_resolution: null },
      indicators: [],
      context_only: [],
      ambiguous: [],
      linked_packages: []
    }
  };
}

/**
 * Whether a case may count toward first-pass accuracy. Returns every problem found.
 * @param {object} c case
 * @param {{ contract_fingerprint?: string }} [opts]
 * @returns {string[]}
 */
export function sealedCaseProblems(c, opts = {}) {
  const problems = [];
  const gt = c?.ground_truth;
  const prov = gt?.provenance || {};
  if (!c?.sampling?.method || !c?.sampling?.drawn_at) problems.push('sampling.method and sampling.drawn_at are required');
  if (!c?.contract_fingerprint) problems.push('contract_fingerprint is required: the score is taken on frozen code');
  if (opts.contract_fingerprint && c?.contract_fingerprint !== opts.contract_fingerprint) problems.push('labelled against a different contract');
  if (!prov.verified_by || !prov.verified_at) problems.push('provenance.verified_by and verified_at are required');
  if (!prov.method || DERIVED_METHOD_RE.test(prov.method)) problems.push(`provenance.method must not derive from TalonHound: "${prov.method || ''}"`);
  if (!prov.coverage_note) problems.push('provenance.coverage_note is required (what was and was not read)');
  if (!Array.isArray(gt?.linked_packages)) problems.push('ground_truth.linked_packages is required, empty if the publisher names none');
  for (const key of ['indicators', 'context_only', 'ambiguous']) {
    for (const e of gt?.[key] || []) {
      const name = `${key} ${e?.type}:${e?.value}`;
      if (!String(e?.evidence || '').trim()) problems.push(`${name}: an evidence reference to the publisher source is required`);
      if (key !== 'ambiguous' && !LABEL_ROLES.includes(e?.role)) problems.push(`${name}: role must be one of ${LABEL_ROLES.join(', ')}`);
    }
  }
  for (const p of gt?.linked_packages || []) {
    if (!p?.url) problems.push('linked package needs its url');
    if (!Array.isArray(p?.expected_identities)) problems.push(`linked package ${p?.url}: expected_identities is required`);
  }
  return problems;
}

const idOf = (e) => `${String(e.type).toLowerCase()}:${String(e.value).trim().toLowerCase()}`;

/**
 * Agreement of two independent labelers on one report, for the disagreement record.
 * @param {object} a ground truth of the first labeler
 * @param {object} b ground truth of the second labeler
 */
export function labelAgreement(a, b) {
  const read = (gt) => {
    const out = new Map();
    for (const e of gt?.indicators || []) out.set(idOf(e), 'indicator');
    for (const e of gt?.context_only || []) out.set(idOf(e), 'context_only');
    for (const e of gt?.ambiguous || []) out.set(idOf(e), 'ambiguous');
    return out;
  };
  const ra = read(a);
  const rb = read(b);
  const all = new Set([...ra.keys(), ...rb.keys()]);
  const disagreements = [];
  let same = 0;
  for (const k of all) {
    if (ra.get(k) === rb.get(k)) same += 1;
    else disagreements.push({ identity: k, first: ra.get(k) || 'not_listed', second: rb.get(k) || 'not_listed' });
  }
  return { values: all.size, agreed: same, agreement: all.size ? Number((same / all.size).toFixed(4)) : 1, disagreements };
}

/**
 * Whether a sealed set may claim anything, stated with its reasons.
 * @param {object[]} cases
 * @param {{ min_reports: number, contract_fingerprint: string }} opts
 */
export function sealedSetReadiness(cases, opts) {
  const invalid = cases.map((c) => ({ id: c.id, problems: sealedCaseProblems(c, { contract_fingerprint: opts.contract_fingerprint }) })).filter((x) => x.problems.length);
  const valid = cases.length - invalid.length;
  const secondLabelled = cases.filter((c) => c.ground_truth?.provenance?.second_labeler).length;
  const needSecond = Math.ceil(valid * SECOND_LABELER_SHARE);
  const blockers = [];
  if (valid < opts.min_reports) blockers.push(`${valid} of ${opts.min_reports} required reports have valid independent labels`);
  if (secondLabelled < needSecond) blockers.push(`${secondLabelled} of ${needSecond} reports have a second labeler`);
  return { valid_reports: valid, second_labelled: secondLabelled, invalid, blockers, ready: blockers.length === 0 };
}

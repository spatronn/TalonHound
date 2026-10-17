/**
 * Threat Library extraction benchmark metrics (pure, no I/O).
 *
 * Scores one deterministic extraction result against independently labeled
 * ground truth. Candidate EXTRACTION failures (the value never became a
 * candidate) are kept apart from Indicator MEMBERSHIP failures (the value was
 * extracted but is not a report Indicator), because they have different
 * causes and different fixes.
 *
 * Membership and Context Only are read through the canonical contract
 * (indicatorMembership.js) on the persisted candidate shape, exactly as the
 * Indicators tab, SQL and MCP counts read them.
 */

import { normalizeCandidateValue } from '../candidateValue.js';
import { buildCandidateEvidenceRecord, SOURCE_ASSERTIONS } from '../evidencePolicy.js';
import { isContextOnlyCandidate, isReportIndicatorMember } from '../indicatorMembership.js';
import { NEGATIVE_ZONES, STRONG_IOC_ZONES } from '../documentZones.js';
import { refangTextForExtraction } from '../defang.js';
import { collapseLetterSpacing } from '../pdfLayout.js';

export const BENCHMARK_METRICS_VERSION = 'tl-benchmark-metrics-v2';

const EXPLICIT_ASSERTIONS = new Set([
  SOURCE_ASSERTIONS.EXPLICIT_IOC,
  SOURCE_ASSERTIONS.EXPLICIT_C2,
  SOURCE_ASSERTIONS.EXPLICIT_OPERATIONAL
]);

/** Section classes a ground-truth section can expect. */
export const SECTION_CLASSES = Object.freeze(['authoritative', 'narrative', 'excluded']);

/**
 * Canonical identity of a ground-truth entry, normalized with the same value
 * normalizer the extractor uses (normalization is not classification).
 * @param {{ type: string, value: string }} entry
 * @returns {string} `type:value`
 */
export function groundTruthIdentity(entry) {
  const type = String(entry?.type || '').toLowerCase();
  const n = normalizeCandidateValue(String(entry?.value || ''), type || null);
  if (n.ok && n.candidateType === type) return `${type}:${n.normalizedValue}`;
  return `${type}:${String(entry?.value || '').trim().toLowerCase()}`;
}

export const candidateIdentity = (c) => `${c.candidate_type}:${c.normalized_value}`;

/** Persisted shape of an extracted candidate (what the read path evaluates). */
export function persistedCandidate(c) {
  return { ...c, evidence: buildCandidateEvidenceRecord(c) };
}

/**
 * Zone class of an annotated block.
 * @param {string|null|undefined} zone
 */
export function zoneClass(zone) {
  const z = String(zone || '');
  if (STRONG_IOC_ZONES.has(z)) return 'authoritative';
  if (NEGATIVE_ZONES.has(z) || z === 'header_footer') return 'excluded';
  return 'narrative';
}

const ratio = (num, den) => (den > 0 ? Math.round((num / den) * 10000) / 10000 : null);

function f1(precision, recall) {
  if (precision == null || recall == null) return null;
  if (precision + recall === 0) return 0;
  return Math.round(((2 * precision * recall) / (precision + recall)) * 10000) / 10000;
}

function candidateSummary(c, mistypedAs = null) {
  if (!c) return mistypedAs ? { extracted: false, mistyped_as: mistypedAs } : { extracted: false };
  return {
    extracted: true,
    member: c.__member,
    context_only: c.__context_only,
    source_assertion: c.source_assertion || null,
    policy_decision: c.policy_decision || null,
    ai_needed: c.ai_needed === true,
    zones: [...new Set((c.occurrences || []).map((o) => o.zone).filter(Boolean))]
  };
}

function headingText(block) {
  return collapseLetterSpacing(String(block?.text || '').trim());
}

/**
 * Section-level structural accuracy: every content block under a labeled
 * heading (until `until` or the next heading) must carry the expected zone
 * class. Layout chrome (page edges, repeated headers/footers) is skipped.
 * @param {object[]} blocks zone-annotated blocks
 * @param {{ heading: string, expected: string, until?: string }[]} sections
 */
export function scoreSections(blocks, sections) {
  const out = { checked: 0, correct: 0, blocks_checked: 0, blocks_correct: 0, mismatches: [] };
  for (const s of sections || []) {
    if (!SECTION_CLASSES.includes(s.expected)) throw new Error(`unknown section class: ${s.expected}`);
    out.checked += 1;
    const start = (blocks || []).findIndex((b) => headingText(b) === String(s.heading).trim());
    if (start < 0) {
      out.mismatches.push({ heading: s.heading, expected: s.expected, reason: 'heading_not_found' });
      continue;
    }
    const zones = {};
    let ok = true;
    let seen = 0;
    for (let i = start + 1; i < blocks.length; i += 1) {
      const b = blocks[i];
      if (s.until ? headingText(b) === String(s.until).trim() : b.type === 'heading') break;
      if (b.layout === 'page_edge' || b.zone === 'header_footer') continue;
      seen += 1;
      const cls = zoneClass(b.zone);
      zones[b.zone || 'unknown'] = (zones[b.zone || 'unknown'] || 0) + 1;
      out.blocks_checked += 1;
      if (cls === s.expected) out.blocks_correct += 1;
      else ok = false;
    }
    if (!seen) {
      out.mismatches.push({ heading: s.heading, expected: s.expected, reason: 'no_content_blocks' });
      continue;
    }
    if (ok) out.correct += 1;
    else out.mismatches.push({ heading: s.heading, expected: s.expected, zones });
  }
  out.accuracy = ratio(out.correct, out.checked);
  out.block_accuracy = ratio(out.blocks_correct, out.blocks_checked);
  return out;
}

function documentHaystack(blocks) {
  return refangTextForExtraction((blocks || []).map((b) => String(b.text || '')).join('\n')).toLowerCase();
}

/** A member whose value does not occur in the source text at all (unsupported). */
function isUnsupported(c, haystack) {
  const values = [c.normalized_value, c.original_value]
    .filter(Boolean)
    .flatMap((v) => [String(v), String(v).replace(/\/$/, '')])
    .map((v) => refangTextForExtraction(v).toLowerCase());
  return !values.some((v) => v && haystack.includes(v));
}

/** Ground-truth categories (an identity belongs to at most one). */
export const GROUND_TRUTH_CATEGORIES = Object.freeze([
  // Publisher-asserted report Indicators (the complete set for the case).
  'indicators',
  // Must be Context Only (reference / provider / reserved / contact context).
  'context_only',
  // Legitimate observables (signed binaries, vendor APIs, loopback) that must never be Indicators.
  'excluded_legitimate',
  // Must not be Indicators; any other state is acceptable (e.g. MODE A narrative hashes).
  'not_indicators',
  // Publisher evidence supports either reading (entry carries a `rationale`):
  // never counted as TP, FN or FP; the observed state is reported instead.
  'ambiguous'
]);

/**
 * Score one case.
 *
 * An entry marked `ai_dependent: true` is decided by the semantic (model)
 * layer, not the deterministic one: it is reported under `ai_dependent` and
 * left out of the deterministic precision / recall.
 * @param {{
 *   groundTruth: { indicators?: object[], context_only?: object[], excluded_legitimate?: object[], not_indicators?: object[], sections?: object[] },
 *   candidates: object[],
 *   blocks?: object[]
 * }} input
 */
export function scoreBenchmarkCase({ groundTruth, candidates, blocks = [] }) {
  const gt = groundTruth || {};
  const byId = new Map();
  for (const raw of candidates || []) {
    const persisted = persistedCandidate(raw);
    byId.set(candidateIdentity(raw), {
      ...raw,
      __member: isReportIndicatorMember(persisted),
      __context_only: isContextOnlyCandidate(persisted)
    });
  }
  const aiDependent = [];
  const index = (key) => {
    const m = new Map();
    for (const e of gt[key] || []) {
      const id = groundTruthIdentity(e);
      if (e.ai_dependent === true) aiDependent.push({ id, category: key, entry: e });
      else m.set(id, e);
    }
    return m;
  };
  const expectedIndicators = index('indicators');
  const expectedContext = index('context_only');
  const expectedExcluded = index('excluded_legitimate');
  const expectedNonIndicators = index('not_indicators');
  const ambiguous = index('ambiguous');
  const aiDependentIds = new Set(aiDependent.map((x) => x.id));
  const members = [...byId.values()].filter((c) => c.__member);
  const memberIds = new Set(members.map(candidateIdentity));
  const scoredMemberIds = new Set([...memberIds].filter((id) => !aiDependentIds.has(id) && !ambiguous.has(id)));

  // Candidate extraction recall over every labeled identity whose state
  // requires a candidate. `not_indicators` / `ambiguous` accept any state,
  // including never being extracted (a thumbprint that is no SHA-1 candidate).
  const labeled = new Set([
    ...expectedIndicators.keys(),
    ...expectedContext.keys(),
    ...expectedExcluded.keys(),
    ...aiDependentIds
  ]);
  // A labeled value that exists only under another candidate type (an MD5
  // typed as an artifact, a domain read as a file name) is a TYPING failure,
  // not a missing extraction.
  const typesByValue = new Map();
  for (const c of byId.values()) {
    const v = String(c.normalized_value || '').toLowerCase();
    if (!typesByValue.has(v)) typesByValue.set(v, []);
    typesByValue.get(v).push(c.candidate_type);
  }
  const mistypedAs = (id) => {
    if (byId.has(id)) return null;
    const i = id.indexOf(':');
    const types = typesByValue.get(id.slice(i + 1).toLowerCase()) || [];
    return types.length ? types.slice().sort().join(',') : null;
  };
  const notExtracted = [...labeled].filter((id) => !byId.has(id)).sort();

  const tp = [...expectedIndicators.keys()].filter((id) => memberIds.has(id)).sort();
  const fnIds = [...expectedIndicators.keys()].filter((id) => !memberIds.has(id)).sort();
  const fpIds = [...scoredMemberIds].filter((id) => !expectedIndicators.has(id)).sort();
  const falseNegatives = fnIds.map((id) => ({ id, ...candidateSummary(byId.get(id), mistypedAs(id)) }));
  const falsePositives = fpIds.map((id) => ({
    id,
    labeled_as: expectedContext.has(id)
      ? 'context_only'
      : expectedExcluded.has(id)
        ? 'excluded_legitimate'
        : expectedNonIndicators.has(id)
          ? 'not_indicators'
          : 'unlabeled',
    ...candidateSummary(byId.get(id))
  }));
  const precision = ratio(tp.length, tp.length + fpIds.length);
  const recall = ratio(tp.length, expectedIndicators.size);

  const contextWrong = [];
  for (const id of expectedContext.keys()) {
    const c = byId.get(id);
    if (!c) contextWrong.push({ id, state: 'not_extracted' });
    else if (c.__member) contextWrong.push({ id, state: 'indicator' });
    else if (!c.__context_only) contextWrong.push({ id, state: 'non_member_not_context_only', ...candidateSummary(c) });
  }
  const legitPromoted = [...expectedExcluded.keys()].filter((id) => memberIds.has(id)).sort();

  const assertionMismatches = [];
  let assertionsChecked = 0;
  for (const [id, e] of expectedIndicators) {
    if (!e.assertion) continue;
    assertionsChecked += 1;
    const actual = byId.get(id)?.source_assertion || null;
    const ok = e.assertion === 'explicit' ? EXPLICIT_ASSERTIONS.has(actual) : actual === e.assertion;
    if (!ok) assertionMismatches.push({ id, expected: e.assertion, actual });
  }

  const haystack = documentHaystack(blocks);
  const unsupported = blocks.length ? members.filter((c) => isUnsupported(c, haystack)).map(candidateIdentity).sort() : [];

  return {
    version: BENCHMARK_METRICS_VERSION,
    members: [...memberIds].sort(),
    candidate_extraction: {
      labeled: labeled.size,
      extracted: labeled.size - notExtracted.length,
      recall: ratio(labeled.size - notExtracted.length, labeled.size),
      not_extracted: notExtracted,
      mistyped: notExtracted.filter((id) => mistypedAs(id)).map((id) => ({ id, extracted_as: mistypedAs(id) }))
    },
    indicators: {
      expected: expectedIndicators.size,
      actual: memberIds.size,
      tp: tp.length,
      fp: fpIds.length,
      fn: fnIds.length,
      // FN split: never extracted / extracted under another type / extracted but not a member.
      fn_not_extracted: falseNegatives.filter((x) => !x.extracted && !x.mistyped_as).length,
      fn_mistyped: falseNegatives.filter((x) => !x.extracted && x.mistyped_as).length,
      fn_not_member: falseNegatives.filter((x) => x.extracted).length,
      precision,
      recall,
      f1: f1(precision, recall),
      false_negatives: falseNegatives,
      false_positives: falsePositives
    },
    context_only: {
      expected: expectedContext.size,
      correct: expectedContext.size - contextWrong.length,
      accuracy: ratio(expectedContext.size - contextWrong.length, expectedContext.size),
      wrong: contextWrong
    },
    legitimate_exclusion: {
      expected: expectedExcluded.size,
      excluded: expectedExcluded.size - legitPromoted.length,
      accuracy: ratio(expectedExcluded.size - legitPromoted.length, expectedExcluded.size),
      promoted: legitPromoted
    },
    assertions: {
      checked: assertionsChecked,
      correct: assertionsChecked - assertionMismatches.length,
      accuracy: ratio(assertionsChecked - assertionMismatches.length, assertionsChecked),
      mismatches: assertionMismatches
    },
    non_indicators: {
      expected: expectedNonIndicators.size,
      promoted: [...expectedNonIndicators.keys()].filter((id) => memberIds.has(id)).sort()
    },
    ambiguous: [...ambiguous.keys()].sort().map((id) => ({
      id,
      member: memberIds.has(id),
      ...candidateSummary(byId.get(id), mistypedAs(id))
    })),
    ai_dependent: aiDependent.map((x) => ({
      id: x.id,
      category: x.category,
      deterministic_state: candidateSummary(byId.get(x.id))
    })),
    sections: scoreSections(blocks, gt.sections || []),
    unsupported_indicators: unsupported
  };
}

/**
 * Micro-averaged aggregate over scored cases.
 * @param {{ id: string, metrics: ReturnType<typeof scoreBenchmarkCase>, elapsed_ms?: number }[]} results
 */
export function aggregateBenchmark(results) {
  const sum = (f) => results.reduce((n, r) => n + (Number(f(r.metrics)) || 0), 0);
  const tp = sum((m) => m.indicators.tp);
  const fp = sum((m) => m.indicators.fp);
  const fn = sum((m) => m.indicators.fn);
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  const labeled = sum((m) => m.candidate_extraction.labeled);
  const extracted = sum((m) => m.candidate_extraction.extracted);
  const sectionsChecked = sum((m) => m.sections.checked);
  const assertionsChecked = sum((m) => m.assertions.checked);
  const contextExpected = sum((m) => m.context_only.expected);
  const legitExpected = sum((m) => m.legitimate_exclusion.expected);
  return {
    cases: results.length,
    cases_exact: results.filter((r) => r.metrics.indicators.fp === 0 && r.metrics.indicators.fn === 0).length,
    indicators: {
      expected: tp + fn,
      tp,
      fp,
      fn,
      fn_not_extracted: sum((m) => m.indicators.fn_not_extracted),
      fn_mistyped: sum((m) => m.indicators.fn_mistyped),
      fn_not_member: sum((m) => m.indicators.fn_not_member),
      precision,
      recall,
      f1: f1(precision, recall)
    },
    candidate_extraction_recall: ratio(extracted, labeled),
    context_only_accuracy: ratio(sum((m) => m.context_only.correct), contextExpected),
    legitimate_exclusion_accuracy: ratio(sum((m) => m.legitimate_exclusion.excluded), legitExpected),
    assertion_accuracy: ratio(sum((m) => m.assertions.correct), assertionsChecked),
    section_accuracy: ratio(sum((m) => m.sections.correct), sectionsChecked),
    non_indicators_promoted: sum((m) => m.non_indicators.promoted.length),
    ai_dependent_entries: sum((m) => m.ai_dependent.length),
    unsupported_indicators: sum((m) => m.unsupported_indicators.length),
    elapsed_ms: results.reduce((n, r) => n + (Number(r.elapsed_ms) || 0), 0)
  };
}

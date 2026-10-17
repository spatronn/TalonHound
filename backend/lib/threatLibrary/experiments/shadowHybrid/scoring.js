/**
 * Shadow-hybrid scoring: deterministic vs section-tree vs Qwen vs hybrid.
 * Distinguishes extraction recall from Indicator membership recall.
 */

import { normalizeCandidateValue } from '../../candidateValue.js';
import { buildCandidateEvidenceRecord } from '../../evidencePolicy.js';
import { isReportIndicatorMember } from '../../indicatorMembership.js';

export function identity(type, value) {
  const t = String(type || '').toLowerCase();
  const n = normalizeCandidateValue(String(value || ''), t === 'ipv4' || t === 'ipv6' ? 'ip' : t);
  const ct = t === 'ipv4' || t === 'ipv6' ? 'ip' : t;
  if (n.ok) return `${n.candidateType || ct}:${n.normalizedValue}`;
  return `${ct}:${String(value || '').trim().toLowerCase()}`;
}

export function gtIdentities(entries) {
  return new Set((entries || []).map((e) => identity(e.type, e.value)));
}

function prf(tp, fp, fn) {
  const precision = tp + fp > 0 ? tp / (tp + fp) : null;
  const recall = tp + fn > 0 ? tp / (tp + fn) : null;
  const f1 = precision != null && recall != null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null;
  const round = (x) => (x == null ? null : Math.round(x * 10000) / 10000);
  return { tp, fp, fn, precision: round(precision), recall: round(recall), f1: round(f1) };
}

/**
 * Score a predicted identity set against ground-truth indicators.
 * @param {Set<string>|string[]} predicted
 * @param {Set<string>|Iterable<string>} expected
 */
export function scoreSet(predicted, expected) {
  const pred = predicted instanceof Set ? predicted : new Set(predicted);
  const exp = expected instanceof Set ? expected : new Set(expected);
  let tp = 0;
  let fp = 0;
  let fn = 0;
  const tpList = [];
  const fpList = [];
  const fnList = [];
  for (const id of pred) {
    if (exp.has(id)) {
      tp += 1;
      tpList.push(id);
    } else {
      fp += 1;
      fpList.push(id);
    }
  }
  for (const id of exp) {
    if (!pred.has(id)) {
      fn += 1;
      fnList.push(id);
    }
  }
  return { ...prf(tp, fp, fn), tp_list: tpList, fp_list: fpList, fn_list: fnList };
}

export function candidateMemberKeys(candidates) {
  const keys = new Set();
  for (const c of candidates || []) {
    const persisted = { ...c, evidence: c.evidence || buildCandidateEvidenceRecord(c) };
    if (isReportIndicatorMember(persisted)) {
      keys.add(`${c.candidate_type}:${c.normalized_value}`);
    }
  }
  return keys;
}

export function candidateExtractedKeys(candidates) {
  return new Set((candidates || []).map((c) => `${c.candidate_type}:${c.normalized_value}`));
}

/**
 * Build hybrid set = deterministic members ∪ grounded Qwen indicator proposals
 * that pass a simple MODE-A-style filter when the document has authoritative scope.
 */
export function hybridMemberKeys(detKeys, qwenAccepted, opts = {}) {
  const out = new Set(detKeys);
  const modeA = opts.modeA !== false;
  for (const p of qwenAccepted || []) {
    const id = identity(p.type, p.value);
    const cat = String(p.assertion_category || '').toLowerCase();
    const assessment = String(p.assessment || '').toLowerCase();
    if (assessment === 'benign' || assessment === 'contextual') continue;
    if (modeA) {
      const okCat = [
        'formal_ioc_appendix',
        'hash_inventory',
        'network_infrastructure_list',
        'c2_list',
        'narrative_assertion'
      ].includes(cat);
      if (!okCat) continue;
    }
    out.add(id);
  }
  return out;
}

export function summarizeApproaches({ expected, deterministicKeys, sectionTreeKeys, qwenKeys, hybridKeys, extractedKeys }) {
  const membership = {
    deterministic: scoreSet(deterministicKeys, expected),
    section_tree: scoreSet(sectionTreeKeys, expected),
    qwen_independent: scoreSet(qwenKeys, expected),
    validated_hybrid: scoreSet(hybridKeys, expected)
  };
  const extraction = {
    deterministic: scoreSet(extractedKeys, expected)
  };
  const qwenOnlyCorrect = [...(qwenKeys || [])].filter((id) => expected.has(id) && !deterministicKeys.has(id));
  const treeOnlyCorrect = [...(sectionTreeKeys || [])].filter((id) => expected.has(id) && !deterministicKeys.has(id));
  const parserOnlyCorrect = [...(deterministicKeys || [])].filter((id) => expected.has(id) && !(qwenKeys || new Set()).has(id));
  return {
    membership,
    extraction,
    qwen_only_correct: qwenOnlyCorrect,
    section_tree_only_correct: treeOnlyCorrect,
    parser_only_correct: parserOnlyCorrect,
    expected_count: expected.size
  };
}

/**
 * Evaluate whether quality / structural signals would selectively invoke Qwen.
 */

import { QUALITY_CODES } from '../../extractionQuality.js';

const DEFAULT_TRIGGER_CODES = new Set([
  QUALITY_CODES.APPENDIX_HEADING_NONMEMBER_ROWS,
  QUALITY_CODES.AUTHORITATIVE_SECTION_EMPTY,
  QUALITY_CODES.APPENDIX_WITHOUT_HASH_INDICATORS,
  QUALITY_CODES.APPENDIX_HASH_INDICATORS_LOW,
  QUALITY_CODES.AUTHORITATIVE_SECTION_WITHOUT_INDICATORS,
  QUALITY_CODES.INDICATOR_ROWS_ADJACENT_TO_SCOPE,
  QUALITY_CODES.INDICATOR_ROWS_OUTSIDE_SCOPE,
  QUALITY_CODES.EXPLICIT_TABLE_ROWS_DROPPED,
  'structural_completeness',
  'body_ioc_table_outside_appendix'
]);

function collectCodes(quality) {
  const codes = new Set();
  for (const w of quality?.warnings || []) {
    if (typeof w === 'string') codes.add(w);
    else if (w?.code) codes.add(w.code);
  }
  for (const c of quality?.codes || []) codes.add(c);
  return codes;
}

/**
 * @param {object|null} quality
 * @param {object[]} candidates
 * @param {{ expected?: Set<string>, deterministicMembers?: Set<string> }} [opts]
 */
export function evaluateSelectiveTriggers(quality, candidates, opts = {}) {
  const codes = collectCodes(quality);
  const status = String(quality?.status || 'unknown');
  const triggeredByCode = [...codes].filter((c) => DEFAULT_TRIGGER_CODES.has(c));

  const nonMemberMalicious = (candidates || []).filter((c) => {
    const assessment = String(c.assessment || '').toLowerCase();
    if (assessment !== 'malicious') return false;
    const key = `${c.candidate_type}:${c.normalized_value}`;
    if (opts.deterministicMembers?.has(key)) return false;
    const assertion = String(c.source_assertion || '').toLowerCase();
    return assertion === 'body_mention' || c.ai_needed === true;
  });

  const triggerNonMemberMalicious = nonMemberMalicious.length >= 3;
  const wouldTrigger = triggeredByCode.length > 0 || triggerNonMemberMalicious;

  let wouldCatchFn = null;
  let fnCount = 0;
  if (opts.expected && opts.deterministicMembers) {
    const fns = [...opts.expected].filter((id) => !opts.deterministicMembers.has(id));
    fnCount = fns.length;
    wouldCatchFn = wouldTrigger && fns.length > 0;
  }

  return {
    status,
    codes: [...codes],
    triggered_by_quality_codes: triggeredByCode,
    non_member_malicious_count: nonMemberMalicious.length,
    trigger_non_member_malicious: triggerNonMemberMalicious,
    would_trigger: wouldTrigger,
    would_catch_known_fn: wouldCatchFn,
    known_fn_count: fnCount,
    clean_but_has_fn: status === 'clean' && fnCount > 0
  };
}

export { DEFAULT_TRIGGER_CODES };

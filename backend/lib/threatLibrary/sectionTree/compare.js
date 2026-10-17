/**
 * Compare deterministic vs section-tree membership previews.
 */

import { buildCandidateEvidenceRecord } from '../evidencePolicy.js';
import { isReportIndicatorMember } from '../indicatorMembership.js';

const MAX_DIFFS = 40;

function persisted(c) {
  return { ...c, evidence: c.evidence || buildCandidateEvidenceRecord(c) };
}

export function candidateMemberKeySet(candidates) {
  const keys = new Set();
  for (const c of candidates || []) {
    if (isReportIndicatorMember(persisted(c))) {
      keys.add(`${c.candidate_type}:${c.normalized_value}`);
    }
  }
  return keys;
}

function parseKey(key) {
  const i = String(key).indexOf(':');
  if (i < 0) return { type: 'unknown', value: key };
  return { type: key.slice(0, i), value: key.slice(i + 1) };
}

/**
 * @param {Set<string>} deterministicKeys
 * @param {Set<string>} treeKeys
 * @param {{ candidatesByKey?: Map<string, object>, treeBlocksById?: Map<string, object> }} [ctx]
 */
export function compareMembershipSets(deterministicKeys, treeKeys, ctx = {}) {
  const det = deterministicKeys instanceof Set ? deterministicKeys : new Set(deterministicKeys);
  const tree = treeKeys instanceof Set ? treeKeys : new Set(treeKeys);
  const additions = [];
  const removals = [];

  for (const key of tree) {
    if (!det.has(key)) {
      const { type, value } = parseKey(key);
      const c = ctx.candidatesByKey?.get(key);
      const occ = c?.occurrences?.find((o) => o.section_tree_upgrade || o.section_tree_rezone_demote) || c?.occurrences?.[0];
      const block = occ?.block_id ? ctx.treeBlocksById?.get(occ.block_id) : null;
      additions.push({
        type,
        value,
        block_id: occ?.block_id || null,
        section_path: (block?.section_path || []).slice(0, 8),
        authoritative_zone: block?.authoritative_zone || occ?.zone || null,
        reason: 'section_tree_authoritative_ancestry'
      });
    }
  }
  for (const key of det) {
    if (!tree.has(key)) {
      const { type, value } = parseKey(key);
      removals.push({
        type,
        value,
        reason: 'lost_under_section_tree_rezone'
      });
    }
  }

  additions.sort((a, b) => `${a.type}:${a.value}`.localeCompare(`${b.type}:${b.value}`));
  removals.sort((a, b) => `${a.type}:${a.value}`.localeCompare(`${b.type}:${b.value}`));

  return {
    deterministic_count: det.size,
    tree_count: tree.size,
    unchanged_count: [...det].filter((k) => tree.has(k)).length,
    additions_total: additions.length,
    removals_total: removals.length,
    additions: additions.slice(0, MAX_DIFFS),
    removals: removals.slice(0, MAX_DIFFS),
    additions_truncated: additions.length > MAX_DIFFS,
    removals_truncated: removals.length > MAX_DIFFS,
    equal: additions.length === 0 && removals.length === 0
  };
}

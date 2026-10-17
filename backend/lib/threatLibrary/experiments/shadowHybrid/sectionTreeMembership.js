/**
 * Shadow membership remapping via section-tree ancestry.
 * Leaves production candidates untouched; returns cloned candidates.
 */

import { buildCandidateEvidenceRecord } from '../../evidencePolicy.js';
import { isReportIndicatorMember, isContextOnlyCandidate } from '../../indicatorMembership.js';
import { STRONG_IOC_ZONES } from '../../documentZones.js';
import { isIndicatorValueLine, isAnnotatedIndicatorRowLine, isObservableListLine } from '../../indicatorScope.js';
import { refangTextForExtraction } from '../../defang.js';
import { annotateSectionTree } from './sectionTree.js';

function rowShaped(text) {
  const t = String(text || '').trim();
  if (!t) return false;
  return isIndicatorValueLine(t) || isAnnotatedIndicatorRowLine(t) || isObservableListLine(t) || t.length <= 120;
}

/** True when the block is essentially the observable (not a narrative sentence). */
function blockIsFocusedOnValue(blockText, value) {
  const raw = refangTextForExtraction(String(blockText || ''))
    .replace(/\[\.\]/g, '.')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
  const v = String(value || '').trim().toLowerCase();
  if (!raw || !v) return false;
  if (raw === v) return true;
  // Allow light annotation: "hash – note", "domain (phishing)"
  if (raw.startsWith(v) && raw.length <= v.length + 80) return true;
  if (raw.endsWith(v) && raw.length <= v.length + 80) return true;
  // Pure hash / IP / URL line with defanging remnants
  if (isIndicatorValueLine(blockText) && raw.includes(v) && raw.length <= v.length + 16) return true;
  return false;
}

/**
 * Recompute MODE A membership as if occurrence zones followed section-tree
 * authoritative ancestry instead of linear zone transitions.
 *
 * @param {object} document canonical document
 * @param {object[]} candidates deterministic extraction candidates
 * @returns {{ tree: object, candidates: object[], members: object[], memberKeys: Set<string> }}
 */
export function remapMembershipWithSectionTree(document, candidates) {
  const tree = annotateSectionTree(document);
  const byId = new Map(tree.blocks.map((b) => [b.id, b]));
  const hasAuth = tree.meta.has_authoritative_scope === true;

  const remapped = (candidates || []).map((c) => {
    const occurrences = Array.isArray(c.occurrences) ? c.occurrences.map((o) => ({ ...o })) : [];
    let gainedAssertion = false;
    for (const occ of occurrences) {
      const block = byId.get(occ.block_id);
      if (!block?.authoritative_zone || !STRONG_IOC_ZONES.has(block.authoritative_zone)) continue;
      const text = String(block.text || occ.evidence_text || occ.text || c.original_value || c.normalized_value || '');
      // Only upgrade inventory / row-shaped blocks focused on this value.
      // Narrative mentions (e.g. google.com in prose under a still-open appendix)
      // must not become Indicators.
      if (!rowShaped(text)) continue;
      if (!blockIsFocusedOnValue(text, c.normalized_value || c.original_value)) continue;
      occ.zone = block.authoritative_zone;
      occ.asserted = true;
      if (!occ.occurrence_kind) occ.occurrence_kind = 'standalone_indicator_row';
      gainedAssertion = true;
    }

    let sourceAssertion = c.source_assertion;
    if (gainedAssertion) {
      const zones = new Set(occurrences.map((o) => o.zone));
      if (zones.has('c2_section')) sourceAssertion = 'explicit_c2';
      else if (zones.has('operational_infrastructure')) sourceAssertion = 'explicit_operational_infrastructure';
      else sourceAssertion = 'explicit_ioc';
    }

    const next = {
      ...c,
      occurrences,
      source_assertion: sourceAssertion,
      document_has_authoritative_scope: hasAuth || c.document_has_authoritative_scope === true,
      shadow_section_tree_asserted: gainedAssertion
    };
    next.evidence = buildCandidateEvidenceRecord(next);
    return next;
  });

  const members = remapped.filter((c) => isReportIndicatorMember(c));
  const memberKeys = new Set(members.map((c) => `${c.candidate_type}:${c.normalized_value}`));
  const contextOnly = remapped.filter((c) => isContextOnlyCandidate(c));

  return { tree, candidates: remapped, members, memberKeys, contextOnly, has_authoritative_scope: hasAuth };
}

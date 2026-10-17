/**
 * Membership *preview* from section-tree ancestry.
 *
 * Structural scope and Indicator membership stay separate:
 *   - annotateSectionTree decides ancestry / tree_zone
 *   - this module only previews how MODE A membership would change if
 *     occurrence authority followed that ancestry
 *
 * Never writes candidates. Never demotes an existing explicit publisher
 * assertion in additive mode (safe default for shadow).
 */

import { buildCandidateEvidenceRecord } from '../evidencePolicy.js';
import { isReportIndicatorMember, isContextOnlyCandidate } from '../indicatorMembership.js';
import { STRONG_IOC_ZONES } from '../documentZones.js';
import { isIndicatorValueLine, isAnnotatedIndicatorRowLine, isObservableListLine } from '../indicatorScope.js';
import { refangTextForExtraction } from '../defang.js';
import { annotateSectionTree } from './annotate.js';
import { SECTION_TREE_MEMBERSHIP_PREVIEW_VERSION } from './version.js';

function rowShaped(text) {
  const t = String(text || '').trim();
  if (!t) return false;
  if (isIndicatorValueLine(t) || isAnnotatedIndicatorRowLine(t) || isObservableListLine(t)) return true;
  // Tight bound — PoC used 120 which promoted narrative sentences.
  return t.length <= 96 && !/[.!?。]/.test(t);
}

function blockIsFocusedOnValue(blockText, value) {
  const raw = refangTextForExtraction(String(blockText || ''))
    .replace(/\[\.\]/g, '.')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
  const v = String(value || '').trim().toLowerCase();
  if (!raw || !v) return false;
  if (raw === v) return true;
  if (raw.startsWith(v) && raw.length <= v.length + 80) return true;
  if (raw.endsWith(v) && raw.length <= v.length + 80) return true;
  if (isIndicatorValueLine(blockText) && raw.includes(v) && raw.length <= v.length + 16) return true;
  return false;
}

function assertionForZones(zones) {
  if (zones.has('c2_section')) return 'explicit_c2';
  if (zones.has('operational_infrastructure')) return 'explicit_operational_infrastructure';
  return 'explicit_ioc';
}

/**
 * Additive preview: upgrade focused inventory rows under tree-authoritative
 * ancestry; never strip an existing explicit_* assertion.
 *
 * @param {object} document
 * @param {object[]} candidates
 * @param {{ tree?: object }} [opts]
 */
export function previewMembershipAdditive(document, candidates, opts = {}) {
  const tree = opts.tree || annotateSectionTree(document);
  const byId = new Map(tree.blocks.map((b) => [b.id, b]));
  const hasAuth = tree.meta.has_authoritative_scope === true;

  const remapped = (candidates || []).map((c) => {
    const occurrences = Array.isArray(c.occurrences) ? c.occurrences.map((o) => ({ ...o })) : [];
    let gainedAssertion = false;
    const priorAssertion = String(c.source_assertion || '').toLowerCase();
    const priorExplicit = priorAssertion.startsWith('explicit_');

    for (const occ of occurrences) {
      const block = byId.get(occ.block_id);
      if (!block?.authoritative_zone || !STRONG_IOC_ZONES.has(block.authoritative_zone)) continue;
      const text = String(block.text || occ.evidence_text || occ.text || c.original_value || c.normalized_value || '');
      if (!rowShaped(text)) continue;
      if (!blockIsFocusedOnValue(text, c.normalized_value || c.original_value)) continue;
      occ.zone = block.authoritative_zone;
      occ.asserted = true;
      if (!occ.occurrence_kind) occ.occurrence_kind = 'standalone_indicator_row';
      occ.section_tree_upgrade = true;
      gainedAssertion = true;
    }

    let sourceAssertion = c.source_assertion;
    if (gainedAssertion && !priorExplicit) {
      sourceAssertion = assertionForZones(new Set(occurrences.map((o) => o.zone)));
    }

    const next = {
      ...c,
      occurrences,
      source_assertion: sourceAssertion,
      document_has_authoritative_scope: hasAuth || c.document_has_authoritative_scope === true,
      section_tree_preview_upgraded: gainedAssertion
    };
    next.evidence = buildCandidateEvidenceRecord(next);
    return next;
  });

  return summarizePreview(tree, remapped, 'additive');
}

/**
 * Full-rezone preview: occurrence zones follow tree ancestry (diagnostics only).
 * More aggressive — can preview removals when linear authority was wrong.
 *
 * @param {object} document
 * @param {object[]} candidates
 * @param {{ tree?: object }} [opts]
 */
export function previewMembershipFullRezone(document, candidates, opts = {}) {
  const tree = opts.tree || annotateSectionTree(document);
  const byId = new Map(tree.blocks.map((b) => [b.id, b]));
  const hasAuth = tree.meta.has_authoritative_scope === true;

  const remapped = (candidates || []).map((c) => {
    const occurrences = Array.isArray(c.occurrences) ? c.occurrences.map((o) => ({ ...o })) : [];
    let anyAsserted = false;
    for (const occ of occurrences) {
      const block = byId.get(occ.block_id);
      const authZone = block?.authoritative_zone;
      if (authZone && STRONG_IOC_ZONES.has(authZone)) {
        const text = String(block.text || occ.evidence_text || occ.text || c.original_value || c.normalized_value || '');
        if (rowShaped(text) && blockIsFocusedOnValue(text, c.normalized_value || c.original_value)) {
          occ.zone = authZone;
          occ.asserted = true;
          if (!occ.occurrence_kind) occ.occurrence_kind = 'standalone_indicator_row';
          anyAsserted = true;
          continue;
        }
      }
      // Non-focused / non-inventory under appendix → narrative body for preview.
      if (STRONG_IOC_ZONES.has(String(occ.zone || '')) && occ.asserted === true) {
        occ.zone = 'report_body';
        occ.asserted = false;
        occ.section_tree_rezone_demote = true;
      }
    }

    let sourceAssertion = c.source_assertion;
    if (anyAsserted) {
      sourceAssertion = assertionForZones(new Set(occurrences.filter((o) => o.asserted).map((o) => o.zone)));
    } else if (String(sourceAssertion || '').startsWith('explicit_')) {
      sourceAssertion = 'body_mention';
    }

    const next = {
      ...c,
      occurrences,
      source_assertion: sourceAssertion,
      document_has_authoritative_scope: hasAuth,
      section_tree_preview_upgraded: anyAsserted
    };
    next.evidence = buildCandidateEvidenceRecord(next);
    return next;
  });

  return summarizePreview(tree, remapped, 'full_rezone');
}

function summarizePreview(tree, remapped, mode) {
  const members = remapped.filter((c) => isReportIndicatorMember(c));
  const memberKeys = new Set(members.map((c) => `${c.candidate_type}:${c.normalized_value}`));
  const contextOnly = remapped.filter((c) => isContextOnlyCandidate(c));
  return {
    version: SECTION_TREE_MEMBERSHIP_PREVIEW_VERSION,
    mode,
    tree,
    candidates: remapped,
    members,
    memberKeys,
    contextOnly,
    has_authoritative_scope: tree.meta.has_authoritative_scope === true
  };
}

/**
 * Section-tree shadow evaluation.
 *
 * Runs alongside deterministic extraction. Never mutates the authoritative
 * candidate list. Failures return a bounded error diagnostic and must not
 * fail the import.
 */

import { annotateSectionTree } from './annotate.js';
import { previewMembershipAdditive, previewMembershipFullRezone } from './membershipPreview.js';
import { candidateMemberKeySet, compareMembershipSets } from './compare.js';
import { isSectionTreeFullRezonePreviewEnabled, isSectionTreeShadowEnabled } from './flags.js';
import { SECTION_TREE_SHADOW_VERSION, SECTION_TREE_VERSION } from './version.js';

/**
 * @param {object} document canonical document
 * @param {object[]} candidates deterministic candidates (authoritative)
 * @param {{ fullRezone?: boolean, enabled?: boolean }} [opts]
 */
export function evaluateSectionTreeShadow(document, candidates, opts = {}) {
  const t0 = Date.now();
  try {
    const tree = annotateSectionTree(document);
    const detKeys = candidateMemberKeySet(candidates);
    const additive = previewMembershipAdditive(document, candidates, { tree });
    const additiveCmp = compareMembershipSets(detKeys, additive.memberKeys, {
      candidatesByKey: new Map(additive.candidates.map((c) => [`${c.candidate_type}:${c.normalized_value}`, c])),
      treeBlocksById: new Map(tree.blocks.map((b) => [b.id, b]))
    });

    let fullRezone = null;
    const wantFull = opts.fullRezone === true || isSectionTreeFullRezonePreviewEnabled();
    if (wantFull) {
      const full = previewMembershipFullRezone(document, candidates, { tree });
      fullRezone = compareMembershipSets(detKeys, full.memberKeys, {
        candidatesByKey: new Map(full.candidates.map((c) => [`${c.candidate_type}:${c.normalized_value}`, c])),
        treeBlocksById: new Map(tree.blocks.map((b) => [b.id, b]))
      });
    }

    return {
      ok: true,
      version: SECTION_TREE_SHADOW_VERSION,
      section_tree_version: SECTION_TREE_VERSION,
      membership_preview_version: additive.version,
      has_authoritative_scope: tree.meta.has_authoritative_scope === true,
      inferred_levels: tree.meta.inferred_levels === true,
      additive: additiveCmp,
      full_rezone: fullRezone,
      elapsed_ms: Date.now() - t0,
      // Bounded structural trace — heading texts only, no body content.
      trace: (tree.meta.trace || []).slice(0, 40)
    };
  } catch (err) {
    return {
      ok: false,
      version: SECTION_TREE_SHADOW_VERSION,
      error: String(err?.message || err).slice(0, 240),
      elapsed_ms: Date.now() - t0
    };
  }
}

/**
 * Attach shadow diagnostics onto extraction diagnostics when the feature flag
 * is enabled. Never throws; never alters candidates.
 *
 * @param {object} document
 * @param {object[]} candidates
 * @param {object|null|undefined} diagnostics
 * @param {{ env?: object }} [opts]
 */
export function attachSectionTreeShadowDiagnostics(document, candidates, diagnostics, opts = {}) {
  const out = diagnostics && typeof diagnostics === 'object' ? diagnostics : {};
  let env;
  try {
    env = opts.env || process.env;
    if (!isSectionTreeShadowEnabled(env)) return out;
  } catch (err) {
    // Flag read must never break extraction (e.g. hostile env proxy in tests).
    out.section_tree_shadow = {
      ok: false,
      version: SECTION_TREE_SHADOW_VERSION,
      error: String(err?.message || err).slice(0, 240),
      elapsed_ms: null
    };
    return out;
  }
  try {
    out.section_tree_shadow = evaluateSectionTreeShadow(document, candidates, {
      fullRezone: isSectionTreeFullRezonePreviewEnabled(env)
    });
  } catch (err) {
    // Absolute fail-soft: never let shadow evaluation break extraction/import.
    out.section_tree_shadow = {
      ok: false,
      version: SECTION_TREE_SHADOW_VERSION,
      error: String(err?.message || err).slice(0, 240),
      elapsed_ms: null
    };
  }
  return out;
}

/**
 * Compact form safe for analysis_progress persistence / logs.
 * Omits raw document text; keeps bounded identity diffs.
 */
export function compactSectionTreeShadow(shadow) {
  if (!shadow || typeof shadow !== 'object') return undefined;
  if (shadow.ok !== true) {
    return {
      ok: false,
      version: shadow.version || SECTION_TREE_SHADOW_VERSION,
      error: shadow.error || 'unknown',
      elapsed_ms: shadow.elapsed_ms ?? null
    };
  }
  const trimDiff = (d) =>
    d
      ? {
          deterministic_count: d.deterministic_count,
          tree_count: d.tree_count,
          unchanged_count: d.unchanged_count,
          additions_total: d.additions_total,
          removals_total: d.removals_total,
          equal: d.equal === true,
          additions: (d.additions || []).slice(0, 20).map((a) => ({
            type: a.type,
            value: a.value,
            block_id: a.block_id || null,
            authoritative_zone: a.authoritative_zone || null,
            section_path: (a.section_path || []).slice(0, 6),
            reason: a.reason || null
          })),
          removals: (d.removals || []).slice(0, 20).map((r) => ({
            type: r.type,
            value: r.value,
            reason: r.reason || null
          })),
          additions_truncated: d.additions_truncated === true,
          removals_truncated: d.removals_truncated === true
        }
      : null;
  return {
    ok: true,
    version: shadow.version,
    section_tree_version: shadow.section_tree_version,
    membership_preview_version: shadow.membership_preview_version,
    has_authoritative_scope: shadow.has_authoritative_scope === true,
    inferred_levels: shadow.inferred_levels === true,
    elapsed_ms: shadow.elapsed_ms ?? null,
    additive: trimDiff(shadow.additive),
    full_rezone: shadow.full_rezone ? trimDiff(shadow.full_rezone) : null,
    trace: (shadow.trace || []).slice(0, 20)
  };
}

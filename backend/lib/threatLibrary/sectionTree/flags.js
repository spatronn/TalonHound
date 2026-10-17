/**
 * Feature flags for section-tree shadow evaluation and authoritative engine selection.
 *
 * Shadow (diagnostics) and scope engine (authoritative membership) are independent.
 * Exactly one scope engine determines final Indicator membership.
 */

import { SCOPE_ENGINE_LEGACY, SCOPE_ENGINE_SECTION_TREE } from './version.js';

/**
 * @param {NodeJS.ProcessEnv|Record<string,string|undefined>} [env]
 * @returns {boolean}
 */
export function isSectionTreeShadowEnabled(env = process.env) {
  const raw = String(env.THREAT_LIBRARY_SECTION_TREE_SHADOW || '')
    .trim()
    .toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

/**
 * Optional: also compute a full-rezone preview (more aggressive; diagnostics only).
 * @param {NodeJS.ProcessEnv|Record<string,string|undefined>} [env]
 */
export function isSectionTreeFullRezonePreviewEnabled(env = process.env) {
  const raw = String(env.THREAT_LIBRARY_SECTION_TREE_SHADOW_FULL_REZONE || '')
    .trim()
    .toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

/**
 * Authoritative scope engine selector.
 *
 *   THREAT_LIBRARY_SCOPE_ENGINE=section_tree  → section-tree owns occurrence authority
 *   THREAT_LIBRARY_SCOPE_ENGINE=legacy        → linear documentZones (emergency rollback)
 *   unset / unknown                          → legacy (safe default until explicitly activated)
 *
 * Invalid values throw when `strict` is true; otherwise fall back to legacy.
 *
 * @param {NodeJS.ProcessEnv|Record<string,string|undefined>} [env]
 * @param {{ strict?: boolean }} [opts]
 * @returns {'legacy'|'section_tree'}
 */
export function getScopeEngine(env = process.env, opts = {}) {
  const raw = String(env.THREAT_LIBRARY_SCOPE_ENGINE || '')
    .trim()
    .toLowerCase();
  if (!raw) return SCOPE_ENGINE_LEGACY;
  if (raw === SCOPE_ENGINE_SECTION_TREE || raw === 'section-tree' || raw === 'tree') {
    return SCOPE_ENGINE_SECTION_TREE;
  }
  if (raw === SCOPE_ENGINE_LEGACY || raw === 'linear' || raw === 'zones') {
    return SCOPE_ENGINE_LEGACY;
  }
  if (opts.strict) {
    throw new Error(
      `Invalid THREAT_LIBRARY_SCOPE_ENGINE=${JSON.stringify(raw)}; expected "section_tree" or "legacy"`
    );
  }
  return SCOPE_ENGINE_LEGACY;
}

/**
 * @param {NodeJS.ProcessEnv|Record<string,string|undefined>} [env]
 */
export function isSectionTreeScopeAuthoritative(env = process.env) {
  return getScopeEngine(env) === SCOPE_ENGINE_SECTION_TREE;
}

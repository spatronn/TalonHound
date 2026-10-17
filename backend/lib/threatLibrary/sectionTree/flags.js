/**
 * Feature flags for section-tree shadow evaluation.
 *
 * Default: OFF. Enabling shadow never changes authoritative Indicator membership.
 */

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

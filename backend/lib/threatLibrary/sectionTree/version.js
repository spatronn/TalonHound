/**
 * Section-tree structural scope (authoritative when SCOPE_ENGINE=section_tree).
 */

/** Structural annotation contract (block ancestry / section paths). */
export const SECTION_TREE_VERSION = 'tl-section-tree-v2';

/** Membership-preview / authority remap contract. */
export const SECTION_TREE_MEMBERSHIP_PREVIEW_VERSION = 'tl-section-tree-membership-preview-v2';

/** Shadow comparison contract (diagnostics payload shape). */
export const SECTION_TREE_SHADOW_VERSION = 'tl-section-tree-shadow-v1';

/** Authoritative scope-engine stamp when section-tree owns membership zones. */
export const SECTION_TREE_SCOPE_ENGINE_VERSION = 'tl-scope-engine-section-tree-v1';

export const SCOPE_ENGINE_LEGACY = 'legacy';
export const SCOPE_ENGINE_SECTION_TREE = 'section_tree';

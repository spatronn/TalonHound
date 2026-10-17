/**
 * Section-tree structural scope (production-ready module family).
 *
 * Shadow evaluation may run alongside linear zones; authoritative membership
 * still comes from the deterministic pipeline until an explicit cutover flag
 * is enabled (not in this phase).
 */

/** Structural annotation contract (block ancestry / section paths). */
export const SECTION_TREE_VERSION = 'tl-section-tree-v1';

/** Membership-preview contract (how ancestry maps to Indicator preview). */
export const SECTION_TREE_MEMBERSHIP_PREVIEW_VERSION = 'tl-section-tree-membership-preview-v1';

/** Shadow comparison contract (diagnostics payload shape). */
export const SECTION_TREE_SHADOW_VERSION = 'tl-section-tree-shadow-v1';

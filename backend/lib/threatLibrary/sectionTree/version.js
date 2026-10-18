/**
 * Section-tree structural scope (authoritative when SCOPE_ENGINE=section_tree).
 */

/**
 * Structural annotation contract (block ancestry / section paths).
 * v3: every real formal IOC section empty (pointer-only, "available for
 * download here") → body blocks join the delegated scope (`delegated_ioc_scope`).
 * v4: a qualified inventory heading ("Observations") is an IOC section only
 * when a declared-type IOC table leads its content (shared with tl-zones-v14).
 * External IOC dataset pointers under an empty formal section set
 * `external_ioc_pointer` and suppress delegated body authority (the linked
 * IOC Source path owns the pack).
 */
export const SECTION_TREE_VERSION = 'tl-section-tree-v4';

/** Membership-preview / authority remap contract. */
export const SECTION_TREE_MEMBERSHIP_PREVIEW_VERSION = 'tl-section-tree-membership-preview-v2';

/** Shadow comparison contract (diagnostics payload shape). */
export const SECTION_TREE_SHADOW_VERSION = 'tl-section-tree-shadow-v1';

/**
 * Authoritative scope-engine stamp when section-tree owns membership zones.
 * v2: delegated scope asserts only publisher-typed inventory rows (network /
 * hash / indicator-typed table columns, endpoints, value lines) and
 * operational / sample statements; free-form table cells assert nothing there.
 */
export const SECTION_TREE_SCOPE_ENGINE_VERSION = 'tl-scope-engine-section-tree-v2';

export const SCOPE_ENGINE_LEGACY = 'legacy';
export const SCOPE_ENGINE_SECTION_TREE = 'section_tree';

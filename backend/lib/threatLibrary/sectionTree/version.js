/**
 * Section-tree structural scope (authoritative when SCOPE_ENGINE=section_tree).
 */

/**
 * Structural annotation contract (block ancestry / section paths).
 * v3: every real formal IOC section empty (pointer-only, "available for
 * download here") → body blocks join the delegated scope (`delegated_ioc_scope`).
 * v4: a qualified inventory heading ("Observations") is an IOC section only
 * when a declared-type IOC table leads its content (shared with tl-zones-v14).
 * v5: a C2 / operational heading opens authority only over an IOC table (an
 * indicator column of observables), list rows or value lines — never over a
 * descriptive table ("Endpoint | Method | Description"); prose that names
 * services only to call them legitimate / unblockable is not inventory, so it
 * no longer vetoes the delegated scope.
 * External IOC dataset pointers under an empty formal section set
 * `external_ioc_pointer` and suppress delegated body authority (the linked
 * IOC Source path owns the pack). Pointer detection uses the shared
 * externalIocReference scorer over visible URLs and structured block.links
 * (htmlBlocks v7 destination-only href anchors).
 */
export const SECTION_TREE_VERSION = 'tl-section-tree-v5';

/** Membership-preview / authority remap contract. */
export const SECTION_TREE_MEMBERSHIP_PREVIEW_VERSION = 'tl-section-tree-membership-preview-v2';

/** Shadow comparison contract (diagnostics payload shape). */
export const SECTION_TREE_SHADOW_VERSION = 'tl-section-tree-shadow-v1';

/**
 * Authoritative scope-engine stamp when section-tree owns membership zones.
 * v2: delegated scope asserts only publisher-typed inventory rows (network /
 * hash / indicator-typed table columns, endpoints, value lines) and
 * operational / sample statements; free-form table cells assert nothing there.
 * v3: a key-value row whose label cell names the value's own type
 * ("SHA256 | <hex>", "C2 | <host>") is a typed row there, unless the table
 * calls the described file / host legitimate.
 */
export const SECTION_TREE_SCOPE_ENGINE_VERSION = 'tl-scope-engine-section-tree-v3';

export const SCOPE_ENGINE_LEGACY = 'legacy';
export const SCOPE_ENGINE_SECTION_TREE = 'section_tree';

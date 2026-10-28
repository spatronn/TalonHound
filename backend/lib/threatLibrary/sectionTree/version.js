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
 * v6 (31-report audit): a paragraph label that IS a formal IOC-section title
 * ("Indicators of Compromise (IoCs)") on a template without heading elements,
 * followed by a real inventory, establishes MODE A like a heading.
 * v7 (22-report adjudication): a real heading whose own lead-in paragraph
 * declares that this / the following section adds, lists or contains
 * indicators opens publisher indicator scope with delegated-authority reading
 * (operational clauses, sample statements, endpoints and rows assert; passing
 * mentions do not).
 * v8 (30-report audit): a heading whose first content blocks caption an
 * actor-attributed hash inventory ("Table 3. Files Used by <X> Ransomware
 * Actors (SHA-256)" over a File Name | Hash table) declares indicator scope
 * the same way; a caption that calls the files legitimate / dual-use does not.
 * v9 (24-report audit): an IOC heading whose own section is only lead-in
 * prose continues into the same-level indicator-class siblings that follow it
 * ("## Indicators of Compromise" → "## Network", "## File hashes"); the first
 * other heading closes it. Qualified IOC headings include inventory-grade
 * qualifiers ("Primary IOCs").
 * v10 (27-report audit): an IOC heading whose inventory is already grouped
 * into deeper indicator-class children ("## IoCs" › "### Files") continues
 * into a same-level indicator-class sibling over an inventory ("## Network").
 */
export const SECTION_TREE_VERSION = 'tl-section-tree-v10';

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

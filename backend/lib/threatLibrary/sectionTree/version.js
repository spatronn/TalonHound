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
 * v11 (42-report audit): an indicator-class label may carry a qualifier
 * ("Observed C2 IPs", "Representative observed domains"), and that sibling's
 * inventory may sit under its own deeper group headings
 * ("### Representative observed domains" › "#### Wave 1 domains" › table).
 * v12 (52-report audit): an "Acknowledgments" heading closes IOC scope like
 * "References" (citation links under an IOC table), and "Reference IoCs"
 * heads an indicator list rather than a bibliography.
 * v13 (52-report audit, 35552): under PDF inferred levels an appendix whose
 * children read shallower than the IOC heading ("Domains" / "Hashes" at 3,
 * "INDICATORS OF COMPROMISE" at 4) stays open for indicator-class labels and,
 * after one, short family labels over a strong inventory; runs of
 * "<digest> (<label>)" are inventory rows; a page-break label tail
 * ("replaced 0528))") is never a heading.
 * v14 (hunt.io Need-Review FNs): a heading that leads with a closed pair of
 * inventory terms ("IOCs and Observables", "IOCs and network observables")
 * declares an IOC inventory, so the infrastructure-lookup table under it is
 * in scope.
 * v15 (70-report audit 35700–35769): a short same-level sibling of an open IOC
 * heading that ends with an indicator class ("<Family> infrastructure") and
 * holds an inventory continues it; "Suspected source / scan-node
 * infrastructure" and "… source IPs" headings title the publisher's address
 * inventory.
 * v17 (review queue 35800–35819): that sibling may carry a scope qualifier
 * and a trailing colon ("<Family> hashes for one 24-hour period:"), may be a
 * "URI Locations:" list, and may hold its rows under deeper sub-headings.
 * v18 (review queue 35858–35869): an appendix titled by an operator-owned
 * resource ("Appendix E: Attacker Management Repository") is an IOC appendix;
 * one that calls the services legitimate or names victims stays narrative.
 * v19 (Qwen-evaluation follow-up, 35446 / 35458): an appendix titled by an
 * observable type opens an IOC scope only with a value-row body and a
 * publisher sentence elsewhere that calls it indicators / C2; a name-prefixed
 * IOC title ("Cluster ClickFix IoCs & Technical details") is an IOC heading;
 * a lead-in-only IOC heading (an external-list pointer included) continues
 * into same-level inventory-dominant siblings, past labels nested in the
 * previous sibling.
 */
export const SECTION_TREE_VERSION = 'tl-section-tree-v19';

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

export const SCOPE_ENGINE_SECTION_TREE = 'section_tree';

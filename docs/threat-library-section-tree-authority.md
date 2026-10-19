# Section-tree authoritative scope engine

## Engine selector

| Env | Default | Effect |
|---|---|---|
| `THREAT_LIBRARY_SCOPE_ENGINE=legacy` | emergency rollback | Linear `annotateDocumentZones` owns occurrence authority |
| `THREAT_LIBRARY_SCOPE_ENGINE=section_tree` | **production default** (compose default since tl-scope-engine-section-tree-v2) | Heading-ancestry remaps occurrence zones; evidence policy re-runs |

Exactly one engine determines final Indicator membership. Shadow diagnostics (`THREAT_LIBRARY_SECTION_TREE_SHADOW`) remain independent and never override the selector. Invalid values fail extraction (`strict`) rather than silently changing membership.

Compose wires the flag to both `backend` and `threat-library-worker`.

## Rollback

1. Set `THREAT_LIBRARY_SCOPE_ENGINE=legacy` in `/opt/TalonHound/.env`
2. `docker compose up -d --no-deps --force-recreate backend threat-library-worker`
3. Verify both containers: `printenv THREAT_LIBRARY_SCOPE_ENGINE` → `legacy`

Do not automatically reprocess historical reports when switching engines.

## Offline compare

```bash
docker compose exec -T backend node scripts/section-tree-authority-compare.js --fixtures
docker compose exec -T backend node scripts/section-tree-authority-compare.js --db-export /app/tmp/st-corpus-export
```

## Provenance

Candidates and diagnostics stamp:

- `scope_engine` / `scope_engine_version` (`tl-scope-engine-section-tree-v3`)
- `section_tree_version` (`tl-section-tree-v6`)

## Architecture

```
Publisher document → Canonical document
  → Section-tree construction (heading ancestry)
  → applySectionTreeAuthority (sole zone authority when selected)
  → Deterministic observable extraction (already run) + evidence policy recompute
  → MODE A / MODE B membership
  → Candidate persistence → Analyst review
```

Legacy linear zones remain available as the `legacy` engine and still participate in typing/table/quality paths before authority remap.

## Empty formal IOC sections (delegated scope, tl-section-tree-v3)

Some publishers keep an "Indicators of compromise" heading whose only content is a pointer to an
external release ("These indicators are also available for download here."). Treating that heading
as the whole curated inventory made every body assertion a narrative non-member (0 Indicators).

When **every** real formal IOC / C2 / sample heading of a document holds no observable inventory
(`hasObservableInventory`: no observable, or a single pointer sentence), the document stays MODE A
(an assertion is required) and its body blocks join the `delegated_ioc_scope` zone:

| Occurrence in the delegated scope | Asserted? |
|---|---|
| ip:port endpoint | yes |
| observable-only list / value line | yes |
| cell of a column the publisher typed as network / hash / indicator values ("Domain / IP", "Key infrastructure", "URL", "SHA256") | yes |
| key-value row whose label cell names the value's own type ("SHA256 \| <hex>", "C2 \| <host>"), unless the table calls the file / host legitimate (scope-engine v3) | yes |
| free-form table cell ("Value", "Variable-name", "Name") | no |
| operational clause ("downloads the installer from X", "communicates with the C2 endpoint X", "the threat actor pasted a URL into the chat: X") | yes |
| lookalike / impersonation role governing the value ("the lookalike domain, X", "X … and other lookalike domains") — never the imitated brand | yes |
| hash named as the analysed artifact ("we examine the following script: H", "Wave A. H …", "a ZIP archive named X.zip (SHA-256: H)", "the JAR file …") | yes |
| neutral mention, provider platform ("abuse of the public X service"), legitimate / dual-use stance ("the legitimate Oracle-signed runtime (SHA-256: H), all malicious logic is in the JAR") | no |

Reference sections, chrome and code blocks never join the delegated scope; a non-empty IOC section
anywhere in the document disables delegation (normal MODE A). Quality check 13
(`delegated_authority_applied`, warning) lists the delegated Indicators for review. Attach the
publisher's external IOC file as a linked IOC Source when it is available.

What counts as "non-empty" (tl-section-tree-v5):

- A C2 / operational topic heading opens authority only over publisher inventory: an IOC table (an
  indicator column whose cells parse as observables, `interpretIocTable` kind `ioc_table`), list
  rows or value lines. A descriptive table under it ("Endpoint | Method | Description",
  "Channel | Authentication | Normal Poll") is technical content: it neither opens C2 authority nor
  makes the topic an inventory that vetoes delegation.
- Prose that names services only to say they are legitimate or cannot be blocked ("Blocking
  docs.example or api.example is not viable") is not inventory.
- A "Contact" heading is a reference block only as a whole contact block ("Contact", "Contact us",
  "Contact information"); a topic such as "Contact Form Engagement" is narrative and joins the
  delegated scope (tl-zones-v15).
- Unchanged (policy D.3): a nested body C2 subsection that does hold an indicator line ("3.3.4 C2
  Beaconing" with the beacon URL) still disables delegation for the whole document.

Values that never become hosts in any scope: a hostname tail after `-` or a redaction placeholder
(`<REDACTED>-my.sharepoint.com` → no `my.sharepoint.com`), and managed-runtime namespaces
(`javax.tools`, `java.net.*`, `System.Net.*`; tl-type-resolver-v12).

## Paragraph-label IOC appendices (tl-section-tree-v6)

Some templates render every section title as a paragraph (no heading elements).
A paragraph label whose whole text is a formal IOC-section title ("Indicators of
Compromise (IoCs)", "IOCs") followed by a real inventory within the next blocks
is the publisher's IOC appendix and establishes MODE A like a heading. Any other
synthetic label never invents MODE A. Quality (`tl-quality-v9`) reports the MODE
the section tree decided — the one membership uses — so the UI / MCP mode and the
candidate rows always agree.

## Publisher stances that cover a row, a list or the report (tl-candidates-v33)

- A table row stating outright that its subject is "not malicious" covers every
  value of the row (MD5 / SHA1 / SHA256 of one file), not only the adjacent cell.
- A sub-heading naming its values legitimate ("Hashes of X (the legitimate
  software used to distribute Y)") covers the value lines under it.
- A list lead-in naming certificate fingerprints / thumbprints decides the
  digest kind of its unlabelled items (non-file digests, never sample hashes).
- A numbered footnote line holding only a live link ("1 https://…") after an
  IOC table is a citation.
- A report-level disclaimer ("… should not be treated as standalone malicious
  indicators") is a document stance: values the publisher does not separately
  assert are Context Only, in MODE B too. A model escalation of a network
  observable needs a publisher assertion (threat vocabulary in the sentence that
  names it, tl-evidence-integrity-v2), never a mere mention.

## Role-labelled lists in IOC sections (tl-candidates-v32)

Inside a curated or delegated IOC scope, a list the publisher labels by the operator's role
("Specific operator-side IPs observed: X (…) and Y (…)", "Attacker domains: X, Y") asserts every
listed value, including the coordinated ones. A legitimate / victim label ("Legitimate Microsoft IPs
observed:", "Victim IPs observed:") asserts nothing.

## Publisher evidence integrity (tl-evidence-integrity-v1)

The deterministic anchor (`evidence_text` + `block_id`) is the publisher evidence and is also stored
as `evidence.publisher_evidence`. A model quote replaces it only when it occurs verbatim (refanged,
quote marks ignored) in a canonical block that names the value; otherwise it is kept as
`evidence.ai_evidence_rejected`. A model malicious / suspicious label is applied only when it is
uncited or cites real publisher text naming the value; `evidence.ai_classification` records what the
model said, whether publisher text supports it and whether it was applied. A publisher legitimate /
dual-use / "not inherently malicious" stance wins over model labels unless another occurrence
asserts the value; that conflict is recorded (`stance_conflict`, quality check 15).

## Qualified inventory headings (tl-section-tree-v4 / tl-zones-v14)

Some vendor templates title their IOC table "Observations" (an `Observable | Type | Name |
Reference` table), others use the same word for a narrative findings section. A qualified inventory
heading ("Observations", "Key observations") opens an IOC section only when the first table of its
section, before the next heading, is a self-proving IOC table: an indicator column plus a declared
observable-type column (`interpretIocTable` `explicit` with `declared_type_column`). Prose, a
descriptive table or a value table without a type column leaves it narrative, so the heading alone
never sets MODE A. Both engines share the check (`confirmedQualifiedIocHeading`).

Inside such a table, a row whose own descriptor cells name the value a category-qualified provider
("Blockchain provider", "DNS resolver") or an explicitly public / legitimate / third-party service is
a provider relation and asserts nothing; a C2, staging, operational, lookalike or weaponized role
keeps the row assertion. A list whose lead-in object phrase names the listed values as providers /
explorers / resolvers ("… through three Blockscout providers:") carries the same stance.

## Linked-source counts (MCP parity)

Linked IOC Source provenance lives in `threat_report_candidate_source_links`. The SQL buckets
(`linkedSourceIndicatorMembershipSql`: type gates + a link row) and the JS buckets
(`countCandidateBuckets`) agree only when the candidate rows carry that provenance. The report
detail API attaches it as `sources`; MCP `get_threat_report` attaches it as
`has_linked_source_occurrence` (`loadReportLinkedSourceCandidateIds`, one query). `counts.indicators`
stays the original-document set; `linked_only` / `total_unique` include linked-file values.

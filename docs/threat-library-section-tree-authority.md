# Section graph: the single structural authority

`annotateSectionTree` builds the section graph of a document. It is the only structural decision in the
pipeline: `annotateDocumentZones` reads its zones from the graph, and candidate extraction, table semantics,
AI block selection, relationship policy, publication date and extraction quality all consume that reading.
There is no engine switch, no fallback engine and no shadow evaluation.

## Pipeline

```
Publisher document -> Canonical document
  -> Section graph (heading ancestry, section authority)
  -> Candidate extraction (traversal, type resolution, evidence construction)
  -> applySectionTreeAuthority (one pass inside extraction)
  -> Evidence policy -> decideMembership (one outcome per candidate)
  -> Candidate persistence and extraction ledger -> Analyst review
```

## Modules

| Module | Responsibility |
|---|---|
| `sectionTree/annotate.js` | Section graph, heading classification, zones |
| `sectionTree/authority.js` | Per-occurrence section authority |
| `documentZones.js` | Zone reading of the graph for consumers |
| `candidateExtraction.js` | Orchestration, post-resolution, diagnostics |
| `candidateTablePass.js` | Typed indicator tables |
| `candidateTextPass.js` | URLs and free-text observable shapes |
| `candidateAccumulator.js` | Identity map; the one place a token becomes a candidate |
| `candidateHelpers.js` | Token patterns and small readers |
| `evidencePolicy.js`, `membershipDecision.js` | Assertion and role, then the membership outcome |

## Rollback

Roll back by deploying the previous image. Stored reports do not change when the code does: a report's
candidates change only on an explicit refresh.

## Provenance

Candidates and diagnostics stamp `scope_engine`, `scope_engine_version` and `section_tree_version`. The
extraction ledger records the whole contract bundle per run.

## Where authority ends (tl-section-tree-v16)

A heading or label under an open appendix keeps its authority only when it is an inventory group:
it holds rows, has deeper groups with rows, or is a real heading naming an indicator class. Otherwise
its own content is not asserted, and a later sibling group is asserted again. Headings naming advice
or page furniture ("About the Author", "Recommendations", "Legitimate files …") never inherit, whatever
follows them. A short line holding a field or a value ("Description: …", an IPv6 row) stays a row.

Plain PDFs set headings in the body font: a whole line that is a formal section title, standing between
sentences, becomes a heading (`isFormalSectionTitleLine`, threat_library_pdf_v7).

## Membership without a curated section (tl-membership-decision-v3)

Structured rows remain the publisher's inventory (R30). A prose statement goes to review (R31), and so
does one a model calls malicious (R32): the analyst sees the model's opinion and approves through the
audited path. "Grounded" means the publisher's text names the value near threat wording, which is equally
true of a legitimate service the operators abused. On stored verdicts, 36 rows on 17 of 690 reports would
have reached R32, and analysts rejected 7 of them, including `file.io`, `paste.sh` and `api.ipbase.com`.
A prose sample hash stays a member (R34), with or without a model verdict.

## Known limitations

- Documentation-range addresses (192.0.2.0/24 and similar) listed in an IOC section are still read as
  asserted. None occur in the 690 stored reports. Bare `example.com` / `.org` / `.net` are placeholders;
  subdomains of them are not treated so.
- A title-cased TLD is read as a domain only when the clause names domains or the block lists several.

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
never sets MODE A. The check is `confirmedQualifiedIocHeading`.

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

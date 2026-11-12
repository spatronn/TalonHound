/**
 * Deterministic IOC / identifier candidate extraction from canonical documents.
 *
 * Model: a candidate is an observable identity (type + normalized value) that
 * aggregates source OCCURRENCES. Every occurrence points at a real text span in
 * a canonical block. Parser-derived facts about a value (the host of a URL, the
 * port of an IP:port endpoint) are kept as `parsed` metadata on that candidate
 * and never become occurrences of another candidate. A standalone host
 * candidate therefore only exists when the report itself mentions the host
 * outside URL syntax (independent evidence).
 *
 * Typed indicator tables (canonical `table` blocks interpreted by
 * tableSemantics) are extracted row by row: the indicator cell is the
 * assertion, the declared-type cell is a typing hint, the description cell is
 * provenance. A value that appears only inside a description cell is related
 * context of that row, never a standalone candidate (same rule as URL hosts).
 */

export { normalizeCandidateValue } from './candidateValue.js';
export {
  candidateHasStandaloneOccurrence,
  isOnlyEmbeddedInDnsHostname,
  isStandaloneObservableSpan
} from './sourceOccurrence.js';

/**
 * Bump when derivation / evidence semantics change. Older candidate sets are
 * rebuilt from the canonical document on the next analysis run.
 * v5: source-scope promotion (authoritative indicator sections vs narrative
 * context), provider/service relation, CIDR as a first-class candidate type.
 * v6: central observable-type resolver — dotted technical identifiers
 * (mutex / class / config keys) and relative paths / routes are never domain /
 * URL candidates; they are retained as non-IOC `technical_artifact` /
 * `relative_path` / `file_path` context with an explainable `type_resolution`
 * record; canonical-shape gate on every network candidate; declared-type
 * sub-headings ("Domain", "IP Addresses") continue an open IOC section.
 * v7: section scope model — descriptive indicator headings open a confirmed
 * authoritative section, sub-labelled short groups inherit it, and every
 * occurrence carries a structural kind (row vs narrative) + relation marker so
 * zone membership alone never asserts maliciousness; scheme-less host/path
 * resources are one URL occurrence (exact source spelling, no invented scheme,
 * path preserved, host as parsed metadata).
 * v8: IPv4 / IPv6 token boundaries — a numeric DNS prefix such as
 * `128.200.178.68.host.example.com` is not a standalone IP; acceptance
 * requires a source span that is not a subspan of a larger hostname.
 * v9: defanged Domain table spellings (`host[.]tld`) are refanged before the
 * hostname-syntax gate so typed indicator rows survive as domain candidates.
 * v10: filesystem path segments and deployable / server-page extensions (war,
 * ear, jspx, …) resolve as technical artifacts; a value typed as an artifact by
 * a table row joins the document-level vote, so body mentions never split it
 * into a separate domain; a declared Domain row is never outvoted.
 * v11: completeness hardening — <br> lines are rows (threat_library_html_v3);
 * multi-value indicator cells verify a table column; nested, arbitrarily
 * labelled sub-headings stay inside an open IOC section when indicator rows
 * follow (tl-zones-v3); scheme-less URL rows are indicator rows; a file name
 * annotation keeps a hash line a row; undelegated suffixes (`Minting.chm`) are
 * weak, never domains by shape alone; the domain of an email address is never
 * a row; prose sample hashes with no decisive relation reach the model instead
 * of the curated-scope context rule; request / fetch URLs are operational (a
 * defanged URL is located in its own clause); benign-component mentions are
 * deterministic context; hosted objects are never the hosting provider;
 * structural completeness diagnostics.
 * v12: a hash-shaped run inside a URL / scheme-less resource span is a URL
 * component, not a file-hash occurrence (per occurrence: a standalone spelling
 * of the same value still creates the hash, its window anchored on it).
 * v13: no non-declared identity in a curated report — a hex run joined to a
 * hostname label by "-" (`pub-<hex>.cdn.dev`) is not a hash; typographic
 * quotes close a URL token; an elided value (`[…]`) is not a URL
 * (tl-type-resolver-v4); a scheme-less "host/path" joins the one absolute URL
 * the report lists for it; prose-only C2 topics and vendor sidebars no longer
 * open / resume a curated section (tl-zones-v4).
 * v14: dotted-token typing reads the focused indicator row the same way the
 * occurrence layer does (row_shape), so a <br>-split IOC line is an explicit
 * indicator row (tl-type-resolver-v5); a domain reading of the publisher's own
 * row for a token is never outvoted by narrative code-shaped mentions of it.
 * v15: `<pre>` / fenced-code publisher IOC lines keep their per-line row
 * structure (threat_library_html_v4); reserved / loopback identities never
 * become actionable report Indicators even when publisher-asserted.
 * v16: credential / token / password labels demote hex runs (not file hashes);
 * config-file suffixes such as `.conf` stay technical artifacts (resolver v6).
 * v17: PDF layout v4 (true glyph height, table row pitch, gutter splits) and
 * table v4 (labelled hash cells, file-name columns) rebuild curated PDF
 * appendices as tables; RFC 8552 `_service` DNS labels stay domains (resolver v7).
 * v18: an IPv4-shaped release number found only in a table's software-version
 * column ("Versions Affected": 2.3.20.2) is version metadata, never an IP (tl-table-v5).
 * v19: the same in prose when the clause marks a release ("Apache Struts
 * 2.3.24.1", "versions prior to 2.3.20.2", "Version=4.0.0.0"); a network cue at
 * the token ("C2 IP 2.3.24.1") keeps the address (ipv4VersionContext.js).
 * v20: an indicator table row keeps the publisher's whole row as evidence
 * (every cell, column order, labels) instead of only the widest unlabelled
 * column, and records the row's publisher observation dates as structured
 * `observation` / candidate `source_observation` (sourceObservation.js).
 * Membership, typing and assessment are unchanged: classification still reads
 * the asserted cells only.
 * v21: a value with no letter or digit (a lone "/" separator in a cell such as
 * "T1497.001 / T1497.003", "./", "--") is never an observable: it is no longer
 * typed as a relative path / Context Only candidate (candidateValue.js).
 * v22: a C2 / operational topic heading is confirmed as an authoritative
 * section only by publisher indicator content in its subtree (an indicator
 * row or an IOC table), never by a code listing, HTTP request example or
 * descriptive table (tl-zones-v5). Prose under such a technical-analysis
 * heading ("validates access through a GET request to <url>") is narrative,
 * so it no longer becomes an asserted narrative_assertion / explicit_c2.
 * v23: topic-label confirmation also applies to synthetic/bold C2 headings
 * (tl-zones-v6); sibling artifact type-labels such as "Receiving a command"
 * terminate the previous authoritative scope instead of continuing it.
 * v24: post-IOC article tag lists close authoritative scope (tl-zones-v7);
 * filename-shaped dotted tokens (`Node.js`) are not indicator lines and a
 * heading-inherited Domains label cannot outvote FILE_EXT / non-delegated
 * suffix readings across occurrences (tl-type-resolver-v8).
 * v25: Filename|MD5 (file-name + hash) component inventories outside curated
 * IOC / C2 / sample headings are not self-proving structural IOC tables
 * (tl-table-v6). MODE A membership keeps formal IOC-appendix hashes and
 * domains without promoting legitimate host-binary hashes from analysis tables.
 * v26: nested HTML headings inside list items keep heading semantics
 * (threat_library_html_v5); filename-first annotated rows continue appendix
 * scope (tl-zones-v10); body Domain/IP/MD5 tables and legitimate-service
 * lists no longer self-prove without type column / authoritative caption /
 * headed scope (tl-table-v7); PDF headings carry inferred levels and
 * filename/hash lines stay as rows (threat_library_pdf_v5).
 * v27: publisher-host family + reporting-contact relation demote advisory
 * chrome; incomplete URL path prefixes that are strict prefixes of sibling
 * URL Indicators are excluded (tl-candidates-v27).
 * v28: a group sub-label over a publisher IOC table keeps appendix scope when
 * heading levels are equal or unknown, and pure filename/hash inventories
 * whose row boundaries were lost read as rows (tl-zones-v11); dense multi-pair
 * PDF inventory lines stay rows (threat_library_pdf_v6).
 * v29 (six-report audit): a mixed indicator cell ("C:\…\x.dll SHA256: <h>",
 * "x.dll (SHA-256 <h>)") keeps its file identity as context and recovers the
 * hash(es) it carries, linked as cell companions (tl-table-v8); certificate /
 * fuzzy-hash attribute columns are never indicator columns (tl-table-v8); a
 * publisher row that calls its value a legitimate / benign component is
 * reference context, not a row assertion; a weak-suffix dotted token on a
 * prose-led short line in a curated zone is not promoted to a domain
 * (tl-type-resolver-v9).
 * v30 (nine-report audit): hex values the publisher labels as non-file digests
 * (ELF build-id, certificate thumbprint / fingerprint, vhash / imphash / ssdeep,
 * cryptographic keys) or digests of trivial inputs (sha256("123456")) are
 * technical artifacts, never file-hash Indicators (digestSemantics.js);
 * `host:port` carries its port; a URL literal stops at a `${` template
 * interpolation (tl-type-resolver-v10); table rows record their own column
 * header (delegated-scope authority).
 * v31 (ten-report audit): markdown-escaped bracket defang (`host\[.\]tld`,
 * `hxxps\[:\]//`) refangs like `[.]`; a table row labelled only by its digest
 * algorithm ("SHA-256") takes the subject from the table caption / heading
 * ("Custom certificate …"); a "Serial" (number) row is a certificate
 * identifier and a bare "key" label a cryptographic key, never file hashes;
 * numbered citation entries and the publisher's own tooling links are
 * references; a typed row / list lead-in naming its value a provider or
 * service, or prose naming the service whose traffic is intercepted, is a
 * provider relation (tl-type-resolver-v11, tl-zones-v14, tl-section-tree-v4).
 * v32 (twelve-report audit): a descriptive table never opens C2 authority and
 * provider-stance prose is not inventory, so a pointer-only IOC section
 * delegates (tl-section-tree-v5); a role-labelled list in an IOC section
 * ("operator-side IPs observed: X and Y") and a lookalike / impersonation role
 * governing the value are assertions; a legitimate stance survives a clause
 * that places the malice in another component; "ZIP archive" / "JAR file"
 * name the analysed sample; camelCase digest keys (`accessTokenHash`) read as
 * words; "Contact Form …" is no longer a reference heading (tl-zones-v15);
 * managed-runtime namespaces (`javax.tools`) are code (tl-type-resolver-v12);
 * a hostname tail after "-" or a redaction placeholder is never derived; a
 * key-value "SHA256 | <hex>" row declares its type in the delegated scope
 * (tl-scope-engine-section-tree-v3).
 * v33 (31-report audit): a declared hash column types only exact digests
 * (an IP / label under "SHA256" falls back to its own syntax); stacked
 * sub-tables (a mid-table "IP Address | Notes" header row) re-declare the
 * column types; spaced / mixed-bracket defang ("x [.]com", "ssd[.}png")
 * refangs and unresolved residue is rejected; a list lead-in names the
 * digest kind of its items (certificate fingerprints); a row stating "not
 * malicious" and a legitimate-stance sub-heading cover every value of the
 * row / list; a numbered footnote link is a citation; a report-level
 * publisher disclaimer ("should not be treated as … indicators") is a
 * document stance; a "no longer infected" remark is a remediated stance.
 * v34: an origin URL (pathname "/") with a longer same-origin sibling is an
 * incomplete prefix unless the publisher also listed that origin in an
 * explicit IOC inventory — path IOCs never authorize a broader root alone.
 * v35: URL boundaries are parenthesis-balanced (a "(?…)" optional-part note
 * and an escaped closing quote are not URL text); a hash-shaped value whose
 * own type label names a mutex is a mutex artifact, never a file hash; an
 * absolute URL glued into code inside a typed IOC-table cell is that row's
 * observable (tableSemantics); "label: ftp://host" rows assert the host.
 * v36: membership follows tl-section-tree-v7 — a section whose lead-in
 * declares it adds / lists indicators is publisher indicator scope.
 * v37 (30-report audit): recoverable URL forms ("http//host", a URL wrapped
 * onto two lines of one cell / row, transport endpoints "tcp://host:443" whose
 * host is the value); a directory URL listed as its own explicit IOC row is
 * not an incomplete prefix; an email local part is never a domain; table
 * description cells keep their observables (Context Only unless the value's
 * own clause gives it an actor-infrastructure role in an explicit IOC table);
 * table reference columns are Context Only; a row description that says what
 * a digest is of governs its file-hash reading (tl-section-tree-v8,
 * tl-table-v9, tl-evidence-integrity-v3).
 * v38 (20-report audit): IPv6 tokens are hex/colon runs validated by
 * `net.isIPv6` (tl-ipv6-tokens-v1) — mid-address `::`, trailing `::` and
 * IPv4-mapped forms are addresses, invalid runs yield nothing (never a valid
 * fragment); a bare IPv6 table cell is an IP, not a hostname; a defanged
 * mixed-case hostname (`EmbersAndBites[.]com`) keeps the domain reading
 * (tl-type-resolver-v16).
 * v39: filename-column consistency (tl-table-v11) demotes only ambiguous
 * file/TLD collisions or rows with explicit file evidence — a publisher-
 * asserted domain in a mixed Item|Description IOC table is never rewritten
 * to a technical artifact merely because sibling cells are filenames.
 * v41 (20-report audit 33356–33375): an IPv6 address with a glued prefix
 * length (`2607:99c0::/32`) is a CIDR, not the bare network address; a bare
 * digest list item takes its subject from the heading above it when there is
 * no lead-in ("SSL Thumbprint"); a table digest cell is labelled by its column
 * header ("Imphash"); a community / open-source resource recommended to
 * defenders is a reference; `host:port` followed by another value of the same
 * cell stays an endpoint (tl-type-resolver-v18).
 * v42 (35-report audit): `hxxp[:]host` without authority slashes refangs
 * (tl-defang-v4); OpenTip/VT path basenames do not demote publisher IOC
 * domains (tl-type-resolver-v19); an origin URL listed under a C2 / sample /
 * operational inventory zone keeps Indicator membership when path siblings
 * exist (same inventory rule as explicit_ioc_section); a block whose visible
 * text glues a one-letter conjunction onto a defanged link ("znews[.]neti"
 * from "znews[.]net" + "i") recovers the structured link text.
 * v43 (27-report audit): a table nested inside a heading element keeps its
 * rows (threat_library_html_v9); an IOC heading grouped into indicator-class
 * children continues into a same-level indicator-class sibling
 * (tl-section-tree-v10); a scheme-less IPv4-host URL with a non-digit path
 * ("91.92.242[.]30/lamq4") is a URL; a list lead-in naming the values as
 * service "instances" is a provider stance; a type cell naming request
 * content ("POST body", "User-Agent") asserts no indicator (tl-table-v13).
 * v44 (32-report audit): a scheme whose bracket splits the authority marker
 * ("http[:/]/host") refangs (tl-defang-v5); a typed IOC-table row whose
 * provider noun is qualified by the operation its sibling rows attribute
 * infrastructure to ("CaptiveCrunch DNS Resolver") or that carries a bare
 * "C2" role label stays an assertion; a structural row naming the value as
 * the resolver used "for domain resolution" is a provider relation.
 * v45 (32-report coverage audit): a shell separator glued to a URL on a command
 * line ("…/kw2-s11;chmod", "…/d&pushd") ends the URL; an escaped-slash scheme
 * ("hXXps:\/\/host/x") refangs (tl-defang-v6); a table-listed URL carrying a
 * glued YubiKey OTP resolves to the corroborated URL of the same document; an
 * analyst may confirm a MODE A narrative value the publisher did not describe
 * as benign / provider / reference (promote_to_ioc, membership by
 * evidence.promoted_from).
 * v46 (19-report audit): `fqdn://host` IOC-table rows stay domains; a
 * `[redacted]` / `[xxx]` tail glued to a hostname is not that hostname; every
 * digest of one legitimate-file row shares the description.
 * v47 (19-report audit): a table-row occurrence keeps the row text (capped at
 * 500) as its scope window. A 140-character focus window ended before
 * "Legitimate binary" when a long filename sat between the earlier digests
 * and the description, so those digests stayed Indicators.
 * v48 (42-report audit): tl-section-tree-v11 / tl-table-v14 (qualified
 * indicator-class sibling groups, bullet / backtick cells, category cells keep
 * the column's declared network type); the operation-owned provider row check
 * reads the publisher grid row (a promoted header row shifted it by one);
 * "DKIM-signed by the operator" is no signed-component stance; a genuine tool
 * named as fetched from a value ("the legitimate <tool> from <URL>") makes
 * that value a benign source.
 * v49 (52-report audit): tl-section-tree-v12 / tl-table-v15 / tl-type-resolver-v21
 * (Acknowledgments closes IOC scope, "Reference IoCs" is an IOC heading, glued
 * cell values split, description-labeled digests, POST-body description rows,
 * redacted "/XXXXX" path segments); a host in parentheses after an address
 * ("1.2.3.0 (Railway.com)") and a value listed among "trusted services like"
 * are providers; "suspicious" negates a signed-component stance.
 * v50 (52-report audit): prose / plain-text domains are typed from the
 * publisher's spelling, so a defanged mixed-case host
 * ("txjIQslrRIg[.]MSwINSOFTUPDLoaD[.]DesiGN") stays a domain (the
 * tl-type-resolver-v16 defang rule) instead of a code identifier.
 * v51 (52-report audit, 35552 / 35573): a block that is only observables (a
 * plain-text pack whose lines were joined) also types from that spelling; in a
 * run of "<digest> (<label>)" rows each digest is classified by its own
 * trailing label ("<sha256> (Ligolo TLS certificate)" is a certificate
 * fingerprint, the next row's agent hash is not).
 * v52 (29-report audit 35575–35605): tl-table-v16 / tl-type-resolver-v22.
 * A table under a "Legitimate File Hashes" heading is a benign inventory; an
 * "AS<n> (host)" annotation names the ASN operator; rows saying "do not
 * block", "placeholder name", "not itself malicious", "abused legitimate
 * infrastructure" or "not operator-specific" are context; "public IP
 * address identification services:" introduces IP-echo providers; values of
 * a non-indicator table's reference / attribution columns ("Handle |
 * Repository") stay provenance under an IOC heading; "log.events.vc0" never
 * yields the host "log.events".
 * v54 (hunt.io Need-Review FNs): tl-table-v17 / tl-section-tree-v14.
 * A wildcard host in an IOC table cell ("*.example.st") asserts its
 * operator-owned apex; tcp:// / udp:// / tls:// endpoints in a table cell
 * assert their host like fqdn://; a domain-only cell in a certificate
 * Common Name column is an indicator candidate; a hash truncated with an
 * ellipsis links to the unique full digest elsewhere in the report instead
 * of becoming a bogus shorter-digest candidate; "closed pair" IOC headings
 * ("IOCs and Observables") open an IOC scope; rows that publish a host as a
 * historical resolution pivot stay context-only in an infrastructure lookup
 * table.
 * v55 (70-report audit 35700–35769): tl-table-v18 / tl-type-resolver-v23 /
 * tl-section-tree-v15. A hex run that is the generated suffix of a word
 * identifier ("anonymous-<32 hex>" account names) is not a digest; a dotted
 * quad glued to a User-Agent product token ("Chrome/149.0.0.1") is a version;
 * a WordPress multiplication sign inside a hostname label ("8×255[.]com") is
 * the letter x.
 * v56: membership is decided by membershipDecision.decideMembership from
 * per-section authority. Structured rows, operational statements and grounded
 * model verdicts outside a curated section reach needs_review instead of silently
 * becoming non-members; CSV / JSON lines in code blocks are rows; [dot], (dot),
 * {dot}, escaped and full-width dots refang.
 * v61 (review queue 35800–35819): tl-section-tree-v17 (qualified "<Family>
 * hashes for <period>:" / "URI Locations:" sibling groups of an open IOC
 * inventory keep its authority); a .onion host needs a service label of at least 16
 * characters ("Tor and [.]onion domains" is not "and.onion"); a Rust source
 * file name ("build.rs") reads like a .md file name, not a .rs domain.
 * v62 (review queue 35820–35850): tl-table-v19. An MD5 the publisher wrote
 * as a hex literal ("0xFD91…", exactly 32 hex) is that digest in an IOC table
 * cell or when it opens a list row / line (never inside prose or code; "0x" +
 * 40 / 64 hex stays an EVM address / transaction hash); a scheme-less resource whose hyperlink text is a strict tail of the
 * matched run is bounded by that anchor ("CVE-…" glued on by adjacent inline
 * markup is not part of the host).
 * v63 (35831 cleanup): a parenthesised comparator ("Software (Before
 * 9.16.4.104, …)", "brotlicffi (before 1.2.1.0)") opens an affected-product
 * version list, and "/" joins its members: release numbers, not IPv4.
 * v64 (review queue 35858–35869): tl-section-tree-v18 (operator-owned
 * resource appendix headings), and a hotfix / "<ver> for v10" cue reads an
 * IPv4-shaped token as a release number ("hotfixes (10.3.4.45 for v10, and
 * 9.15.2.70 for v7 …)"); a network cue at the token still wins.
 * v65 (35862 follow-up): a bare re-mention of a value the same block already
 * read as a release number ("… and we verified that 10.3.4.45 blocks …")
 * keeps that reading unless a network cue sits at the token.
 */
export const THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION = 'tl-candidates-v65';

import { normalizeObservable } from '../observable-normalization.js';
import { refangObservable, refangTextForExtraction } from './defang.js';
import { annotateDocumentZones } from './documentZones.js';
import { applySectionTreeAuthority } from './sectionTree/authority.js';
import { hostnameFromUrl } from './candidateTyping.js';
import { joinWrappedUrlTail } from './tableSemantics.js';
import { annotateListStances, discoverDocumentIndicatorScope, isIndicatorValueLine } from './indicatorScope.js';
import { NON_NETWORK_RESOLVED_TYPES, RESOLVED_TYPES, buildTypeResolutionRecord, validateCanonicalIocValue } from './observableTypeResolver.js';
import { createExplicitTableAssertionTracker, structuralCompleteness } from './explicitTableCompleteness.js';
import { inferSlashDateOrder } from './sourceObservation.js';
import { markIncompleteUrlPrefixes, markTruncatedUrlDuplicates, resolveOtpSuffixedTableUrls, MAX_TOKEN_LOG, candidateKey, listLeadInsByBlock, valueLineLeadInsByBlock, codeListNamesByBlock, tableCellTexts } from './candidateHelpers.js';
import { createCandidateAccumulator } from './candidateAccumulator.js';
import { readTypedTables } from './candidateTablePass.js';
import { readDocumentText } from './candidateTextPass.js';

export { surroundingWindow, OCCURRENCE_FORMS, candidateKey } from './candidateHelpers.js';

export function extractCandidatesWithDiagnostics(doc, opts = {}) {
  const sourceUrl = opts.sourceUrl || doc.meta?.source_url || doc.meta?.sourceUrl || null;
  let sourceHost = '';
  try {
    if (sourceUrl) sourceHost = hostnameFromUrl(sourceUrl);
  } catch {
    sourceHost = '';
  }
  const normalizedSourceUrl = sourceUrl ? normalizeObservable('url', refangObservable(sourceUrl)) : null;

  const annotated = annotateDocumentZones(doc, { sourceUrl, sourceHost });
  const blocks = annotated.blocks || [];
  /** table block id → ordinal among the document's tables (evidence locator). */
  const tableOrdinals = new Map(blocks.filter((b) => b.type === 'table').map((b, i) => [b.id, i]));
  const documentScope = discoverDocumentIndicatorScope(annotated.blocks || []);
  // The lead-in sentence a publisher writes above a list ("Certificate
  // SHA-256 Hashes for Fingerprints and Corresponding Hosts:") names the
  // subject of its unlabelled items (tl-candidates-v33): it is the digest
  // scope of every list item up to the next non-list block.
  const listLeadIns = listLeadInsByBlock(annotated.blocks || []);
  const valueLineLeadIns = valueLineLeadInsByBlock(annotated.blocks || []);
  const codeListNames = codeListNamesByBlock(annotated.blocks || []);
  const diagnostics = {
    extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
    explicit_tables: {
      tables_seen: 0,
      ioc_tables: 0,
      explicit_tables: 0,
      rows_seen: 0,
      rows_valid: 0,
      rows_rejected: 0,
      values_asserted: 0,
      candidates_created: 0,
      rejection_reasons: {},
      inconsistent: false,
      missing_identities: [],
      dropped_asserted_identities: [],
      /** Indicator cells holding a file identity plus observables (tl-table mixed cells). */
      mixed_cells: { decomposed: 0, recovered_values: 0, residual_unparsed: 0, residual_observables: [] },
      tables: []
    },
    /** Observable-type resolution: what the syntax guessed vs what the source supports. */
    type_resolution: {
      syntactic_occurrences: 0,
      network_ioc_candidates: 0,
      artifact_candidates: 0,
      artifact_occurrences_dropped: 0,
      relative_paths: 0,
      canonical_rejections: 0,
      rejected_values: {},
      excluded_reasons: {},
      examples: [],
      /** Host/path resources written without a scheme: preserved verbatim as URL values. */
      scheme_less_resources: { count: 0, rejected: {}, examples: [] }
    }
  };
  const typeDiag = diagnostics.type_resolution;
  /** IOC identities a valid explicit table asserted, recorded before add(). */
  const explicitTableAssertions = createExplicitTableAssertionTracker();
  /** Tokens rejected before becoming a candidate: each gets a disposition record. */
  const tokenLog = [];
  const noteRejectedToken = (raw, type, block, reason, disposition = 'rejected') => {
    if (tokenLog.length >= MAX_TOKEN_LOG) return;
    tokenLog.push({
      observable_type: type || 'unknown',
      raw_value: String(raw ?? '').slice(0, 500),
      normalized_value: String(raw ?? '').trim().toLowerCase().slice(0, 500) || null,
      disposition,
      reason_code: reason,
      block_id: block?.id || null,
      excerpt: block?.text ? String(block.text).slice(0, 240) : null
    });
  };

  /** Non-indicator table id → `type:value` keys of its reference-column cells. */
  const referenceColumnValues = new Map();
  const acc = createCandidateAccumulator({
    tableOrdinals, listLeadIns, valueLineLeadIns, codeListNames, sourceHost, normalizedSourceUrl,
    typeDiag, explicitTableAssertions, referenceColumnValues, noteRejectedToken,
    extractionVersion: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
  });
  const { byKey, urlHostIndex, countReason, rememberExample, resolveTruncatedDigests, resolvePendingDotted, foldSchemeLessUrlAliases } = acc;

  // Publisher stance about a whole list ("These endpoints are legitimate …").
  annotateListStances(blocks);
  // Format-agnostic "indicator row": PDF list rows, HTML <li>/<td>, or any line that is a single observable.
  const isObservableRow = (block) =>
    block.type === 'list_item' ||
    block.layout === 'observable_row' ||
    ((block.type === 'list' || block.type === 'table') && isIndicatorValueLine(block.text || ''));

  /**
   * Text the regex passes read for a block. An indicator row that is one URL
   * wrapped by the publisher's layout ("http://h/" + "x.exe") is read joined,
   * so the URL is one value and its tail never becomes a file-name token.
   */
  const scanText = (block) => {
    const raw = block.text || '';
    const joined = isObservableRow(block) ? joinWrappedUrlTail(raw) : null;
    return refangTextForExtraction(joined || raw);
  };
  /** Transport endpoints seen in the regex pass: [type, host, endpoint spelling]. */
  const networkEndpoints = [];

  /** Blocks handled row-by-row (typed indicator tables) — skipped by the regex passes. */
  const tableHandled = new Set();
  // Publisher observation dates in indicator rows: slash-date order is decided
  // once per document from its own table cells (sourceObservation.js).
  const slashDateOrder = inferSlashDateOrder(tableCellTexts(blocks));
  const observationNotAfter = opts.observationNotAfter || null;

  readTypedTables(blocks, acc, { diagnostics, explicitTableAssertions, tableHandled, referenceColumnValues, networkEndpoints, slashDateOrder, observationNotAfter, noteRejectedToken });
  readDocumentText(blocks, acc, { typeDiag, tableHandled, networkEndpoints, scanText, isObservableRow, noteRejectedToken });

  // Truncated digests join the report's unique full digest (or read as before).
  resolveTruncatedDigests();

  // Decide deferred dotted tokens (domain vs technical artifact) per document.
  resolvePendingDotted();

  // Endpoint provenance: the publisher's "tcp://host:port" spelling stays on
  // the host identity (parsed metadata, never a second value).
  for (const [type, host, spelling] of networkEndpoints) {
    const entry = byKey.get(candidateKey(type, host));
    if (!entry) continue;
    const list = Array.isArray(entry.parsed.network_endpoints) ? entry.parsed.network_endpoints : [];
    if (!list.includes(spelling) && list.length < 8) list.push(spelling);
    entry.parsed.network_endpoints = list;
  }

  resolveOtpSuffixedTableUrls(byKey, explicitTableAssertions);
  markTruncatedUrlDuplicates([...byKey.values()]);

  // One resource written "host/path" in one place and "https://host/path" in
  // another is one identity: the scheme-less spelling joins the absolute URL
  // the publisher wrote (no scheme is invented). When both http and https
  // spellings exist the scheme is ambiguous and the value stays as written.
  foldSchemeLessUrlAliases();

  // Incomplete path prefixes of sibling URLs (…/t/ when …/t/abc exists).
  markIncompleteUrlPrefixes(byKey);

  // Finalize: parser-derived host cross references
  const drafts = [];
  for (const entry of byKey.values()) {
    if (entry.candidate_type === 'url' && entry.parsed.host) {
      const hostType = entry.parsed.host_kind === 'ip' ? 'ip' : 'domain';
      const hostKey = candidateKey(hostType, entry.parsed.host);
      entry.parsed.host_independently_asserted = byKey.has(hostKey);
    }
    if ((entry.candidate_type === 'ip' || entry.candidate_type === 'domain') && urlHostIndex.has(entry.normalized_value)) {
      entry.parsed.also_url_host_of = [...urlHostIndex.get(entry.normalized_value)].map((k) => k.split('\0')[1]).slice(0, 20);
    }
    if (entry.table_rows.length) {
      entry.parsed.table_rows = entry.table_rows.length;
      entry.parsed.declared_types = [...new Set(entry.table_rows.map((r) => r.declared_type).filter(Boolean))];
    } else {
      delete entry.table_rows;
    }
    entry.occurrence_count = entry.occurrences.length;
    entry.document_has_authoritative_scope = annotated.section_graph.meta.has_authoritative_scope === true;
    drafts.push(entry);
  }

  // The one policy pass: section authority from the graph, then the evidence policy.
  const applied = applySectionTreeAuthority(annotated, drafts, { tree: annotated.section_graph });
  diagnostics.scope_engine = {
    engine: applied.scope_engine,
    version: applied.scope_engine_version,
    section_tree_version: applied.section_tree_version,
    has_authoritative_scope: applied.has_authoritative_scope === true,
    remapped_occurrences: applied.remapped_occurrences,
    demoted_occurrences: applied.demoted_occurrences,
    delegated_scope: applied.delegated_scope === true,
    external_ioc_pointer: applied.external_ioc_pointer === true,
    delegated_occurrences: applied.delegated_occurrences || 0
  };
  const out = [];
  for (const entry of applied.candidates) {
    const canonical = entry.is_ioc !== false ? validateCanonicalIocValue(entry.candidate_type, entry.normalized_value) : null;
    if (canonical && !canonical.ok) typeDiag.canonical_rejections += 1;
    entry.type_resolution = buildTypeResolutionRecord({
      raw: entry.original_value,
      syntaxGuess: entry.syntax_guess || entry.candidate_type,
      resolvedType: entry.resolved_type || entry.candidate_type,
      reason: entry.typing_reason || (entry.is_ioc === false ? entry.policy_decision : 'syntax_valid'),
      promotion: entry.is_ioc === false || entry.assessment === 'context_only' ? 'excluded' : 'eligible',
      signals: entry.typing_signals || undefined,
      normalizedPath: entry.parsed?.normalized_path || null,
      port: entry.parsed?.port ?? null,
      canonical
    });
    if (entry.artifact_kind) entry.type_resolution.artifact_kind = entry.artifact_kind;
    if (entry.type_scores) entry.type_resolution.scores = entry.type_scores;
    delete entry.typing_signals;
    delete entry.syntax_guess;
    delete entry.type_scores;
    if (NON_NETWORK_RESOLVED_TYPES.has(entry.candidate_type)) {
      typeDiag.artifact_candidates += 1;
      if (entry.candidate_type === RESOLVED_TYPES.RELATIVE_PATH || entry.candidate_type === RESOLVED_TYPES.FILE_PATH) typeDiag.relative_paths += 1;
      rememberExample(entry.type_resolution);
    } else if (entry.is_ioc !== false) {
      typeDiag.network_ioc_candidates += 1;
    }
    out.push(entry);
  }

  // Completeness gate: every IOC identity a valid explicit table row asserted
  // must exist as a candidate. Comparison is asserted − created, including
  // identities that add() rejected. A mismatch is diagnostic only.
  const t = diagnostics.explicit_tables;
  Object.assign(t, explicitTableAssertions.finalize(out));
  // Structured IOC section / table that degraded to the AI path (diagnostic only).
  diagnostics.structural_completeness = structuralCompleteness(annotated.blocks || [], out);
  diagnostics.document_scope = {
    ...documentScope,
    has_authoritative_indicator_scope: applied.has_authoritative_scope === true
  };
  diagnostics.scope = buildScopeDiagnostics(annotated, out);

  // `annotated` is the zone-annotated document the candidates were read from
  // (read-only consumers: quality assessment, benchmark scoring).
  return { candidates: out, diagnostics, annotated, tokenLog };
}

/**
 * Developer diagnostics for scope decisions: which headings opened / continued
 * / closed authoritative sections, and how occurrences were read (row vs
 * narrative, relation marker) per zone. Bounded; not analyst UI.
 * @param {object} annotated zone-annotated document
 * @param {object[]} candidates
 */
export function buildScopeDiagnostics(annotated, candidates) {
  const kinds = {};
  const markers = {};
  const byPolicy = {};
  const perCandidate = [];
  for (const c of candidates || []) {
    byPolicy[c.policy_decision || 'none'] = (byPolicy[c.policy_decision || 'none'] || 0) + 1;
    const occ = Array.isArray(c.occurrences) ? c.occurrences : [];
    for (const o of occ) {
      const k = o.occurrence_kind || 'unclassified';
      kinds[k] = (kinds[k] || 0) + 1;
      const m = o.relation_marker || 'none';
      markers[m] = (markers[m] || 0) + 1;
    }
    if (perCandidate.length < 80 && c.is_ioc !== false) {
      perCandidate.push({
        type: c.candidate_type,
        value: String(c.normalized_value || '').slice(0, 120),
        assessment: c.assessment,
        policy: c.policy_decision || null,
        ai_needed: c.ai_needed === true,
        occurrences: occ.slice(0, 6).map((o) => ({
          block_id: o.block_id,
          zone: o.zone,
          zone_reason: o.zone_reason || null,
          opened_by: o.scope_opening_id || null,
          heading: o.section_heading ? String(o.section_heading).slice(0, 80) : null,
          kind: o.occurrence_kind || null,
          relation: o.source_relation || null,
          marker: o.relation_marker || null,
          asserted: o.asserted === true
        }))
      });
    }
  }
  return {
    zones_version: annotated?.meta?.zones_version || null,
    trace: Array.isArray(annotated?.meta?.scope_trace) ? annotated.meta.scope_trace.slice(0, 60) : [],
    occurrence_kinds: kinds,
    relation_markers: markers,
    policy_decisions: byPolicy,
    candidates: perCandidate
  };
}

/**
 * @param {import('./canonicalDocument.js').CanonicalDocument} doc
 * @param {{ sourceUrl?: string|null }} [opts]
 */
export function extractCandidatesFromDocument(doc, opts = {}) {
  return extractCandidatesWithDiagnostics(doc, opts).candidates;
}

/**
 * Review-set partition used by the pipeline, prompts and UI summaries.
 * @param {object[]} candidates
 */
export function summarizeCandidateSet(candidates) {
  const s = {
    total: 0,
    ioc_candidates: 0,
    explicit_assertions: 0,
    table_assertions: 0,
    body_assertions: 0,
    context_only: 0,
    non_ioc: 0,
    ai_needed: 0,
    raw_occurrences: 0
  };
  for (const c of candidates || []) {
    s.total += 1;
    s.raw_occurrences += Array.isArray(c.occurrences) ? c.occurrences.length : 0;
    if (c.is_ioc === false) {
      s.non_ioc += 1;
      continue;
    }
    if (c.assessment === 'context_only') {
      s.context_only += 1;
      continue;
    }
    s.ioc_candidates += 1;
    if (c.source_assertion === 'explicit_ioc' || c.source_assertion === 'explicit_c2' || c.source_assertion === 'explicit_operational_infrastructure') s.explicit_assertions += 1;
    else s.body_assertions += 1;
    if (Array.isArray(c.table_rows) ? c.table_rows.length : c.parsed?.table_rows) s.table_assertions += 1;
    if (c.ai_needed) s.ai_needed += 1;
  }
  return s;
}

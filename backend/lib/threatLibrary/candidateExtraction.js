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

import { normalizeObservable } from '../observable-normalization.js';
import { isValidIpAddress } from '../publicIp.js';
import { refangObservable, refangTextForExtraction } from './defang.js';
import { annotateDocumentZones, NEGATIVE_ZONES, STRONG_IOC_ZONES } from './documentZones.js';
import {
  resolveDottedTokenType,
  hostnameFromUrl,
  pathBasenameFromUrl
} from './candidateTyping.js';
import { applyEvidencePolicy } from './evidencePolicy.js';
import { normalizeCandidateValue } from './candidateValue.js';
import { joinWrappedUrlTail, parseIndicatorCell } from './tableSemantics.js';
import { ipv4VersionContext } from './ipv4VersionContext.js';
import {
  annotateListStances,
  discoverDocumentIndicatorScope,
  isCredentialLabeledHex,
  isIndicatorRowShape,
  isIndicatorValueLine,
  lineContainingObservable,
  textDescribesValueAsBenign
} from './indicatorScope.js';
import {
  FILE_EXT_HINT,
  NON_NETWORK_RESOLVED_TYPES,
  RESOLVED_TYPES,
  buildTypeResolutionRecord,
  hasDelegatedDnsSuffix,
  isMutexLabeledValue,
  parseArtifactTypeLabel,
  trimUrlBoundary,
  validateCanonicalIocValue,
  validateUrlCandidate
} from './observableTypeResolver.js';
import { hexRunIsHostnameLabelFragment, ipv4MatchIsStandalone, isOnlyEmbeddedInDnsHostname } from './sourceOccurrence.js';
import { findIpv6Tokens } from './ipv6Tokens.js';
import { DIGEST_KINDS, NON_FILE_DIGEST_KINDS, classifyHexDigest } from './digestSemantics.js';
import { createExplicitTableAssertionTracker, structuralCompleteness } from './explicitTableCompleteness.js';
import {
  buildRowObservation,
  inferSlashDateOrder,
  isDateCell,
  recoverHeaderLabels
} from './sourceObservation.js';

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
 */
export const THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION = 'tl-candidates-v38';

const VERSION_CELL_TOKEN_SPLIT_RE = /[^0-9a-z.]+/i;

/** Same site family: exact host or subdomain (www. stripped). */
function samePublisherHostFamily(a, b) {
  const na = String(a || '')
    .toLowerCase()
    .replace(/^www\./, '');
  const nb = String(b || '')
    .toLowerCase()
    .replace(/^www\./, '');
  if (!na || !nb) return false;
  return na === nb || na.endsWith(`.${nb}`) || nb.endsWith(`.${na}`);
}

/** True when the candidate was also written in an explicit IOC inventory. */
function hasExplicitIocSectionOccurrence(entry) {
  return (entry.occurrences || []).some((o) => o.zone === 'explicit_ioc_section');
}

/**
 * Actor-infrastructure role words a publisher writes next to a value in a
 * table description cell ("(C2 SystemBC)", "exfiltration server").
 */
const DESCRIPTION_ROLE_WORDS =
  String.raw`(?:c2|c&c|cnc|command\s*(?:and|&)\s*control|exfil(?:tration)?\s+(?:server|domain|host|ip|infrastructure|endpoint)|malicious\s+(?:domain|host|server|ip|url|infrastructure)|phishing\s+(?:domain|site|page|url|server)|payload\s+(?:server|host|domain|url)|(?:download|staging|delivery)\s+server)`;
/** The role right before the value: "C2 domain X", "C2: X", "C&C server - X". */
const ROLE_BEFORE_VALUE_RE = new RegExp(
  String.raw`(?:^|[^a-z0-9])${DESCRIPTION_ROLE_WORDS}(?:\s+(?:domain|host|server|ip|url|address|endpoint)s?)?\s*[:=\-–—]?\s*$`,
  'i'
);
/** The role right after the value: "X (C2 SystemBC)", "X - C2", "X is a C2 server". */
const ROLE_AFTER_VALUE_RE = new RegExp(
  String.raw`^\s*[\-–—:(\[]*\s*(?:is\s+(?:an?\s+|the\s+)?)?${DESCRIPTION_ROLE_WORDS}(?:[^a-z0-9]|$)`,
  'i'
);

/**
 * A description cell asserts `value` when the clause that names it — split at
 * ";", "·", line breaks or sentence ends — names only this observable, gives
 * that observable itself an actor-infrastructure role (right before or right
 * after it, no relation word between: "resolved C2 domains via X" or "C2,
 * associated with host X" name another subject's role) and does not call it
 * benign.
 * @param {string} cell description cell text (publisher spelling)
 * @param {string} value refanged value
 */
function descriptionClauseAssertsRole(cell, value) {
  const text = refangTextForExtraction(cell);
  const v = String(value || '').toLowerCase();
  if (!v) return false;
  const clause = text.split(/[;·¶\n]|\.\s+(?=[A-Z])/).find((c) => c.toLowerCase().includes(v));
  if (!clause) return false;
  const observables = parseIndicatorCell(clause, null).values.filter((x) => x.is_ioc !== false);
  if (observables.length !== 1 || textDescribesValueAsBenign(clause, [v])) return false;
  const at = clause.toLowerCase().indexOf(v);
  return ROLE_BEFORE_VALUE_RE.test(clause.slice(Math.max(0, at - 40), at)) || ROLE_AFTER_VALUE_RE.test(clause.slice(at + v.length, at + v.length + 40));
}

/**
 * True when the publisher wrote this value as its own row of an explicit IOC
 * table: a typed table cell, or a one-cell table row whose whole text is the
 * value. A line of a pasted dump, a PDF row list or a sentence is not.
 */
function hasExplicitSingleValueRowOccurrence(entry) {
  return (entry.occurrences || []).some((o) => {
    if (o.zone !== 'explicit_ioc_section') return false;
    if (o.form === 'table_row') return true;
    // A one-cell table row holding only this URL (an HTML IOC table of URL
    // rows). A line of a pasted dump / PDF row list keeps the prefix rule.
    return o.form === 'list_row' && o.block_type === 'table' && isIndicatorValueLine(String(o.surrounding_text || ''));
  });
}

/**
 * Mark URL candidates that are incomplete path prefixes of a longer sibling
 * URL in the same document (e.g. http://host:443/t/ vs …/t/a779ab).
 * An origin URL (pathname "/") with a longer same-origin sibling is incomplete
 * unless the publisher also listed that origin in an explicit IOC inventory —
 * path IOCs never authorize a broader root alone (tl-candidates-v34).
 * A directory URL ("http://h/555/") the publisher listed as its own row of an
 * explicit IOC table is a complete value, not a prefix (tl-candidates-v37); a
 * bare prefix line in a pasted URL dump or PDF row list keeps the protection.
 * @param {Map<string, object>} byKey
 */
function markIncompleteUrlPrefixes(byKey) {
  const urls = [...byKey.values()].filter((e) => e.candidate_type === 'url' && e.normalized_value);
  for (const a of urls) {
    const av = String(a.normalized_value);
    if (!av.endsWith('/')) continue;
    let pathname = '';
    try {
      pathname = new URL(av).pathname || '';
    } catch {
      continue;
    }
    if (!pathname) continue;
    const longer = urls.some(
      (b) => b !== a && String(b.normalized_value).startsWith(av) && String(b.normalized_value).length > av.length
    );
    if (!longer) continue;
    if (pathname === '/') {
      if (!hasExplicitIocSectionOccurrence(a)) a.incomplete_url_prefix = true;
      continue;
    }
    if (hasExplicitSingleValueRowOccurrence(a)) continue;
    a.incomplete_url_prefix = true;
  }
}

/** Cell texts of every canonical table block (publisher date-order evidence). */
function* tableCellTexts(blocks) {
  for (const block of blocks || []) {
    if (block?.type !== 'table' || !Array.isArray(block.table?.rows)) continue;
    for (const row of block.table.rows) {
      if (Array.isArray(row)) for (const cell of row) yield String(cell ?? '');
    }
  }
}

/**
 * Column labels of an interpreted indicator table: its own header (table
 * headers or a promoted header row), else the label line printed just above
 * a headerless table (PDF appendices repeat "IP Address First Seen Last Seen"
 * on every page as a separate line). Recovered labels must agree with the
 * columns they name; they only label row evidence (observation dates), never
 * change column intent or assertion.
 * @param {object} interp tableSemantics.interpretIocTable result
 * @param {object|undefined} previousBlock
 * @returns {Array<string|null>|null}
 */
function tableColumnLabels(interp, previousBlock) {
  const columns = Array.isArray(interp?.columns) ? interp.columns : [];
  if (!columns.length) return null;
  const own = columns.map((c) => (c.header ? String(c.header) : null));
  if (own.some(Boolean)) return own;
  if (!previousBlock || previousBlock.type === 'table' || previousBlock.type === 'list_item') return null;
  const rows = (interp.rows || []).filter((r) => r.status === 'valid' && Array.isArray(r.cells));
  if (!rows.length) return null;
  const dateColumns = columns
    .map((c) => c.index)
    .filter((i) => rows.every((r) => !r.cells[i] || isDateCell(r.cells[i])) && rows.some((r) => isDateCell(r.cells[i])));
  if (!dateColumns.length) return null;
  return recoverHeaderLabels(previousBlock.text || '', {
    width: columns.length,
    indicatorColumns: interp.indicator_columns || [],
    dateColumns
  });
}

/**
 * IPv4-shaped tokens of a table block split by column role: those found in its
 * software-version columns (`block.version_columns`, header row excluded) and
 * those found anywhere else in the table. Null for non-table blocks or tables
 * without a version column.
 * @param {object} block
 */
function versionColumnTokens(block) {
  const cols = Array.isArray(block?.version_columns) ? new Set(block.version_columns) : null;
  if (block?.type !== 'table' || !cols?.size || !block.table) return null;
  const rows = Array.isArray(block.table.rows) ? block.table.rows : [];
  const inVersion = new Set();
  const elsewhere = new Set();
  const collect = (cell, into) => {
    for (const tok of refangTextForExtraction(String(cell ?? '')).split(VERSION_CELL_TOKEN_SPLIT_RE)) {
      const t = tok.replace(/\.+$/, '');
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(t)) into.add(t);
    }
  };
  rows.forEach((row, r) => {
    if (r === 0 && block.version_header_row) return;
    (Array.isArray(row) ? row : []).forEach((cell, c) => collect(cell, cols.has(c) ? inVersion : elsewhere));
  });
  for (const h of Array.isArray(block.table.headers) ? block.table.headers : []) collect(h, elsewhere);
  return { inVersion, elsewhere };
}

/**
 * Relation classification must see the clause around THIS observable, not the
 * first 280 characters of a long PDF paragraph (which may be a different
 * sentence, or a running footer glued onto a C2 discussion).
 * @param {string} text
 * @param {string} value
 * @param {number} [radius]
 * @param {number} [ordinal] which spelling of `value` in `text` this occurrence is (0 = first)
 */
export function surroundingWindow(text, value, radius = 140, ordinal = 0) {
  const hay = String(text || '');
  if (!hay) return null;
  if (ordinal > 0) {
    // Anchor on the ordinal-th spelling of the value (an earlier copy in the
    // same block was not this occurrence, e.g. a URL component). The window
    // never reaches back over that earlier copy; unknown ordinal → first hit.
    const hits = hitOffsets(hay, value);
    if (hits.length > ordinal) {
      const idx = hits[ordinal];
      const len = String(value).length;
      const start = Math.max(idx - radius, hits[ordinal - 1] + len);
      return hay.slice(start, idx + len + radius);
    }
  }
  const needles = [...new Set([
    String(value || ''),
    String(value || '').replace(/\./g, '[.]'),
    String(value || '').replace(/\[\.\]/g, '.')
  ])].filter(Boolean);
  const low = hay.toLowerCase();
  let idx = -1;
  let nlen = 0;
  for (const n of needles) {
    const i = low.indexOf(String(n).toLowerCase());
    if (i >= 0) {
      idx = i;
      nlen = String(n).length;
      break;
    }
  }
  if (idx < 0) {
    // Defanged source spelling ("hxxps://host[.]tld" for "https://host.tld/"):
    // locate the value in the refanged text, so the relation classifier reads
    // the clause that mentions it rather than the paragraph's first sentences.
    const refanged = refangTextForExtraction(hay);
    const rlow = refanged.toLowerCase();
    const bare = String(value || '').replace(/\/$/, '');
    for (const n of [...new Set([String(value || ''), bare])].filter(Boolean)) {
      const i = rlow.indexOf(n.toLowerCase());
      if (i >= 0) return refanged.slice(Math.max(0, i - radius), i + n.length + radius);
    }
    return hay.slice(0, Math.min(280, hay.length));
  }
  const start = Math.max(0, idx - radius);
  return hay.slice(start, idx + nlen + radius);
}

// `\b` alone is not enough: `.` is a non-word character, so the first four
// numeric labels of `128.200.178.68.host.example.com` match as IPv4. Lookaround
// plus the span check in Pass 2 reject DNS continuation on either side.
const IPV4_RE =
  /(?<![A-Za-z0-9_-]\.)\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(?:3[0-2]|[12]?\d))?\b(?!\.[A-Za-z0-9_-])/g;
const IPV4_PORT_RE =
  /(?<![A-Za-z0-9_-]\.)\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))[:：](\d{1,5})\b/g;
/** Bare IPv6 loopback — leading `\b` fails because `:` is a non-word character. */
const IPV6_LOOPBACK_RE = /(?<![0-9a-fA-F:])::1(?![0-9a-fA-F:])/g;
// Typographic quotes / guillemets never occur raw inside a URL (they are
// percent-encoded); in prose they close a quoted URL ("“https://x/y.exe”").
// ")" is matched and then balanced by trimUrlBoundary, so path parentheses
// ("report_(final).pdf") survive while prose / annotation parentheses do not.
const URL_RE = /\bhttps?:\/\/[^\s<>"'`\]‘’“”«»]+/gi;
/**
 * Scheme-less network resource: DNS-shaped host + path ("js.cache-mcp.com/layer.js").
 * The publisher gave no scheme, so none is invented: the exact host/path is
 * the value. Not preceded by a scheme separator, "@" or another label.
 */
const HOST_PATH_RE = /(?<![\w@:\/.\-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?::\d{1,5})?(\/[^\s<>"'`\]，。；‘’“”«»]+)/gi;
const URL_SCHEME_PREFIX_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
/**
 * Transport endpoint written with a non-HTTP scheme ("tcp://c2.example:443",
 * "udp://198.51.100.7:53", "socks5://h:1080"). TalonHound URL values are web
 * resources, so the endpoint's host is the observable: the scheme declares it
 * a network host (never a `key: value` pair), the port is endpoint context and
 * the publisher's endpoint spelling is kept as provenance (tl-candidates-v37).
 */
const NETWORK_ENDPOINT_RE =
  /\b(tcp|udp|tls|ssl|socks[45]h?):\/\/((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))(?::(\d{1,5}))?(?![\w.-])/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b/gi;

/** A redaction placeholder right before a hostname tail ("<REDACTED>", "[redacted]", "REDACTED", "xxx"). */
const REDACTION_PLACEHOLDER_END_RE = /(?:<\s*[^<>\s]{0,24}\s*>|\[\s*[^\[\]\s]{0,24}\s*\]|\bredacted|\b[x*]{3,})\s*$/i;

/**
 * True when the DOMAIN_RE match starting at `start` is only the tail of a
 * longer publisher hostname the regex could not read ("<REDACTED>-my.x.com",
 * "<REDACTED>.example.com").
 * @param {string} text
 * @param {number} start
 */
function isTruncatedHostTail(text, start) {
  if (start <= 0) return false;
  const prev = text[start - 1];
  if (prev === '-') return true;
  if (prev === '.') return REDACTION_PLACEHOLDER_END_RE.test(text.slice(Math.max(0, start - 40), start - 1));
  return false;
}
const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const ATTACK_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

const MAX_TABLE_ROWS_PER_CANDIDATE = 20;

export const OCCURRENCE_FORMS = Object.freeze({
  STANDALONE: 'standalone',
  URL: 'url',
  IP_PORT: 'ip_port',
  LIST_ROW: 'list_row',
  TABLE_ROW: 'table_row',
  /** Domain part of an email address: parsed metadata of that address, never a row. */
  EMAIL_DOMAIN: 'email_domain'
});

/**
 * The publisher's own spelling of a refanged token (defanged host dots kept),
 * so evidence shows "js.cache-mcp[.]com/layer.js" rather than a rewritten form.
 * @param {string} blockText
 * @param {string} refanged
 * @param {string} host
 */
function sourceSpelling(blockText, refanged) {
  const hay = String(blockText || '');
  if (hay.includes(refanged)) return refanged;
  // Publishers defang any subset of the dots ("js.cache-mcp[.]com/layer.js"):
  // every "." may appear as ".", "[.]", "(.)" or "{.}" in the source.
  const pattern = String(refanged)
    .replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&')
    .replace(/\\\./g, '(?:\\.|\\[\\.\\]|\\(\\.\\)|\\{\\.\\})');
  try {
    const m = hay.match(new RegExp(pattern, 'i'));
    if (m) return m[0];
  } catch {
    /* fall through */
  }
  return refanged;
}

/**
 * Parse port from an http(s) URL when explicitly present.
 * @param {string} url
 */
function portFromUrl(url) {
  try {
    const u = new URL(String(url));
    return u.port ? Number(u.port) : null;
  } catch {
    return null;
  }
}

/**
 * @param {Array<[number, number]>} spans
 * @param {number} start
 * @param {number} end
 */
function insideAnySpan(spans, start, end) {
  for (const [s, e] of spans) {
    if (start >= s && end <= e) return true;
  }
  return false;
}

/** Case-insensitive, non-overlapping offsets of `value` in `text`. */
function hitOffsets(text, value) {
  const hay = String(text || '').toLowerCase();
  const needle = String(value || '').toLowerCase();
  const out = [];
  if (!needle) return out;
  for (let i = hay.indexOf(needle); i >= 0; i = hay.indexOf(needle, i + needle.length)) out.push(i);
  return out;
}

/** File hashes, longest first: `\b` keeps a shorter length from matching inside a longer hex run. */
const HASH_PATTERNS = [
  [SHA256_RE, 'sha256'],
  [SHA1_RE, 'sha1'],
  [MD5_RE, 'md5']
];

/**
 * Candidate key used everywhere (DB unique constraint mirrors it).
 * @param {string} type
 * @param {string} value
 */
export function candidateKey(type, value) {
  return `${type}\0${value}`;
}

/**
 * Values mentioned inside a description cell (related context, not assertions).
 * @param {string|null} description
 */
function relatedValuesFromDescription(description) {
  if (!description) return [];
  const parsed = parseIndicatorCell(description, null);
  return parsed.values
    .filter((v) => v.is_ioc !== false)
    .filter((v) => v.candidate_type !== 'domain' || v.normalized_value.includes('.'))
    .map((v) => (v.port ? `${v.normalized_value}:${v.port}` : v.normalized_value))
    .slice(0, 8);
}

/**
 * @param {import('./canonicalDocument.js').CanonicalDocument} doc
 * @param {{ sourceUrl?: string|null }} [opts]
 * @returns {{ candidates: object[], diagnostics: object, annotated: object }}
 */
/**
 * block id → lead-in text of the list the block belongs to: the paragraph
 * immediately before a run of list blocks when it ends with a colon.
 * @param {object[]} blocks
 */
function listLeadInsByBlock(blocks) {
  const out = new Map();
  let leadIn = null;
  for (const b of blocks) {
    if (b?.type === 'list') {
      if (leadIn) out.set(b.id, leadIn);
      continue;
    }
    const t = String(b?.text || '').trim();
    leadIn = (b?.type === 'paragraph' || b?.type === 'heading') && t.length <= 200 && /:\s*$/.test(t) ? t : null;
  }
  return out;
}

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
  const documentScope = discoverDocumentIndicatorScope(annotated.blocks || []);
  // The lead-in sentence a publisher writes above a list ("Certificate
  // SHA-256 Hashes for Fingerprints and Corresponding Hosts:") names the
  // subject of its unlabelled items (tl-candidates-v33): it is the digest
  // scope of every list item up to the next non-list block.
  const listLeadIns = listLeadInsByBlock(annotated.blocks || []);
  /** @type {Map<string, object>} */
  const byKey = new Map();
  const urlPathBasenames = new Set();
  const knownUrlHosts = new Set();
  /** host → Set<url candidate key> (parser-derived metadata index, not occurrences) */
  const urlHostIndex = new Map();
  if (sourceHost) knownUrlHosts.add(sourceHost.toLowerCase());

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
  const countReason = (bucket, reason) => {
    bucket[reason] = (bucket[reason] || 0) + 1;
  };
  const rememberExample = (record) => {
    if (typeDiag.examples.length < 24) typeDiag.examples.push(record);
  };
  /** IOC identities a valid explicit table asserted, recorded before add(). */
  const explicitTableAssertions = createExplicitTableAssertionTracker();
  /** Last rejection reason from add(); diagnostic only. */
  let lastAddRejection = null;

  function occurrenceFor(block, extra = {}, focusValue = '') {
    const zone = block?.zone || 'unknown';
    const text = extra.rowText || (block?.text ? String(block.text) : null);
    const focus = extra.originalValue || focusValue;
    const form = extra.form || OCCURRENCE_FORMS.STANDALONE;
    // Structural reading is decided here, where the whole block is visible:
    // row placement (list / table / observable-row layout / discovered list)
    // or a short "value – note" / "label: value" line.
    // The domain inside an email address ("ops@mail.example") is never an
    // indicator row by itself, whatever line / list the address sits on.
    const emailPart = form === OCCURRENCE_FORMS.EMAIL_DOMAIN;
    const structuralRow = !emailPart && (
      form === OCCURRENCE_FORMS.TABLE_ROW ||
      form === OCCURRENCE_FORMS.LIST_ROW ||
      form === OCCURRENCE_FORMS.IP_PORT ||
      block?.type === 'list_item' ||
      block?.layout === 'observable_row' ||
      block?.zone_reason === 'observable_list' ||
      block?.zone_reason === 'cidr_list' ||
      block?.zone_reason === 'ioc_table');
    const rowShape = !emailPart && !structuralRow && text ? isIndicatorRowShape(text, focus || focusValue) : false;
    return {
      block_id: block?.id || null,
      page: block?.page ?? null,
      zone,
      zone_reason: block?.zone_reason || null,
      scope_opening_id: block?.scope_opening_id || null,
      section_kind: zone,
      section_heading: block?.section_heading || null,
      block_type: block?.type || null,
      layout: block?.layout || null,
      form,
      structural_row: structuralRow,
      row_shape: rowShape,
      port: extra.port ?? null,
      table_row: extra.tableRow ? extra.tableRow.row_index : null,
      surrounding_text: (extra.evidenceRowText || text)
        ? surroundingWindow(extra.evidenceRowText || text, focus, 140, extra.focusOrdinal || 0)
        : null,
      typing_reason: extra.typingReason || null,
      ...(extra.referenceCell === true ? { reference_cell: true } : {}),
      ...(extra.descriptionCell === true ? { description_cell: true } : {}),
      ...(block?.list_stance ? { list_stance: block.list_stance } : {})
    };
  }

  function pushOccurrence(entry, block, extra = {}) {
    const occ = occurrenceFor(block, extra, entry.normalized_value || entry.original_value);
    if (!Array.isArray(entry.occurrences)) entry.occurrences = [];
    const dup = entry.occurrences.find(
      (o) => o.block_id && o.block_id === occ.block_id && (o.table_row == null || o.table_row === occ.table_row)
    );
    if (dup) {
      // Same block: keep one occurrence but remember a stronger assertion form / port.
      if (occ.port != null && dup.port == null) dup.port = occ.port;
      if (dup.form === OCCURRENCE_FORMS.STANDALONE && occ.form !== OCCURRENCE_FORMS.STANDALONE) dup.form = occ.form;
      if (occ.port != null) rememberPort(entry, occ.port);
      return;
    }
    entry.occurrences.push(occ);
    if (occ.port != null) rememberPort(entry, occ.port);
  }

  function rememberPort(entry, port) {
    if (!Array.isArray(entry.parsed.ports)) entry.parsed.ports = [];
    if (!entry.parsed.ports.includes(port)) entry.parsed.ports.push(port);
  }

  function evidenceTextFor(block, extra = {}) {
    if (extra.evidenceRowText || extra.rowText) return String(extra.evidenceRowText || extra.rowText).slice(0, 500);
    if (!block?.text) return null;
    const text = String(block.text).slice(0, 500);
    if ((block.type === 'list_item' || block.layout === 'observable_row') && block.section_heading) {
      return `${String(block.section_heading).slice(0, 80)}: ${text}`.slice(0, 500);
    }
    return text;
  }

  /**
   * Create-or-get the candidate entry for a resolved identity and attach one
   * occurrence (row provenance, evidence anchor preference).
   * @param {object} spec
   */
  function materialize(spec) {
    const { candidateType, normalizedValue, originalValue, n, block, extra, typingMeta, isIoc, artifactKind, typingSignals, syntaxGuess } = spec;
    const zone = block?.zone || 'unknown';
    const key = candidateKey(candidateType, normalizedValue);
    let entry = byKey.get(key);
    if (!entry) {
      entry = {
        candidate_type: candidateType,
        original_value: originalValue,
        normalized_value: normalizedValue,
        assessment: isIoc && !n.likelyContextOnly ? 'unknown' : 'context_only',
        role: n.likelyContextOnly ? (n.reservedAddress ? 'reference' : 'legitimate_service') : isIoc ? 'unknown' : 'reference',
        confidence: n.likelyContextOnly ? 0.75 : null,
        evidence_text: evidenceTextFor(block, extra),
        block_id: block?.id || null,
        page_number: block?.page ?? null,
        section: zone,
        zone,
        is_ioc: isIoc,
        resolved_type: typingMeta.resolved_type || candidateType,
        typing_reason: typingMeta.typing_reason || null,
        artifact_kind: isIoc ? null : artifactKind || null,
        syntax_guess: syntaxGuess,
        typing_signals: typingSignals || null,
        occurrences: [],
        parsed: n.parsed && typeof n.parsed === 'object' ? { ...n.parsed } : {},
        table_rows: [],
        derived_from: null,
        is_direct_source_observable: true,
        is_parser_derived_metadata: false,
        extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
      };
      if (n.likelyContextOnly && !n.reservedAddress && !n.nonActionableLocal) entry.rfc_example = true;
      if (n.reservedAddress) entry.reserved_address = true;
      if (n.nonActionableLocal) entry.non_actionable_local = true;
      // Report's own source URL / host (and same-site subdomains) are provenance,
      // never findings — e.g. report.ncsc.gov.uk on an ncsc.gov.uk advisory.
      if (candidateType === 'domain' && sourceHost && samePublisherHostFamily(normalizedValue, sourceHost)) {
        entry.is_report_source = true;
      } else if (candidateType === 'url') {
        const urlHost = hostnameFromUrl(normalizedValue);
        if (
          (normalizedSourceUrl && normalizedValue === normalizedSourceUrl) ||
          (sourceHost && urlHost && samePublisherHostFamily(urlHost, sourceHost))
        ) {
          entry.is_report_source = true;
        }
      }
      byKey.set(key, entry);
    }
    pushOccurrence(entry, block, { ...extra, typingReason: typingMeta.typing_reason || null });
    if (extra.tableRow && entry.table_rows.length < MAX_TABLE_ROWS_PER_CANDIDATE) {
      entry.table_rows.push(extra.tableRow);
    }
    // Prefer strong-zone evidence text / anchor block
    const anchorIsStrong = STRONG_IOC_ZONES.has(entry.zone);
    if (STRONG_IOC_ZONES.has(block?.zone) && (block?.text || extra.rowText) && !anchorIsStrong) {
      entry.evidence_text = evidenceTextFor(block, extra);
      entry.block_id = block.id;
      entry.page_number = block.page ?? null;
      entry.section = block.zone;
      entry.zone = block.zone;
      if (extra.originalValue) entry.original_value = extra.originalValue;
    } else if (NEGATIVE_ZONES.has(entry.zone) && !NEGATIVE_ZONES.has(block?.zone) && block?.text) {
      // Body mention beats a footer/reference anchor for display purposes
      entry.evidence_text = evidenceTextFor(block, extra);
      entry.block_id = block.id;
      entry.page_number = block.page ?? null;
      entry.section = block.zone || 'unknown';
      entry.zone = block.zone || 'unknown';
    }
    return entry;
  }

  /**
   * Dotted tokens are typed once per document: every occurrence is resolved
   * against its own context (label, clause, zone, form) and the readings are
   * weighed together, so "Exploit.in" mentioned beside the word "module" in
   * one sentence does not split the same token into two identities.
   * @type {Map<string, { token: string, occurrences: object[] }>}
   */
  const pendingDotted = new Map();

  /**
   * @param {string} raw
   * @param {string|null} hintType
   * @param {object} block
   * @param {{ form?: string, port?: number|null, typing?: object, originalValue?: string, tableRow?: object, rowText?: string, typeLabel?: string|null, declaredType?: string|null, explicitTable?: boolean }} [extra]
   */
  function add(raw, hintType, block, extra = {}) {
    typeDiag.syntactic_occurrences += 1;
    lastAddRejection = null;
    const n = normalizeCandidateValue(raw, hintType);
    if (!n.ok) {
      lastAddRejection = n.error || 'unrecognized';
      countReason(typeDiag.rejected_values, lastAddRejection);
      return null;
    }
    // Credential / token labels: a hex run is not a malware hash just because
    // it matches md5/sha length. Hash vocabulary on the same label ("SHA-256:",
    // "Hardcoded Hash:") keeps the hash reading; length/type still follow value.
    if (n.candidateType === 'md5' || n.candidateType === 'sha1' || n.candidateType === 'sha256') {
      const hay = extra.rowText || block?.text || '';
      const line = lineContainingObservable(hay, n.normalizedValue) || hay;
      if (isCredentialLabeledHex(line, n.normalizedValue)) {
        lastAddRejection = 'credential_labeled_hex';
        countReason(typeDiag.rejected_values, lastAddRejection);
        return null;
      }
      // The value's own type label (sub-heading / table type cell) names a
      // mutex: a hex mutex name is not a file digest, whatever its length.
      // Only the mutex family is decisive — "Configuration" / "Registry"
      // headings can sit over genuine file hashes. A declared hash type wins.
      const ownLabel = extra.typeLabel || block?.type_label || null;
      const declaredHash = /^(?:md5|sha1|sha256|hash)$/.test(String(extra.declaredType || block?.declared_type_label || ''));
      if (!declaredHash && ((ownLabel && parseArtifactTypeLabel(ownLabel)?.kind === 'mutex') || isMutexLabeledValue(line, n.normalizedValue))) {
        countReason(typeDiag.excluded_reasons, 'mutex_type_label');
        return materialize({
          candidateType: RESOLVED_TYPES.TECHNICAL_ARTIFACT,
          normalizedValue: n.normalizedValue,
          originalValue: extra.originalValue || n.originalValue,
          n,
          block,
          extra,
          typingMeta: { resolved_type: RESOLVED_TYPES.TECHNICAL_ARTIFACT, typing_reason: 'mutex_type_label' },
          isIoc: false,
          artifactKind: 'mutex',
          typingSignals: null,
          syntaxGuess: n.candidateType
        });
      }
      // Build-ids, certificate thumbprints, vhash / fuzzy hashes, keys and
      // digests of trivial inputs share the hex shape but name no file: keep
      // them as report context (technical artifact), never as a sample hash.
      // Table rows: the caption / section heading names the subject a bare
      // algorithm label leaves open ("Custom certificate …" > "SHA-256 | <v>").
      const scopeLabel = block?.type === 'table'
        ? block?.table?.caption || block?.section || null
        : block?.type === 'list' ? listLeadIns.get(block.id) || null : null;
      const digest = classifyHexDigest(line, n.normalizedValue, { scopeLabel, rowDescription: extra.tableRow?.description || null });
      if (NON_FILE_DIGEST_KINDS.has(digest.kind) && digest.kind !== DIGEST_KINDS.CREDENTIAL) {
        countReason(typeDiag.excluded_reasons, `non_file_digest_${digest.kind}`);
        const artifact = materialize({
          candidateType: RESOLVED_TYPES.TECHNICAL_ARTIFACT,
          normalizedValue: n.normalizedValue,
          originalValue: extra.originalValue || n.originalValue,
          n,
          block,
          extra,
          typingMeta: {
            resolved_type: RESOLVED_TYPES.TECHNICAL_ARTIFACT,
            typing_reason: `non_file_digest_${digest.kind}`
          },
          isIoc: false,
          artifactKind: digest.kind,
          typingSignals: null,
          syntaxGuess: n.candidateType
        });
        if (artifact) {
          artifact.digest_kind = digest.kind;
          artifact.digest_shape = n.candidateType;
        }
        return artifact;
      }
    }
    // IP/IPv6: reject when this block's only evidence is a numeric prefix of a
    // larger DNS token. Do not consult originalValue/raw — those may already be
    // the carved IP. Unknown spelling (no hit) is not treated as embedding.
    if (n.candidateType === 'ip' || n.candidateType === 'ipv6') {
      const sourceHay = extra.rowText || block?.text || '';
      if (sourceHay && isOnlyEmbeddedInDnsHostname(sourceHay, n.candidateType, n.normalizedValue)) {
        lastAddRejection = 'embedded_in_dns_hostname';
        countReason(typeDiag.rejected_values, lastAddRejection);
        return null;
      }
    }
    const typingMeta = { ...(extra.typing || {}) };
    const zone = block?.zone || 'unknown';
    const strongZone = STRONG_IOC_ZONES.has(zone);

    // Dotted tokens: resolve per occurrence, decide per document (see pendingDotted).
    if (n.candidateType === 'domain') {
      const token = String(extra.originalValue || n.originalValue || raw).trim().replace(/\.$/, '');
      const form = extra.form || OCCURRENCE_FORMS.STANDALONE;
      const lineText = extra.rowText || block?.text || '';
      const typed = resolveDottedTokenType(token, {
        surroundingText: surroundingWindow(lineText, token, 160),
        typeLabel: extra.typeLabel || block?.type_label || null,
        declaredType: extra.declaredType || block?.declared_type_label || null,
        zone,
        blockType: block?.type || null,
        form,
        // Same focus-aware row reading occurrenceFor records as row_shape: a
        // <br>-split HTML line ("evil-host[.]com") is an indicator row for this
        // token even though its block is a paragraph, while a file name in a
        // hash row's description ("<sha256> - loader.node") is not.
        indicatorRow: strongZone && form !== OCCURRENCE_FORMS.EMAIL_DOMAIN && isIndicatorRowShape(lineText, token),
        strongZone,
        urlPathBasenames,
        knownUrlHosts
      });
      if (typed.kind === 'skip') {
        lastAddRejection = typed.reason;
        countReason(typeDiag.rejected_values, lastAddRejection);
        return null;
      }
      const id = n.normalizedValue;
      if (!pendingDotted.has(id)) pendingDotted.set(id, { token, occurrences: [] });
      pendingDotted.get(id).occurrences.push({ n, block, extra, typed, token, strongZone });
      return { deferred: true, candidate_type: 'domain', normalized_value: n.normalizedValue, is_ioc: true, typed };
    }

    let candidateType = n.candidateType;
    let isIoc = n.isIoc !== false && candidateType !== 'cve' && candidateType !== 'attack_technique';
    let artifactKind = typingMeta.artifact_kind || null;
    const syntaxGuess = NON_NETWORK_RESOLVED_TYPES.has(candidateType)
      ? candidateType === RESOLVED_TYPES.TECHNICAL_ARTIFACT
        ? 'domain'
        : 'url'
      : candidateType;
    if (NON_NETWORK_RESOLVED_TYPES.has(candidateType)) {
      isIoc = false;
      typingMeta.resolved_type = candidateType;
      typingMeta.typing_reason = typingMeta.typing_reason || n.typingReason || null;
      artifactKind = artifactKind || (candidateType === RESOLVED_TYPES.TECHNICAL_ARTIFACT ? 'identifier' : 'path');
      countReason(typeDiag.excluded_reasons, typingMeta.typing_reason || candidateType);
    } else if (candidateType === 'url') {
      typingMeta.resolved_type = 'url';
      typingMeta.typing_reason = typingMeta.typing_reason || n.typingReason || 'absolute_url';
    }
    return materialize({
      candidateType,
      normalizedValue: n.normalizedValue,
      originalValue: extra.originalValue || n.originalValue,
      n,
      block,
      extra,
      typingMeta,
      isIoc,
      artifactKind,
      typingSignals: typingMeta.typing_signals || null,
      syntaxGuess
    });
  }

  /** Evidence weight of one occurrence reading (domain vs artifact). */
  const READING_WEIGHT = Object.freeze({
    declared_network_type: 100,
    mutex_label: 100, code_label: 100, config_label: 100, registry_label: 100, file_label: 100, path_label: 100,
    command_label: 100, process_label: 100, metadata_label: 100,
    network_relation: 50,
    single_instance_identifier_context: 50, inline_artifact_label: 50, path_segment: 50,
    url_host: 40, explicit_indicator_row: 40, url_path_basename: 40,
    code_identifier_shape: 30, code_context: 30, multi_dot_ext: 30, file_extension: 30, extension_without_host_context: 20,
    method_suffix: 30, code_call: 30, code_block_weak_suffix: 20,
    network_context: 10, network_context_mixed_case: 10,
    artifact_context: 10, code_context_label: 10, config_context: 10, registry_context: 10, path_context: 10,
    command_context: 10, process_context: 10, metadata_context: 10, file_context: 10,
    hostname_shape: 1,
    no_network_semantics: 1
  });

  /**
   * Decide every deferred dotted token and materialize its candidate.
   */
  function resolvePendingDotted() {
    // Same value already typed as an artifact by a source-typed table row
    // ("File Name" column): that reading votes too, so one value never splits
    // into a domain (body mentions) and an artifact (the table).
    const tableArtifacts = new Map();
    for (const entry of byKey.values()) {
      if (!NON_NETWORK_RESOLVED_TYPES.has(entry.candidate_type)) continue;
      if (!entry.occurrences.some((o) => o.form === OCCURRENCE_FORMS.TABLE_ROW)) continue;
      tableArtifacts.set(String(entry.normalized_value).toLowerCase(), entry);
    }
    for (const [id, pending] of pendingDotted) {
      let domainScore = 0;
      let artifactScore = 0;
      let best = null;
      for (const occ of pending.occurrences) {
        const w = READING_WEIGHT[occ.typed.reason] ?? 5;
        if (occ.typed.kind === 'domain') domainScore += w;
        else artifactScore += w;
        if (!best || w > best.w) best = { w, occ };
      }
      const tableArtifact = tableArtifacts.get(String(id).toLowerCase()) || null;
      if (tableArtifact) artifactScore += READING_WEIGHT[tableArtifact.typing_reason] ?? READING_WEIGHT.file_label;
      // A source-declared network type from a typed Domain *table* cell is never
      // outvoted: explicit indicator tables stay complete. Heading-inherited
      // "Domains" labels only force domain for real delegated DNS suffixes —
      // eight `Node.js` prose mentions must not become a domain because one tag
      // inherited the preceding Domains sub-heading.
      const declaredNetwork = pending.occurrences.some((o) => {
        if (o.typed.reason !== 'declared_network_type') return false;
        if (o.extra.form === OCCURRENCE_FORMS.TABLE_ROW) return true;
        return hasDelegatedDnsSuffix(String(o.n.normalizedValue || ''));
      });
      // Nor is a domain reading of the publisher's own indicator row for this
      // exact token: narrative code-shaped spellings of the same value elsewhere
      // (`iRM eViLhOsT[.]COM` in an obfuscated command) cannot demote a curated
      // IOC entry. Only the focused row's own domain reading counts — an
      // artifact reading of a row (file extension, code shape) never does.
      // File-extension tokens without a delegated DNS suffix never count as an
      // asserted-row network reading (tag "Node.js" under Domains and IPs).
      const assertedRowNetwork = pending.occurrences.some((o) => {
        if (o.typed.kind !== 'domain' || o.typed.signals?.explicit_indicator_row !== true) return false;
        const last = String(o.n.normalizedValue || '')
          .toLowerCase()
          .split('.')
          .filter(Boolean)
          .pop();
        if (last && FILE_EXT_HINT.has(last) && !hasDelegatedDnsSuffix(String(o.n.normalizedValue || ''))) {
          return false;
        }
        return true;
      });
      const isDomain = declaredNetwork || assertedRowNetwork || domainScore > artifactScore;
      const winning = pending.occurrences
        .filter((o) => (o.typed.kind === 'domain') === isDomain)
        .sort((a, b) => (READING_WEIGHT[b.typed.reason] ?? 5) - (READING_WEIGHT[a.typed.reason] ?? 5))[0] || best.occ;
      const typed = winning.typed;
      const labelled = pending.occurrences.some((o) => (o.typed.kind === 'domain') === isDomain && o.typed.labelled);
      const asserted = pending.occurrences.some(
        (o) => o.extra.form === OCCURRENCE_FORMS.TABLE_ROW || o.extra.form === OCCURRENCE_FORMS.LIST_ROW || o.strongZone
      );
      if (!isDomain) {
        countReason(typeDiag.excluded_reasons, typed.reason);
        // A table-typed artifact identity already exists: body mentions attach to it.
        const retain = labelled || asserted || Boolean(tableArtifact);
        if (!retain) {
          // Incidental identifiers in prose (bytes.Index, Foo.Bar.Baz) are not report intelligence.
          typeDiag.artifact_occurrences_dropped += pending.occurrences.length;
          rememberExample(
            buildTypeResolutionRecord({
              raw: pending.token,
              syntaxGuess: 'domain',
              resolvedType: RESOLVED_TYPES.TECHNICAL_ARTIFACT,
              reason: typed.reason,
              promotion: 'excluded',
              signals: typed.signals
            })
          );
          continue;
        }
      }
      const candidateType = isDomain ? 'domain' : RESOLVED_TYPES.TECHNICAL_ARTIFACT;
      // Artifact reading joins the table's artifact identity when one exists.
      const artifactValue = !isDomain && tableArtifact && tableArtifact.candidate_type === candidateType
        ? tableArtifact.normalized_value
        : pending.token;
      for (const occ of pending.occurrences) {
        const typingMeta = {
          ...(occ.extra.typing || {}),
          resolved_type: candidateType,
          typing_reason: typed.reason,
          occurrence_reason: occ.typed.reason
        };
        const entry = materialize({
          candidateType,
          normalizedValue: isDomain ? occ.n.normalizedValue : artifactValue,
          originalValue: occ.extra.originalValue || occ.n.originalValue,
          n: occ.n,
          block: occ.block,
          extra: { ...occ.extra, typing: { ...(occ.extra.typing || {}), typing_reason: occ.typed.reason } },
          typingMeta: { ...typingMeta, typing_reason: typed.reason },
          isIoc: isDomain,
          artifactKind: isDomain ? null : typed.artifact_kind,
          typingSignals: typed.signals,
          syntaxGuess: 'domain'
        });
        // pushOccurrence recorded the document-level reason; keep the per-occurrence one too.
        const last = entry.occurrences[entry.occurrences.length - 1];
        if (last && last.block_id === (occ.block?.id || null)) last.typing_reason = occ.typed.reason;
      }
      const entry = byKey.get(candidateKey(candidateType, isDomain ? pending.occurrences[0].n.normalizedValue : artifactValue));
      if (entry) {
        entry.type_scores = { domain: domainScore, artifact: artifactScore };
      }
    }
    pendingDotted.clear();
  }

  /** "Host/path" identity of a URL value: scheme dropped, host case-folded, path verbatim. */
  function hostPathIdentity(value) {
    const rest = String(value || '').replace(URL_SCHEME_PREFIX_RE, '');
    const slash = rest.indexOf('/');
    if (slash <= 0) return null;
    return `${rest.slice(0, slash).toLowerCase()}${rest.slice(slash)}`;
  }

  function foldSchemeLessUrlAliases() {
    /** host/path → absolute URL entries with that host/path */
    const absolute = new Map();
    for (const entry of byKey.values()) {
      if (entry.candidate_type !== 'url' || !URL_SCHEME_PREFIX_RE.test(entry.normalized_value)) continue;
      const id = hostPathIdentity(entry.normalized_value);
      if (!id) continue;
      if (!absolute.has(id)) absolute.set(id, []);
      absolute.get(id).push(entry);
    }
    for (const [key, alias] of [...byKey]) {
      // Scheme-less spellings come from prose / rows (Pass 1b) and table cells alike.
      if (alias.candidate_type !== 'url' || URL_SCHEME_PREFIX_RE.test(alias.normalized_value)) continue;
      const targets = absolute.get(hostPathIdentity(alias.normalized_value)) || [];
      if (targets.length !== 1) continue;
      const target = targets[0];
      for (const occ of alias.occurrences) {
        const dup = target.occurrences.some(
          (o) => o.block_id && o.block_id === occ.block_id && (o.table_row == null || o.table_row === occ.table_row)
        );
        if (!dup) target.occurrences.push(occ);
      }
      for (const row of alias.table_rows || []) {
        if (target.table_rows.length < MAX_TABLE_ROWS_PER_CANDIDATE) target.table_rows.push(row);
      }
      if (STRONG_IOC_ZONES.has(alias.zone) && !STRONG_IOC_ZONES.has(target.zone)) {
        target.evidence_text = alias.evidence_text;
        target.block_id = alias.block_id;
        target.page_number = alias.page_number;
        target.section = alias.section;
        target.zone = alias.zone;
      }
      target.parsed.scheme_less_aliases = [...(target.parsed.scheme_less_aliases || []), alias.original_value].slice(0, 8);
      for (const keys of urlHostIndex.values()) {
        if (keys.delete(key)) keys.add(candidateKey('url', target.normalized_value));
      }
      explicitTableAssertions.rememberAlias('url', alias.normalized_value, target.normalized_value);
      byKey.delete(key);
    }
  }

  const blocks = annotated.blocks || [];
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

  // Pass 0: typed indicator tables — every valid row is a source assertion with row provenance.
  for (let blockIndex = 0; blockIndex < blocks.length; blockIndex += 1) {
    const block = blocks[blockIndex];
    if (block.type !== 'table' || !block.table) continue;
    const t = diagnostics.explicit_tables;
    t.tables_seen += 1;
    const interp = block.ioc_table;
    const summary = {
      table_id: block.id,
      page: block.page ?? null,
      zone: block.zone || null,
      section_heading: block.section_heading || null,
      kind: interp?.kind || 'not_ioc_table',
      explicit: Boolean(interp?.explicit),
      reason: interp?.reason || null,
      columns: Array.isArray(interp?.columns) ? interp.columns.map((c) => ({ index: c.index, header: c.header, intent: c.intent, method: c.method })) : [],
      rows_seen: interp?.stats?.rows_seen ?? 0,
      rows_valid: interp?.stats?.rows_valid ?? 0,
      rows_rejected: interp?.stats?.rows_rejected ?? 0,
      rejection_reasons: interp?.stats?.rejection_reasons || {},
      rejected_rows: []
    };
    t.tables.push(summary);
    if (!interp || (interp.kind !== 'ioc_table' && interp.kind !== 'artifact_table')) continue;
    if (interp.kind === 'ioc_table') t.ioc_tables += 1;
    if (interp.explicit) t.explicit_tables += 1;
    tableHandled.add(block.id);
    t.rows_seen += summary.rows_seen;
    t.rows_valid += summary.rows_valid;
    t.rows_rejected += summary.rows_rejected;
    for (const [reason, n] of Object.entries(summary.rejection_reasons)) {
      t.rejection_reasons[reason] = (t.rejection_reasons[reason] || 0) + n;
    }
    const columnLabels = tableColumnLabels(interp, blocks[blockIndex - 1]);
    for (const row of interp.rows || []) {
      if (row.status !== 'valid') {
        if (summary.rejected_rows.length < 12) summary.rejected_rows.push({ row_index: row.row_index, reason: row.reason });
        continue;
      }
      // Classification haystack (typing / credential / embedded-host checks)
      // stays the asserted cells; evidence shows the publisher's whole row.
      const rowText = [row.type_cell, row.values[0]?.indicator_cell, row.description].filter(Boolean).join(' | ');
      const rowCells = Array.isArray(row.cells) ? row.cells : [];
      const fullRowText = rowCells.filter(Boolean).join(' | ') || rowText;
      const observation = buildRowObservation({
        cells: rowCells,
        headers: columnLabels,
        indicatorColumns: interp.indicator_columns,
        slashOrder: slashDateOrder,
        notAfter: observationNotAfter
      });
      const attributeKinds = new Map((interp.columns || []).filter((c) => c.attribute_kind).map((c) => [c.index, c.attribute_kind]));
      const contextCells = rowCells
        .map((text, index) => ({
          column_index: index,
          header: columnLabels?.[index] || null,
          text,
          // Certificate / fuzzy-hash attribute of the row's sample (never an Indicator).
          ...(attributeKinds.has(index) ? { attribute_kind: attributeKinds.get(index) } : {})
        }))
        .filter((c) => c.text && !interp.indicator_columns.includes(c.column_index))
        .slice(0, 8)
        .map((c) => ({ ...c, text: c.text.slice(0, 160) }));
      const related = relatedValuesFromDescription(row.description);
      for (const v of row.values) {
        t.values_asserted += 1;
        const assertedIoc = Boolean(interp.explicit) && v.is_ioc !== false;
        if (assertedIoc && v.candidate_type && v.normalized_value) {
          explicitTableAssertions.rememberAsserted(v.candidate_type, v.normalized_value);
        }
        const tableRow = {
          table_id: block.id,
          page: block.page ?? null,
          row_index: row.row_index,
          column_index: v.column_index,
          // Publisher header of the value's own column ("Domain / IP", "URL").
          column_header: columnLabels?.[v.column_index] || null,
          declared_type: v.declared_type || null,
          type_cell: row.type_cell,
          indicator_cell: v.indicator_cell,
          raw_value: v.raw,
          description: row.description,
          explicit: Boolean(interp.explicit),
          declared_type_mismatch: v.declared_type_mismatch === true || undefined,
          related_values: related.length ? related : undefined,
          resolved_type: v.resolved_type || v.candidate_type,
          typing_reason: v.typing_reason || undefined,
          cells: contextCells.length ? contextCells : undefined,
          observation: observation || undefined,
          // Mixed cell provenance: the file identity and the hash(es) it carries.
          cell_companions: v.cell_companions?.length ? v.cell_companions : undefined,
          cell_residual: v.cell_residual || undefined
        };
        if (v.cell_companions?.length && v.is_ioc !== false) t.mixed_cells.recovered_values += 1;
        if (v.cell_companions?.length && v.is_ioc === false) t.mixed_cells.decomposed += 1;
        if (v.cell_residual) {
          t.mixed_cells.residual_unparsed += 1;
          for (const id of v.residual_observables || []) {
            if (t.mixed_cells.residual_observables.length < 24) {
              t.mixed_cells.residual_observables.push({ table_id: block.id, row_index: row.row_index, identity: id, zone: block.zone || null });
            }
          }
        }
        const entry = add(v.refanged, v.candidate_type, block, {
          form: OCCURRENCE_FORMS.TABLE_ROW,
          port: v.port ?? null,
          originalValue: v.raw,
          tableRow,
          rowText,
          evidenceRowText: fullRowText,
          typeLabel: row.type_cell || null,
          declaredType: v.declared_type || null,
          typing: {
            typing_reason: v.typing_reason || null,
            artifact_kind: v.artifact_kind || null,
            typing_signals: v.typing_signals || null
          },
          explicitTable: Boolean(interp.explicit)
        });
        if (assertedIoc && entry?.digest_kind && entry.candidate_type !== v.candidate_type) {
          explicitTableAssertions.rememberReclassified(v.candidate_type, v.normalized_value, entry.candidate_type);
        }
        if (assertedIoc && !entry) {
          explicitTableAssertions.rememberDropped(
            v.candidate_type,
            v.normalized_value,
            lastAddRejection || 'rejected'
          );
        }
      }
    }
    // Description cells: observables written in a row's prose cell. One whose
    // own clause gives it an actor-infrastructure role ("evil.example (C2
    // SystemBC)") in an explicit IOC table is that row's assertion; any other
    // is Context Only provenance — kept, never dropped (tl-candidates-v37).
    const descriptionCols = (interp.columns || []).filter((c) => c.intent === 'description');
    for (const row of interp.rows || []) {
      const rowValues = new Set((row.values || []).map((v) => candidateKey(v.candidate_type, v.normalized_value)));
      for (const col of descriptionCols) {
        const cell = String(row.cells?.[col.index] || '').trim();
        if (!cell) continue;
        for (const v of parseIndicatorCell(cell, null).values) {
          if (v.is_ioc === false || rowValues.has(candidateKey(v.candidate_type, v.normalized_value))) continue;
          if (v.candidate_type === 'domain' && !String(v.normalized_value).includes('.')) continue;
          const rowText = (row.cells || []).filter(Boolean).join(' | ');
          if (Boolean(interp.explicit) && descriptionClauseAssertsRole(cell, v.refanged)) {
            explicitTableAssertions.rememberAsserted(v.candidate_type, v.normalized_value);
            add(v.refanged, v.candidate_type, block, {
              form: OCCURRENCE_FORMS.TABLE_ROW,
              port: v.port ?? null,
              originalValue: v.raw,
              rowText,
              evidenceRowText: rowText,
              tableRow: {
                table_id: block.id,
                page: block.page ?? null,
                row_index: row.row_index,
                column_index: col.index,
                column_header: columnLabels?.[col.index] || null,
                declared_type: null,
                type_cell: row.type_cell || null,
                indicator_cell: cell,
                raw_value: v.raw,
                description: row.description,
                explicit: true,
                description_value: true
              },
              explicitTable: true
            });
          } else {
            // Context only: the value is related row metadata, so an endpoint
            // port written beside it is not recorded as the value's port.
            add(v.refanged, v.candidate_type, block, {
              form: OCCURRENCE_FORMS.STANDALONE,
              originalValue: v.raw,
              rowText,
              descriptionCell: true
            });
          }
        }
      }
    }
    // Reference columns ("Source" / "Download" / "Homepage" links of a tool
    // table): provenance of the row's subject, kept as Context Only values
    // and never asserted, whatever section the table sits in (tl-table-v9).
    // Resolution columns ("Resolved IP") are the same kind of provenance: the
    // row domain's DNS answer, not an actor address (tl-table-v10).
    for (const col of (interp.columns || []).filter((c) => c.attribute_kind === 'reference' || c.attribute_kind === 'resolution')) {
      const typingReason = col.attribute_kind === 'resolution' ? 'resolution_column' : 'reference_column';
      for (const row of interp.rows || []) {
        const cell = String(row.cells?.[col.index] || '').trim();
        if (!cell) continue;
        for (const v of parseIndicatorCell(cell, null).values) {
          if (v.is_ioc === false) continue;
          add(v.refanged, v.candidate_type, block, {
            form: OCCURRENCE_FORMS.STANDALONE,
            originalValue: v.raw,
            rowText: (row.cells || []).filter(Boolean).join(' | '),
            referenceCell: true,
            typingReason,
            typing: { typing_reason: typingReason }
          });
        }
      }
    }
    // Version-column release numbers of an indicator table are never row
    // values (tl-table-v5); keep them as version metadata, as the text pass does.
    const versionTokens = versionColumnTokens(block);
    for (const value of versionTokens?.inVersion || []) {
      if (versionTokens.elsewhere.has(value)) continue;
      add(value, RESOLVED_TYPES.TECHNICAL_ARTIFACT, block, {
        form: OCCURRENCE_FORMS.STANDALONE,
        originalValue: value,
        typing: { typing_reason: 'version_column', artifact_kind: 'metadata' }
      });
    }
  }

  // Pass 1: URLs — one candidate per URL; host/port/basename are parsed metadata only.
  /** @type {Map<string, Array<[number, number]>>} block id → URL spans */
  const urlSpansByBlock = new Map();
  for (const block of blocks) {
    if (tableHandled.has(block.id)) continue;
    const text = scanText(block);
    if (!text.trim()) continue;
    const spans = [];
    for (const m of text.matchAll(URL_RE)) {
      // Code interpolation ends the literal URL: `…/read?domain=${encodeURIComponent(d)}`
      // is the publisher URL "…/read?domain=" followed by a template expression.
      const literal = m[0].split('${')[0];
      const url = trimUrlBoundary(literal);
      if (!url) continue;
      spans.push([m.index, m.index + url.length]);
      const host = hostnameFromUrl(url);
      const base = pathBasenameFromUrl(url);
      if (host) knownUrlHosts.add(host);
      if (base && base.includes('.')) urlPathBasenames.add(base.toLowerCase());
      const isRow = isObservableRow(block);
      const entry = add(url, 'url', block, { form: isRow ? OCCURRENCE_FORMS.LIST_ROW : OCCURRENCE_FORMS.URL });
      if (entry) {
        if (host && !entry.parsed.host) {
          entry.parsed.host = host;
          entry.parsed.host_kind = isValidIpAddress(host) ? 'ip' : 'domain';
        }
        const port = portFromUrl(url);
        if (port != null) rememberPort(entry, port);
        if (base && !entry.parsed.path_basename) entry.parsed.path_basename = base;
        if (host) {
          if (!urlHostIndex.has(host)) urlHostIndex.set(host, new Set());
          urlHostIndex.get(host).add(candidateKey('url', entry.normalized_value));
        }
      }
    }
    // Pass 1b: scheme-less host/path resources ("js.cache-mcp[.]com/layer.js").
    // One URL occurrence in the publisher's exact spelling — no scheme is
    // invented, the path stays in the value, the host is parsed metadata only
    // (same no-over-derivation rule as absolute URLs) and the basename never
    // becomes a domain / artifact of its own.
    for (const m of text.matchAll(HOST_PATH_RE)) {
      const start = m.index;
      const raw = trimUrlBoundary(m[0]);
      if (!raw || insideAnySpan(spans, start, start + raw.length)) continue;
      const v = validateUrlCandidate(raw);
      if (!v.ok || v.reason !== 'scheme_less_url_with_dns_host' || v.host_kind !== 'domain') {
        countReason(typeDiag.scheme_less_resources.rejected, v.reason || 'invalid');
        continue;
      }
      const path = raw.slice(raw.indexOf('/'));
      if (path.length < 2) continue;
      spans.push([start, start + raw.length]);
      const base = pathBasenameFromUrl(`http://${raw}`);
      if (v.host) knownUrlHosts.add(v.host);
      if (base && base.includes('.')) urlPathBasenames.add(base.toLowerCase());
      const isRow = isObservableRow(block);
      const entry = add(raw, 'url', block, {
        form: isRow ? OCCURRENCE_FORMS.LIST_ROW : OCCURRENCE_FORMS.URL,
        originalValue: sourceSpelling(block.text, raw),
        typing: { typing_reason: 'scheme_less_url_with_dns_host' }
      });
      typeDiag.scheme_less_resources.count += 1;
      if (entry) {
        entry.parsed.scheme = null;
        entry.parsed.scheme_less = true;
        entry.parsed.path = path;
        if (v.host && !entry.parsed.host) {
          entry.parsed.host = v.host;
          entry.parsed.host_kind = 'domain';
        }
        if (base && !entry.parsed.path_basename) entry.parsed.path_basename = base;
        if (!urlHostIndex.has(v.host)) urlHostIndex.set(v.host, new Set());
        urlHostIndex.get(v.host).add(candidateKey('url', entry.normalized_value));
        if (typeDiag.scheme_less_resources.examples.length < 12) {
          typeDiag.scheme_less_resources.examples.push({
            block_id: block.id,
            raw: raw.slice(0, 200),
            resolved: { candidate_type: 'url', normalized_value: entry.normalized_value, host: v.host, path },
            decision: 'preserved_as_scheme_less_url',
            not_promotable_as: 'absolute_url_without_scheme'
          });
        }
      }
    }
    if (spans.length) urlSpansByBlock.set(block.id, spans);
  }

  // Pass 2: other observables. Host-like matches inside a URL span are the URL's
  // own host component — not an independent assertion — and are skipped.
  for (const block of blocks) {
    if (tableHandled.has(block.id)) continue;
    const text = scanText(block);
    if (!text.trim()) continue;
    const urlSpans = urlSpansByBlock.get(block.id) || [];
    const isRow = isObservableRow(block);
    const standaloneForm = isRow ? OCCURRENCE_FORMS.LIST_ROW : OCCURRENCE_FORMS.STANDALONE;
    /** @type {Array<[number, number]>} */
    const consumed = [];
    const versionTokens = versionColumnTokens(block);
    // Prose version reading applies outside publisher IOC sections and rows,
    // where a bare value is the publisher's assertion and stays authoritative.
    const proseVersions = !isRow && !STRONG_IOC_ZONES.has(block.zone || '');

    // Non-HTTP transport endpoints ("tcp://host:443"): the host, read as a
    // declared network host with its port; the endpoint spelling is provenance.
    for (const m of text.matchAll(NETWORK_ENDPOINT_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end)) continue;
      const host = m[2].toLowerCase();
      const isIp = isValidIpAddress(host);
      const port = m[3] && Number(m[3]) >= 1 && Number(m[3]) <= 65535 ? Number(m[3]) : null;
      const added = add(host, isIp ? 'ip' : 'domain', block, {
        form: isIp && port != null ? OCCURRENCE_FORMS.IP_PORT : standaloneForm,
        port,
        declaredType: isIp ? null : 'domain',
        typing: { typing_reason: 'network_endpoint_scheme' }
      });
      if (added) {
        networkEndpoints.push([isIp ? 'ip' : 'domain', host, m[0]]);
        consumed.push([start, end]);
      }
    }

    // IPv6 first: its spans keep an IPv4-mapped tail (`::ffff:192.0.2.1`)
    // from also reading as a separate IPv4 address.
    const ipv6Tokens = findIpv6Tokens(text).filter((t) => !insideAnySpan(urlSpans, t.start, t.end));
    const ipv6Spans = ipv6Tokens.map((t) => [t.start, t.end]);

    // IP:port endpoints (direct C2 endpoint assertions)
    for (const m of text.matchAll(IPV4_PORT_RE)) {
      const start = m.index;
      const ipEnd = start + m[1].length;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end) || insideAnySpan(ipv6Spans, start, end)) continue;
      if (!ipv4MatchIsStandalone(text, start, ipEnd)) continue;
      const port = Number(m[2]);
      if (!Number.isFinite(port) || port < 1 || port > 65535) continue;
      const entry = add(m[1], 'ip', block, { form: OCCURRENCE_FORMS.IP_PORT, port });
      if (entry) {
        // Keep the faithful source spelling when the endpoint form is the first sighting
        if (entry.occurrences.length === 1 && !entry.original_value.includes(':')) {
          entry.original_value = `${m[1]}:${m[2]}`;
        }
        consumed.push([start, end]);
      }
    }

    for (const m of text.matchAll(IPV4_RE)) {
      const start = m.index;
      const raw = String(m[0]);
      const slash = raw.indexOf('/');
      const ipEnd = start + (slash >= 0 ? slash : raw.length);
      const end = start + raw.length;
      if (insideAnySpan(urlSpans, start, end) || insideAnySpan(consumed, start, end) || insideAnySpan(ipv6Spans, start, end)) continue;
      if (!ipv4MatchIsStandalone(text, start, ipEnd)) continue;
      if (slash >= 0) add(raw, 'cidr', block, { form: standaloneForm });
      else if (versionTokens?.inVersion.has(raw) && !versionTokens.elsewhere.has(raw)) {
        // A release number in a software-version column ("Versions Affected":
        // 2.3.20.2) is version metadata, not an address. The same string in any
        // other cell of the table keeps the IPv4 reading.
        add(raw, RESOLVED_TYPES.TECHNICAL_ARTIFACT, block, {
          form: standaloneForm,
          originalValue: raw,
          typing: { typing_reason: 'version_column', artifact_kind: 'metadata' }
        });
      } else {
        const version = proseVersions ? ipv4VersionContext(text, start, end, { code: block.type === 'code' }) : null;
        if (version) {
          // A release number in prose ("Apache Struts 2.3.24.1 is vulnerable") is
          // version metadata; the same value under a network cue elsewhere keeps
          // its own IPv4 occurrence and identity.
          add(raw, RESOLVED_TYPES.TECHNICAL_ARTIFACT, block, {
            form: standaloneForm,
            originalValue: raw,
            typing: { typing_reason: 'version_context', artifact_kind: 'metadata' }
          });
        } else add(raw, 'ip', block, { form: standaloneForm });
      }
    }
    for (const t of ipv6Tokens) {
      if (!ipv4MatchIsStandalone(text, t.start, t.end)) continue;
      add(t.value, 'ipv6', block, { form: standaloneForm });
    }
    for (const m of text.matchAll(IPV6_LOOPBACK_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end) || insideAnySpan(consumed, start, end)) continue;
      add(m[0], 'ipv6', block, { form: standaloneForm });
    }
    // A hex run inside a URL / scheme-less resource span is that URL's path,
    // query or fragment component, not an independent file-hash occurrence.
    // Containment is per occurrence: a standalone spelling of the same value
    // in this block (or elsewhere) still creates the hash, and its evidence
    // window is anchored on that spelling, not on the URL copy.
    for (const [re, type] of HASH_PATTERNS) {
      for (const m of text.matchAll(re)) {
        if (insideAnySpan(urlSpans, m.index, m.index + m[0].length)) continue;
        // `pub-<hex>.r2.dev`: the run is part of a hostname label, not a hash.
        if (hexRunIsHostnameLabelFragment(text, m.index, m.index + m[0].length)) continue;
        const focusOrdinal = hitOffsets(text.slice(0, m.index), m[0]).length;
        add(m[0], type, block, { form: standaloneForm, focusOrdinal });
      }
    }
    for (const m of text.matchAll(CVE_RE)) add(m[0], 'cve', block, { form: standaloneForm });
    for (const m of text.matchAll(ATTACK_RE)) {
      if (/^T(1\d{3}|10\d{2}|11\d{2}|12\d{2}|15\d{2}|16\d{2})/.test(m[0])) {
        add(m[0], 'attack_technique', block, { form: standaloneForm });
      }
    }
    for (const m of text.matchAll(DOMAIN_RE)) {
      const start = m.index;
      const end = start + m[0].length;
      if (insideAnySpan(urlSpans, start, end) || insideAnySpan(consumed, start, end)) continue;
      // The local part of an email address ("decrypt.support@mail.example")
      // is a mailbox name whose dots only look like a hostname
      // (tl-candidates-v37): never a domain of its own.
      if (/^@[a-z0-9]/i.test(text.slice(end, end + 2))) continue;
      // Truncated publisher hostname: "online-driver.kro.k" (from "kro[.]k")
      // matches DOMAIN_RE as the prefix "...kro" because a 1-char final label
      // cannot be a TLD. Do not invent a shorter complete domain from that.
      if (/^\.[a-z0-9](?![a-z0-9-])/i.test(text.slice(end))) continue;
      // Redacted / truncated publisher hostname: "<REDACTED>-my.sharepoint.com"
      // matches only its tail "my.sharepoint.com". A hostname label never
      // starts with "-", and a redaction placeholder glued with "." hides the
      // leading labels: the tail is a different (parent) host, never derive it.
      if (isTruncatedHostTail(text, start)) continue;
      // `user@host.example`: the host is the address's domain (same
      // no-over-derivation rule as a URL host). Email is not a candidate type,
      // so the domain stays a candidate but never a structural row assertion.
      const emailDomain = start > 0 && text[start - 1] === '@';
      // `host.example:443`: keep the port as parsed endpoint context of the
      // domain (the occurrence form stays standalone — a port alone asserts
      // nothing about a hostname the way an ip:port endpoint does).
      const portM = emailDomain ? null : /^:(\d{1,5})(?!\d)/.exec(text.slice(end));
      const port = portM && Number(portM[1]) > 0 && Number(portM[1]) <= 65535 ? Number(portM[1]) : null;
      // Original spelling: identifier segmentation (Loader.Program.Main) is case-visible.
      add(m[0], 'domain', block, {
        form: emailDomain ? OCCURRENCE_FORMS.EMAIL_DOMAIN : standaloneForm,
        originalValue: m[0],
        ...(port != null ? { port } : {})
      });
    }
  }

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

  // One resource written "host/path" in one place and "https://host/path" in
  // another is one identity: the scheme-less spelling joins the absolute URL
  // the publisher wrote (no scheme is invented). When both http and https
  // spellings exist the scheme is ambiguous and the value stays as written.
  foldSchemeLessUrlAliases();

  // Incomplete path prefixes of sibling URLs (…/t/ when …/t/abc exists).
  markIncompleteUrlPrefixes(byKey);

  // Finalize: evidence policy + parser-derived host cross references
  const out = [];
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
    entry.document_has_authoritative_scope = documentScope.has_authoritative_indicator_scope;
    applyEvidencePolicy(entry);
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
  diagnostics.document_scope = documentScope;
  diagnostics.scope = buildScopeDiagnostics(annotated, out);

  // `annotated` is the zone-annotated document the candidates were read from
  // (read-only consumers: quality assessment, benchmark scoring).
  return { candidates: out, diagnostics, annotated };
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

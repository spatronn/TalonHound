/**
 * Shared token patterns and small readers for candidate extraction.
 */

import { refangObservable, refangTextForExtraction } from './defang.js';
import { STRONG_IOC_ZONES } from './documentZones.js';
import { parseIndicatorCell } from './tableSemantics.js';
import { isIndicatorValueLine, isObservableListLine, textDescribesValueAsBenign } from './indicatorScope.js';
import { hasDelegatedDnsSuffix, trimUrlBoundary } from './observableTypeResolver.js';
import { isDateCell, recoverHeaderLabels } from './sourceObservation.js';

/**
 * Recover a publisher-defanged domain from structured `block.links` when the
 * flattened block text glued a one-letter conjunction residue onto it
 * (Securelist "Domains and IPs" rows: "znews[.]net i investika…" → block text
 * "znews[.]neti" while the anchor text stays "znews[.]net").
 * @param {object} block
 * @param {string} matched DOMAIN_RE match from block text
 * @returns {string|null} preferred original spelling, or null
 */
export function recoverDefangedLinkDomain(block, matched) {
  const links = Array.isArray(block?.links) ? block.links : [];
  if (!links.length) return null;
  const matchedRef = refangObservable(matched).toLowerCase();
  if (!matchedRef) return null;
  for (const link of links) {
    const lt = String(link?.text || '').trim();
    if (!lt || !/\[\.\]|\(\.\)|\{\.\}/.test(lt)) continue;
    const ref = refangObservable(lt).toLowerCase();
    if (!ref || !hasDelegatedDnsSuffix(ref)) continue;
    if (matchedRef === ref) return lt;
    if (matchedRef.startsWith(ref) && matchedRef.length === ref.length + 1) return lt;
  }
  return null;
}

export const VERSION_CELL_TOKEN_SPLIT_RE = /[^0-9a-z.]+/i;

/** Same site family: exact host or subdomain (www. stripped). */
export function samePublisherHostFamily(a, b) {
  const na = String(a || '')
    .toLowerCase()
    .replace(/^www\./, '');
  const nb = String(b || '')
    .toLowerCase()
    .replace(/^www\./, '');
  if (!na || !nb) return false;
  return na === nb || na.endsWith(`.${nb}`) || nb.endsWith(`.${na}`);
}

/**
 * Origin URLs (`http://host/`) with path siblings: keep Indicator membership
 * when the publisher listed that origin as its own inventory row — either in
 * `explicit_ioc_section`, or as a list/table row under a C2 / sample /
 * operational subsection (Steam wallpaper C2 servers). A bare C2 paragraph
 * that only restates a path URL's origin stays demoted (RC-11 / MacSync).
 * @param {object} entry
 */
export function hasInventoryOriginOccurrence(entry) {
  return (entry.occurrences || []).some((o) => {
    const zone = String(o.zone || '');
    if (zone === 'explicit_ioc_section') return true;
    if (
      zone !== 'c2_section' &&
      zone !== 'sample_table' &&
      zone !== 'operational_infrastructure' &&
      zone !== 'delegated_ioc_scope'
    ) {
      return false;
    }
    // List/table inventory only. A bare C2 paragraph that restates a path
    // URL's origin keeps row_shape but is not inventory (RC-11 / MacSync).
    return (
      o.form === 'list_row' ||
      o.form === 'table_row' ||
      o.block_type === 'list_item' ||
      o.block_type === 'table'
    );
  });
}

/**
 * Actor-infrastructure role words a publisher writes next to a value in a
 * table description cell ("(C2 SystemBC)", "exfiltration server").
 */
export const DESCRIPTION_ROLE_WORDS =
  String.raw`(?:c2|c&c|cnc|command\s*(?:and|&)\s*control|exfil(?:tration)?\s+(?:server|domain|host|ip|infrastructure|endpoint)|malicious\s+(?:domain|host|server|ip|url|infrastructure)|phishing\s+(?:domain|site|page|url|server)|payload\s+(?:server|host|domain|url)|(?:download|staging|delivery)\s+server)`;
/** The role right before the value: "C2 domain X", "C2: X", "C&C server - X". */
export const ROLE_BEFORE_VALUE_RE = new RegExp(
  String.raw`(?:^|[^a-z0-9])${DESCRIPTION_ROLE_WORDS}(?:\s+(?:domain|host|server|ip|url|address|endpoint)s?)?\s*[:=\-–—]?\s*$`,
  'i'
);
/** The role right after the value: "X (C2 SystemBC)", "X - C2", "X is a C2 server". */
export const ROLE_AFTER_VALUE_RE = new RegExp(
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
export function descriptionClauseAssertsRole(cell, value) {
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
export function hasExplicitSingleValueRowOccurrence(entry) {
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
export function markIncompleteUrlPrefixes(byKey) {
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
      if (!hasInventoryOriginOccurrence(a)) a.incomplete_url_prefix = true;
      continue;
    }
    if (hasExplicitSingleValueRowOccurrence(a)) continue;
    a.incomplete_url_prefix = true;
  }
}

/** Cell texts of every canonical table block (publisher date-order evidence). */
export function* tableCellTexts(blocks) {
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
export function tableColumnLabels(interp, previousBlock) {
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
export function versionColumnTokens(block) {
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
export const IPV4_RE =
  /(?<![A-Za-z0-9_-]\.)\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(?:3[0-2]|[12]?\d))?\b(?!\.[A-Za-z0-9_-])/g;
export const IPV4_PORT_RE =
  /(?<![A-Za-z0-9_-]\.)\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))[:：](\d{1,5})\b/g;
/** Bare IPv6 loopback — leading `\b` fails because `:` is a non-word character. */
export const IPV6_LOOPBACK_RE = /(?<![0-9a-fA-F:])::1(?![0-9a-fA-F:])/g;
// Typographic quotes / guillemets never occur raw inside a URL (they are
// percent-encoded); in prose they close a quoted URL ("“https://x/y.exe”").
// ")" is matched and then balanced by trimUrlBoundary, so path parentheses
// ("report_(final).pdf") survive while prose / annotation parentheses do not.
// http(s) plus WebSocket C2 (wss?/ws). FTP/SSH/etc. stay host-only via
// NON_HTTP_NETWORK_SCHEME_RE — matching only http(s) collapsed `wss://host`
// to a bare domain (tl-candidates-v53).
export const URL_RE = /\b(?:https?|wss?):\/\/[^\s<>"'`\]‘’“”«»]+/gi;
/**
 * Scheme-less network resource: DNS-shaped host + path ("js.cache-mcp.com/layer.js").
 * The publisher gave no scheme, so none is invented: the exact host/path is
 * the value. Not preceded by a scheme separator, "@" or another label.
 */
export const HOST_PATH_RE = /(?<![\w@:\/.\-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?::\d{1,5})?(\/[^\s<>"'`\]，。；‘’“”«»]+)/gi;
/**
 * Scheme-less resource on an IPv4 host ("91.92.242[.]30/lamq4"). The path must
 * carry a non-digit so a CIDR prefix ("10.0.0.0/8") never reads as a URL
 * (tl-candidates-v43).
 */
export const IPV4_HOST_PATH_HEAD_RE = /^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\/(?=\S*[a-z_~%])/i;
export const IP_HOST_PATH_RE = /(?<![\w@:\/.\-])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?::\d{1,5})?(\/(?=[^\s<>"'`\]]*[a-z_~%])[^\s<>"'`\]，。；‘’“”«»]+)/gi;
export const URL_SCHEME_PREFIX_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
/**
 * A shell command separator glued to a URL on a command line starts the next
 * command, not a path segment: "fetch … http://h/kw2-s11;chmod${IFS}+x …",
 * "curl -skLo t https://h/d&pushd C:\…" (tl-candidates-v45). Only a bare word
 * after `;` / `&` / `|` in the path is cut; a query separator ("?a=1&b") or a
 * path parameter with a value (";jsessionid=…") is URL syntax and stays.
 */
export const SHELL_CONTINUATION_TAIL_RE = /(?:;|&&?|\|\|?)[A-Za-z_][\w.-]*$/;
export function trimShellContinuation(url) {
  const v = String(url || '');
  const m = SHELL_CONTINUATION_TAIL_RE.exec(v);
  if (!m) return v;
  const query = v.indexOf('?');
  if (query >= 0 && query < m.index) return v;
  const head = v.slice(0, m.index);
  return head.replace(URL_SCHEME_PREFIX_RE, '').includes('/') ? head : v;
}
/**
 * Transport endpoint written with a non-HTTP scheme ("tcp://c2.example:443",
 * "udp://198.51.100.7:53", "socks5://h:1080"). TalonHound URL values are web
 * resources, so the endpoint's host is the observable: the scheme declares it
 * a network host (never a `key: value` pair), the port is endpoint context and
 * the publisher's endpoint spelling is kept as provenance (tl-candidates-v37).
 */
export const NETWORK_ENDPOINT_RE =
  /\b(tcp|udp|tls|ssl|socks[45]h?|fqdn):\/\/((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}|(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))(?::(\d{1,5}))?(?![\w.-])/gi;
export const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b/gi;
/** A letter / mark / digit outside ASCII: part of an internationalised hostname label. */
export const NON_ASCII_LABEL_CHAR_RE = /[^\x00-\x7f](?<=[\p{L}\p{M}\p{N}])/u;
/**
 * Internationalised hostname (U-label spelling, ASCII TLD): "adidaš.com",
 * "rołex.com", "pаypal.com" (Cyrillic а). DOMAIN_RE only reads ASCII labels;
 * callers keep matches that contain a non-ASCII character (tl-candidates-v59).
 */
export const IDN_DOMAIN_RE =
  /(?<![\p{L}\p{M}\p{N}_.@-])(?:[\p{L}\p{N}](?:[\p{L}\p{M}\p{N}-]{0,61}[\p{L}\p{M}\p{N}])?\.)+[a-z]{2,63}(?![\p{L}\p{M}\p{N}_-])/giu;

/**
 * A URL written outside any table that is a truncation of a URL the publisher
 * lists in a table — it stops inside a path segment of the listed value
 * ("…/8250d149-…-ea925eae0a4" vs the table's "…/8250d149-…-ea925eae0a4c/") —
 * is a mistyped copy of that value, not a second resource. Its occurrences
 * are marked `truncated_duplicate` (row context, never an assertion); the
 * listed value carries the Indicator (tl-candidates-v40). A prefix that ends
 * at a segment boundary ("https://host/" vs "https://host/gate.php") is a
 * different resource and is left alone.
 * @param {object[]} entries candidate entries of the document
 */
export function markTruncatedUrlDuplicates(entries) {
  const urls = entries.filter((e) => e.candidate_type === 'url' && Array.isArray(e.occurrences));
  const listed = urls.filter((e) => e.occurrences.some((o) => o.form === OCCURRENCE_FORMS.TABLE_ROW));
  if (!listed.length) return;
  const strip = (v) => String(v || '').toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  for (const e of urls) {
    if (e.occurrences.some((o) => o.form === OCCURRENCE_FORMS.TABLE_ROW)) continue;
    const v = strip(e.normalized_value);
    if (!v.includes('/') || /[/?#=&]$/.test(v)) continue;
    const of = listed.find((l) => {
      const lv = strip(l.normalized_value);
      return lv.length > v.length && lv.startsWith(v) && /[A-Za-z0-9_-]/.test(lv[v.length]);
    });
    if (!of) continue;
    for (const o of e.occurrences) o.truncated_duplicate = true;
    e.truncated_duplicate_of = `url:${of.normalized_value}`;
  }
}

/**
 * A YubiKey one-time password (44 ModHex characters, factory public id
 * starting "cccc") pasted onto the end of a value by an accidental key touch:
 * "…&export=download" + "cccccdcjeegr…" (tl-candidates-v45).
 */
export const MODHEX_OTP_SUFFIX_RE = /cccc[cbdefghijklnrtuv]{40}$/;

/**
 * A table-listed URL whose value is another URL of the same document plus a
 * glued YubiKey OTP is that URL: the publisher listed the resource and the
 * OTP is a keyboard artifact. Only when the stripped value is corroborated
 * verbatim elsewhere in the document; a value with no corroboration stays as
 * written. The table occurrences (and their raw cell text, kept in
 * `table_rows[].raw_value`) move to the corroborated identity, so the
 * publisher's row assertion is not lost and stays traceable.
 * @param {Map<string, object>} byKey
 * @param {{ rememberAlias?: Function }} [tableAssertions] explicit-table tracker
 */
export function resolveOtpSuffixedTableUrls(byKey, tableAssertions) {
  const strip = (v) => String(v || '').replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  for (const [key, e] of [...byKey.entries()]) {
    if (e.candidate_type !== 'url' || !Array.isArray(e.occurrences)) continue;
    if (!e.occurrences.some((o) => o.form === OCCURRENCE_FORMS.TABLE_ROW)) continue;
    const m = MODHEX_OTP_SUFFIX_RE.exec(e.normalized_value);
    if (!m) continue;
    const clean = strip(e.normalized_value.slice(0, m.index));
    if (!clean.includes('/')) continue;
    const target = [...byKey.values()].find((c) => c !== e && c.candidate_type === 'url' && strip(c.normalized_value) === clean);
    if (!target) continue;
    for (const o of e.occurrences) {
      o.value_artifact = 'modhex_otp_suffix';
      target.occurrences.push(o);
    }
    target.table_rows = [...(e.table_rows || []), ...(target.table_rows || [])].slice(0, MAX_TABLE_ROWS_PER_CANDIDATE);
    if (STRONG_IOC_ZONES.has(e.zone) && !STRONG_IOC_ZONES.has(target.zone)) {
      for (const f of ['evidence_text', 'block_id', 'page_number', 'section', 'zone']) target[f] = e[f];
    }
    target.value_artifact_resolved_from = e.original_value || e.normalized_value;
    tableAssertions?.rememberAlias?.('url', e.normalized_value, target.normalized_value);
    byKey.delete(key);
  }
}

/** A defanged at-sign right before an address's domain ("[@]", "(@)", "{@}", "[at]", "(at)"). */
export const DEFANGED_AT_BEFORE_RE = /\w(?:\[@\]|\(@\)|\{@\}|\[at\]|\(at\))$/i;
/** The publisher says the sender address is forged ("Spoofed sender impersonating Boots UK"). */
export const SPOOFED_SENDER_RE = /\b(?:spoof\w*|impersonat\w*|forged|faked?\s+sender|display[\s-]?name\s+spoof\w*)\b/i;

/** A redaction placeholder right before a hostname tail ("<REDACTED>", "[redacted]", "REDACTED", "xxx"). */
export const REDACTION_PLACEHOLDER_END_RE = /(?:<\s*[^<>\s]{0,24}\s*>|\[\s*[^\[\]\s]{0,24}\s*\]|\bredacted|\b[x*]{3,})\s*$/i;
// A placeholder glued onto the hostname with no separator. Email defang
// ("user[@]onionmail[.]org") also ends in "]" and must not match.
export const GLUED_REDACTION_END_RE = /(?:<\s*(?:redacted|x{3,}|\*{3,})\s*>|\[\s*(?:redacted|x{3,}|\*{3,})\s*\])\s*$/i;

/**
 * True when the DOMAIN_RE match starting at `start` is only the tail of a
 * longer publisher hostname the regex could not read ("<REDACTED>-my.x.com",
 * "<REDACTED>.example.com").
 * @param {string} text
 * @param {number} start
 */
export function isTruncatedHostTail(text, start) {
  if (start <= 0) return false;
  const prev = text[start - 1];
  if (prev === '-') return true;
  // "niḳe.com" / "rołex.com": the ASCII matcher reads only the tail after the
  // non-ASCII letter ("e.com", "ex.com"). That tail is a different, unrelated
  // host; the whole internationalised name is read by IDN_DOMAIN_RE
  // (tl-candidates-v59).
  if (NON_ASCII_LABEL_CHAR_RE.test(prev)) return true;
  // "<REDACTED>.example.com" hides labels behind the dot. "[redacted]post-app.com"
  // and "<REDACTED>benefitsportal.com" glue the placeholder directly onto the
  // visible tail: that tail is not the publisher's hostname (tl-candidates-v46).
  if (prev === '.') {
    return REDACTION_PLACEHOLDER_END_RE.test(text.slice(Math.max(0, start - 48), start - 1));
  }
  if (prev === ']' || prev === '>') {
    return GLUED_REDACTION_END_RE.test(text.slice(Math.max(0, start - 48), start));
  }
  return false;
}
export const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
export const SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
export const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
export const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
export const ATTACK_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

export const MAX_TABLE_ROWS_PER_CANDIDATE = 20;

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
export function sourceSpelling(blockText, refanged) {
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
 * The publisher's spelling of `refanged` when it stands alone on a line of
 * the block ("txjIQslrRIg[.]MSwINSOFTUPDLoaD[.]DesiGN" in a pack), else null.
 * @param {string} blockText
 * @param {string} refanged
 */
export function standaloneLineSpelling(blockText, refanged) {
  const want = String(refanged || '').toLowerCase();
  for (const line of String(blockText || '').split(/\r?\n/)) {
    const t = line.trim().replace(/^[-*•·▪]\s*/, '');
    if (t && (refangObservable(t) || t).toLowerCase() === want) return t;
  }
  // A block that is only observables (a plain-text pack whose lines the
  // document joined) lists the token as one of its rows.
  if (isObservableListLine(refangTextForExtraction(String(blockText || '')))) {
    const spelled = sourceSpelling(blockText, refanged);
    if (spelled && spelled !== refanged) return spelled;
  }
  return null;
}

/**
 * "<label>: <digest>" for a digest in a run of "<digest> (<label>)" rows
 * (tl-candidates-v50), else null.
 * @param {string} line
 * @param {string} value
 */
export function annotatedDigestWindow(line, value) {
  const text = String(line || '');
  if ((text.match(/\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b\s*\(/gi) || []).length < 2) return null;
  const at = text.toLowerCase().indexOf(String(value || '').toLowerCase());
  if (at < 0) return null;
  let i = at + String(value).length;
  while (i < text.length && /\s/.test(text[i])) i += 1;
  if (text[i] !== '(') return null;
  let depth = 0;
  let j = i;
  for (; j < text.length; j += 1) {
    if (text[j] === '(') depth += 1;
    else if (text[j] === ')') {
      depth -= 1;
      if (depth === 0) break;
    }
  }
  // The label as the digest's own lead label ("Ligolo TLS certificate: <hex>").
  return `${text.slice(i + 1, j).trim()}: ${text.slice(at, at + String(value).length)}`;
}

/**
 * Parse port from an http(s) URL when explicitly present.
 * @param {string} url
 */
export function portFromUrl(url) {
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
export function insideAnySpan(spans, start, end) {
  for (const [s, e] of spans) {
    if (start >= s && end <= e) return true;
  }
  return false;
}

/** Case-insensitive, non-overlapping offsets of `value` in `text`. */
export function hitOffsets(text, value) {
  const hay = String(text || '').toLowerCase();
  const needle = String(value || '').toLowerCase();
  const out = [];
  if (!needle) return out;
  for (let i = hay.indexOf(needle); i >= 0; i = hay.indexOf(needle, i + needle.length)) out.push(i);
  return out;
}

/**
 * A row description that LEADS with "Historical resolution for / of <name>":
 * the value is that name's passive-DNS answer. A description that merely
 * mentions the history ("Open-directory staging server; historically resolved
 * C2 domains via x.com") asserts the value itself and never matches.
 */
export const DEFANGED_DOT_PATTERN = '(?:\\.|\\s?\\\\?\\[\\.\\\\?\\]\\s?|\\(\\.\\)|\\{\\.\\}|\\[dot\\]|\\(dot\\))';
export const DEFANGED_SCHEME_PATTERN = '[a-z]{2,6}';
export const DEFANGED_AUTHORITY_PATTERN = '(?:\\[?:\\]?|\\[:/?\\]?)(?:\\\\?/){1,2}';

/** Bound on tokens logged as rejected per document. */
export const MAX_TOKEN_LOG = 4000;

/**
 * Character offsets of a value in its block's text (the publisher's spelling
 * first, then case-insensitive). Null when the spelling is not verbatim there,
 * e.g. a value joined from a wrapped cell.
 * @param {string|null|undefined} text
 * @param {string|null|undefined} value
 */
export function locateInBlockText(text, value) {
  const hay = String(text || '');
  const needle = String(value || '');
  if (!hay || !needle) return null;
  let at = hay.indexOf(needle);
  if (at < 0) at = hay.toLowerCase().indexOf(needle.toLowerCase());
  if (at >= 0) return { start: at, end: at + needle.length };
  // The block holds the publisher's defanged spelling of a normalized value.
  const pattern = needle
    .slice(0, 400)
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\\\./g, DEFANGED_DOT_PATTERN)
    .replace(/^(?:https?|wss?|ftp)/i, DEFANGED_SCHEME_PATTERN)
    .replace(/:\/\//, DEFANGED_AUTHORITY_PATTERN);
  const m = new RegExp(pattern, 'i').exec(hay);
  return m ? { start: m.index, end: m.index + m[0].length } : null;
}

export const HISTORICAL_RESOLUTION_ROW_RE = /(?:^|·\s*)\s*historical\s+(?:dns\s+)?resolutions?\s+(?:for|of)\b/i;
export const HASH_CANDIDATE_TYPES = new Set(['md5', 'sha1', 'sha256']);
/** A truncated digest shorter than this identifies nothing (tl-candidates-v54). */
export const MIN_TRUNCATED_DIGEST_PREFIX = 16;
/** File hashes, longest first: `\b` keeps a shorter length from matching inside a longer hex run. */
export const HASH_PATTERNS = [
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
export function relatedValuesFromDescription(description) {
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
export function listLeadInsByBlock(blocks) {
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

/** A lead-in that introduces the run of values after it ("these IPs …", "the following …"). */
export const VALUE_RUN_LEAD_IN_RE = /\b(?:these|the\s+following|following|below)\b/i;

/**
 * block id → lead-in of a run of bare value lines written as paragraphs
 * ("Microsoft assesses that these IPs are part of the C2 infrastructure." then
 * "• 93.115[.]10.35" paragraphs): the prose paragraph right before the run,
 * when it introduces it (tl-candidates-v48). A heading or any other block ends
 * the run.
 * @param {object[]} blocks
 */
export function valueLineLeadInsByBlock(blocks) {
  const out = new Map();
  let leadIn = null;
  for (const b of blocks) {
    const t = String(b?.text || '').trim();
    if ((b?.type === 'paragraph' || b?.type === 'list_item') && isIndicatorValueLine(t)) {
      if (leadIn) out.set(b.id, leadIn);
      continue;
    }
    leadIn = b?.type === 'paragraph' && t.length <= 400 && VALUE_RUN_LEAD_IN_RE.test(t) ? t : null;
  }
  return out;
}

/** A list assignment in a hunting query / code sample: `let c2ip = dynamic([`, `deliveryHosts = [`. */
export const CODE_LIST_ASSIGN_RE = /\b(?:let\s+|var\s+|const\s+|set\s+)?([A-Za-z_][\w]*)\s*=\s*(?:dynamic\s*\(\s*)?\[/g;

/**
 * block id → name of the code list the block's values belong to. Publishers
 * render one hunting-query line per code block, so an open list (`let c2ip =
 * dynamic([` …) continues over the following code blocks until it closes
 * (tl-candidates-v48). The name is recorded on the occurrence only; it never
 * changes the relation or membership.
 * @param {object[]} blocks
 */
export function codeListNamesByBlock(blocks) {
  const out = new Map();
  let open = null;
  for (const b of blocks) {
    if (b?.type !== 'code') {
      open = null;
      continue;
    }
    const t = String(b?.text || '');
    let name = open;
    CODE_LIST_ASSIGN_RE.lastIndex = 0;
    let m;
    let at = -1;
    while ((m = CODE_LIST_ASSIGN_RE.exec(t)) !== null) {
      name = m[1];
      at = m.index + m[0].length;
    }
    if (name) out.set(b.id, name);
    const tail = at >= 0 ? t.slice(at) : t;
    open = name && !/\]/.test(tail) ? name : null;
  }
  return out;
}

/**
 * Header of the table column that holds `value` (a digest cell), from the
 * block's declared headers or its first row when that row holds no digest.
 * @param {object} block
 * @param {string} value normalized hex value
 * @returns {string|null}
 */
export function digestColumnHeader(block, value) {
  const rows = block?.type === 'table' && Array.isArray(block?.table?.rows) ? block.table.rows : null;
  if (!rows || rows.length < 2) return null;
  const v = String(value || '').toLowerCase();
  const declared = Array.isArray(block.table.headers) && block.table.headers.length ? block.table.headers : null;
  const first = rows[0].map((c) => String(c ?? ''));
  const header = declared || (first.some((c) => /\b[0-9a-f]{32,}\b/i.test(c)) ? null : first);
  if (!header) return null;
  for (let r = declared ? 0 : 1; r < rows.length; r += 1) {
    const row = Array.isArray(rows[r]) ? rows[r] : [];
    const col = row.findIndex((c) => String(c ?? '').toLowerCase().includes(v));
    if (col >= 0) return String(header[col] ?? '').trim() || null;
  }
  return null;
}

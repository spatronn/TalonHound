/**
 * Prose context of one IPv4-shaped token: software version or address?
 *
 * The numeric value never decides — "2.3.24.1" is a release number after
 * "Apache Struts" / "versions prior to" and an address after "C2 server:".
 * Only the clause around the token (never the paragraph) is read, and the
 * result is conservative: anything short of explicit version evidence keeps
 * the existing IPv4 reading.
 *
 *   network cue at the token ("C2 IP", "server", "connected to") → address
 *   version cue (keyword / non-IPv4 range sibling / "and earlier" /
 *   product name right before)                                  → version
 *   neither                                                      → address
 */

/** Dotted numeric release token (2.3.19, 9.9.7-P2, 8.2R12.1, 4.x) — any shape. */
const VERSIONISH = String.raw`\d+(?:\.[0-9x*]+)+[a-z0-9-]*`;
const RANGE_CONNECTOR = String.raw`(?:to|through|thru|until|-|–|—)`;
const LIST_CONNECTOR = String.raw`(?:,|;|and|or|${RANGE_CONNECTOR})`;
/** Trailing run of earlier list members ("2.3.19 to ", "2.3.20.2, 2.3.21 and ") before the token. */
const LIST_TAIL_RE = new RegExp(`(?:\\(?\\s*${VERSIONISH}\\s*\\)?\\s*${LIST_CONNECTOR}\\s*)+$`, 'i');
const IPV4_SHAPE_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** Network / IOC relation right before the token (after list members are skipped). */
const NETWORK_CUE_BEFORE_RE =
  /\b(?:ip|ips|ipv4|ip\s+address(?:es)?|address(?:es)?|addr|c2|c&c|cnc|command\s+and\s+control|server|servers|host|hosts|hostname|node|nodes|relay|proxy|gateway|endpoint|endpoints|infrastructure|sinkhole[ds]?|panel|controller|beacon(?:s|ed|ing)?(?:\s+to)?|callback(?:s)?(?:\s+to)?|connect(?:s|ed|ing|ion|ions)?(?:\s+(?:to|from|with))?|contact(?:s|ed|ing)?|communicat(?:e|es|ed|ing)\s+with|traffic\s+(?:to|from)|resolv(?:e|es|ed|ing)\s+to|egress|ingress|exfiltrat\w*\s+to|download(?:s|ed|ing)?\s+from|upload(?:s|ed|ing)?\s+to|hosted\s+(?:on|at)|listen(?:s|ed|ing)?\s+on|destination|source|src|dst|attacker|actor)\W*$/i;

/** Version keyword right before the token, optionally followed by a list verb. */
const VERSION_CUE_BEFORE_RE = new RegExp(
  String.raw`(?:\b(?:versions?|ver\.?|release[sd]?|build(?:s)?|firmware|revision|rev\.?|patch(?:ed)?|fixed\s+in|introduced\s+in|upgrade[ds]?\s+(?:from|to)|downgrade[ds]?\s+(?:from|to))` +
    String.raw`(?:\s*(?:[:=#]|number|no\.?|is|was|are|were|of|include[sd]?|including|prior\s+to|before|after|up\s+to|through|from|between|earlier\s+than|later\s+than|older\s+than|newer\s+than|<=?|>=?))*\s*\(?\s*)$`,
  'i'
);

/** Version phrase right after the token ("is vulnerable", "and earlier"). */
const VERSION_CUE_AFTER_RE =
  /^\s*\)?\s*(?:(?:and|or)\s+(?:earlier|later|prior|older|newer|above|below|lower|higher)\b|(?:is|are|was|were)\s+(?:vulnerable|affected|impacted|patched|fixed|unsupported|end[-\s]of[-\s]life|deprecated)\b|(?:release|build|version)\b)/i;

/** Role / network nouns that may precede an address in title case ("Server 1.2.3.4"). */
const NOT_A_PRODUCT = new Set(
  (
    'ip ips address addresses host hosts server servers node nodes relay proxy gateway endpoint endpoints client clients victim victims attacker attackers actor actors operator operators controller panel beacon bot bots machine machines system systems device devices router routers sensor sensors honeypot domain domains from to at via on in and or the a an then also source destination target targets scanner scanners resolver resolvers dns vps asn subnet network networks peer peers infrastructure callback sinkhole ' +
    // sentence adverbs / determiners that may open a clause in title case
    'initially later finally additionally subsequently next first second also this that these those its their both each all only between during after before since when while where which'
  ).split(' ')
);
/**
 * A product name right before the token is the weakest cue: it also needs a
 * vulnerability / release word in the same clause ("After exploitation, Struts
 * 2.3.24.1 …"), never applies in code, and never to a `value: label` row
 * ("Pitboss Shell 62.133.62.80: Payload Delivery").
 */
const RELEASE_CLAUSE_RE = /\b(?:vulnerab\w*|exploit\w*|cve-\d|patch\w*|affected|releases?|versions?|updates?|updated|upgrade[ds]?|fixed|end[-\s]of[-\s]life)\b/i;
const LABEL_ROW_AFTER_RE = /^\s*:(?!\d)/;
/** A product name: one word with lower-case letters (Struts, OpenSSL, WebLogic), not a role noun. */
const PRODUCT_WORD_BEFORE_RE = /(?:^|[\s(])([A-Z][A-Za-z0-9+._-]*[a-z][A-Za-z0-9+._-]*)\s+\(?\s*$/;

/** Clause boundaries: sentence ends, semicolons, table cells / rows, line breaks. */
function clauseBefore(text, start, max = 90) {
  const head = text.slice(Math.max(0, start - max), start);
  const cut = Math.max(head.lastIndexOf('. '), head.lastIndexOf('; '), head.lastIndexOf('\n'), head.lastIndexOf(' ¶ '), head.lastIndexOf(' | '), head.lastIndexOf('! '), head.lastIndexOf('? '));
  return cut >= 0 ? head.slice(cut + 2) : head;
}
function clauseAfter(text, end, max = 50) {
  const tail = text.slice(end, end + max);
  const m = tail.search(/(?:[.;!?](?:\s|$)|\n| ¶ | \| )/);
  return m >= 0 ? tail.slice(0, m) : tail;
}

/**
 * @param {string} text   refanged block text
 * @param {number} start  token start
 * @param {number} end    token end
 * @param {{ code?: boolean }} [opts] code: the block is a code / command sample
 * @returns {{ kind: 'version', cue: string }|null} null = keep the IPv4 reading
 */
export function ipv4VersionContext(text, start, end, opts = {}) {
  const s = String(text || '');
  const before = clauseBefore(s, start);
  const after = clauseAfter(s, end);
  const listTail = before.match(LIST_TAIL_RE);
  const head = listTail ? before.slice(0, listTail.index) : before;
  // A network relation at the token always wins (also when it introduces a list).
  if (NETWORK_CUE_BEFORE_RE.test(before) || NETWORK_CUE_BEFORE_RE.test(head)) return null;
  if (VERSION_CUE_BEFORE_RE.test(before) || (listTail && VERSION_CUE_BEFORE_RE.test(head))) return { kind: 'version', cue: 'version_keyword' };
  // A range whose other end is a release number, never an address ("2.3.19 to 2.3.20.2").
  const prevSibling = before.match(new RegExp(`(${VERSIONISH})\\s*${RANGE_CONNECTOR}\\s*$`, 'i'));
  const nextSibling = after.match(new RegExp(`^\\s*${RANGE_CONNECTOR}\\s*(${VERSIONISH})`, 'i'));
  if ((prevSibling && !IPV4_SHAPE_RE.test(prevSibling[1])) || (nextSibling && !IPV4_SHAPE_RE.test(nextSibling[1]))) {
    return { kind: 'version', cue: 'version_range' };
  }
  if (VERSION_CUE_AFTER_RE.test(after)) return { kind: 'version', cue: 'version_phrase' };
  if (opts.code || LABEL_ROW_AFTER_RE.test(after)) return null;
  const product = head.match(PRODUCT_WORD_BEFORE_RE);
  if (product && !NOT_A_PRODUCT.has(product[1].toLowerCase()) && RELEASE_CLAUSE_RE.test(`${before} ${after}`)) {
    return { kind: 'version', cue: 'product_version' };
  }
  return null;
}

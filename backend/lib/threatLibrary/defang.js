/**
 * Defang / refang helpers for threat-report text.
 * Converts common defanged forms to strings that existing TalonHound normalizers accept.
 * Does not invent conflicting normalization — output is fed into normalizeObservable / etc.
 */

// hxxp://, hxxp[://], hxxp[:]//, hxxp[:][//]
const HXXP_RE = /\bhxxps?(?::\/\/|\[:\/\/\]|\[:\]\/\/|\[:\]\[\/\/\])/gi;
// http[://], http[:]//, http[:][//]
const SCHEME_BRACKET_RE = /\b(https?)(?:\[:\/\/\]|\[:\]\/\/|\[:\]\[\/\/\])/gi;
// hxxp[:]host / http[:]host — bracketed colon without any authority slashes
// (Unit42 Gremlin shape "hxxp[:]194.87.92[.]109/i.php", tl-defang-v4). Only
// when a dotted host or IPv4 follows, so "http: status" prose stays.
const BRACKET_COLON_NO_SLASH_SCHEME_RE =
  /\b(h(?:tt|xx)ps?)\[:\](?!\/)(?=(?:[a-z0-9-]+(?:\.|\[\.\]|\(\.\)))+[a-z0-9-]+|\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}\b)/gi;
// After bracket-colon → colon: "hxxp:194.87…" / "http:host.tld/path" still
// missing "//". Same host lookahead (tl-defang-v4).
const COLON_NO_SLASH_SCHEME_RE =
  /\b(h(?:tt|xx)ps?):(?!\/\/)(?=(?:[a-z0-9-]+(?:\.|\[\.\]|\(\.\)))+[a-z0-9-]+(?:[:/?#\s]|$)|\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}\b)/gi;
// Publisher typo "http//host" / "hxxps//host" (the scheme colon dropped,
// tl-defang-v3): recovered only when a dotted host (name or IPv4, fanged or
// bracket-defanged) follows the slashes, so prose such as "http//" alone or
// "see http//docs" stays untouched.
const MISSING_COLON_SCHEME_RE =
  /\b(h(?:tt|xx)ps?)\/\/(?=(?:[a-z0-9-]+(?:\.|\[\.\]|\(\.\)))+[a-z0-9-]+(?:[:/?#\s]|$)|\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}\b)/gi;
// "https[:]/host/path" / "https:/host" (one slash of the authority marker
// dropped): recovered after the colon / dot refang, only before a dotted host
// followed by a path, port, query or end (tl-defang-v3).
const SINGLE_SLASH_SCHEME_RE = /\b(https?):\/(?!\/)(?=(?:[a-z0-9-]+\.)+[a-z0-9-]+(?:[/:?#\s]|$))/gi;
// The bracket closes inside the authority marker ("http[:/]/host",
// "hxxp[:]/" + "/host", tl-defang-v5): the colon and exactly two slashes split
// across the bracket. Same dotted-host lookahead as the forms above.
const SPLIT_BRACKET_SCHEME_RE =
  /\b(h(?:tt|xx)ps?)\[:(\/{0,2})\](\/{0,2})(?=(?:[a-z0-9-]+(?:\.|\[\.\]|\(\.\)))+[a-z0-9-]+|\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}(?:\.|\[\.\])\d{1,3}\b)/gi;
const BRACKET_DOT_RE = /\[\.\]|\(\.\)|\{\.\}/g;
// Publisher variants of the bracketed dot between two hostname characters
// (tl-defang-v2): whitespace inside the brackets ("evil[ . ]com"), a single
// space on ONE side ("sfrclak [.]com", "evil[.] com") and mismatched square /
// curly pairs ("ssd[.}png"). Hostname characters are required on both sides;
// a dot spaced on both sides ("a [.] b") or a parenthesised dot with outer
// whitespace ("item (.) list") is prose and stays untouched.
const BRACKET_DOT_LEFT_SPACE_RE = /([A-Za-z0-9-]) ?[[{] *\. *[\]}](?=[A-Za-z0-9-])/g;
const BRACKET_DOT_RIGHT_SPACE_RE = /([A-Za-z0-9-])[[{] *\. *[\]}] ?(?=[A-Za-z0-9-])/g;
/** Bracketed-dot defang residue left in a value after refanging. */
export const DEFANG_RESIDUE_RE = /[[({] *\. *[\])}]|\[ *\.|\. *\]|\{ *\.|\. *\}/;

function refangDots(text) {
  return String(text || '')
    .replace(BRACKET_DOT_LEFT_SPACE_RE, '$1.')
    .replace(BRACKET_DOT_RIGHT_SPACE_RE, '$1.')
    .replace(BRACKET_DOT_RE, '.');
}
const BRACKET_COLON_RE = /\[:\]|\(:\)|\{:\}/g;
// Markdown-escaped bracket defang emitted verbatim by some CMSes inside code
// spans: `evil\[.\]com`, `hxxps\[:\]//`, `evil\[.]com`. Only the escape of a
// bracket that encloses a defang token is removed; other backslashes stay.
const MD_ESCAPED_DEFANG_RE = /\\\[(\.|:|:\/\/|\/\/)\\?\]|\[(\.|:|:\/\/|\/\/)\\\]/g;
const MD_ESCAPED_DEFANG_TEST_RE = /\\\[(?:\.|:|:\/\/|\/\/)\\?\]|\[(?:\.|:|:\/\/|\/\/)\\\]/;

export function unescapeMarkdownDefang(text) {
  return String(text || '').replace(MD_ESCAPED_DEFANG_RE, (_, a, b) => `[${a ?? b}]`);
}

/**
 * Zero-width / invisible format characters (ZWSP, ZWNJ, ZWJ, word joiner,
 * BOM, soft hyphen) pasted into publisher HTML: never part of an observable,
 * and they must not glue a label to a value ("Server: ​ftp://host").
 * @param {string} text
 */
export function stripInvisibleFormatChars(text) {
  return String(text || '').replace(/[­​-‍⁠﻿]/g, '');
}

function normalizeScheme(scheme) {
  return String(scheme || '').toLowerCase().replace('hxxp', 'http');
}

function refangSchemes(text) {
  return String(text || '')
    .replace(SPLIT_BRACKET_SCHEME_RE, (m, scheme, inner, outer) =>
      (inner.length + outer.length === 2 ? `${normalizeScheme(scheme)}://` : m))
    .replace(MISSING_COLON_SCHEME_RE, (_, scheme) => `${normalizeScheme(scheme)}://`)
    .replace(BRACKET_COLON_NO_SLASH_SCHEME_RE, (_, scheme) => `${normalizeScheme(scheme)}://`)
    .replace(HXXP_RE, (m) => (m.toLowerCase().startsWith('hxxps') ? 'https://' : 'http://'))
    .replace(SCHEME_BRACKET_RE, (_, scheme) => `${scheme.toLowerCase()}://`);
}

/**
 * Refang a single token or short string.
 * @param {string} value
 */
export function refangObservable(value) {
  let v = stripInvisibleFormatChars(String(value || '')).trim();
  if (!v) return '';
  v = refangSchemes(unescapeMarkdownDefang(v));
  v = refangDots(v);
  v = v.replace(BRACKET_COLON_RE, ':');
  // meow:// → http:// (rare vendor defang)
  v = v.replace(/\bmeow:\/\//gi, 'http://');
  // "hxxp:host" / "http:194.87…" left after bracket-colon → colon (tl-defang-v4).
  v = v.replace(COLON_NO_SLASH_SCHEME_RE, (_, scheme) => `${normalizeScheme(scheme)}://`);
  v = v.replace(SINGLE_SLASH_SCHEME_RE, (_, scheme) => `${scheme.toLowerCase()}://`);
  return v.trim();
}

/**
 * Light-touch prep of a text blob so deterministic extractors see fanged IOCs.
 * Keeps surrounding prose intact.
 * @param {string} text
 */
export function refangTextForExtraction(text) {
  let t = refangSchemes(unescapeMarkdownDefang(stripInvisibleFormatChars(String(text ?? ''))));
  t = refangDots(t);
  t = t.replace(BRACKET_COLON_RE, ':');
  t = t.replace(/\bmeow:\/\//gi, 'http://');
  t = t.replace(COLON_NO_SLASH_SCHEME_RE, (_, scheme) => `${normalizeScheme(scheme)}://`);
  t = t.replace(SINGLE_SLASH_SCHEME_RE, (_, scheme) => `${scheme.toLowerCase()}://`);
  return t;
}

/**
 * @param {string} value
 */
export function looksDefanged(value) {
  const v = String(value || '');
  return /hxxps?(?::\/\/|\[:)/i.test(v) || /\[\.\]|\(\.\)|\{\.\}/.test(v) || /\[:\]|\[:\/{1,2}\]/.test(v)
    || MD_ESCAPED_DEFANG_TEST_RE.test(v);
}

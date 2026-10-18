/**
 * Defang / refang helpers for threat-report text.
 * Converts common defanged forms to strings that existing TalonHound normalizers accept.
 * Does not invent conflicting normalization — output is fed into normalizeObservable / etc.
 */

// hxxp://, hxxp[://], hxxp[:]//, hxxp[:][//]
const HXXP_RE = /\bhxxps?(?::\/\/|\[:\/\/\]|\[:\]\/\/|\[:\]\[\/\/\])/gi;
// http[://], http[:]//, http[:][//]
const SCHEME_BRACKET_RE = /\b(https?)(?:\[:\/\/\]|\[:\]\/\/|\[:\]\[\/\/\])/gi;
const BRACKET_DOT_RE = /\[\.\]|\(\.\)|\{\.\}/g;
const BRACKET_COLON_RE = /\[:\]|\(:\)|\{:\}/g;
// Markdown-escaped bracket defang emitted verbatim by some CMSes inside code
// spans: `evil\[.\]com`, `hxxps\[:\]//`, `evil\[.]com`. Only the escape of a
// bracket that encloses a defang token is removed; other backslashes stay.
const MD_ESCAPED_DEFANG_RE = /\\\[(\.|:|:\/\/|\/\/)\\?\]|\[(\.|:|:\/\/|\/\/)\\\]/g;
const MD_ESCAPED_DEFANG_TEST_RE = /\\\[(?:\.|:|:\/\/|\/\/)\\?\]|\[(?:\.|:|:\/\/|\/\/)\\\]/;

export function unescapeMarkdownDefang(text) {
  return String(text || '').replace(MD_ESCAPED_DEFANG_RE, (_, a, b) => `[${a ?? b}]`);
}

function refangSchemes(text) {
  return String(text || '')
    .replace(HXXP_RE, (m) => (m.toLowerCase().startsWith('hxxps') ? 'https://' : 'http://'))
    .replace(SCHEME_BRACKET_RE, (_, scheme) => `${scheme.toLowerCase()}://`);
}

/**
 * Refang a single token or short string.
 * @param {string} value
 */
export function refangObservable(value) {
  let v = String(value || '').trim();
  if (!v) return '';
  v = refangSchemes(unescapeMarkdownDefang(v));
  v = v.replace(BRACKET_DOT_RE, '.');
  v = v.replace(BRACKET_COLON_RE, ':');
  // meow:// → http:// (rare vendor defang)
  v = v.replace(/\bmeow:\/\//gi, 'http://');
  return v.trim();
}

/**
 * Light-touch prep of a text blob so deterministic extractors see fanged IOCs.
 * Keeps surrounding prose intact.
 * @param {string} text
 */
export function refangTextForExtraction(text) {
  let t = refangSchemes(unescapeMarkdownDefang(text));
  t = t.replace(BRACKET_DOT_RE, '.');
  t = t.replace(BRACKET_COLON_RE, ':');
  t = t.replace(/\bmeow:\/\//gi, 'http://');
  return t;
}

/**
 * @param {string} value
 */
export function looksDefanged(value) {
  const v = String(value || '');
  return /hxxps?(?::\/\/|\[:)/i.test(v) || /\[\.\]|\(\.\)|\{\.\}/.test(v) || /\[:\]|\[:\/\/\]/.test(v)
    || MD_ESCAPED_DEFANG_TEST_RE.test(v);
}

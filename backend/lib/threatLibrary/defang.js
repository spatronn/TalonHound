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
  v = refangSchemes(v);
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
  let t = refangSchemes(text);
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
  return /hxxps?(?::\/\/|\[:)/i.test(v) || /\[\.\]|\(\.\)|\{\.\}/.test(v) || /\[:\]|\[:\/\/\]/.test(v);
}

/**
 * IPv6 token recognition for Threat Library extraction (tl-ipv6-tokens-v1).
 *
 * A regular expression only proposes maximal hex/colon runs (with an optional
 * dotted-quad tail for IPv4-mapped / -embedded forms); `net.isIPv6` decides.
 * This accepts every RFC 4291 spelling — full, leading `::`, trailing `::`,
 * mid-address `::` (`2400:8d60:2::1:841d:5dd`) and `::ffff:192.0.2.1` — and
 * never emits a fragment of a longer run: an invalid run yields nothing
 * rather than its valid-looking pieces.
 *
 * Shapes that pass `isIPv6` but are not addresses in prose are rejected:
 * a run without any decimal digit (`Bad::Face`, `dead::beef` read as code),
 * and a run with fewer than two hex groups (`::`, `1::`). The bare loopback
 * `::1` is handled by the caller's dedicated loopback pass.
 */
import { isIPv6 } from 'node:net';

export const IPV6_TOKENS_VERSION = 'tl-ipv6-tokens-v1';

// Left boundary: not inside a word, hostname, decimal or longer colon run.
// The dotted-quad tail alternative comes first: a plain hex run would
// otherwise swallow its first octet (`::ffff:198` + `.51.100.7`).
const IPV6_RUN_RE =
  /(?<![0-9A-Za-z_.:-])(?=[0-9A-Fa-f]*:)(?:[0-9A-Fa-f:]*:\d{1,3}(?:\.\d{1,3}){3}(?![\d.])|[0-9A-Fa-f:]+)/g;

function hexGroupCount(value) {
  const head = value.replace(/\d{1,3}(?:\.\d{1,3}){3}$/, '');
  return head.split(':').filter((g) => /^[0-9A-Fa-f]{1,4}$/.test(g)).length + (head === value ? 0 : 2);
}

function acceptable(value) {
  if (!value || !isIPv6(value)) return false;
  if (!/\d/.test(value)) return false;
  return hexGroupCount(value) >= 2;
}

/**
 * Every standalone, valid IPv6 address in `text`.
 * @param {string} text already-refanged text
 * @returns {Array<{ value: string, start: number, end: number }>}
 */
export function findIpv6Tokens(text) {
  const hay = String(text || '');
  const out = [];
  for (const m of hay.matchAll(IPV6_RUN_RE)) {
    const start = m.index;
    let value = m[0];
    const right = hay[start + value.length] || '';
    // Glued to a longer word / hostname label: not a standalone address.
    if (/[0-9A-Za-z_]/.test(right)) continue;
    if (right === '.' && /[0-9A-Za-z]/.test(hay[start + value.length + 1] || '')) continue;
    if (!acceptable(value) && value.endsWith(':') && !value.endsWith('::')) {
      // Sentence / label punctuation after the address ("relay 2001:db8::5:").
      value = value.slice(0, -1);
    }
    if (!acceptable(value)) continue;
    out.push({ value, start, end: start + value.length });
  }
  return out;
}

/**
 * Evidence-aware typing for dotted tokens (domain vs technical artifact).
 * Thin compatibility layer over observableTypeResolver — no vendor/domain
 * allowlists; decisions are canonical syntax + source semantics + provenance.
 */

import { resolveDottedToken } from './observableTypeResolver.js';

/**
 * @param {string} token
 */
export function splitDottedToken(token) {
  return String(token || '')
    .toLowerCase()
    .replace(/^\.+|\.+$/g, '')
    .split('.')
    .filter(Boolean);
}

/**
 * @param {string} token original spelling (case preserved when available)
 * @param {{
 *   surroundingText?: string,
 *   typeLabel?: string|null,
 *   declaredType?: string|null,
 *   zone?: string|null,
 *   blockType?: string|null,
 *   form?: string|null,
 *   strongZone?: boolean,
 *   urlPathBasenames?: Set<string>,
 *   knownUrlHosts?: Set<string>
 * }} [ctx]
 * @returns {{ kind: 'domain'|'technical_artifact'|'skip', reason: string, labelled: boolean, artifact_kind: string|null, signals: object }}
 */
export function resolveDottedTokenType(token, ctx = {}) {
  return resolveDottedToken(token, ctx);
}

/**
 * Extract hostname from URL string.
 * @param {string} url
 */
export function hostnameFromUrl(url) {
  try {
    const u = new URL(String(url));
    return (u.hostname || '').toLowerCase().replace(/\.$/, '');
  } catch {
    const m = String(url).match(/^https?:\/\/([^\/?#:]+)/i);
    return m ? m[1].toLowerCase() : '';
  }
}

/**
 * Path basename from URL.
 * @param {string} url
 */
export function pathBasenameFromUrl(url) {
  try {
    const u = new URL(String(url));
    const parts = u.pathname.split('/').filter(Boolean);
    return parts.length ? parts[parts.length - 1].toLowerCase() : '';
  } catch {
    const path = String(url).split(/[?#]/)[0];
    const parts = path.split('/').filter(Boolean);
    const last = parts[parts.length - 1] || '';
    return last.includes('.') ? last.toLowerCase() : '';
  }
}

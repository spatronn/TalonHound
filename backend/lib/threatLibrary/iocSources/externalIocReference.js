/**
 * Shared detection of explicit publisher external IOC dataset references.
 *
 * Used by:
 * - Additional IOC Source discovery (HTML + canonical blocks with `links`)
 * - Section-tree authority (`external_ioc_pointer` / delegated-scope suppression)
 *
 * Both paths must agree on the same evidence: pointer phrasing + IOC cues +
 * a concrete destination (visible URL or structured hyperlink href).
 */

import {
  IOC_SOURCE_DISCOVERY_CUES,
  IOC_SOURCE_DISCOVERY_SCORE_THRESHOLD,
  IOC_SOURCE_DISCOVERY_URL_CUES
} from './constants.js';

/** Publisher points at an externally published indicator file / pack. */
export const EXTERNAL_IOC_POINTER_RE =
  /\b(?:available|download(?:able|ed)?|can\s+be\s+found|found\s+(?:in|at|on)|see|refer\s+to|published|released|hosted|listed|provided|accessible)\b[^.]{0,120}\b(?:here|below|github|gitlab|repository|repo|file|files|csv|json|stix|misp|txt|package|archive|link|page|website)\b/i;

export const IOC_HEADING_RE =
  /\b(?:indicators?\s+of\s+compromise|indicators?(?:\s+of\s+compromise)?|iocs?|compromise\s+indicators?)\b/i;

const IOC_PROSE_RE =
  /\b(?:ioc|iocs|indicators?|observables?|download|repository|repo|github|gitlab|csv|stix|misp)\b/i;

const ABSOLUTE_URL_RE = /\bhttps?:\/\/\S+/i;

function normalizeHay(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function collectTextCues(hay) {
  const matched = [];
  for (const cue of IOC_SOURCE_DISCOVERY_CUES) {
    if (hay.includes(cue)) matched.push(cue);
  }
  return matched;
}

function collectUrlPathCues(urlHay) {
  const matched = [];
  for (const cue of IOC_SOURCE_DISCOVERY_URL_CUES) {
    if (urlHay.includes(cue)) matched.push(`url:${cue}`);
  }
  return matched;
}

/**
 * Score a candidate external IOC reference destination.
 * @returns {{ score: number, matchedCues: string[], hasTextEvidence: boolean }}
 */
export function scoreIocSourceCandidate({ href, linkText, surrounding, headingText, reportHost }) {
  // Strip absolute URLs from prose before cue / pointer matching so a bare
  // https://github.com/... hostname cannot satisfy "… available … github …".
  const proseForCues = `${linkText || ''} ${surrounding || ''} ${headingText || ''}`.replace(/https?:\/\/\S+/gi, ' ');
  const textHay = normalizeHay(proseForCues);
  const urlHay = normalizeHay(href);
  const textCues = collectTextCues(textHay);
  const pathCues = collectUrlPathCues(urlHay);
  const matchedCues = [...textCues, ...pathCues];
  let score = 0;

  for (const cue of textCues) {
    score += cue.length >= 18 ? 4 : cue.length >= 12 ? 3 : 2;
  }
  for (const _cue of pathCues) {
    score += 3;
  }

  const pointer = EXTERNAL_IOC_POINTER_RE.test(proseForCues);
  if (pointer) {
    score += 6;
    matchedCues.push('external_pointer');
  }

  if (headingText && IOC_HEADING_RE.test(headingText)) {
    score += 5;
    matchedCues.push('ioc_heading');
  }

  let hostOk = false;
  try {
    const u = new URL(href);
    const host = u.hostname.toLowerCase().replace(/^www\./, '');
    hostOk = true;

    if (host === 'github.com' || host === 'raw.githubusercontent.com' || host === 'gitlab.com') {
      if (/\/(?:ioc|iocs|indicators?)(?:\/|$)/i.test(u.pathname)) {
        score += 5;
        matchedCues.push('host_ioc_path');
      } else if (textCues.length || pointer) {
        score += 2;
        matchedCues.push('host_with_text_evidence');
      }
    }

    if (reportHost) {
      const rh = String(reportHost).toLowerCase().replace(/^www\./, '');
      if (host === rh || host.endsWith(`.${rh}`) || rh.endsWith(`.${host}`)) {
        if (textCues.length || pointer || pathCues.length) score += 2;
      }
    }

    if (/\b(twitter|x\.com|linkedin|facebook|youtube|mailto:)\b/i.test(href)) score -= 10;
    if (/\/(about|careers|privacy|terms|login|contact|blog\/?$)\b/i.test(u.pathname) && !textCues.length && !pointer) {
      score -= 5;
    }
    if (
      (host === 'github.com' || host === 'gitlab.com') &&
      /^\/[^/]+\/[^/]+\/?$/.test(u.pathname) &&
      !textCues.length &&
      !pointer
    ) {
      score = 0;
    }
  } catch {
    return { score: 0, matchedCues: [], hasTextEvidence: false };
  }

  if (!hostOk) return { score: 0, matchedCues: [], hasTextEvidence: false };

  const hasIocHeading = Boolean(headingText && IOC_HEADING_RE.test(headingText));
  const hasStrongPath = pathCues.some((c) => /url:\/(?:ioc|iocs|indicators?)\//.test(c));
  const hasTextEvidence = textCues.length > 0 || hasIocHeading || hasStrongPath;
  if (!hasTextEvidence) {
    return { score: 0, matchedCues, hasTextEvidence: false };
  }

  return { score, matchedCues, hasTextEvidence: true };
}

export function isAcceptedIocSourceScore(result) {
  return Boolean(result?.hasTextEvidence && (result.score || 0) >= IOC_SOURCE_DISCOVERY_SCORE_THRESHOLD);
}

/**
 * Normalize optional block.links entries to { href, text }.
 * @param {object} block
 * @returns {{ href: string, text: string }[]}
 */
export function blockHyperlinks(block) {
  const raw = Array.isArray(block?.links) ? block.links : [];
  const out = [];
  for (const item of raw) {
    const href = String(item?.href || item?.url || '').trim();
    if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('javascript:')) continue;
    out.push({ href, text: String(item?.text || item?.link_text || '').trim().slice(0, 240) });
  }
  return out;
}

/**
 * Whether a content block under an IOC section is an explicit external pack
 * pointer (visible URL and/or structured hyperlink), using the same scorer as
 * discovery.
 *
 * @param {object} block
 * @param {{ headingText?: string|null, reportHost?: string|null, reportUrl?: string|null }} [opts]
 */
export function blockIsExternalIocReference(block, opts = {}) {
  const t = String(block?.text || '').trim();
  if (!t) return false;
  const prose = t.replace(/https?:\/\/\S+/gi, ' ');
  if (!EXTERNAL_IOC_POINTER_RE.test(prose) || !IOC_PROSE_RE.test(prose)) return false;

  const headingText = opts.headingText || null;
  const reportHost = opts.reportHost || null;
  const links = blockHyperlinks(block);
  const hasVisibleUrl = ABSOLUTE_URL_RE.test(t);

  if (hasVisibleUrl) {
    // Visible URL in text: accept when pointer + IOC prose (destination may be
    // scored loosely — authority only needs to know the section owns an
    // external pack, not which URL wins discovery).
    const urlMatch = t.match(/https?:\/\/[^\s<>"')\]]+/i);
    if (urlMatch) {
      const scored = scoreIocSourceCandidate({
        href: urlMatch[0].replace(/[.,;:)]+$/, ''),
        linkText: '',
        surrounding: t,
        headingText,
        reportHost
      });
      if (isAcceptedIocSourceScore(scored)) return true;
      // Fallback: pointer + IOC prose + any http(s) URL under an IOC heading.
      if (headingText && IOC_HEADING_RE.test(headingText)) return true;
    }
  }

  for (const link of links) {
    let absolute = link.href;
    try {
      absolute = new URL(link.href, opts.reportUrl || undefined).href;
    } catch {
      continue;
    }
    const scored = scoreIocSourceCandidate({
      href: absolute,
      linkText: link.text,
      surrounding: t,
      headingText,
      reportHost
    });
    if (isAcceptedIocSourceScore(scored)) return true;
  }

  return false;
}

/**
 * Scan annotated / canonical blocks for external IOC pack references.
 * Prefers structured `links` (href-only anchors) then absolute URLs in text.
 *
 * @param {object[]} blocks
 * @param {{ reportUrl?: string|null }} [opts]
 * @returns {Array<{ href: string, linkText: string, surrounding: string, headingText: string, blockId: string|null, score: number, matchedCues: string[] }>}
 */
export function findExternalIocReferencesInBlocks(blocks, opts = {}) {
  const list = Array.isArray(blocks) ? blocks : [];
  let reportHost = null;
  try {
    if (opts.reportUrl) reportHost = new URL(opts.reportUrl).hostname;
  } catch {
    reportHost = null;
  }

  /** @type {Map<string, object>} */
  const byHref = new Map();
  let lastHeading = '';

  for (const b of list) {
    if (b?.type === 'heading' && b.text) {
      lastHeading = String(b.text).slice(0, 200);
      continue;
    }
    const t = String(b?.text || '');
    const links = blockHyperlinks(b);
    const candidates = [];

    for (const link of links) {
      try {
        candidates.push({
          href: new URL(link.href, opts.reportUrl || undefined).href,
          linkText: link.text,
          surrounding: t
        });
      } catch {
        /* skip */
      }
    }
    for (const match of t.matchAll(/https?:\/\/[^\s<>"')\]]+/gi)) {
      candidates.push({
        href: String(match[0] || '').replace(/[.,;:)]+$/, ''),
        linkText: '',
        surrounding: t.slice(Math.max(0, (match.index || 0) - 160), Math.min(t.length, (match.index || 0) + String(match[0]).length + 160))
      });
    }

    for (const c of candidates) {
      const scored = scoreIocSourceCandidate({
        href: c.href,
        linkText: c.linkText,
        surrounding: c.surrounding,
        headingText: lastHeading,
        reportHost
      });
      if (!isAcceptedIocSourceScore(scored)) continue;
      const prev = byHref.get(c.href);
      if (prev && prev.score >= scored.score) continue;
      byHref.set(c.href, {
        href: c.href,
        linkText: c.linkText,
        surrounding: c.surrounding.slice(0, 400),
        headingText: lastHeading,
        blockId: b.id || null,
        score: scored.score,
        matchedCues: scored.matchedCues
      });
    }
  }

  return [...byHref.values()].sort((a, b) => b.score - a.score);
}

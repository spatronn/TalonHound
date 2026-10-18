/**
 * Selective discovery of explicit publisher IOC dataset references.
 *
 * Discovery never fetches, attaches, or extracts — it only upserts
 * `threat_report_ioc_sources` rows in `discovered` state for analyst review.
 *
 * Why selective: the prior scorer treated `github.com/` as a URL cue that
 * self-reinforced every GitHub link (header social icons, bare org roots) into
 * pending sources. This module requires textual IOC-dataset evidence (or a
 * strong `/ioc|indicators/` path) and never accepts a bare host match alone.
 */

import { parseHtml, findElements } from '../extract/htmlBlocks.js';
import { canonicalizeReportUrl } from '../importIdentity.js';
import {
  IOC_SOURCE_DISCOVERY_CUES,
  IOC_SOURCE_DISCOVERY_SCORE_THRESHOLD,
  IOC_SOURCE_DISCOVERY_URL_CUES,
  IOC_SOURCE_LIFECYCLE
} from './constants.js';
import { guessTypeFromUrl } from './sourceType.js';

const ABSOLUTE_URL_RE = /https?:\/\/[^\s<>"')\]]+/gi;

/** Same shape as sectionTree EXTERNAL_POINTER_RE — publisher points elsewhere. */
export const EXTERNAL_IOC_POINTER_RE =
  /\b(?:available|download(?:able|ed)?|can\s+be\s+found|found\s+(?:in|at|on)|see|refer\s+to|published|released|hosted|listed|provided|accessible)\b[^.]{0,120}\b(?:here|below|github|gitlab|repository|repo|file|files|csv|json|stix|misp|txt|package|archive|link|page|website)\b/i;

const IOC_HEADING_RE =
  /\b(?:indicators?\s+of\s+compromise|indicators?(?:\s+of\s+compromise)?|iocs?|compromise\s+indicators?)\b/i;

function normalizeHay(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function textOf(node) {
  if (!node) return '';
  if (node.type === 'text') return String(node.data || '');
  if (!Array.isArray(node.children)) return '';
  return node.children.map(textOf).join('');
}

function nearestHeadingText(node) {
  let cur = node;
  while (cur) {
    let sib = cur.prev;
    while (sib) {
      if (sib.type === 'tag') {
        const tag = String(sib.name || '').toLowerCase();
        if (/^h[1-6]$/.test(tag)) return textOf(sib).trim().slice(0, 200);
      }
      sib = sib.prev;
    }
    cur = cur.parent;
  }
  return '';
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
 * Score a candidate external IOC reference.
 * @returns {{ score: number, matchedCues: string[], hasTextEvidence: boolean }}
 */
export function scoreIocSourceCandidate({ href, linkText, surrounding, headingText, reportHost }) {
  // Strip absolute URLs from prose before cue / pointer matching so a bare
  // https://github.com/... hostname cannot satisfy "… available … github …".
  const proseForCues = `${linkText} ${surrounding} ${headingText || ''}`.replace(/https?:\/\/\S+/gi, ' ');
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
      // Path evidence of an IOC pack — not the bare host.
      if (/\/(?:ioc|iocs|indicators?)(?:\/|$)/i.test(u.pathname)) {
        score += 5;
        matchedCues.push('host_ioc_path');
      } else if (textCues.length || pointer) {
        // Host is plausible only when text already asserts an IOC dataset.
        score += 2;
        matchedCues.push('host_with_text_evidence');
      }
      // Bare github.com / org root with no text → score stays 0 from host.
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
    // Reject bare repository roots without an IOC-ish path when text is weak.
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

  // Accept only with IOC text cues, an IOC heading, or a strong /ioc|indicators/
  // path. Pointer phrasing boosts score but cannot alone promote a tooling link.
  const hasIocHeading = Boolean(headingText && IOC_HEADING_RE.test(headingText));
  const hasStrongPath = pathCues.some((c) => /url:\/(?:ioc|iocs|indicators?)\//.test(c));
  const hasTextEvidence = textCues.length > 0 || hasIocHeading || hasStrongPath;
  if (!hasTextEvidence) {
    return { score: 0, matchedCues, hasTextEvidence: false };
  }

  return { score, matchedCues, hasTextEvidence: true };
}

function acceptScore(result) {
  return result.score >= IOC_SOURCE_DISCOVERY_SCORE_THRESHOLD && result.hasTextEvidence;
}

function toDiscoveryRow({ absolute, canonical, score, matchedCues, linkText, surrounding, headingText, reportUrl }) {
  return {
    original_url: absolute,
    canonical_url: canonical,
    discovery_method: 'auto',
    source_type: guessTypeFromUrl(canonical),
    score,
    discovery_evidence: {
      link_text: String(linkText || '').slice(0, 240),
      surrounding_text: String(surrounding || '').slice(0, 400),
      heading_text: headingText ? String(headingText).slice(0, 200) : null,
      matched_cues: matchedCues.slice(0, 16),
      score,
      report_url: reportUrl || null
    }
  };
}

/**
 * Discover IOC-pack hyperlinks from retained HTML (preserves href + anchor text).
 * @param {string} html
 * @param {{ reportUrl?: string|null }} [opts]
 */
export function discoverIocSourcesFromHtml(html, opts = {}) {
  const raw = String(html || '');
  if (!raw.trim()) return [];
  let reportHost = null;
  try {
    if (opts.reportUrl) reportHost = new URL(opts.reportUrl).hostname;
  } catch {
    reportHost = null;
  }

  const dom = parseHtml(raw);
  const anchors = findElements(dom, (el) => String(el?.name || '').toLowerCase() === 'a');
  const byCanon = new Map();

  for (const a of anchors) {
    const hrefRaw = a.attribs?.href || '';
    if (!hrefRaw || hrefRaw.startsWith('#') || hrefRaw.startsWith('mailto:') || hrefRaw.startsWith('javascript:')) {
      continue;
    }
    let absolute;
    try {
      absolute = new URL(hrefRaw, opts.reportUrl || undefined).href;
    } catch {
      continue;
    }
    const canonical = canonicalizeReportUrl(absolute);
    if (!canonical) continue;

    const linkText = textOf(a).trim();
    const parentText = textOf(a.parent || a).trim().slice(0, 400);
    const headingText = nearestHeadingText(a);
    const scored = scoreIocSourceCandidate({
      href: absolute,
      linkText,
      surrounding: parentText,
      headingText,
      reportHost
    });
    if (!acceptScore(scored)) continue;

    const prev = byCanon.get(canonical);
    if (prev && prev.score >= scored.score) continue;
    byCanon.set(
      canonical,
      toDiscoveryRow({
        absolute,
        canonical,
        score: scored.score,
        matchedCues: scored.matchedCues,
        linkText,
        surrounding: parentText,
        headingText,
        reportUrl: opts.reportUrl
      })
    );
  }

  return [...byCanon.values()].sort((a, b) => b.score - a.score);
}

/**
 * Discover absolute http(s) URLs with IOC cues from plain text / PDF blocks.
 * @param {string} text
 * @param {{ reportUrl?: string|null }} [opts]
 */
export function discoverIocSourcesFromText(text, opts = {}) {
  const raw = String(text || '');
  if (!raw.trim()) return [];
  let reportHost = null;
  try {
    if (opts.reportUrl) reportHost = new URL(opts.reportUrl).hostname;
  } catch {
    reportHost = null;
  }

  const byCanon = new Map();
  for (const match of raw.matchAll(ABSOLUTE_URL_RE)) {
    const absolute = String(match[0] || '').replace(/[.,;:)]+$/, '');
    const canonical = canonicalizeReportUrl(absolute);
    if (!canonical) continue;
    const idx = match.index || 0;
    const surrounding = raw.slice(Math.max(0, idx - 160), Math.min(raw.length, idx + absolute.length + 160));
    const scored = scoreIocSourceCandidate({
      href: absolute,
      linkText: '',
      surrounding,
      headingText: '',
      reportHost
    });
    if (!acceptScore(scored)) continue;
    const prev = byCanon.get(canonical);
    if (prev && prev.score >= scored.score) continue;
    byCanon.set(
      canonical,
      toDiscoveryRow({
        absolute,
        canonical,
        score: scored.score,
        matchedCues: scored.matchedCues,
        linkText: '',
        surrounding,
        headingText: '',
        reportUrl: opts.reportUrl
      })
    );
  }
  return [...byCanon.values()].sort((a, b) => b.score - a.score);
}

/**
 * Persist discovery results for a report (idempotent by canonical_url).
 * Never reactivates dismissed sources. Never attaches or extracts.
 * @param {import('pg').Pool} pool
 * @param {number} reportId
 * @param {Array<object>} discovered
 */
export async function upsertDiscoveredSources(pool, reportId, discovered) {
  const list = Array.isArray(discovered) ? discovered : [];
  const results = { inserted: 0, skipped: 0, unchanged: 0 };
  for (const item of list) {
    const canonical = item.canonical_url || canonicalizeReportUrl(item.original_url);
    if (!canonical) {
      results.skipped += 1;
      continue;
    }
    const { rows } = await pool.query(
      `INSERT INTO threat_report_ioc_sources (
         report_id, original_url, canonical_url, source_type, discovery_method,
         discovery_evidence, lifecycle_status
       ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)
       ON CONFLICT (report_id, canonical_url) DO UPDATE SET
         discovery_evidence = CASE
           WHEN threat_report_ioc_sources.lifecycle_status = 'dismissed' THEN threat_report_ioc_sources.discovery_evidence
           ELSE EXCLUDED.discovery_evidence
         END,
         original_url = CASE
           WHEN threat_report_ioc_sources.lifecycle_status = 'dismissed' THEN threat_report_ioc_sources.original_url
           ELSE EXCLUDED.original_url
         END,
         updated_at = CASE
           WHEN threat_report_ioc_sources.lifecycle_status = 'dismissed' THEN threat_report_ioc_sources.updated_at
           ELSE NOW()
         END
       RETURNING (xmax = 0) AS inserted, lifecycle_status`,
      [
        reportId,
        item.original_url || canonical,
        canonical,
        item.source_type || guessTypeFromUrl(canonical),
        item.discovery_method || 'auto',
        JSON.stringify(item.discovery_evidence || {}),
        IOC_SOURCE_LIFECYCLE.DISCOVERED
      ]
    );
    if (rows[0]?.inserted) results.inserted += 1;
    else results.unchanged += 1;
  }
  return results;
}

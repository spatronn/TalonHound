/**
 * Selective discovery of explicit publisher IOC dataset references.
 *
 * Discovery never fetches, attaches, or extracts — it only upserts
 * `threat_report_ioc_sources` rows in `discovered` state for analyst review.
 *
 * Evidence scoring lives in externalIocReference.js (shared with section-tree
 * authority) so href-only anchors and visible URLs are classified consistently.
 */

import { parseHtml, findElements } from '../extract/htmlBlocks.js';
import { canonicalizeReportUrl } from '../importIdentity.js';
import { IOC_SOURCE_LIFECYCLE } from './constants.js';
import {
  EXTERNAL_IOC_POINTER_RE,
  findExternalIocReferencesInBlocks,
  isAcceptedIocSourceScore,
  scoreIocSourceCandidate
} from './externalIocReference.js';
import { guessTypeFromUrl } from './sourceType.js';

export { EXTERNAL_IOC_POINTER_RE, scoreIocSourceCandidate } from './externalIocReference.js';

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

const BLOCK_TAGS = new Set(['p', 'li', 'td', 'th', 'dd', 'dt', 'div', 'section', 'blockquote', 'figcaption', 'caption', 'pre']);

function isBlank(node) {
  return node?.type === 'text' && !String(node.data || '').trim();
}

function previousElement(node) {
  let sib = node?.prev;
  while (sib && (isBlank(sib) || sib.type === 'comment')) sib = sib.prev;
  return sib && sib.type === 'tag' ? sib : null;
}

/**
 * The publisher's lead-in for the anchor's list / block (tl-ioc-source-discovery-v3):
 * the element right before the list item's list ("For a downloadable copy of
 * IOCs, see:" + a <ul> of STIX links), or the paragraph right before the
 * anchor's own paragraph when that paragraph ends with a colon. Headings are
 * not lead-ins (they are scored separately as the section heading).
 */
function leadInTextOf(anchor) {
  let node = anchor?.parent || null;
  while (node && !(node.type === 'tag' && BLOCK_TAGS.has(String(node.name || '').toLowerCase()))) node = node.parent;
  // Climb a few wrapper levels (<li> → <ul>; download-widget <div>s); at each
  // level walk back over sibling link-only blocks (the other files of the same
  // download list) to the publisher sentence that introduces them.
  for (let depth = 0; node && depth < 4; depth += 1) {
    let sib = previousElement(node);
    for (let hops = 0; sib && hops < 8; hops += 1) {
      const tag = String(sib.name || '').toLowerCase();
      if (/^h[1-6]$/.test(tag)) return '';
      const text = textOf(sib).replace(/\s+/g, ' ').trim();
      if (text && text.length <= 300 && (/:\s*$/.test(text) || LEAD_IN_NOUN_RE.test(text)) && !isLinkOnlyBlock(sib)) return text;
      if (!isLinkOnlyBlock(sib)) break;
      sib = previousElement(sib);
    }
    const parent = node.parent;
    if (!parent || parent.type !== 'tag' || /^(?:article|main|body|section)$/i.test(String(parent.name || ''))) return '';
    node = parent;
  }
  return '';
}

/** Indicator nouns that let a lead-in without a trailing colon qualify. */
const LEAD_IN_NOUN_RE = /\b(?:iocs?|indicators?|observables?)\b/i;

/** A short block that is essentially one link (a download widget / list entry). */
function isLinkOnlyBlock(el) {
  const links = findElements(el, (x) => String(x?.name || '').toLowerCase() === 'a');
  if (!links.length) return false;
  const text = textOf(el).replace(/\s+/g, ' ').trim();
  return text.length <= 200;
}

function toDiscoveryRow({ absolute, canonical, score, matchedCues, linkText, surrounding, headingText, reportUrl, leadIn }) {
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
      ...(leadIn ? { lead_in_text: String(leadIn).slice(0, 300) } : {}),
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
    const leadIn = leadInTextOf(a);
    const scored = scoreIocSourceCandidate({
      href: absolute,
      linkText,
      surrounding: parentText,
      headingText,
      reportHost,
      leadIn
    });
    if (!isAcceptedIocSourceScore(scored)) continue;

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
        reportUrl: opts.reportUrl,
        leadIn
      })
    );
  }

  return [...byCanon.values()].sort((a, b) => b.score - a.score);
}

/**
 * Discover from canonical / annotated blocks (uses structured `links` + text URLs).
 * @param {object[]} blocks
 * @param {{ reportUrl?: string|null }} [opts]
 */
export function discoverIocSourcesFromBlocks(blocks, opts = {}) {
  const found = findExternalIocReferencesInBlocks(blocks, opts);
  const byCanon = new Map();
  for (const item of found) {
    const canonical = canonicalizeReportUrl(item.href);
    if (!canonical) continue;
    const prev = byCanon.get(canonical);
    if (prev && prev.score >= item.score) continue;
    byCanon.set(
      canonical,
      toDiscoveryRow({
        absolute: item.href,
        canonical,
        score: item.score,
        matchedCues: item.matchedCues,
        linkText: item.linkText,
        surrounding: item.surrounding,
        headingText: item.headingText,
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
  return discoverIocSourcesFromBlocks([{ id: 'text', type: 'paragraph', text: raw }], opts);
}

/**
 * Persist discovery results for a report (idempotent by canonical_url).
 * Insert-only: an existing row — discovered, inspected, extracted or dismissed
 * by an analyst — is never rewritten by a re-run of analysis / refresh.
 * Never attaches or extracts.
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
       ON CONFLICT (report_id, canonical_url) DO NOTHING
       RETURNING id`,
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
    if (rows.length) results.inserted += 1;
    else results.unchanged += 1;
  }
  return results;
}

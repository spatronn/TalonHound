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
 * Lookup / sandbox / search services: a link there names one indicator's
 * report page (opentip, VirusTotal, urlscan …), never a publisher IOC pack.
 */
const LOOKUP_SERVICE_HOST_RE =
  /(?:^|\.)(?:opentip\.kaspersky\.com|virustotal\.com|urlscan\.io|otx\.alienvault\.com|threatfox\.abuse\.ch|bazaar\.abuse\.ch|urlhaus\.abuse\.ch|shodan\.io|censys\.io|search\.censys\.io|hybrid-analysis\.com|any\.run|app\.any\.run|tria\.ge|joesandbox\.com|threatbook\.(?:cn|io)|x\.threatbook\.(?:cn|com)|exchange\.xforce\.ibmcloud\.com|talosintelligence\.com|abuseipdb\.com|whois\.domaintools\.com|google\.com|bing\.com|akismet\.com|gravatar\.com|wordpress\.com|addtoany\.com|twitter\.com|x\.com|linkedin\.com|facebook\.com|youtube\.com|t\.me|reddit\.com)$/i;
/** File extensions that are payloads / archives / code, never an IOC data pack. */
const NON_PACK_FILE_EXT_RE = /\.(?:zip|7z|rar|gz|tgz|tar|bz2|xz|exe|msi|dll|dmg|pkg|apk|ipa|deb|rpm|iso|img|bin|jar|js|mjs|ts|py|ps1|sh|bat|vbs|hta|lnk|docx?|xlsx?|pptx?|png|jpe?g|gif|svg|webp|mp4|mov)$/i;
/** Data-pack file extensions (a linked file must be one of these to qualify). */
const PACK_FILE_EXT_RE = /\.(?:txt|csv|json|ndjson|jsonl|stix|misp|xml|ioc|md|adoc|yml|yaml|sha256|sha1|md5|tsv|pdf)$/i;
/** Anchor text naming an IOC exchange format ("AA25-203A STIX XML", "MISP event JSON", "OpenIOC"). */
const IOC_FORMAT_LINK_TEXT_RE = /\b(?:stix(?:\s*2(?:\.\d)?)?|misp|openioc)\b/i;
/**
 * A lead-in that announces a downloadable indicator package ("For a
 * downloadable copy of Nov. 13, 2025 IOCs, see:", "Downloadable IOCs:").
 */
const IOC_PACKAGE_LEAD_IN_RE =
  /\b(?:a\s+downloadable\s+(?:copy|list|version|file|set)\s+of\s+(?:the\s+)?(?:[\w.,()-]+\s+){0,4}?(?:iocs?|indicators?)|downloadable\s+(?:iocs?|indicators?))\b/i;
/** Indicator nouns in the anchor's own sentence. */
const LOCAL_IOC_NOUN_RE = /\b(?:iocs?|indicators?|observables?)\b/i;
/** The link text is itself an observable (a per-indicator lookup link). */
const OBSERVABLE_LINK_TEXT_RE =
  /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|(?:\d{1,3}(?:\[?\.\]?)){3}\d{1,3}|(?:[a-z0-9-]+(?:\[\.\]|\.))+[a-z]{2,63})$/i;

/**
 * Score a candidate external IOC reference destination (tl-ioc-source-discovery-v3).
 *
 * Evidence is ANCHOR-LOCAL: the link text and the sentence / block around it.
 * An IOC section heading adds weight but never validates a link by itself —
 * tag pages, author links, "Cancel", next / previous posts and per-indicator
 * lookup links that happen to sit under an "Indicators of compromise" heading
 * are not IOC packs.
 * @returns {{ score: number, matchedCues: string[], hasTextEvidence: boolean, rejected?: string }}
 */
export function scoreIocSourceCandidate({ href, linkText, surrounding, headingText, reportHost, leadIn }) {
  // Strip absolute URLs from prose before cue / pointer matching so a bare
  // https://github.com/... hostname cannot satisfy "… available … github …".
  // The publisher's lead-in for the anchor's list ("For a downloadable copy of
  // IOCs, see:") is anchor-local: it introduces exactly these links (v3).
  const localProse = `${leadIn || ''} ${linkText || ''} ${surrounding || ''}`.replace(/https?:\/\/\S+/gi, ' ');
  const textHay = normalizeHay(localProse);
  const urlHay = normalizeHay(href);
  const textCues = collectTextCues(textHay);
  const pathCues = collectUrlPathCues(urlHay);
  const matchedCues = [...textCues, ...pathCues];
  const none = (rejected) => ({ score: 0, matchedCues, hasTextEvidence: false, ...(rejected ? { rejected } : {}) });
  let score = 0;

  let u;
  try {
    u = new URL(href);
  } catch {
    return none('unparseable_url');
  }
  if (!/^https?:$/i.test(u.protocol)) return none('unsupported_scheme');
  const host = u.hostname.toLowerCase().replace(/^www\./, '');
  const path = decodeURIComponent(u.pathname || '/');
  const lastSegment = path.split('/').filter(Boolean).pop() || '';

  if (LOOKUP_SERVICE_HOST_RE.test(host)) return none('lookup_or_social_service');
  const linkLabel = String(linkText || '').trim();
  if (OBSERVABLE_LINK_TEXT_RE.test(linkLabel) && !PACK_FILE_EXT_RE.test(linkLabel)) return none('per_indicator_link');
  if (NON_PACK_FILE_EXT_RE.test(lastSegment)) return none('non_pack_file');
  const isGitHost = host === 'github.com' || host === 'raw.githubusercontent.com' || host === 'gitlab.com';
  // A file inside a code host must be a data pack (txt / csv / json / README …).
  if (isGitHost && /\/(?:blob|raw)\//.test(path) && !PACK_FILE_EXT_RE.test(lastSegment)) return none('non_pack_file');

  const pointer = EXTERNAL_IOC_POINTER_RE.test(localProse);
  const hasIocHeading = Boolean(headingText && IOC_HEADING_RE.test(headingText));
  const hasStrongPath = pathCues.some((c) => /url:\/(?:ioc|iocs|indicators?)\//.test(c)) || (isGitHost && /(?:^|[-_/])iocs?(?:[-_/.]|$)/i.test(path));
  // Anchor-local evidence: an IOC-dataset phrase, or a pointer sentence that
  // names indicators ("These indicators are available for download here").
  // v3: or the anchor text itself is the indicator noun / an IOC data format
  // ("observables" linking to an /indicators/ path; "STIX XML" / "MISP JSON").
  const packageLeadIn = IOC_PACKAGE_LEAD_IN_RE.test(String(leadIn || ''));
  const localEvidence = textCues.length > 0 || (pointer && LOCAL_IOC_NOUN_RE.test(localProse)) || packageLeadIn ||
    (hasStrongPath && LOCAL_IOC_NOUN_RE.test(linkLabel)) ||
    (IOC_FORMAT_LINK_TEXT_RE.test(linkLabel) && PACK_FILE_EXT_RE.test(lastSegment));

  // Same-site links (navigation, tags, authors, other posts) qualify only as
  // a data file the anchor itself presents as an IOC pack.
  if (reportHost) {
    const rh = String(reportHost).toLowerCase().replace(/^www\./, '');
    const sameSite = host === rh || host.endsWith(`.${rh}`) || rh.endsWith(`.${host}`);
    if (sameSite && !(localEvidence && PACK_FILE_EXT_RE.test(lastSegment))) return none('same_site_navigation');
  }
  if (!localEvidence && !(hasStrongPath && pointer)) return none('no_anchor_local_evidence');
  // Outside a code host the destination itself must look like a data pack
  // (a pack file or an IOC path): a product page, an advisory, another blog
  // post or a WHOIS page is a citation, whatever the sentence says.
  const iocPath = /(?:^|\/)(?:iocs?|indicators?)(?:[-_./]|$)/i.test(path);
  if (!isGitHost && !PACK_FILE_EXT_RE.test(lastSegment) && !iocPath) return none('destination_not_a_pack');

  for (const cue of textCues) {
    score += cue.length >= 18 ? 4 : cue.length >= 12 ? 3 : 2;
  }
  for (const _cue of pathCues) {
    score += 3;
  }
  if (pointer) {
    score += 6;
    matchedCues.push('external_pointer');
  } else if (packageLeadIn) {
    score += 6;
    matchedCues.push('ioc_package_lead_in');
  }
  if (hasIocHeading) {
    score += 5;
    matchedCues.push('ioc_heading');
  }
  if (isGitHost) {
    if (/\/(?:ioc|iocs|indicators?)(?:\/|$)/i.test(path)) {
      score += 5;
      matchedCues.push('host_ioc_path');
    } else {
      score += 2;
      matchedCues.push('host_with_text_evidence');
    }
  }
  if (PACK_FILE_EXT_RE.test(lastSegment)) {
    score += 2;
    matchedCues.push('pack_file_extension');
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
  let previousText = '';

  for (const b of list) {
    if (b?.type === 'heading' && b.text) {
      lastHeading = String(b.text).slice(0, 200);
      previousText = '';
      continue;
    }
    // Lead-in of a list: the block right before it ending with a colon (v3).
    const leadIn = (b?.type === 'list' || b?.type === 'list_item') && /:\s*$/.test(previousText) ? previousText.slice(0, 300) : '';
    previousText = String(b?.text || '').trim();
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
        reportHost,
        leadIn
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

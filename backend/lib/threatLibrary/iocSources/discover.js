/**
 * Automatic discovery of external IOC source references from a processed report.
 * Discovery never fetches or attaches — it only upserts discovered source rows.
 */

import { parseHtml, findElements } from '../extract/htmlBlocks.js';
import { canonicalizeReportUrl } from '../importIdentity.js';
import {
  IOC_SOURCE_DISCOVERY_CUES,
  IOC_SOURCE_DISCOVERY_URL_CUES,
  IOC_SOURCE_LIFECYCLE
} from './constants.js';

const ABSOLUTE_URL_RE = /https?:\/\/[^\s<>"')\]]+/gi;

function normalizeHay(s) {
  return String(s || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function textOf(node) {
  if (!node) return '';
  if (node.type === 'text') return String(node.data || '');
  if (!Array.isArray(node.children)) return '';
  return node.children.map(textOf).join('');
}

function scoreCandidate({ href, linkText, surrounding, reportHost }) {
  const hay = normalizeHay(`${linkText} ${surrounding}`);
  const urlHay = normalizeHay(href);
  let score = 0;
  const matchedCues = [];

  for (const cue of IOC_SOURCE_DISCOVERY_CUES) {
    if (hay.includes(cue)) {
      score += cue.length >= 12 ? 4 : 2;
      matchedCues.push(cue);
    }
  }
  for (const cue of IOC_SOURCE_DISCOVERY_URL_CUES) {
    if (urlHay.includes(cue)) {
      score += 2;
      matchedCues.push(`url:${cue}`);
    }
  }

  try {
    const u = new URL(href);
    if (u.hostname === 'github.com' || u.hostname === 'www.github.com' || u.hostname === 'raw.githubusercontent.com') {
      if (/\/ioc\b|indicators?/i.test(u.pathname)) score += 5;
      else if (matchedCues.length) score += 2;
    }
    if (reportHost) {
      const rh = String(reportHost).toLowerCase().replace(/^www\./, '');
      const hh = u.hostname.toLowerCase().replace(/^www\./, '');
      if (hh === rh || hh.endsWith(`.${rh}`) || rh.endsWith(`.${hh}`)) {
        if (matchedCues.length) score += 2;
      }
    }
  } catch {
    return { score: 0, matchedCues };
  }

  // Nav / social noise
  if (/\b(twitter|x\.com|linkedin|facebook|youtube|mailto:)\b/i.test(href)) score -= 10;
  if (/\/(about|careers|privacy|terms|login|contact)\b/i.test(href) && matchedCues.length === 0) score -= 5;

  return { score, matchedCues };
}

/**
 * Discover IOC-pack hyperlinks from retained HTML.
 * @param {string} html
 * @param {{ reportUrl?: string|null }} [opts]
 * @returns {Array<object>}
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
    const hrefRaw = a.attribs?.href || a.attribs?.HREF || '';
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
    const { score, matchedCues } = scoreCandidate({
      href: absolute,
      linkText,
      surrounding: parentText,
      reportHost
    });
    if (score < 3 || matchedCues.length === 0) continue;

    const prev = byCanon.get(canonical);
    if (prev && prev.score >= score) continue;
    byCanon.set(canonical, {
      original_url: absolute,
      canonical_url: canonical,
      discovery_method: 'auto',
      source_type: guessTypeFromUrl(canonical),
      score,
      discovery_evidence: {
        link_text: linkText.slice(0, 240),
        surrounding_text: parentText.slice(0, 400),
        matched_cues: matchedCues.slice(0, 12),
        score,
        report_url: opts.reportUrl || null
      }
    });
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
    const surrounding = raw.slice(Math.max(0, idx - 120), Math.min(raw.length, idx + absolute.length + 120));
    const { score, matchedCues } = scoreCandidate({
      href: absolute,
      linkText: '',
      surrounding,
      reportHost
    });
    if (score < 3 || matchedCues.length === 0) continue;
    const prev = byCanon.get(canonical);
    if (prev && prev.score >= score) continue;
    byCanon.set(canonical, {
      original_url: absolute,
      canonical_url: canonical,
      discovery_method: 'auto',
      source_type: guessTypeFromUrl(canonical),
      score,
      discovery_evidence: {
        link_text: '',
        surrounding_text: surrounding.slice(0, 400),
        matched_cues: matchedCues.slice(0, 12),
        score,
        report_url: opts.reportUrl || null
      }
    });
  }
  return [...byCanon.values()].sort((a, b) => b.score - a.score);
}

export function guessTypeFromUrl(url) {
  const u = String(url || '').toLowerCase();
  // GitHub blob/tree URLs are source packs even when the path ends in .txt/.csv.
  if (u.includes('github.com/')) {
    if (/\/blob\//.test(u)) return 'github_file';
    if (/\/tree\//.test(u) || /\/ioc\b/.test(u)) return 'github_dir';
  }
  if (u.includes('raw.githubusercontent.com/')) return 'github_file';
  if (/\.pdf(\?|$)/i.test(u)) return 'pdf';
  if (/\.csv(\?|$)/i.test(u)) return 'csv';
  if (/\.json(\?|$)/i.test(u)) return 'json';
  if (/\.(txt|md|ioc|ya?ml)(\?|$)/i.test(u)) return 'txt';
  if (/\.(html?|htm)(\?|$)/i.test(u)) return 'html';
  return 'unknown';
}

/**
 * Persist discovery results for a report (idempotent by canonical_url).
 * Never reactivates dismissed sources.
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
        item.source_type || 'unknown',
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

/**
 * Campaign scoping for linked IOC packs (tl-ioc-source-scope-v1).
 *
 * A publisher IOC repository folder can hold one campaign (a README that links
 * back to exactly this report) or many (one README section per blog post, plus
 * hash lists that mix every campaign). Only content the publisher ties to THIS
 * report is linked-source evidence:
 *
 * - AsciiDoc READMEs are read structurally (headings + `|===` tables), never as
 *   flat text: a "Hosting provider" cell must stay a column, not a provider
 *   stance of the row's C2 IP.
 * - A multi-campaign README contributes only the section whose heading matches
 *   the report title or whose body links the report; its folder-wide hash
 *   lists cannot be attributed and are not ingested.
 * - MITRE ATT&CK / reference sections and links back to the publisher's own
 *   articles are never indicators.
 * - A repository root is never ingested: the campaign folder is resolved from
 *   the report's own distinctive names and must be corroborated by a README
 *   that links the report.
 *
 * Pure helpers (no network) except resolveGitHubCampaignFolder, which takes an
 * injected listing / fetch function with explicit request bounds.
 */

import { createCanonicalDocument, createTableBlock } from '../canonicalDocument.js';
import { canonicalizeReportUrl } from '../importIdentity.js';

// v9: a linked PDF yields its canonical document (the pdfIngest wrapper was read as
// the document → 0 values), scoped to its own report Indicator membership.
export const IOC_SOURCE_SCOPE_VERSION = 'tl-ioc-source-scope-v9';

/**
 * Section headings that never hold indicators. Antivirus detection-name lists
 * ("ESET detection names") label samples; they are README structure, never a
 * second campaign (v2 — a single-campaign ESET README resolves).
 */
const NON_INDICATOR_SECTION_RE = /\b(?:mitre|att&ck|attack\s+techniques|references?|acknowledg\w*|license|changelog|contact|detection\s+names?)\b/i;
/** Generic IOC-section headings (structure of one campaign, not a campaign title). */
const GENERIC_IOC_SECTION_RE =
  /^(?:iocs?|indicators?(?:\s+of\s+compromise)?(?:\s*\(iocs?\))?|files?|network|hashes|samples?|domains?|ip\s+addresses|urls?|registry|file\s+paths?|mutex(?:es)?|certificates?|yara|sigma|detections?|mitre\s+att&ck\s+techniques)\b/i;
const STOPWORDS = new Set([
  'the', 'and', 'for', 'with', 'from', 'into', 'over', 'that', 'this', 'new', 'old', 'same', 'how', 'what', 'why',
  'its', 'their', 'your', 'our', 'are', 'was', 'were', 'has', 'have', 'inside', 'part', 'takes', 'via', 'using',
  'attack', 'attacks', 'campaign', 'campaigns', 'malware', 'analysis', 'report', 'research', 'threat', 'threats',
  'indicators', 'compromise', 'targeting', 'targets', 'operation', 'group', 'actor', 'actors'
]);

function stripAdocInline(s) {
  return String(s || '')
    .replace(/`\+([^`]*?)\+`/g, '$1')
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\+\+([^+]*)\+\+/g, '$1')
    .replace(/\*\*?([^*]+)\*\*?/g, '$1')
    .trim();
}

/**
 * AsciiDoc (ESET malware-ioc README.adoc style) → canonical document:
 * `= Title` / `== Section` headings, `|===` tables (first row = header when
 * the block attribute says options="header" or the row has no observable),
 * paragraphs otherwise. Link macros keep their URL in text.
 * @param {string} text
 * @param {{ title?: string, sourceUrl?: string|null }} [meta]
 */
export function asciidocToCanonicalDocument(text, meta = {}) {
  const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
  const blocks = [];
  let idx = 0;
  let section = null;
  const nextId = () => `b${String((idx += 1)).padStart(3, '0')}`;
  let pendingAttr = '';
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i];
    const line = raw.trim();
    if (!line || line.startsWith('//')) continue;
    const heading = line.match(/^(={1,6})\s+(.+?)\s*$/);
    if (heading) {
      section = stripAdocInline(heading[2]);
      blocks.push({ id: nextId(), type: 'heading', level: heading[1].length, text: section, section, page: null });
      pendingAttr = '';
      continue;
    }
    if (/^\[.*\]$/.test(line)) {
      pendingAttr = line;
      continue;
    }
    if (line === '|===') {
      const rows = [];
      let j = i + 1;
      let current = null;
      for (; j < lines.length && lines[j].trim() !== '|==='; j += 1) {
        const l = lines[j].trim();
        if (!l) {
          if (current) rows.push(current);
          current = null;
          continue;
        }
        if (l.startsWith('|')) {
          const cells = l.slice(1).split(/\s*\|\s*/).map(stripAdocInline);
          if (current && current.length && rows.length && rows[0] && current.length < rows[0].length) {
            current.push(...cells);
          } else {
            if (current) rows.push(current);
            current = cells;
          }
        } else if (current) {
          // Continuation of the previous cell (multi-line cell content).
          current[current.length - 1] = `${current[current.length - 1]} ${stripAdocInline(l)}`.trim();
        }
      }
      if (current) rows.push(current);
      const width = Math.max(0, ...rows.map((r) => r.length));
      const normalized = rows.map((r) => (r.length === width ? r : [...r, ...Array(width - r.length).fill('')]));
      const headerRow = /options\s*=\s*"?header/i.test(pendingAttr) ? normalized.shift() : null;
      const block = createTableBlock({ id: nextId(), headers: headerRow, rows: normalized, section, source: 'asciidoc' });
      if (block) blocks.push(block);
      i = j;
      pendingAttr = '';
      continue;
    }
    pendingAttr = '';
    // Listing / literal block delimiters carry no text.
    if (/^(?:-{4,}|\.{4,}|\*{4,}|_{4,}|\+{4,})$/.test(line)) continue;
    // Link macro `url[text]` → "text url"; a defang bracket ("host[.]co.kr",
    // "hxxp[:]//") is part of the value, never link text.
    const textLine = stripAdocInline(line.replace(/\b(https?:\/\/[^\s[]+)\[(?![.:]\]|\/\/\])([^\]]*)\]/g, '$2 $1'));
    blocks.push({ id: nextId(), type: 'paragraph', text: textLine, section, page: null });
  }
  return createCanonicalDocument({
    title: meta.title || 'IOC source',
    language: null,
    blocks,
    meta: { source_url: meta.sourceUrl || null, extractor: 'threat_library_asciidoc_v1', adapter: 'asciidoc' }
  });
}

function normToken(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
}

/**
 * Distinctive names a report uses for its subject (title words and short
 * section titles): "MATCHBOIL", "UAC-0099", "OceanLotus", "Webworm".
 * @param {{ title?: string|null, headings?: string[] }} report
 */
export function distinctiveReportTokens(report) {
  const out = new Set();
  const take = (text, { headingWord = false } = {}) => {
    for (const w of String(text || '').split(/[\s:;,.!?()'"“”‘’|/]+/)) {
      const n = normToken(w);
      if (n.length < 4 || STOPWORDS.has(n)) continue;
      // Title words always count; heading words only when they look like a
      // proper name (capitals / digits / hyphenated designator).
      if (!headingWord || /[A-Z].*[A-Z]|\d|-/.test(w) || /^[A-Z][a-z]+[A-Z]/.test(w)) out.add(n);
    }
  };
  take(report?.title);
  for (const h of report?.headings || []) if (String(h).length <= 60) take(h, { headingWord: true });
  return [...out];
}

function titleSimilarity(a, b) {
  const ta = new Set(String(a || '').toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length >= 3 && !STOPWORDS.has(w)));
  const tb = new Set(String(b || '').toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length >= 3 && !STOPWORDS.has(w)));
  if (!ta.size || !tb.size) return 0;
  let inter = 0;
  for (const w of ta) if (tb.has(w)) inter += 1;
  return inter / Math.min(ta.size, tb.size);
}

function reportLinkHost(hostname) {
  return String(hostname || '').toLowerCase().replace(/^www\./, '');
}

/** Last non-empty path segment — Elastic slug (`taking-shellter`). */
function pathSlug(pathname) {
  const parts = String(pathname || '').toLowerCase().split('/').filter(Boolean);
  return parts.length ? parts[parts.length - 1] : '';
}

function linksReport(text, reportUrl) {
  const canon = reportUrl ? canonicalizeReportUrl(reportUrl) : null;
  if (!canon) return false;
  let canonPath = '';
  let canonHost = '';
  let canonSlug = '';
  try {
    const cu = new URL(canon);
    canonPath = cu.pathname.replace(/\/+$/, '').toLowerCase();
    canonHost = reportLinkHost(cu.hostname);
    canonSlug = pathSlug(cu.pathname);
  } catch {
    return false;
  }
  for (const m of String(text || '').matchAll(/https?:\/\/[^\s<>"'`[\]]+/gi)) {
    const cleaned = m[0].replace(/[.,;:)]+$/, '');
    if (canonicalizeReportUrl(cleaned) === canon) return true;
    // Elastic Security Labs READMEs often cite the same article with www /
    // non-www hosts, or with/without a `/threat-command/` path prefix while
    // keeping the same terminal slug.
    try {
      const u = new URL(cleaned);
      const host = reportLinkHost(u.hostname);
      if (host !== canonHost) continue;
      const path = u.pathname.replace(/\/+$/, '').toLowerCase();
      if (canonPath && path === canonPath) return true;
      const slug = pathSlug(u.pathname);
      if (canonSlug && slug && slug === canonSlug && slug.length >= 6) return true;
    } catch {
      // ignore
    }
  }
  return false;
}

/**
 * Lightweight Markdown → canonical document for campaign README scoping.
 * Preserves ATX headings (`#` / `##`) so selectCampaignScope can see sections.
 * @param {string} text
 * @param {{ title?: string, sourceUrl?: string|null }} [meta]
 */
export function markdownToCanonicalDocument(text, meta = {}) {
  const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
  const blocks = [];
  let idx = 0;
  let section = null;
  const nextId = () => `b${String((idx += 1)).padStart(3, '0')}`;
  let para = [];
  const flushPara = () => {
    if (!para.length) return;
    const t = para.join('\n').trim();
    para = [];
    if (!t) return;
    blocks.push({ id: nextId(), type: 'paragraph', text: t, section, page: null });
  };
  for (const raw of lines) {
    const heading = raw.match(/^(#{1,6})\s+(.+?)\s*$/);
    if (heading) {
      flushPara();
      section = heading[2].trim();
      blocks.push({
        id: nextId(),
        type: 'heading',
        level: heading[1].length,
        text: section,
        section,
        page: null
      });
      continue;
    }
    if (!raw.trim()) {
      flushPara();
      continue;
    }
    // Keep markdown link URLs visible for linksReport.
    const withUrls = raw.replace(/\[([^\]]*)\]\((https?:[^)\s]+)\)/g, '$1 $2');
    para.push(withUrls);
  }
  flushPara();
  return createCanonicalDocument({
    title: meta.title || 'Markdown IOC source',
    language: null,
    blocks,
    meta: { source_url: meta.sourceUrl || null, extractor: 'tl-markdown-readme-v1', adapter: 'markdown_readme' }
  });
}

/**
 * Select the part of a README document that belongs to the report.
 * @param {object} document canonical document (asciidoc / markdown)
 * @param {{ reportUrl?: string|null, reportTitle?: string|null }} report
 * @returns {{ status: 'single_campaign'|'campaign_section'|'unresolved', document: object|null, section_heading: string|null, multi_campaign: boolean, excluded_sections: string[] }}
 */
export function selectCampaignScope(document, report = {}) {
  const blocks = Array.isArray(document?.blocks) ? document.blocks : [];
  // Sections = level-2 headings (level 1 is the README title + intro).
  const sections = [];
  let intro = { heading: null, blocks: [] };
  let cur = null;
  for (const b of blocks) {
    if (b.type === 'heading' && Number(b.level) === 2) {
      cur = { heading: b.text, blocks: [b] };
      sections.push(cur);
      continue;
    }
    if (b.type === 'heading' && Number(b.level) === 1) {
      intro = { heading: b.text, blocks: [b] };
      cur = null;
      continue;
    }
    (cur || intro).blocks.push(b);
  }
  const text = (bs) => bs.map((b) => b.text || '').join('\n');
  const excluded = sections.filter((s) => NON_INDICATOR_SECTION_RE.test(s.heading)).map((s) => s.heading);
  const kept = sections.filter((s) => !NON_INDICATOR_SECTION_RE.test(s.heading));
  const campaignSections = kept.filter((s) => !GENERIC_IOC_SECTION_RE.test(String(s.heading || '').trim()));
  const multi = campaignSections.length > 1 || (campaignSections.length === 1 && kept.length > 1 && !linksReport(text(intro.blocks), report.reportUrl));
  const build = (bs) => createCanonicalDocument({ ...document, blocks: bs });

  if (!multi) {
    // One campaign: the README must tie itself to this report (intro or body
    // link, or a campaign section titled like the report).
    const all = [...intro.blocks, ...kept.flatMap((s) => s.blocks)];
    const tied = linksReport(text(all), report.reportUrl) ||
      campaignSections.some((s) => titleSimilarity(s.heading, report.reportTitle) >= 0.6) ||
      titleSimilarity(intro.heading, report.reportTitle) >= 0.6;
    if (!tied) return { status: 'unresolved', document: null, section_heading: null, multi_campaign: false, excluded_sections: excluded };
    return { status: 'single_campaign', document: build(all), section_heading: intro.heading || null, multi_campaign: false, excluded_sections: excluded };
  }
  const match = campaignSections.filter((s) => linksReport(text(s.blocks), report.reportUrl) || titleSimilarity(s.heading, report.reportTitle) >= 0.6);
  if (match.length !== 1) {
    return { status: 'unresolved', document: null, section_heading: null, multi_campaign: true, excluded_sections: excluded };
  }
  return {
    status: 'campaign_section',
    document: build(match[0].blocks),
    section_heading: match[0].heading,
    multi_campaign: true,
    excluded_sections: [...excluded, ...campaignSections.filter((s) => s !== match[0]).map((s) => s.heading)]
  };
}

/**
 * Whether a linked candidate is a reference to the publisher's own material
 * (the report itself, another article on the report host) or to ATT&CK — never
 * a linked indicator.
 * @param {{ candidate_type: string, normalized_value: string }} c
 * @param {{ reportUrl?: string|null }} report
 */
export function isPublisherReferenceCandidate(c, report = {}) {
  const type = String(c?.candidate_type || '');
  if (type !== 'url' && type !== 'domain') return false;
  const value = String(c?.normalized_value || '');
  let host = '';
  try {
    host = type === 'url' ? new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http://${value}`).hostname.toLowerCase() : value.toLowerCase();
  } catch {
    return false;
  }
  host = host.replace(/^www\./, '');
  if (host === 'attack.mitre.org' || host.endsWith('.mitre.org')) return true;
  let reportHost = '';
  try {
    reportHost = report.reportUrl ? new URL(report.reportUrl).hostname.toLowerCase().replace(/^www\./, '') : '';
  } catch {
    reportHost = '';
  }
  return Boolean(reportHost) && (host === reportHost || host.endsWith(`.${reportHost}`));
}

/** File names that are a folder's README (campaign description + IOC tables). */
export function isReadmePath(path) {
  return /(^|\/)readme\.(?:adoc|asciidoc|md|markdown|txt)$/i.test(String(path || ''));
}

/** Folder-wide hash lists (ESET `samples.sha256`): unattributable in a multi-campaign folder. */
export function isFolderHashListPath(path) {
  return /(^|\/)samples?\.(?:md5|sha1|sha256)$/i.test(String(path || ''));
}

/** Delimited inventories that can carry a metadata row naming their report. */
const DELIMITED_INVENTORY_PATH_RE = /\.(?:csv|tsv|txt)$/i;
/**
 * A metadata row at the head of a delimited IOC inventory that names the
 * article the file belongs to: `description,https://publisher/blog/x,…`,
 * `report: https://…`, `source<TAB>https://…`. A data row of type `url` is
 * never a back-link.
 */
const INVENTORY_BACKLINK_ROW_RE =
  /^\s*["']?(?:description|report|source|reference|blog|article|publication)["']?\s*[,;:\t|]\s*["']?(https?:\/\/[^\s,;"'|]+)/i;

/**
 * The report URL a delimited inventory declares in its own metadata rows
 * (first 8 non-empty lines), or null (tl-ioc-source-scope-v3).
 * @param {string} body
 * @param {string|null} path
 * @returns {string|null}
 */
export function inventoryReportBacklink(body, path) {
  if (path && !DELIMITED_INVENTORY_PATH_RE.test(String(path))) return null;
  const lines = String(body || '').replace(/^﻿/, '').split(/\r?\n/).filter((l) => l.trim()).slice(0, 8);
  for (const line of lines) {
    const m = INVENTORY_BACKLINK_ROW_RE.exec(line);
    if (m) return m[1].replace(/[.,;:)]+$/, '');
  }
  return null;
}

/**
 * Scope verdict of one inventory file against the report: `matches` when the
 * file's back-link is this report, `other_report` when it names a different
 * article (another campaign of a shared folder), `undeclared` without one.
 * @param {string} body
 * @param {string|null} path
 * @param {{ reportUrl?: string|null }} report
 * @returns {{ verdict: 'matches'|'other_report'|'undeclared', backlink: string|null }}
 */
export function inventoryBacklinkScope(body, path, report = {}) {
  const backlink = inventoryReportBacklink(body, path);
  if (!backlink) return { verdict: 'undeclared', backlink: null };
  if (!report.reportUrl) return { verdict: 'undeclared', backlink };
  return { verdict: linksReport(backlink, report.reportUrl) ? 'matches' : 'other_report', backlink };
}

/** File name without directory and extension(s): `2026/01/uat-8837.json` → `uat-8837`. */
function fileStem(path) {
  const base = String(path || '').split('/').pop() || '';
  return base.replace(/(?:\.[a-z0-9]{1,8})+$/i, '');
}

/**
 * Files of a shared folder named after the report (tl-ioc-source-scope-v4).
 * A publisher month folder (Cisco Talos `IOCs/2026/01`) holds one inventory
 * per article, named by the article slug: `uat-8837.txt` belongs to
 * `/uat-8837/`, `UAT-7290.json` to another post. When at least one file stem
 * equals (or extends, `<slug>-keyword.txt`) the report URL slug and others do
 * not, only the slug-named files are this report's; otherwise nothing is
 * decided here (a campaign folder's `samples.sha256` / `domains.txt` carry
 * no slug at all).
 * @param {string[]} paths
 * @param {string|null|undefined} reportUrl
 * @returns {Set<string>|null} paths to deselect, or null when undecided
 */
export function reportSlugForeignFiles(paths, reportUrl) {
  let slug = '';
  try {
    slug = normToken(pathSlug(new URL(String(reportUrl || '')).pathname));
  } catch {
    return null;
  }
  if (slug.length < 6) return null;
  const files = (paths || []).filter((p) => !isReadmePath(p));
  const own = files.filter((p) => normToken(fileStem(p)).startsWith(slug));
  if (!own.length || own.length === files.length) return null;
  return new Set(files.filter((p) => !own.includes(p)));
}

/** Folder names under which publishers keep per-campaign inventories. */
const INVENTORY_DIR_RE = /^(?:iocs?|indicators?|intel|intelligence|threat[-_]?intel|data|feeds?|csv|json|stix2?|misp|txt|network|hosts|domains|campaigns?|reports?|research|\d{4}|0?[1-9]|1[0-2]|\d{4}[-_]\d{2})$/i;

/** Date spellings a file name could carry for a publication date. */
function publicationDateTokens(publishedAt) {
  const d = publishedAt ? new Date(publishedAt) : null;
  if (!d || Number.isNaN(d.getTime())) return [];
  // A file can be stamped the day before or after the post goes out.
  const out = [];
  for (const offset of [0, -1, 1]) {
    const x = new Date(d.getTime() + offset * 86_400_000);
    const y = String(x.getUTCFullYear());
    const m = String(x.getUTCMonth() + 1).padStart(2, '0');
    const day = String(x.getUTCDate()).padStart(2, '0');
    out.push(`${y}${m}${day}`, `${m}${day}${y}`);
  }
  return out;
}

const DAY_MS = 86_400_000;
/**
 * How far a file's date stamp may sit from the post and still be the same publication.
 * Indicators are often packaged weeks before the post goes out; later stamps are rarer.
 */
const STAMP_BEFORE_POST_DAYS = 90;
const STAMP_AFTER_POST_DAYS = 30;

/** Months between the post and the year/month folder a file sits in ("2026/09/x", "2026-06/x"). */
function monthFolderDistance(path, published) {
  const m = /(?:^|\/)(20\d{2})[/_-](0[1-9]|1[0-2])\//.exec(String(path || ''));
  if (!m) return null;
  const post = new Date(published);
  return Math.abs((Number(m[1]) - post.getUTCFullYear()) * 12 + (Number(m[2]) - 1 - post.getUTCMonth()));
}

/** The date a file name is stamped with: "x_iocs_20260921", "2017-05-09_x", "x-02-20-2026". */
function fileNameStamp(path) {
  const stem = fileStem(path);
  const iso = /(?<!\d)(20\d{2})[-_.]?(0[1-9]|1[0-2])[-_.]?(0[1-9]|[12]\d|3[01])(?!\d)/.exec(stem);
  if (iso) return Date.UTC(Number(iso[1]), Number(iso[2]) - 1, Number(iso[3]));
  const us = /(?<!\d)(0[1-9]|1[0-2])[-_.]?(0[1-9]|[12]\d|3[01])[-_.]?(20\d{2})(?!\d)/.exec(stem);
  return us ? Date.UTC(Number(us[3]), Number(us[1]) - 1, Number(us[2])) : null;
}

/**
 * A folder named for an actor or family keeps that name across its publications, so
 * its name does not say which of them a file belongs to; the date stamp does.
 *   - A file stamped for this publication makes other stamped files foreign.
 *   - A stamp far from the post is another publication, whatever the name says.
 *   - So is a file in a year/month folder more than a month from the post.
 *   - A folder whose stamps are all foreign is a long-lived actor folder, so its
 *     unstamped files cannot be tied to this report either.
 * A file named by the report's own URL slug is exempt. No publication date, no decision.
 */
function separatePublications(matches, publishedAt) {
  const published = publishedAt ? new Date(publishedAt).getTime() : NaN;
  if (Number.isNaN(published)) return { kept: matches, foreign: [] };
  const daysOff = (m) => Math.abs(m.stamp - published) / DAY_MS;
  const outsideWindow = (m) => (m.stamp <= published ? (published - m.stamp) / DAY_MS > STAMP_BEFORE_POST_DAYS : (m.stamp - published) / DAY_MS > STAMP_AFTER_POST_DAYS);
  const stamped = matches.map((m) => ({ ...m, stamp: fileNameStamp(m.path) }));
  const dated = stamped.filter((m) => m.stamp != null && m.evidence !== 'report_slug');
  const exact = dated.some((m) => daysOff(m) < 2);
  const isForeign = (m) => {
    if (m.evidence === 'report_slug') return false;
    if (m.stamp != null) return exact ? daysOff(m) >= 2 : outsideWindow(m);
    return (monthFolderDistance(m.path, published) ?? 0) > 1;
  };
  const ownFolders = new Set(stamped.filter((m) => m.folder && m.stamp != null && !isForeign(m)).map((m) => m.folder));
  const foreignFolders = new Set(stamped.filter((m) => m.folder && isForeign(m)).map((m) => m.folder));
  const kept = [];
  const foreign = [];
  for (const { stamp, ...m } of stamped) {
    if (isForeign({ ...m, stamp })) foreign.push({ path: m.path, evidence: m.evidence, reason: 'file_dated_for_another_publication' });
    else if (m.folder && stamp == null && foreignFolders.has(m.folder) && !ownFolders.has(m.folder)) foreign.push({ path: m.path, evidence: m.evidence, reason: 'folder_holds_other_publications' });
    else kept.push(m);
  }
  return { kept, foreign };
}

/** A folder like "2026-10-13 Ivanti": the publication date and a title word. Never the date alone. */
function datedFolderForReport(name, titleNames, publishedAt) {
  const joined = normToken(name);
  if (!publicationDateTokens(publishedAt).some((t) => joined.includes(t))) return false;
  return String(name).toLowerCase().split(/[^a-z0-9]+/).some((w) => titleNames.has(w));
}

/** Consecutive title words, joined: "EDR killers" gives "edrkillers" for a folder `edr_killers`. */
function titlePhrases(title) {
  const words = String(title || '').split(/[\s:;,.!?()'"“”‘’|/]+/).map(normToken).filter(Boolean);
  const out = new Set();
  for (let i = 0; i < words.length; i += 1) {
    for (const n of [2, 3]) {
      const phrase = words.slice(i, i + n);
      if (phrase.length === n && phrase.join('').length >= 8) out.add(phrase.join(''));
    }
  }
  return out;
}

/** File name words that say nothing about which campaign a file belongs to. */
const GENERIC_FILE_WORD_RE = /^(?:iocs?|indicators?|cta|csv|json|txt|stix|misp|all|data|list|final|v?\d+|[ivx]{1,4})$/i;

/** Name words of a file stem found in the report's URL slug: "drop_catch" in "dropcatch-scavengers-…". */
function slugWords(parts, slug) {
  const words = parts.filter((p) => !GENERIC_FILE_WORD_RE.test(p) && !/^\d+$/.test(p));
  if (!words.length || !slug) return [];
  const joined = words.join('');
  if (joined.length >= 6 && slug.includes(joined)) return words;
  return words.filter((w) => w.length >= 5 && slug.includes(w));
}

/**
 * Evidence that a file name refers to this report (pure). The content of the file
 * is never consulted, so indicator overlap cannot associate a file with a report.
 *
 *   report_slug      the stem starts with the report URL slug
 *   designator       the stem holds a designator of the report ("UAT-8837")
 *   title_names      the stem holds two or more of the report's distinctive names
 *   date_and_name    the stem holds the publication date and one distinctive name
 *   date_and_slug_word  the publication date and a name word of the report's URL slug
 *
 * A date alone or one ordinary word alone is not evidence.
 * @param {string} path
 * @param {{ reportUrl?: string|null, reportTitle?: string|null, headings?: string[], publishedAt?: string|Date|null }} report
 * @returns {{ matched: boolean, evidence: string|null, names: string[], date: boolean }}
 */
export function fileNameReportEvidence(path, report = {}) {
  const stem = fileStem(path);
  const parts = stem.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const joined = normToken(stem);
  const names = distinctiveReportTokens({ title: report.reportTitle, headings: report.headings })
    .filter((t) => parts.includes(t) || (/\d/.test(t) && joined.includes(t)));
  const date = publicationDateTokens(report.publishedAt).some((t) => joined.includes(t));
  let slug = '';
  try {
    slug = normToken(pathSlug(new URL(String(report.reportUrl || '')).pathname));
  } catch {
    slug = '';
  }
  let evidence = null;
  if (slug.length >= 6 && joined.startsWith(slug)) evidence = 'report_slug';
  else if (names.some((t) => /\d/.test(t) && /[a-z]/.test(t) && t.length >= 5)) evidence = 'designator';
  else if (names.length >= 2) evidence = 'title_names';
  else if (date && names.length >= 1) evidence = 'date_and_name';
  else if (date && slugWords(parts, slug).length >= 1) evidence = 'date_and_slug_word';
  return { matched: Boolean(evidence), evidence, names, date };
}

/**
 * Find inventory files of a report in a shared repository from safe metadata: the
 * directory listing only, through a bounded walk of inventory-shaped folders.
 * Nothing is read and nothing is approved here; a matched file is still inspected,
 * its own back-link can still reject it, and an analyst decides.
 *
 * @param {{ path?: string }} gh
 * @param {{ reportUrl?: string|null, reportTitle?: string|null, headings?: string[], publishedAt?: string|Date|null }} report
 * @param {{ listDir: (path: string) => Promise<Array<{ name: string, type: string, path: string, size?: number|null }>> }} io
 * @param {{ maxDirs?: number, maxDepth?: number, maxMatches?: number }} [limits]
 */
export async function resolveGitHubCampaignFiles(gh, report, io, limits = {}) {
  const maxDirs = limits.maxDirs ?? 16;
  const maxDepth = limits.maxDepth ?? 3;
  const maxMatches = limits.maxMatches ?? 12;
  const start = String(gh.path || '').replace(/^\/+|\/+$/g, '');
  // Year and month folders of the publication date go first, so a repository with
  // many years stays inside the walk limit.
  const published = report.publishedAt ? new Date(report.publishedAt) : null;
  const year = published && !Number.isNaN(published.getTime()) ? String(published.getUTCFullYear()) : null;
  const month = year ? String(published.getUTCMonth() + 1).padStart(2, '0') : null;
  const priority = (name) => (name === year || name === month || name === `${year}-${month}` || name === `${year}_${month}` ? 0 : /^\d+$/.test(name) ? 2 : 1);
  const titleNames = new Set(distinctiveReportTokens({ title: report.reportTitle }));
  const titleWordRuns = titlePhrases(report.reportTitle);
  const queue = [{ path: start, depth: 0 }];
  const matches = [];
  const checked = [];
  let requests = 0;
  let filesSeen = 0;
  while (queue.length && requests < maxDirs) {
    const { path, depth } = queue.shift();
    requests += 1;
    checked.push(path || '/');
    const entries = (await io.listDir(path)) || [];
    // A folder named exactly for the report ("webworm", "indicators/shellter", "edr_killers"):
    // its files are the candidates. Only title words count, and the name must be distinctive.
    const namedForReport = (x) => {
      const n = normToken(x.name);
      return x.type === 'dir' && !INVENTORY_DIR_RE.test(x.name) && ((titleNames.has(n) && n.length >= 5) || titleWordRuns.has(n) || datedFolderForReport(x.name, titleNames, report.publishedAt));
    };
    for (const e of entries.filter(namedForReport)) {
      if (requests >= maxDirs) break;
      requests += 1;
      checked.push(e.path);
      for (const inner of (await io.listDir(e.path)) || []) {
        if (inner.type === 'file' && (DATA_FILE_RE.test(inner.name) || isReadmePath(inner.name) || IOC_NOTE_FILE_RE.test(inner.name))) {
          filesSeen += 1;
          matches.push({ path: inner.path, size: inner.size ?? null, evidence: 'folder_named_for_report', names: [normToken(e.name)], date: false, folder: e.path });
        }
      }
    }
    // A post is not filed under another year, so when its own year has a folder the others
    // are not listed: each listing spends the shared hourly GitHub allowance.
    const hasOwnYear = entries.some((e) => e.type === 'dir' && e.name === year);
    const dirs = entries
      .filter((e) => e.type === 'dir' && depth + 1 < maxDepth && INVENTORY_DIR_RE.test(e.name))
      .filter((e) => !hasOwnYear || !/^\d{4}$/.test(e.name) || e.name === year)
      .sort((a, b) => priority(a.name) - priority(b.name));
    queue.unshift(...dirs.filter((d) => priority(d.name) === 0).map((d) => ({ path: d.path, depth: depth + 1 })));
    queue.push(...dirs.filter((d) => priority(d.name) !== 0).map((d) => ({ path: d.path, depth: depth + 1 })));
    for (const e of entries) {
      if (e.type === 'dir') {
        continue;
      } else if (e.type === 'file' && DATA_FILE_RE.test(e.name)) {
        filesSeen += 1;
        const ev = fileNameReportEvidence(e.path, report);
        if (ev.matched) matches.push({ path: e.path, size: e.size ?? null, evidence: ev.evidence, names: ev.names, date: ev.date });
      }
    }
  }
  const truncated = queue.length > 0;
  // Several posts on one actor share a designator: keep the stems with the most
  // evidence, and name the others so an analyst can see what was set aside.
  const { kept: samePublication, foreign } = separatePublications(matches, report.publishedAt);
  const scored = samePublication.map((m) => ({ ...m, score: FILE_EVIDENCE_RANK[m.evidence] + m.names.length + (m.date ? 1 : 0) }));
  const best = scored.reduce((n, m) => Math.max(n, m.score), 0);
  const kept = scored.filter((m) => m.score === best);
  const setAside = [...foreign, ...scored.filter((m) => m.score < best).map((m) => ({ path: m.path, evidence: m.evidence, reason: 'weaker_match_than_another_file' }))];
  matches.length = 0;
  matches.push(...kept);
  if (!matches.length) {
    return { ok: false, reason: foreign.length ? 'named_files_belong_to_other_publications' : 'no_file_named_for_report', files: [], set_aside: setAside.slice(0, 20), candidates_checked: checked, files_seen: filesSeen, requests, truncated };
  }
  return { ok: true, reason: 'file_names_match_report', files: matches.slice(0, maxMatches), set_aside: setAside.slice(0, 20), not_listed: Math.max(0, matches.length - maxMatches), candidates_checked: checked, files_seen: filesSeen, requests, truncated };
}

const FILE_EVIDENCE_RANK = Object.freeze({ report_slug: 6, folder_named_for_report: 5, title_names: 4, designator: 3, date_and_name: 2, date_and_slug_word: 2 });

/** Inside a folder named for the report, a Markdown file named as its indicators: "x-campaign-iocs.md". */
const IOC_NOTE_FILE_RE = /(?:^|[-_ .])(?:iocs?|indicators?)(?:[-_ .].*)?\.md$/i;

/** Machine-readable inventories a root walk may match by name. */
const DATA_FILE_RE = /\.(?:csv|tsv|txt|json|ndjson|jsonl|stix|xml|sha256|sha1|md5|ioc)$/i;

/**
 * Resolve the campaign folder of a repository-root pointer. Candidate folders
 * are only those whose NAME equals one of the report's distinctive names
 * (bounded breadth / depth); a folder is accepted only when its README links
 * the report. Never walks the repository.
 *
 * @param {{ owner: string, repo: string, ref: string, path: string }} gh
 * @param {{ reportUrl: string|null, reportTitle?: string|null, headings?: string[] }} report
 * @param {{ listDir: (path: string) => Promise<Array<{ name: string, type: string, path: string }>>, readFile: (path: string) => Promise<string|null> }} io
 * @param {{ maxCandidates?: number, maxDepth?: number }} [limits]
 * @returns {Promise<{ ok: boolean, path?: string, reason: string, candidates_checked: string[], requests: number }>}
 */
export async function resolveGitHubCampaignFolder(gh, report, io, limits = {}) {
  const maxCandidates = limits.maxCandidates ?? 3;
  const maxDepth = limits.maxDepth ?? 2;
  const tokens = distinctiveReportTokens({ title: report.reportTitle, headings: report.headings });
  const checked = [];
  let requests = 0;
  if (!tokens.length) return { ok: false, reason: 'no_distinctive_report_names', candidates_checked: checked, requests };
  const matches = (name) => {
    const n = normToken(name);
    return n.length >= 4 && tokens.some((t) => t === n);
  };
  let frontier = [String(gh.path || '').replace(/^\/+|\/+$/g, '')];
  for (let depth = 0; depth < maxDepth && frontier.length; depth += 1) {
    const next = [];
    for (const dir of frontier) {
      requests += 1;
      const entries = await io.listDir(dir);
      const named = (entries || []).filter((e) => e.type === 'dir' && matches(e.name)).slice(0, maxCandidates);
      for (const folder of named) {
        checked.push(folder.path);
        requests += 1;
        const entriesInFolder = await io.listDir(folder.path);
        const readme = (entriesInFolder || []).find((e) => e.type === 'file' && isReadmePath(e.name));
        if (readme) {
          requests += 1;
          const body = await io.readFile(readme.path);
          if (body && linksReport(body, report.reportUrl)) {
            return { ok: true, path: folder.path, reason: 'readme_links_report', candidates_checked: checked, requests };
          }
        }
        next.push(folder.path);
      }
    }
    frontier = next.slice(0, maxCandidates);
  }
  return { ok: false, reason: 'no_corroborated_campaign_folder', candidates_checked: checked, requests };
}

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

export const IOC_SOURCE_SCOPE_VERSION = 'tl-ioc-source-scope-v1';

/** Section headings that never hold indicators. */
const NON_INDICATOR_SECTION_RE = /\b(?:mitre|att&ck|attack\s+techniques|references?|acknowledg\w*|license|changelog|contact)\b/i;
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

function linksReport(text, reportUrl) {
  const canon = reportUrl ? canonicalizeReportUrl(reportUrl) : null;
  if (!canon) return false;
  for (const m of String(text || '').matchAll(/https?:\/\/[^\s<>"'`[\]]+/gi)) {
    if (canonicalizeReportUrl(m[0].replace(/[.,;:)]+$/, '')) === canon) return true;
  }
  return false;
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

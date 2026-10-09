/**
 * Pure helpers for IOC detail tag badges (manual orange / feed blue /
 * Threat Library context teal).
 */

function reportTitles(reports) {
  return reports.map((r) => String(r?.title || '').trim()).filter(Boolean);
}

function reportList(titles) {
  return `Threat Library report${titles.length > 1 ? 's' : ''}: ${titles.join('; ')}`;
}

/**
 * Why a Threat Library report tag shows on this IOC. A report tag is an IOC
 * tag only when the report's evidence for THIS IOC names it (`ioc_evidence`);
 * otherwise it is report-level context (campaign, sector, theme) and the
 * tooltip says so — never "inherited", which reads as an IOC assertion.
 * @param {Array<{ title?: string, ioc_evidence?: boolean }>} reports
 * @param {{ iocEvidence?: boolean }} [opts] entry-level flag when no report titles are known
 */
export function describeThreatLibraryTagSources(reports = [], opts = {}) {
  const list = Array.isArray(reports) ? reports : [];
  const named = reportTitles(list.filter((r) => r?.ioc_evidence === true));
  const context = reportTitles(list.filter((r) => r?.ioc_evidence !== true));
  const parts = [];
  if (named.length) parts.push(`Named for this IOC in ${reportList(named)}`);
  if (context.length) parts.push(`Report context from ${reportList(context)} (not an assertion about this IOC)`);
  if (parts.length) return parts.join('. ');
  return opts.iocEvidence === true
    ? 'Named for this IOC in a Threat Library report'
    : 'Report context from a Threat Library report (not an assertion about this IOC)';
}

export function formatTagSourcesCell(sources = [], { maxVisible = 2 } = {}) {
  const list = Array.isArray(sources) ? sources.filter(Boolean).map(String) : [];
  if (!list.length) return { text: '—', title: '' };
  if (list.length <= maxVisible) {
    const text = list.join(', ');
    return { text, title: text };
  }
  const visible = list.slice(0, maxVisible);
  const rest = list.length - maxVisible;
  return {
    text: `${visible.join(', ')} +${rest}`,
    title: list.join(', ')
  };
}

/**
 * Build display badges for IOC Tags card.
 * Manual assignments win (orange). Feed tags dedupe by normalized name.
 * Disabled catalog names hide matching feed badges.
 *
 * @param {{
 *   manualTags?: Array<{ id: number|string, name: string, is_active?: boolean }>,
 *   feedTags?: Array<{ tag?: string, normalized?: string, source_name?: string }>,
 *   contextTags?: Array<{ name: string, reports?: Array<{ id: string, title: string }> }>,
 *   disabledTagNames?: Iterable<string>
 * }} opts
 *
 * contextTags = tags of linked Threat Library reports (GET
 * /api/ioc/:id/tags/threat-library), each with `ioc_evidence`: true when the
 * report's evidence for this IOC names the tag (an IOC tag), false when it is
 * report-level context only. They are shown in their own group (never as
 * direct assignments) and cannot be removed here — they are managed on the
 * report. When the same tag is also assigned directly or by a feed, that badge
 * wins and its tooltip notes the report source.
 */
export function buildIocTagBadges({
  manualTags = [],
  feedTags = [],
  contextTags = [],
  disabledTagNames = []
} = {}) {
  const disabled = new Set(
    [...(disabledTagNames || [])].map((n) => String(n || '').trim().toLowerCase()).filter(Boolean)
  );

  const manual = [];
  const manualNorms = new Set();
  for (const tag of manualTags || []) {
    const name = String(tag?.name || '').trim();
    if (!name) continue;
    const normalized = name.toLowerCase();
    if (disabled.has(normalized)) continue;
    if (tag?.is_active === false) continue;
    manualNorms.add(normalized);
    manual.push({
      kind: 'manual',
      key: `manual-${tag.id}`,
      id: tag.id,
      label: name,
      normalized,
      title: 'Added by analyst',
      sources: ['Manual']
    });
  }

  const feedByNorm = new Map();
  for (const ft of feedTags || []) {
    const normalized = String(ft?.normalized || ft?.tag || '').trim().toLowerCase();
    if (!normalized) continue;
    if (disabled.has(normalized)) continue;
    if (manualNorms.has(normalized)) continue;
    const label = String(ft?.tag || ft?.normalized || '').trim() || normalized;
    const source = String(ft?.source_name || '').trim();
    const existing = feedByNorm.get(normalized);
    if (existing) {
      if (source && !existing.sources.includes(source)) existing.sources.push(source);
      continue;
    }
    feedByNorm.set(normalized, {
      kind: 'feed',
      key: `feed-${normalized}`,
      label,
      normalized,
      sources: source ? [source] : []
    });
  }

  const feed = [...feedByNorm.values()].map((item) => ({
    ...item,
    title: item.sources.length
      ? `Imported from ${item.sources.join(', ')}`
      : 'Imported from feed'
  }));

  const context = [];
  const seenContext = new Set();
  for (const ct of contextTags || []) {
    const label = String(ct?.name || '').trim();
    const normalized = label.toLowerCase();
    if (!normalized || disabled.has(normalized) || seenContext.has(normalized)) continue;
    seenContext.add(normalized);
    const reports = Array.isArray(ct?.reports) ? ct.reports : [];
    const iocEvidence = ct?.ioc_evidence === true || reports.some((r) => r?.ioc_evidence === true);
    const inheritedNote = describeThreatLibraryTagSources(reports, { iocEvidence });
    const owner = manual.find((m) => m.normalized === normalized) || feed.find((f) => f.normalized === normalized);
    if (owner) {
      owner.title = `${owner.title}. Also ${inheritedNote.charAt(0).toLowerCase()}${inheritedNote.slice(1)}`;
      owner.inheritedReports = reports;
      continue;
    }
    context.push({
      kind: 'threat_library',
      key: `tl-${normalized}`,
      label,
      normalized,
      reports,
      iocEvidence,
      title: inheritedNote
    });
  }

  return {
    manual,
    feed,
    context,
    hasTags: manual.length > 0 || feed.length > 0 || context.length > 0
  };
}

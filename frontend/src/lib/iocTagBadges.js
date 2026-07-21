/**
 * Pure helpers for IOC detail tag badges (manual orange / feed blue).
 */

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
 *   disabledTagNames?: Iterable<string>
 * }} opts
 */
export function buildIocTagBadges({
  manualTags = [],
  feedTags = [],
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

  return { manual, feed, hasTags: manual.length > 0 || feed.length > 0 };
}

export const THREAT_ACTOR_MANAGER_PAGE_SIZE = 25;
export const THREAT_ACTOR_MANAGER_SEARCH_DEBOUNCE_MS = 300;

export const EMPTY_THREAT_ACTOR_FORM = {
  name: '',
  aliases: '',
  description: '',
  active: true
};

export function formatThreatActorManagerShowingLabel({ page, pageSize = THREAT_ACTOR_MANAGER_PAGE_SIZE, totalItems }) {
  const total = Math.max(0, Number(totalItems) || 0);
  if (total === 0) return 'Showing 0 of 0';
  const size = Math.max(1, Number(pageSize) || THREAT_ACTOR_MANAGER_PAGE_SIZE);
  const p = Math.max(1, Number(page) || 1);
  const from = (p - 1) * size + 1;
  const to = Math.min(p * size, total);
  return `Showing ${from}–${to} of ${total}`;
}

export function buildThreatActorManagerQueryParams({
  page = 1,
  search = '',
  showInactive = true,
  pageSize = THREAT_ACTOR_MANAGER_PAGE_SIZE
} = {}) {
  const params = {
    page: Math.max(1, Number(page) || 1),
    page_size: pageSize,
    include_inactive: showInactive ? 'true' : 'false'
  };
  const q = String(search || '').trim();
  if (q) params.search = q;
  return params;
}

export function buildThreatActorManagerUrlSearchParams({ page = 1, search = '', showInactive = true } = {}) {
  const next = new URLSearchParams();
  const q = String(search || '').trim();
  if (q) next.set('search', q);
  if (Number(page) > 1) next.set('page', String(page));
  if (!showInactive) next.set('show_inactive', 'false');
  return next;
}

export function parseThreatActorManagerUrlState(searchParams) {
  const page = Math.max(1, Number(searchParams?.get?.('page') || 1) || 1);
  const search = String(searchParams?.get?.('search') || '');
  const showInactiveRaw = searchParams?.get?.('show_inactive');
  const showInactive = showInactiveRaw == null ? true : showInactiveRaw !== 'false';
  return { page, search, showInactive };
}

export function clampThreatActorManagerPage(page, totalItems, pageSize = THREAT_ACTOR_MANAGER_PAGE_SIZE) {
  const totalPages = Math.max(1, Math.ceil(Math.max(0, Number(totalItems) || 0) / pageSize) || 1);
  return Math.min(Math.max(1, Number(page) || 1), totalPages);
}

export function formatThreatActorAliases(aliases) {
  if (!aliases) return '—';
  if (Array.isArray(aliases)) return aliases.length ? aliases.join(', ') : '—';
  return String(aliases).trim() || '—';
}

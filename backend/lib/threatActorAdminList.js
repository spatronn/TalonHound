import { normalizeTagSearch } from './tagHelpers.js';

export const THREAT_ACTOR_ADMIN_DEFAULT_PAGE_SIZE = 25;
export const THREAT_ACTOR_ADMIN_MAX_PAGE_SIZE = 100;

export function parseThreatActorAdminListQuery(query = {}) {
  const rawPage = Number(query.page);
  const page = Number.isFinite(rawPage) && rawPage >= 1 ? Math.floor(rawPage) : 1;

  const rawSize = Number(query.page_size ?? query.pageSize);
  let pageSize = THREAT_ACTOR_ADMIN_DEFAULT_PAGE_SIZE;
  if (Number.isFinite(rawSize) && rawSize >= 1) {
    pageSize = Math.min(Math.floor(rawSize), THREAT_ACTOR_ADMIN_MAX_PAGE_SIZE);
  }

  const includeInactive = String(query.include_inactive ?? 'true') !== 'false';
  const search = normalizeTagSearch(query.search ?? query.q ?? '');

  return {
    page,
    page_size: pageSize,
    offset: (page - 1) * pageSize,
    include_inactive: includeInactive,
    search
  };
}

export function buildThreatActorAdminPagination({ page, page_size, total_items }) {
  const totalItems = Math.max(0, Number(total_items) || 0);
  const pageSize = Math.max(1, Number(page_size) || THREAT_ACTOR_ADMIN_DEFAULT_PAGE_SIZE);
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize) || 1);
  const safePage = Math.min(Math.max(1, Number(page) || 1), totalPages);
  return {
    page: safePage,
    page_size: pageSize,
    total_items: totalItems,
    total_pages: totalPages,
    has_previous: safePage > 1,
    has_next: safePage < totalPages && totalItems > 0
  };
}

export function formatThreatActorAdminShowingRange({ page, page_size, total_items }) {
  const total = Math.max(0, Number(total_items) || 0);
  if (total === 0) return { from: 0, to: 0, label: 'Showing 0 of 0' };
  const size = Math.max(1, Number(page_size) || THREAT_ACTOR_ADMIN_DEFAULT_PAGE_SIZE);
  const p = Math.max(1, Number(page) || 1);
  const from = (p - 1) * size + 1;
  const to = Math.min(p * size, total);
  return { from, to, label: `Showing ${from}–${to} of ${total}` };
}

export function buildThreatActorAdminFilterClause({ include_inactive, search }, startParamIndex = 1) {
  const params = [];
  const parts = [];
  let i = startParamIndex;

  if (!include_inactive) {
    parts.push('ta.active = TRUE');
  }

  if (search) {
    params.push(search.toLowerCase());
    const p = `$${i}`;
    i += 1;
    parts.push(`(
      lower(ta.name) LIKE '%' || ${p} || '%'
      OR (ta.description IS NOT NULL AND lower(ta.description) LIKE '%' || ${p} || '%')
      OR EXISTS (
        SELECT 1
        FROM unnest(COALESCE(ta.aliases, '{}'::text[])) AS alias
        WHERE lower(alias) LIKE '%' || ${p} || '%'
      )
    )`);
  }

  return {
    sql: parts.length ? `WHERE ${parts.join(' AND ')}` : '',
    params,
    nextParamIndex: i
  };
}

export function buildThreatActorAdminCountQuery(opts) {
  const filter = buildThreatActorAdminFilterClause(opts, 1);
  return {
    sql: `SELECT COUNT(*)::int AS total_items FROM threat_actors ta ${filter.sql}`,
    params: filter.params
  };
}

export function buildThreatActorAdminPageQuery(opts) {
  const { page_size, offset } = opts;
  const filter = buildThreatActorAdminFilterClause(opts, 1);
  const limitIdx = filter.nextParamIndex;
  const offsetIdx = limitIdx + 1;
  const params = [...filter.params, page_size, offset];

  const sql = `
    SELECT ta.*
    FROM threat_actors ta
    ${filter.sql}
    ORDER BY ta.active DESC, ta.name ASC, ta.id ASC
    LIMIT $${limitIdx} OFFSET $${offsetIdx}
  `;

  return { sql, params };
}

export async function listAdminThreatActors(client, query = {}) {
  const parsed = parseThreatActorAdminListQuery(query);
  const countQ = buildThreatActorAdminCountQuery(parsed);
  const countRes = await client.query(countQ.sql, countQ.params);
  const totalItems = Number(countRes.rows[0]?.total_items || 0);

  let pagination = buildThreatActorAdminPagination({
    page: parsed.page,
    page_size: parsed.page_size,
    total_items: totalItems
  });

  const effective = {
    ...parsed,
    page: pagination.page,
    offset: (pagination.page - 1) * pagination.page_size
  };

  const listQ = buildThreatActorAdminPageQuery(effective);
  const listRes = await client.query(listQ.sql, listQ.params);

  pagination = buildThreatActorAdminPagination({
    page: effective.page,
    page_size: effective.page_size,
    total_items: totalItems
  });

  return { items: listRes.rows, pagination, query: effective };
}

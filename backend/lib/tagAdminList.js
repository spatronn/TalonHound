import { mapAdminTagRow } from './tagCatalogService.js';
import { normalizeTagName, parsePositiveInt } from './tagHelpers.js';

export const TAG_ADMIN_DEFAULT_PAGE_SIZE = 25;
export const TAG_ADMIN_MAX_PAGE_SIZE = 100;

/**
 * Parse Tag Manager list query params.
 * Invalid page/page_size are coerced to safe defaults (not 400) for UX stability.
 */
export function parseTagAdminListQuery(query = {}) {
  const rawPage = Number(query.page);
  const page = Number.isFinite(rawPage) && rawPage >= 1 ? Math.floor(rawPage) : 1;

  const rawSize = Number(query.page_size ?? query.pageSize);
  let pageSize = TAG_ADMIN_DEFAULT_PAGE_SIZE;
  if (Number.isFinite(rawSize) && rawSize >= 1) {
    pageSize = Math.min(Math.floor(rawSize), TAG_ADMIN_MAX_PAGE_SIZE);
  }

  const includeInactive = String(query.include_inactive ?? 'true') !== 'false';
  const search = normalizeTagName(query.search ?? query.q ?? '');

  return {
    page,
    page_size: pageSize,
    offset: (page - 1) * pageSize,
    include_inactive: includeInactive,
    search
  };
}

export function buildTagAdminPagination({ page, page_size, total_items }) {
  const totalItems = Math.max(0, Number(total_items) || 0);
  const pageSize = Math.max(1, Number(page_size) || TAG_ADMIN_DEFAULT_PAGE_SIZE);
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

export function formatTagAdminShowingRange({ page, page_size, total_items }) {
  const total = Math.max(0, Number(total_items) || 0);
  if (total === 0) return { from: 0, to: 0, label: 'Showing 0 of 0' };
  const size = Math.max(1, Number(page_size) || TAG_ADMIN_DEFAULT_PAGE_SIZE);
  const p = Math.max(1, Number(page) || 1);
  const from = (p - 1) * size + 1;
  const to = Math.min(p * size, total);
  return { from, to, label: `Showing ${from}–${to} of ${total}` };
}

/**
 * Shared WHERE clause for count + page id selection (identical filters).
 * @returns {{ sql: string, params: any[] }}
 */
export function buildTagAdminFilterClause({ include_inactive, search }, startParamIndex = 1) {
  const params = [];
  const parts = [];
  let i = startParamIndex;

  if (!include_inactive) {
    parts.push('t.enabled = TRUE');
  }

  if (search) {
    params.push(search);
    const p = `$${i}`;
    i += 1;
    // names are stored normalized/lowercase; description/source use lower() for safety
    parts.push(`(
      t.name LIKE '%' || ${p} || '%'
      OR (t.description IS NOT NULL AND lower(t.description) LIKE '%' || ${p} || '%')
      OR EXISTS (
        SELECT 1
        FROM ioc_tags it_search
        WHERE it_search.tag_id = t.id
          AND it_search.source_name IS NOT NULL
          AND lower(it_search.source_name) LIKE '%' || ${p} || '%'
      )
      OR (${p} = 'manual' AND t.created_origin = 'manual')
    )`);
  }

  return {
    sql: parts.length ? `WHERE ${parts.join(' AND ')}` : '',
    params,
    nextParamIndex: i
  };
}

export function buildTagAdminCountQuery(opts) {
  const filter = buildTagAdminFilterClause(opts, 1);
  return {
    sql: `SELECT COUNT(*)::int AS total_items FROM tags t ${filter.sql}`,
    params: filter.params
  };
}

export function buildTagAdminPageQuery(opts) {
  const { page_size, offset } = opts;
  const filter = buildTagAdminFilterClause(opts, 1);
  const limitIdx = filter.nextParamIndex;
  const offsetIdx = limitIdx + 1;
  const params = [...filter.params, page_size, offset];

  const sql = `
    SELECT
      t.id, t.name, t.slug, t.description, t.color, t.category, t.type, t.enabled,
      t.created_origin, t.created_at, t.updated_at,
      COALESCE(
        array_agg(DISTINCT it.origin) FILTER (WHERE it.origin IS NOT NULL),
        '{}'::text[]
      ) AS assignment_origins,
      COALESCE(
        array_agg(DISTINCT it.source_name) FILTER (WHERE it.source_name IS NOT NULL AND btrim(it.source_name) <> ''),
        '{}'::text[]
      ) AS assignment_sources
    FROM tags t
    LEFT JOIN ioc_tags it ON it.tag_id = t.id
    WHERE t.id IN (
      SELECT page_ids.id
      FROM (
        SELECT t.id
        FROM tags t
        ${filter.sql}
        ORDER BY t.name ASC, t.id ASC
        LIMIT $${limitIdx} OFFSET $${offsetIdx}
      ) page_ids
    )
    GROUP BY t.id
    ORDER BY t.name ASC, t.id ASC
  `;

  return { sql, params };
}

/**
 * Execute Tag Manager list (count + page) against a pg client/pool.
 */
export async function listAdminTags(client, query = {}) {
  const parsed = parseTagAdminListQuery(query);
  const countQ = buildTagAdminCountQuery(parsed);
  const countRes = await client.query(countQ.sql, countQ.params);
  const totalItems = Number(countRes.rows[0]?.total_items || 0);

  let pagination = buildTagAdminPagination({
    page: parsed.page,
    page_size: parsed.page_size,
    total_items: totalItems
  });

  // If client asked for a page past the end, clamp and re-query that page.
  const effective = {
    ...parsed,
    page: pagination.page,
    offset: (pagination.page - 1) * pagination.page_size
  };

  const listQ = buildTagAdminPageQuery(effective);
  const listRes = await client.query(listQ.sql, listQ.params);
  const items = listRes.rows.map((r) => mapAdminTagRow(r));

  pagination = buildTagAdminPagination({
    page: effective.page,
    page_size: effective.page_size,
    total_items: totalItems
  });

  return { items, pagination, query: effective };
}

export function parsePositivePage(value) {
  return parsePositiveInt(value);
}

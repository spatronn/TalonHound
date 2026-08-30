/**
 * API-key IOC read / search / bounded export.
 * Reuses Search DSL parse+classify+SQL and the public IocResponse serializer.
 */

import {
  parseSearchQuery,
  buildWhereClause,
  classifyQuery,
  isDslError,
  getQueryTimeoutMs
} from './iocSearchDsl/index.js';
import { buildPlainSearchPageSql } from './iocSearchDsl/searchPageSql.js';
import { fetchIocThreatClassificationSlugs } from './iocThreatClassifications.js';
import { toApiIocResponse, loadManualTags } from './apiIocService.js';
import { csvRow } from './iocSearchExport/csv.js';
import { API_ERROR_CODE } from './apiV1Errors.js';

export const API_IOC_PAGE_MAX = 100;
export const API_IOC_PAGE_DEFAULT = 50;
export const API_IOC_EXPORT_MAX = 10_000;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function clampApiIocPageSize(raw, fallback = API_IOC_PAGE_DEFAULT) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), 1), API_IOC_PAGE_MAX);
}

export function encodeApiIocCursor(cursor) {
  return Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64url');
}

export function decodeApiIocCursor(raw) {
  if (!raw) return null;
  try {
    const obj = JSON.parse(Buffer.from(String(raw), 'base64url').toString('utf8'));
    if (obj && typeof obj.t === 'string' && obj.id != null) {
      return { t: obj.t, id: String(obj.id) };
    }
  } catch {
    /* invalid */
  }
  return { invalid: true };
}

function listItem(row) {
  return toApiIocResponse(row);
}

export async function getApiIoc(pool, idOrPublicId) {
  const raw = String(idOrPublicId || '').trim();
  if (!raw) {
    return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'IOC id is required' } };
  }
  let row;
  if (UUID_RE.test(raw)) {
    const q = await pool.query(`SELECT * FROM ioc_items WHERE public_id = $1::uuid LIMIT 1`, [raw]);
    row = q.rows[0];
  } else {
    const id = Number(raw);
    if (!Number.isInteger(id) || id <= 0) {
      return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'Invalid IOC id' } };
    }
    const q = await pool.query(`SELECT * FROM ioc_items WHERE id = $1 LIMIT 1`, [id]);
    row = q.rows[0];
  }
  if (!row) {
    return { status: 404, error: { code: API_ERROR_CODE.IOC_NOT_FOUND, message: 'IOC not found' } };
  }
  const [classifications, tags] = await Promise.all([
    fetchIocThreatClassificationSlugs(pool, row.id, row.observable_type),
    loadManualTags(pool, row.id, row.observable_type)
  ]);
  return {
    status: 200,
    body: toApiIocResponse(row, {
      classifications,
      tags: tags.map((t) => t.name)
    })
  };
}

export async function listApiIocs(pool, { cursor, limit, type, status } = {}) {
  const pageSize = clampApiIocPageSize(limit);
  const decoded = decodeApiIocCursor(cursor);
  if (decoded?.invalid) {
    return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'Invalid cursor' } };
  }

  const filters = [];
  const params = [];
  const typeNorm = String(type || '').trim().toLowerCase();
  if (typeNorm) {
    params.push(typeNorm);
    filters.push(`observable_type = $${params.length}`);
  }
  const statusNorm = String(status || '').trim().toLowerCase();
  if (statusNorm) {
    if (!['active', 'expired', 'suppressed', 'disabled'].includes(statusNorm)) {
      return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'Invalid status filter' } };
    }
    params.push(statusNorm);
    filters.push(`COALESCE(status, 'active') = $${params.length}`);
  }
  if (decoded?.t && decoded?.id) {
    params.push(decoded.t, decoded.id);
    filters.push(`(created_at, id) < ($${params.length - 1}::timestamptz, $${params.length}::bigint)`);
  }
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  params.push(pageSize + 1);
  const { rows } = await pool.query(
    `SELECT id, public_id, observable, observable_type, status, confidence, note, created_at,
            threat_classification
     FROM ioc_items
     ${where}
     ORDER BY created_at DESC, id DESC
     LIMIT $${params.length}`,
    params
  );
  const hasMore = rows.length > pageSize;
  const page = rows.slice(0, pageSize);
  const last = page[page.length - 1];
  return {
    status: 200,
    body: {
      items: page.map(listItem),
      limit: pageSize,
      has_more: hasMore,
      next_cursor: hasMore && last
        ? encodeApiIocCursor({ t: new Date(last.created_at).toISOString(), id: String(last.id) })
        : null
    }
  };
}

function parseDslOrError(rawQuery) {
  const q = String(rawQuery ?? '').trim();
  if (!q) {
    return { error: { status: 400, code: API_ERROR_CODE.VALIDATION_ERROR, message: 'query is required' } };
  }
  try {
    const parsed = parseSearchQuery(q);
    const classified = classifyQuery(parsed.ast);
    if (classified.mode === 'deep_search') {
      return {
        error: {
          status: 400,
          code: API_ERROR_CODE.QUERY_TOO_EXPENSIVE,
          message: 'Query is too expensive for the interactive API. Narrow the query (avoid leading wildcards, NOT, source scans, and broad OR).',
          details: { reason: classified.reason }
        }
      };
    }
    return { parsed };
  } catch (err) {
    if (isDslError(err)) {
      return {
        error: {
          status: 400,
          code: API_ERROR_CODE.VALIDATION_ERROR,
          message: err.message,
          details: err.toJSON?.() || undefined
        }
      };
    }
    return { error: { status: 400, code: API_ERROR_CODE.VALIDATION_ERROR, message: 'Invalid search query' } };
  }
}

export async function searchApiIocs(pool, { query, cursor, limit } = {}) {
  const parsedOrErr = parseDslOrError(query);
  if (parsedOrErr.error) {
    const e = parsedOrErr.error;
    return { status: e.status, error: { code: e.code, message: e.message, details: e.details } };
  }
  const { parsed } = parsedOrErr;
  const pageSize = clampApiIocPageSize(limit);
  const decoded = decodeApiIocCursor(cursor);
  if (decoded?.invalid) {
    return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'Invalid cursor' } };
  }

  const built = buildWhereClause(parsed.ast);
  const params = [...built.params];
  let keysetClause = '';
  let cursorParamStart = null;
  if (decoded?.t && decoded?.id) {
    params.push(decoded.t, decoded.id);
    cursorParamStart = built.params.length + 1;
    keysetClause = ` AND (i.created_at, i.id) < ($${cursorParamStart}::timestamptz, $${cursorParamStart + 1}::bigint)`;
  }
  params.push(pageSize + 1);
  const limitIdx = params.length;
  const pageSql = buildPlainSearchPageSql({
    whereSql: built.sql,
    keysetClause,
    limitParamIdx: limitIdx
  });

  const timeoutMs = Math.max(100, Math.min(Math.trunc(getQueryTimeoutMs()), 120000));
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL statement_timeout = ${timeoutMs}`);
    await client.query('SET LOCAL max_parallel_workers_per_gather = 0');
    const pageRes = await client.query(pageSql, params);
    await client.query('COMMIT');
    const hasMore = pageRes.rows.length > pageSize;
    const page = pageRes.rows.slice(0, pageSize);
    const last = page[page.length - 1];
    return {
      status: 200,
      body: {
        normalized_query: parsed.normalizedQuery,
        items: page.map(listItem),
        limit: pageSize,
        has_more: hasMore,
        next_cursor: hasMore && last
          ? encodeApiIocCursor({ t: new Date(last.created_at).toISOString(), id: String(last.id) })
          : null
      }
    };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    if (err?.code === '57014') {
      return {
        status: 400,
        error: {
          code: API_ERROR_CODE.QUERY_TOO_EXPENSIVE,
          message: 'Query exceeded the interactive timeout. Narrow the query or use a more selective predicate.'
        }
      };
    }
    throw err;
  } finally {
    client.release();
  }
}

export async function exportApiIocs(pool, { query, format } = {}) {
  const fmt = String(format || 'json').trim().toLowerCase();
  if (!['json', 'csv'].includes(fmt)) {
    return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'format must be json or csv' } };
  }
  const parsedOrErr = parseDslOrError(query);
  if (parsedOrErr.error) {
    const e = parsedOrErr.error;
    return { status: e.status, error: { code: e.code, message: e.message, details: e.details } };
  }
  const { parsed } = parsedOrErr;
  const built = buildWhereClause(parsed.ast);
  const params = [...built.params, API_IOC_EXPORT_MAX + 1];
  const timeoutMs = Math.max(100, Math.min(Math.trunc(getQueryTimeoutMs() * 4), 120000));
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL statement_timeout = ${timeoutMs}`);
    await client.query('SET LOCAL max_parallel_workers_per_gather = 0');
    const { rows } = await client.query(
      `SELECT i.id, i.public_id, i.observable, i.observable_type, i.status, i.confidence,
              i.note, i.created_at, i.threat_classification
       FROM ioc_items i
       WHERE ${built.sql}
       ORDER BY i.created_at DESC, i.id DESC
       LIMIT $${params.length}`,
      params
    );
    await client.query('COMMIT');
    const truncated = rows.length > API_IOC_EXPORT_MAX;
    const page = rows.slice(0, API_IOC_EXPORT_MAX);
    const items = page.map(listItem);
    if (fmt === 'csv') {
      const header = csvRow(['id', 'public_id', 'type', 'value', 'status', 'confidence', 'created_at']);
      const lines = [header, ...items.map((it) => csvRow([
        it.id, it.public_id, it.type, it.value, it.status, it.confidence, it.created_at
      ]))];
      return {
        status: 200,
        contentType: 'text/csv; charset=utf-8',
        bodyText: `${lines.join('\n')}\n`,
        truncated
      };
    }
    return {
      status: 200,
      body: {
        normalized_query: parsed.normalizedQuery,
        truncated,
        limit: API_IOC_EXPORT_MAX,
        count: items.length,
        items
      }
    };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    if (err?.code === '57014') {
      return {
        status: 400,
        error: {
          code: API_ERROR_CODE.QUERY_TOO_EXPENSIVE,
          message: 'Export query exceeded the timeout. Narrow the query.'
        }
      };
    }
    throw err;
  } finally {
    client.release();
  }
}

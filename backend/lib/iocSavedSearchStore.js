/**
 * Personal saved IOC Search queries.
 */

import { parseSearchQuery, isDslError } from './iocSearchDsl/index.js';
import { actorUserId, actorEmail, canAccessOwnedArtifact } from './artifactOwnership.js';

export const SAVED_SEARCH_NAME_MAX = 120;
export const SAVED_SEARCH_DESC_MAX = 500;
export const SAVED_SEARCH_LIST_MAX = 200;

export function canAccessSavedSearch(req, row) {
  return canAccessOwnedArtifact(req, { requested_by_id: row?.owner_id });
}

export function normalizeSavedSearchName(raw) {
  return String(raw || '').trim().replace(/\s+/g, ' ');
}

export function normalizeSavedSearchDescription(raw) {
  if (raw == null) return null;
  const s = String(raw).trim();
  return s ? s : null;
}

export function parseSavedSearchWrite({ name, query, description } = {}, { requireQuery = true, requireName = true } = {}) {
  const errors = [];
  let n = undefined;
  if (requireName || name !== undefined) {
    n = normalizeSavedSearchName(name);
    if (!n) errors.push('name');
    else if (n.length > SAVED_SEARCH_NAME_MAX) errors.push('name');
  }

  let desc = undefined;
  if (description !== undefined) {
    desc = normalizeSavedSearchDescription(description);
    if (desc && desc.length > SAVED_SEARCH_DESC_MAX) errors.push('description');
  }

  let parsed = null;
  let originalQuery = undefined;
  if (requireQuery || query !== undefined) {
    originalQuery = String(query ?? '');
    try {
      parsed = parseSearchQuery(originalQuery);
    } catch (err) {
      if (isDslError(err)) {
        return { ok: false, dslError: err };
      }
      return { ok: false, errors: ['query'], message: 'Invalid search query' };
    }
  }

  if (errors.length) {
    return { ok: false, errors, message: 'Invalid saved search' };
  }
  return {
    ok: true,
    name: n,
    description: desc,
    originalQuery,
    parsed
  };
}

export function toPublicSavedSearch(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? null,
    original_query: row.original_query,
    normalized_query: row.normalized_query,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

export async function listSavedSearches(pool, ownerId) {
  const { rows } = await pool.query(
    `SELECT id, name, description, original_query, normalized_query, created_at, updated_at
     FROM ioc_saved_searches
     WHERE owner_id = $1
     ORDER BY updated_at DESC, name ASC
     LIMIT ${SAVED_SEARCH_LIST_MAX}`,
    [ownerId]
  );
  return rows.map(toPublicSavedSearch);
}

export async function getSavedSearchRow(pool, id) {
  const { rows } = await pool.query(
    `SELECT id, name, description, original_query, normalized_query, normalized_ast,
            owner_id, owner_username, created_at, updated_at
     FROM ioc_saved_searches
     WHERE id = $1::uuid
     LIMIT 1`,
    [id]
  );
  return rows[0] || null;
}

export async function insertSavedSearch(pool, {
  name, description, originalQuery, parsed, ownerId, ownerUsername
}) {
  try {
    const { rows } = await pool.query(
      `INSERT INTO ioc_saved_searches
         (name, description, original_query, normalized_query, normalized_ast, owner_id, owner_username)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
       RETURNING id, name, description, original_query, normalized_query, owner_id, created_at, updated_at`,
      [
        name,
        description ?? null,
        originalQuery,
        parsed.normalizedQuery,
        JSON.stringify(parsed.ast),
        ownerId,
        ownerUsername
      ]
    );
    return { row: rows[0] };
  } catch (err) {
    if (err?.code === '23505') {
      return { duplicate: true };
    }
    throw err;
  }
}

export async function updateSavedSearch(pool, id, fields) {
  const sets = [];
  const params = [];
  if (fields.name != null) {
    params.push(fields.name);
    sets.push(`name = $${params.length}`);
  }
  if (fields.description !== undefined) {
    params.push(fields.description);
    sets.push(`description = $${params.length}`);
  }
  if (fields.originalQuery != null && fields.parsed) {
    params.push(fields.originalQuery);
    sets.push(`original_query = $${params.length}`);
    params.push(fields.parsed.normalizedQuery);
    sets.push(`normalized_query = $${params.length}`);
    params.push(JSON.stringify(fields.parsed.ast));
    sets.push(`normalized_ast = $${params.length}::jsonb`);
  }
  if (!sets.length) {
    return { row: await getSavedSearchRow(pool, id) };
  }
  sets.push('updated_at = NOW()');
  params.push(id);
  try {
    const { rows } = await pool.query(
      `UPDATE ioc_saved_searches
       SET ${sets.join(', ')}
       WHERE id = $${params.length}::uuid
       RETURNING id, name, description, original_query, normalized_query, owner_id, created_at, updated_at`,
      params
    );
    return { row: rows[0] || null };
  } catch (err) {
    if (err?.code === '23505') {
      return { duplicate: true };
    }
    throw err;
  }
}

export async function deleteSavedSearch(pool, id) {
  const { rowCount } = await pool.query(
    `DELETE FROM ioc_saved_searches WHERE id = $1::uuid`,
    [id]
  );
  return rowCount > 0;
}

export { actorUserId, actorEmail };

/**
 * Exact-lookup identity resolution for API / MCP IOC lookups.
 *
 * A direct (observable_type, observable) match is always tried first by the
 * caller and keeps its historical semantics. When a file hash (md5/sha1/sha256)
 * has no ioc_items row of its own, this module resolves it through the SAME
 * proven file-artifact alias membership the IOC Search DSL uses
 * (artifactAliasIocMembershipSql), so lookup and search agree on logical-file
 * identity. Only exact hashes proven in file_artifact_hashes qualify — never a
 * fuzzy / partial match — and the path is gated by FILE_ARTIFACTS_READ_ENABLED
 * exactly like search.
 */

import { isFileArtifactsReadEnabled } from './fileArtifacts/flags.js';
import { artifactAliasIocMembershipSql } from './fileArtifacts/hashIdentitySql.js';

export const IOC_MATCHED_VIA = Object.freeze({
  EXACT: 'exact',
  FILE_ARTIFACT_ALIAS: 'file_artifact_alias'
});

const FILE_HASH_TYPES = new Set(['md5', 'sha1', 'sha256']);

// Stronger identity hashes first when several IOC rows share one artifact.
const HASH_TYPE_RANK = Object.freeze({ sha256: 0, sha1: 1, md5: 2 });

function toMillis(value) {
  if (value == null) return Number.POSITIVE_INFINITY;
  const t = new Date(value).getTime();
  return Number.isFinite(t) ? t : Number.POSITIVE_INFINITY;
}

/**
 * Deterministic primary-membership order for one logical file artifact:
 *   1. active rows before non-active (expired/suppressed/…)
 *   2. strongest stored hash type (sha256 > sha1 > md5)
 *   3. oldest created_at, then lowest id — the same tiebreak the exact
 *      lookup applies to multiple rows of one observable.
 * Never depends on SQL row order.
 */
export function compareArtifactAliasMemberships(a, b) {
  const aActive = (a.status || 'active') === 'active' ? 0 : 1;
  const bActive = (b.status || 'active') === 'active' ? 0 : 1;
  if (aActive !== bActive) return aActive - bActive;
  const aRank = HASH_TYPE_RANK[a.observable_type] ?? 99;
  const bRank = HASH_TYPE_RANK[b.observable_type] ?? 99;
  if (aRank !== bRank) return aRank - bRank;
  const aT = toMillis(a.created_at);
  const bT = toMillis(b.created_at);
  if (aT !== bT) return aT - bT;
  return Number(a.id) - Number(b.id);
}

export function lookupIdentityKey(type, value) {
  return `${type}\0${value}`;
}

/**
 * Batched alias resolution: ONE query for any number of (hash type, value)
 * inputs. Non-hash inputs are ignored; nothing is queried when artifact reads
 * are disabled or no hash input is present.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {Array<{ type: string, value: string }>} inputs concrete storage type + normalized value
 * @param {{ fileArtifactsReadEnabled?: boolean }} [opts]
 * @returns {Promise<Map<string, object[]>>} lookupIdentityKey(type, value) → full ioc_items
 *   rows linked to that hash's artifact, sorted primary-first (compareArtifactAliasMemberships)
 */
export async function resolveArtifactAliasMemberships(db, inputs, opts = {}) {
  const out = new Map();
  const enabled = opts.fileArtifactsReadEnabled ?? isFileArtifactsReadEnabled();
  if (!enabled) return out;

  const seen = new Set();
  const types = [];
  const values = [];
  for (const input of Array.isArray(inputs) ? inputs : []) {
    const type = String(input?.type || '');
    const value = String(input?.value || '').toLowerCase();
    if (!FILE_HASH_TYPES.has(type) || !value) continue;
    const key = lookupIdentityKey(type, value);
    if (seen.has(key)) continue;
    seen.add(key);
    types.push(type);
    values.push(value);
  }
  if (!types.length) return out;

  try {
    const { rows } = await db.query(
      `SELECT q.hash_type AS alias_queried_type, q.hash_value AS alias_queried_value, i.*
       FROM unnest($1::text[], $2::text[]) AS q(hash_type, hash_value)
       CROSS JOIN LATERAL (
         ${artifactAliasIocMembershipSql('q.hash_type', 'q.hash_value')}
       ) m
       JOIN ioc_items i
         ON i.observable_type = m.ioc_observable_type
        AND i.id = m.ioc_item_id`,
      [types, values]
    );
    const dedupe = new Set();
    for (const row of rows) {
      const key = lookupIdentityKey(row.alias_queried_type, row.alias_queried_value);
      const rowKey = `${key}\0${row.observable_type}\0${row.id}`;
      if (dedupe.has(rowKey)) continue;
      dedupe.add(rowKey);
      const { alias_queried_type: _t, alias_queried_value: _v, ...iocRow } = row;
      if (!out.has(key)) out.set(key, []);
      out.get(key).push(iocRow);
    }
  } catch (err) {
    // Schema without file-artifact tables — alias resolution unavailable, exact-only.
    if (err && (err.code === '42P01' || String(err.message || '').includes('file_artifact'))) {
      return out;
    }
    throw err;
  }
  for (const list of out.values()) list.sort(compareArtifactAliasMemberships);
  return out;
}

/** Compact membership descriptor used in lookup responses. */
export function describeIocMembership(row) {
  return {
    id: Number(row.id),
    public_id: row.public_id || null,
    type: row.observable_type,
    value: row.observable,
    status: row.status || null
  };
}

/**
 * Additive, backward-compatible match metadata for a lookup hit.
 *   queried      — what the caller asked for (concrete type + normalized value)
 *   matched_via  — 'exact' | 'file_artifact_alias'
 *   record       — the ioc_items row actually returned
 *   artifact_memberships — alias hits only: every IOC row of the logical file,
 *                  primary first, so a caller knows more than one exists.
 */
export function buildLookupMatchMetadata({ queriedType, queriedValue, record, matchedVia, memberships = null }) {
  const meta = {
    matched_via: matchedVia,
    queried: { type: queriedType, value: queriedValue },
    record: {
      id: Number(record.id),
      public_id: record.public_id || null,
      type: record.observable_type,
      value: record.observable
    }
  };
  if (matchedVia === IOC_MATCHED_VIA.FILE_ARTIFACT_ALIAS && Array.isArray(memberships)) {
    meta.artifact_memberships = memberships.map(describeIocMembership);
  }
  return meta;
}

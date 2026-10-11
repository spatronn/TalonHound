/**
 * Analyst-confirmed catalog identity for source-reported Threat Actors and
 * Malware Families (IOC Details → Overview "+" on an unlinked chip).
 *
 * Three different statements, never conflated:
 *   - source assertion    ioc_source_attributions row: "AlienVault OTX Pulse P
 *                         associates this IOC with the label 'PureRAT'". Feed
 *                         provenance, lifecycle and source/ingestion timestamps
 *                         are owned by ingestion and never written here.
 *   - catalog resolution  entity_id on that row: "the label 'PureRAT' on this
 *                         IOC means local catalog entity X". This module sets it
 *                         with resolution_method = 'analyst' (+ resolved_by /
 *                         resolved_at). Re-ingestion keeps it
 *                         (iocSourceAttributions.upsertSourceAttribution), and
 *                         withdrawal of the source claim keeps it too (the row
 *                         only changes assertion_status).
 *   - analyst attribution ioc_threat_actors / ioc_malware_families (Edit).
 *                         NOT written here: linking the label does not confirm
 *                         the source's claim.
 *
 * Because catalog IOC inventories, counts, IOC Details and MCP all read
 * ioc_source_attributions.entity_id, a link shows up everywhere as the same
 * source-reported association, now pointing at the catalog entity.
 *
 * Duplicate prevention (authoritative, server-side):
 *   - exact identity = case/whitespace-insensitive name or alias, slug, or (for
 *     malware) ATT&CK id from a "<name> - S1234" label. Creating an entity whose
 *     name/alias/slug collides exactly with an existing one (active or not) is
 *     refused; the analyst links the existing entity instead.
 *   - "similar" = same letters/digits ignoring spaces and punctuation
 *     ("Pure RAT" ~ "PureRAT", "APT 28" ~ "APT28"). Suggestion only, never a
 *     merge: creating despite similar entities requires confirm_distinct.
 *   - creates are serialized per entity kind (transaction advisory lock) and the
 *     catalog slug unique constraint is the final guard; links are serialized per
 *     (IOC, kind, label), so retries and concurrent analysts are idempotent.
 */

import { normalizeTagSlug, MAX_TAG_NAME_LENGTH } from './tagHelpers.js';
import {
  ANALYST_RESOLUTION_METHOD,
  ENTITY_KIND,
  RESOLUTION_STATUS,
  normalizeAttributionLabel,
  normalizeAttributionLabelKey
} from './iocSourceAttributions.js';
import { parseAttackSuffixedLabel } from './malwareFamilySourceResolution.js';

export const CATALOG_LINK_MODE = Object.freeze({ LINK: 'link', CREATE: 'create' });

export const CATALOG_LINK_OUTCOME = Object.freeze({
  LINKED: 'linked',
  CREATED_AND_LINKED: 'created_and_linked',
  ALREADY_LINKED: 'already_linked'
});

export const CANDIDATE_MATCH = Object.freeze({
  NAME: 'name',
  ATTACK_ID: 'attack_id',
  ALIAS: 'alias',
  SLUG: 'slug',
  SIMILAR: 'similar',
  SEARCH: 'search'
});

const EXACT_MATCHES = new Set([
  CANDIDATE_MATCH.NAME,
  CANDIDATE_MATCH.ATTACK_ID,
  CANDIDATE_MATCH.ALIAS,
  CANDIDATE_MATCH.SLUG
]);
const MATCH_RANK = [
  CANDIDATE_MATCH.NAME,
  CANDIDATE_MATCH.ATTACK_ID,
  CANDIDATE_MATCH.ALIAS,
  CANDIDATE_MATCH.SLUG,
  CANDIDATE_MATCH.SIMILAR,
  CANDIDATE_MATCH.SEARCH
];

export const MAX_CATALOG_ALIASES = 32;
export const MAX_CATALOG_DESCRIPTION_LENGTH = 4000;
export const MAX_CANDIDATES = 25;
export const MAX_EVIDENCE_ROWS = 20;

const UNKNOWN_ACTOR_SLUG = 'unknown';

/** Whitelisted per-kind catalog config (table names never come from input). */
export const CATALOG_KINDS = Object.freeze({
  [ENTITY_KIND.THREAT_ACTOR]: Object.freeze({
    kind: ENTITY_KIND.THREAT_ACTOR,
    table: 'threat_actors',
    noun: 'threat actor',
    maxNameLength: MAX_TAG_NAME_LENGTH,
    referenceColumn: 'NULL::jsonb'
  }),
  [ENTITY_KIND.MALWARE_FAMILY]: Object.freeze({
    kind: ENTITY_KIND.MALWARE_FAMILY,
    table: 'malware_families',
    noun: 'malware family',
    maxNameLength: 128,
    referenceColumn: 't.reference_sources'
  })
});

export class CatalogLinkError extends Error {
  constructor(status, code, message, details = {}) {
    super(message);
    this.name = 'CatalogLinkError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function catalogKindConfig(entityKind) {
  return CATALOG_KINDS[String(entityKind || '').trim()] || null;
}

/** Same key as ioc_source_attributions.source_label_normalized. */
export const catalogLabelKey = normalizeAttributionLabelKey;

/**
 * Letters + digits only, lowercased: "Pure RAT" / "pure-rat" / "PureRAT" →
 * "purerat". Used ONLY to suggest possible duplicates, never to resolve.
 */
export function compactEntityKey(raw) {
  const s = String(raw ?? '').normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, '');
  return s || null;
}

function attackIdOf(row) {
  const id = row?.reference_sources?.['mitre-attack']?.external_id;
  return id ? String(id).toUpperCase() : null;
}

/** Identity keys for a label: itself, plus the name part of "<name> - S1234" (malware). */
export function labelIdentity(entityKind, label) {
  const key = catalogLabelKey(label);
  const attack = entityKind === ENTITY_KIND.MALWARE_FAMILY ? parseAttackSuffixedLabel(key) : null;
  const keys = [...new Set([key, attack?.namePart].filter(Boolean))];
  return {
    key,
    keys,
    slugs: [...new Set(keys.map((k) => normalizeTagSlug(k)).filter(Boolean))],
    compacts: [...new Set(keys.map((k) => compactEntityKey(k)).filter(Boolean))],
    attackId: attack?.attackId || null
  };
}

/**
 * Why a catalog row is a candidate for a source label (pure; unit-tested).
 * @returns {{ match: string, match_detail: string|null }}
 */
export function classifyCatalogCandidate(row, identity) {
  const nameKey = catalogLabelKey(row?.name);
  const aliasKeys = (Array.isArray(row?.aliases) ? row.aliases : [])
    .map((a) => ({ raw: a, key: catalogLabelKey(a) }))
    .filter((a) => a.key);
  const rowAttack = attackIdOf(row);
  const conflictingAttack = Boolean(identity.attackId && rowAttack && rowAttack !== identity.attackId);

  const reasons = [];
  if (identity.attackId && rowAttack === identity.attackId) {
    reasons.push({ match: CANDIDATE_MATCH.ATTACK_ID, match_detail: rowAttack });
  }
  if (!conflictingAttack) {
    if (nameKey && identity.keys.includes(nameKey)) reasons.push({ match: CANDIDATE_MATCH.NAME, match_detail: null });
    const alias = aliasKeys.find((a) => identity.keys.includes(a.key));
    if (alias) reasons.push({ match: CANDIDATE_MATCH.ALIAS, match_detail: alias.raw });
    if (row?.slug && identity.slugs.includes(String(row.slug))) {
      reasons.push({ match: CANDIDATE_MATCH.SLUG, match_detail: row.slug });
    }
  }
  if (!reasons.length) {
    const compactName = compactEntityKey(row?.name);
    const compactAlias = aliasKeys.find((a) => identity.compacts.includes(compactEntityKey(a.raw)));
    if ((compactName && identity.compacts.includes(compactName)) || compactAlias || conflictingAttack) {
      reasons.push({
        match: CANDIDATE_MATCH.SIMILAR,
        match_detail: conflictingAttack
          ? `different ATT&CK id ${rowAttack}`
          : (compactAlias && !(compactName && identity.compacts.includes(compactName)) ? compactAlias.raw : null)
      });
    }
  }
  if (!reasons.length) return { match: CANDIDATE_MATCH.SEARCH, match_detail: null };
  reasons.sort((a, b) => MATCH_RANK.indexOf(a.match) - MATCH_RANK.indexOf(b.match));
  return reasons[0];
}

export function isExactCandidateMatch(match) {
  return EXACT_MATCHES.has(match);
}

function escapeLike(value) {
  return String(value).replace(/[\\%_]/g, (c) => `\\${c}`);
}

const ALIAS_KEY_SQL = `lower(btrim(regexp_replace(alias, '\\s+', ' ', 'g')))`;
const COMPACT_SQL = (expr) => `regexp_replace(lower(${expr}), '[^[:alnum:]]+', '', 'g')`;

function serializeCandidate(cfg, row, classification) {
  const attackId = attackIdOf(row);
  return {
    id: row.id,
    name: row.name,
    slug: row.slug || null,
    aliases: Array.isArray(row.aliases) ? row.aliases : [],
    active: row.active !== false,
    linkable: row.active !== false && !(cfg.kind === ENTITY_KIND.THREAT_ACTOR && row.slug === UNKNOWN_ACTOR_SLUG),
    attack_id: attackId,
    match: classification.match,
    match_detail: classification.match_detail,
    exact: isExactCandidateMatch(classification.match)
  };
}

/**
 * Catalog candidates for a source label (exact / similar identity, inactive
 * included so duplicates stay visible) plus an optional analyst search `q`.
 * Two bounded queries on the small catalog tables; no per-chip work.
 */
export async function findCatalogCandidates(client, entityKind, { label, q = '', limit = MAX_CANDIDATES } = {}) {
  const cfg = catalogKindConfig(entityKind);
  if (!cfg) throw new CatalogLinkError(400, 'INVALID_ENTITY_KIND', 'entity_kind must be threat_actor or malware_family');
  const identity = labelIdentity(cfg.kind, label);
  const cap = Math.min(Math.max(Number(limit) || MAX_CANDIDATES, 1), 50);

  const identityRows = identity.key
    ? (await client.query(
      `SELECT t.id, t.name, t.slug, t.aliases, t.active, ${cfg.referenceColumn} AS reference_sources
       FROM ${cfg.table} t
       WHERE lower(t.name) = ANY($1::text[])
          OR t.slug = ANY($2::text[])
          OR ${COMPACT_SQL('t.name')} = ANY($3::text[])
          OR EXISTS (
            SELECT 1 FROM unnest(COALESCE(t.aliases, '{}'::text[])) AS alias
            WHERE ${ALIAS_KEY_SQL} = ANY($1::text[])
               OR ${COMPACT_SQL('alias')} = ANY($3::text[])
          )
          ${cfg.kind === ENTITY_KIND.MALWARE_FAMILY
        ? `OR ($4::text <> '' AND upper(t.reference_sources #>> '{mitre-attack,external_id}') = $4::text)`
        : `OR ($4::text <> '' AND FALSE)`}
       ORDER BY t.active DESC, t.name ASC
       LIMIT 50`,
      [identity.keys, identity.slugs, identity.compacts, identity.attackId || '']
    )).rows
    : [];

  const search = String(q || '').trim().slice(0, 100);
  const searchRows = search
    ? (await client.query(
      `SELECT t.id, t.name, t.slug, t.aliases, t.active, ${cfg.referenceColumn} AS reference_sources
       FROM ${cfg.table} t
       WHERE t.name ILIKE $1 ESCAPE '\\'
          OR t.slug ILIKE $1 ESCAPE '\\'
          OR EXISTS (
            SELECT 1 FROM unnest(COALESCE(t.aliases, '{}'::text[])) AS alias
            WHERE alias ILIKE $1 ESCAPE '\\'
          )
       ORDER BY (lower(t.name) = lower($2)) DESC, (t.name ILIKE $3 ESCAPE '\\') DESC,
                t.active DESC, t.name ASC
       LIMIT $4`,
      [`%${escapeLike(search)}%`, search, `${escapeLike(search)}%`, cap]
    )).rows
    : [];

  const byId = new Map();
  for (const row of [...identityRows, ...searchRows]) {
    if (byId.has(String(row.id))) continue;
    byId.set(String(row.id), serializeCandidate(cfg, row, classifyCatalogCandidate(row, identity)));
  }
  const fromIdentity = new Set(identityRows.map((r) => String(r.id)));
  const items = [...byId.values()].map((c) => (
    // Came back from the identity query but JS normalization differs (exotic
    // Unicode): keep it visible as a suggestion rather than dropping it.
    c.match === CANDIDATE_MATCH.SEARCH && fromIdentity.has(String(c.id))
      ? { ...c, match: CANDIDATE_MATCH.SIMILAR }
      : c
  ));
  items.sort((a, b) => (
    MATCH_RANK.indexOf(a.match) - MATCH_RANK.indexOf(b.match)
    || Number(b.active) - Number(a.active)
    || String(a.name).localeCompare(String(b.name))
  ));
  return { identity, candidates: items.slice(0, Math.max(cap, identityRows.length)) };
}

/** Exact name/alias/slug collisions for a proposed new catalog entity (any active state). */
async function findCreateCollisions(client, cfg, { name, slug, aliases }) {
  const keys = [...new Set([name, ...aliases].map((x) => catalogLabelKey(x)).filter(Boolean))];
  const compacts = [...new Set([name, ...aliases].map((x) => compactEntityKey(x)).filter(Boolean))];
  const { rows } = await client.query(
    `SELECT t.id, t.name, t.slug, t.aliases, t.active, ${cfg.referenceColumn} AS reference_sources,
            (lower(t.name) = ANY($1::text[])
              OR t.slug = $2
              OR EXISTS (
                SELECT 1 FROM unnest(COALESCE(t.aliases, '{}'::text[])) AS alias
                WHERE ${ALIAS_KEY_SQL} = ANY($1::text[])
              )) AS exact
     FROM ${cfg.table} t
     WHERE lower(t.name) = ANY($1::text[])
        OR t.slug = $2
        OR ${COMPACT_SQL('t.name')} = ANY($3::text[])
        OR EXISTS (
          SELECT 1 FROM unnest(COALESCE(t.aliases, '{}'::text[])) AS alias
          WHERE ${ALIAS_KEY_SQL} = ANY($1::text[])
             OR ${COMPACT_SQL('alias')} = ANY($3::text[])
        )
     ORDER BY t.active DESC, t.name ASC
     LIMIT 20`,
    [keys, slug, compacts]
  );
  const identity = { key: keys[0], keys, slugs: [slug], compacts, attackId: null };
  const shaped = rows.map((row) => ({
    ...serializeCandidate(cfg, row, row.exact
      ? classifyCatalogCandidate(row, identity)
      : { match: CANDIDATE_MATCH.SIMILAR, match_detail: null }),
    exact: Boolean(row.exact)
  }));
  return { exact: shaped.filter((c) => c.exact), similar: shaped.filter((c) => !c.exact) };
}

function parseAliasList(raw) {
  if (raw == null || raw === '') return [];
  const list = Array.isArray(raw) ? raw : String(raw).split(',');
  return list.map((x) => normalizeAttributionLabel(x)).filter(Boolean);
}

/**
 * Validate the analyst-entered create form (pure). Only analyst-entered
 * fields: nothing is derived from feed metadata except the prefilled name the
 * analyst submitted.
 */
export function validateCreateInput(entityKind, raw = {}) {
  const cfg = catalogKindConfig(entityKind);
  if (!cfg) return { ok: false, error: 'entity_kind must be threat_actor or malware_family' };
  const name = String(raw?.name ?? '').trim().replace(/\s+/g, ' ');
  if (!name) return { ok: false, error: 'name is required' };
  if (name.length > cfg.maxNameLength) return { ok: false, error: `name is too long (max ${cfg.maxNameLength})` };
  const slug = normalizeTagSlug(name);
  if (!slug) return { ok: false, error: 'name must contain letters or digits (slug could not be generated)' };
  if (cfg.kind === ENTITY_KIND.THREAT_ACTOR && slug === UNKNOWN_ACTOR_SLUG) {
    return { ok: false, error: '"unknown" is reserved' };
  }
  const nameKey = catalogLabelKey(name);
  const seen = new Set([nameKey]);
  const aliases = [];
  for (const alias of parseAliasList(raw?.aliases)) {
    if (alias.length > cfg.maxNameLength) return { ok: false, error: `alias "${alias.slice(0, 40)}…" is too long` };
    const key = catalogLabelKey(alias);
    if (seen.has(key)) continue;
    seen.add(key);
    aliases.push(alias);
  }
  if (aliases.length > MAX_CATALOG_ALIASES) return { ok: false, error: `at most ${MAX_CATALOG_ALIASES} aliases` };
  const description = raw?.description == null ? null : (String(raw.description).trim() || null);
  if (description && description.length > MAX_CATALOG_DESCRIPTION_LENGTH) {
    return { ok: false, error: `description is too long (max ${MAX_CATALOG_DESCRIPTION_LENGTH})` };
  }
  return { ok: true, value: { name, slug, aliases, description } };
}

const SUPPRESSED_SQL = `EXISTS (
  SELECT 1 FROM ioc_attribution_overrides o
  WHERE o.cleared_at IS NULL
    AND o.action = 'suppress'
    AND o.ioc_id = a.ioc_id
    AND o.ioc_observable_type = a.ioc_observable_type
    AND o.entity_kind = a.entity_kind
    AND (o.feed_key IS NULL OR o.feed_key = a.feed_key)
    AND (o.evidence_ref_type IS NULL OR o.evidence_ref_type = a.evidence_ref_type)
    AND (o.evidence_ref_id IS NULL OR o.evidence_ref_id = a.evidence_ref_id)
    AND (
      (o.entity_id IS NOT NULL AND o.entity_id = a.entity_id)
      OR (o.source_label_normalized IS NOT NULL AND o.source_label_normalized = a.source_label_normalized)
    )
)`;

/** The IOC's stored assertions for one (kind, label) — the only trusted provenance. */
async function loadLabelAssertions(client, { iocId, observableType, entityKind, labelKey, forUpdate = false }) {
  const { rows } = await client.query(
    `SELECT a.id, a.source_label, a.entity_id, a.resolution_status, a.resolution_method,
            a.resolved_at, a.resolved_by, a.feed_key, a.source_name, a.evidence_ref_type,
            a.evidence_ref_id, a.evidence_url, a.evidence_title, a.association_kind,
            a.assertion_status, a.observed_at, a.first_ingested_at, a.last_ingested_at,
            a.provider_metadata->>'field' AS provider_field,
            ${SUPPRESSED_SQL} AS suppressed
     FROM ioc_source_attributions a
     WHERE a.ioc_id = $1
       AND a.ioc_observable_type = $2
       AND a.entity_kind = $3
       AND a.source_label_normalized = $4
     ORDER BY a.first_ingested_at ASC, a.id ASC
     ${forUpdate ? 'FOR UPDATE OF a' : ''}`,
    [iocId, observableType, entityKind, labelKey]
  );
  return rows.map((row) => ({
    ...row,
    visible: row.assertion_status === 'current' && !row.suppressed
  }));
}

/**
 * Provider metadata field that carried the label → the entity type the PROVIDER
 * asserted (e.g. OTX Pulse `malware_families` / `adversary`). This is the
 * source's classification, not TalonHound's; it is never used to pick or change
 * the local catalog (that is entity_kind, fixed at ingestion).
 */
export const PROVIDER_FIELD_ENTITY_TYPE = Object.freeze({
  malware_families: ENTITY_KIND.MALWARE_FAMILY,
  adversary: ENTITY_KIND.THREAT_ACTOR
});

export function providerEntityType(row) {
  const field = row?.provider_field || null;
  return { provider_field: field, provider_entity_type: (field && PROVIDER_FIELD_ENTITY_TYPE[field]) || null };
}

export function serializeEvidence(row) {
  return {
    source_name: row.source_name,
    ...providerEntityType(row),
    feed_key: row.feed_key,
    source_label: row.source_label,
    evidence_ref_type: row.evidence_ref_type,
    evidence_ref_id: row.evidence_ref_id,
    evidence_url: row.evidence_url || null,
    evidence_title: row.evidence_title || null,
    association_kind: row.association_kind,
    assertion_status: row.assertion_status,
    observed_at: row.observed_at || null,
    first_ingested_at: row.first_ingested_at || null,
    last_ingested_at: row.last_ingested_at || null
  };
}

/**
 * Link state of a label's assertions on one IOC (pure).
 * unlinked: visible assertions without a catalog identity exist ("+" applies)
 * linked:   every assertion already carries a catalog identity
 * none:     nothing visible to act on (absent, withdrawn or suppressed only)
 */
export function summarizeLabelAssertions(rows) {
  const visible = rows.filter((r) => r.visible);
  const unlinkedVisible = visible.filter((r) => !r.entity_id);
  const linkedIds = [...new Set(visible.filter((r) => r.entity_id).map((r) => String(r.entity_id)))];
  let state = 'none';
  if (unlinkedVisible.length) state = 'unlinked';
  else if (visible.length) state = 'linked';
  return { state, visible, unlinkedVisible, linkedIds };
}

async function fetchIoc(client, iocId, observableType) {
  const { rows } = await client.query(
    `SELECT id, public_id, observable, observable_type
     FROM ioc_items WHERE id = $1 AND observable_type = $2`,
    [iocId, observableType]
  );
  return rows[0] || null;
}

async function fetchCatalogEntity(client, cfg, id, { lock = false } = {}) {
  const { rows } = await client.query(
    `SELECT t.id, t.name, t.slug, t.aliases, t.active, ${cfg.referenceColumn} AS reference_sources
     FROM ${cfg.table} t WHERE t.id = $1::uuid
     ${lock ? 'FOR SHARE' : ''}`,
    [id]
  );
  return rows[0] || null;
}

async function fetchCatalogEntities(client, cfg, ids) {
  if (!ids.length) return [];
  const { rows } = await client.query(
    `SELECT t.id, t.name, t.slug, t.aliases, t.active FROM ${cfg.table} t WHERE t.id = ANY($1::uuid[])`,
    [ids]
  );
  return rows;
}

export function serializeCatalogEntity(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    slug: row.slug || null,
    aliases: Array.isArray(row.aliases) ? row.aliases : [],
    active: row.active !== false,
    attack_id: attackIdOf(row)
  };
}

/**
 * Exact name / alias / slug matches of a label in the OTHER catalog
 * (threat actor ↔ malware family). Informational only: many names are
 * legitimately shared (ATT&CK itself names groups and their malware alike), so
 * this never blocks, links or converts anything — it lets the analyst see that
 * the provider's classification might not be the only reading of the name.
 */
export async function findCrossCatalogMatches(client, entityKind, names) {
  const own = catalogKindConfig(entityKind);
  if (!own) return [];
  const otherKind = own.kind === ENTITY_KIND.THREAT_ACTOR ? ENTITY_KIND.MALWARE_FAMILY : ENTITY_KIND.THREAT_ACTOR;
  const other = CATALOG_KINDS[otherKind];
  const keys = [...new Set((names || []).flatMap((n) => labelIdentity(own.kind, n).keys))];
  if (!keys.length) return [];
  const slugs = [...new Set(keys.map((k) => normalizeTagSlug(k)).filter(Boolean))];
  const { rows } = await client.query(
    `SELECT t.id, t.name, t.slug, t.aliases, t.active, ${other.referenceColumn} AS reference_sources
     FROM ${other.table} t
     WHERE lower(t.name) = ANY($1::text[])
        OR t.slug = ANY($2::text[])
        OR EXISTS (
          SELECT 1 FROM unnest(COALESCE(t.aliases, '{}'::text[])) AS alias
          WHERE ${ALIAS_KEY_SQL} = ANY($1::text[])
        )
     ORDER BY t.active DESC, t.name ASC
     LIMIT 10`,
    [keys, slugs]
  );
  const identity = { key: keys[0], keys, slugs, compacts: [], attackId: null };
  return rows
    .filter((row) => !(other.kind === ENTITY_KIND.THREAT_ACTOR && row.slug === UNKNOWN_ACTOR_SLUG))
    .map((row) => {
      const c = classifyCatalogCandidate(row, identity);
      return {
        entity_kind: other.kind,
        id: row.id,
        name: row.name,
        active: row.active !== false,
        match: c.match,
        match_detail: c.match_detail,
        attack_id: attackIdOf(row)
      };
    });
}

function parseTarget({ iocId, observableType, entityKind, sourceLabel }) {
  const id = Number(iocId);
  if (!Number.isInteger(id) || id <= 0) throw new CatalogLinkError(400, 'INVALID_IOC', 'Invalid IOC id');
  const type = String(observableType || '').trim();
  if (!type) throw new CatalogLinkError(400, 'INVALID_IOC', 'observable_type is required');
  const cfg = catalogKindConfig(entityKind);
  if (!cfg) throw new CatalogLinkError(400, 'INVALID_ENTITY_KIND', 'entity_kind must be threat_actor or malware_family');
  const labelKey = catalogLabelKey(sourceLabel);
  if (!labelKey) throw new CatalogLinkError(400, 'INVALID_SOURCE_LABEL', 'source_label is required');
  return { iocId: id, observableType: type, cfg, labelKey };
}

/**
 * Dialog context: verified source evidence for the label on this IOC, its link
 * state and catalog candidates. Read-only.
 */
export async function loadCatalogLinkContext(pool, { iocId, observableType, entityKind, sourceLabel, q = '' }) {
  const target = parseTarget({ iocId, observableType, entityKind, sourceLabel });
  const ioc = await fetchIoc(pool, target.iocId, target.observableType);
  if (!ioc) throw new CatalogLinkError(404, 'IOC_NOT_FOUND', 'IOC not found');
  const rows = await loadLabelAssertions(pool, {
    iocId: target.iocId,
    observableType: target.observableType,
    entityKind: target.cfg.kind,
    labelKey: target.labelKey
  });
  if (!rows.length) {
    throw new CatalogLinkError(404, 'SOURCE_LABEL_NOT_FOUND',
      `No source-reported ${target.cfg.noun} "${normalizeAttributionLabel(sourceLabel)}" on this IOC`);
  }
  const summary = summarizeLabelAssertions(rows);
  const displayLabel = (summary.visible[0] || rows[0]).source_label;
  const [{ candidates }, linked, crossCatalog] = await Promise.all([
    findCatalogCandidates(pool, target.cfg.kind, { label: displayLabel, q }),
    fetchCatalogEntities(pool, target.cfg, summary.linkedIds),
    findCrossCatalogMatches(pool, target.cfg.kind, [displayLabel])
  ]);
  const evidenceRows = summary.visible.length ? summary.visible : rows;
  return {
    ioc,
    entity_kind: target.cfg.kind,
    source_label: displayLabel,
    source_label_key: target.labelKey,
    link_state: summary.state,
    linked_entities: linked.map(serializeCatalogEntity),
    evidence: evidenceRows.slice(0, MAX_EVIDENCE_ROWS).map(serializeEvidence),
    evidence_total: evidenceRows.length,
    candidates,
    exact_candidate_ids: candidates.filter((c) => c.exact).map((c) => c.id),
    // The same name in the other catalog (informational; never blocks or converts).
    cross_catalog_matches: crossCatalog,
    // TalonHound's catalog for this label = the provider field it arrived in;
    // linking/creating never moves it to another catalog.
    local_entity_kind: target.cfg.kind,
    // Prefill = what the source reported, nothing else (analyst edits it).
    create_prefill: { name: displayLabel }
  };
}

function lockKey(...parts) {
  return ['talonhound:catalog-link', ...parts].join(':');
}

async function insertCatalogEntity(client, cfg, { name, slug, aliases, description }, actorLabel) {
  if (cfg.kind === ENTITY_KIND.THREAT_ACTOR) {
    const { rows } = await client.query(
      `INSERT INTO threat_actors (name, slug, aliases, description, active, catalog_sources, created_by, updated_by)
       VALUES ($1, $2, $3, $4, TRUE, ARRAY['manual']::text[], $5, $5)
       RETURNING *`,
      [name, slug, aliases.length ? aliases : null, description, actorLabel]
    );
    return rows[0];
  }
  const { rows } = await client.query(
    `INSERT INTO malware_families (name, slug, aliases, description, active, catalog_sources, created_by, updated_by)
     VALUES ($1, $2, $3::text[], $4, TRUE, ARRAY['manual']::text[], $5, $5)
     RETURNING *`,
    [name, slug, aliases, description, actorLabel]
  );
  return rows[0];
}

/**
 * Link (or create + link) the IOC's source-reported label to a catalog entity.
 * One transaction; idempotent; never writes analyst attribution.
 *
 * @param {import('pg').Pool} pool
 * @param {{ iocId: number, observableType: string, entityKind: string, sourceLabel: string,
 *   mode: 'link'|'create', entityId?: string, create?: object, confirmDistinct?: boolean,
 *   canCreate?: boolean, actorLabel?: string|null }} input
 * @returns {Promise<{ outcome: string, ioc: object, entity: object, created_entity: object|null,
 *   linked_assertions: number, evidence: object[], source_label: string, source_label_key: string }>}
 */
export async function linkSourceLabelToCatalog(pool, input) {
  const target = parseTarget(input);
  const { cfg, labelKey } = target;
  const mode = String(input.mode || '').trim();
  if (mode !== CATALOG_LINK_MODE.LINK && mode !== CATALOG_LINK_MODE.CREATE) {
    throw new CatalogLinkError(400, 'INVALID_MODE', 'mode must be link or create');
  }
  let entityId = null;
  let createValue = null;
  if (mode === CATALOG_LINK_MODE.LINK) {
    entityId = String(input.entityId || '').trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(entityId)) {
      throw new CatalogLinkError(400, 'INVALID_ENTITY_ID', 'entity_id must be a UUID');
    }
  } else {
    if (!input.canCreate) {
      throw new CatalogLinkError(403, 'CATALOG_CREATE_FORBIDDEN',
        `Creating a ${cfg.noun} in the catalog requires an administrator; link an existing entry instead`);
    }
    const check = validateCreateInput(cfg.kind, input.create || {});
    if (!check.ok) throw new CatalogLinkError(400, 'INVALID_CREATE_INPUT', check.error);
    createValue = check.value;
  }
  const actorLabel = input.actorLabel || null;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Lock order (always): catalog create (per kind) → IOC label. Link-only
    // requests take just the second, so no cycle.
    if (createValue) {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [lockKey('create', cfg.kind)]);
    }
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))',
      [lockKey(cfg.kind, target.observableType, String(target.iocId), labelKey)]);

    const ioc = await fetchIoc(client, target.iocId, target.observableType);
    if (!ioc) throw new CatalogLinkError(404, 'IOC_NOT_FOUND', 'IOC not found');

    const rows = await loadLabelAssertions(client, {
      iocId: target.iocId,
      observableType: target.observableType,
      entityKind: cfg.kind,
      labelKey,
      forUpdate: true
    });
    const summary = summarizeLabelAssertions(rows);
    if (!rows.length || summary.state === 'none') {
      throw new CatalogLinkError(404, 'SOURCE_LABEL_NOT_FOUND',
        `No current source-reported ${cfg.noun} "${normalizeAttributionLabel(input.sourceLabel)}" on this IOC`);
    }
    const displayLabel = (summary.visible[0] || rows[0]).source_label;

    if (summary.state === 'linked') {
      // Retry or concurrent analyst: return the existing resolution when it is
      // the one requested; otherwise explain who it points to.
      const linked = await fetchCatalogEntities(client, cfg, summary.linkedIds);
      const same = linked.length === 1 && (
        (entityId && String(linked[0].id).toLowerCase() === entityId.toLowerCase())
        || (createValue && catalogLabelKey(linked[0].name) === catalogLabelKey(createValue.name))
      );
      if (same) {
        await client.query('COMMIT');
        return {
          outcome: CATALOG_LINK_OUTCOME.ALREADY_LINKED,
          ioc,
          entity: serializeCatalogEntity(linked[0]),
          created_entity: null,
          linked_assertions: 0,
          evidence: summary.visible.slice(0, MAX_EVIDENCE_ROWS).map(serializeEvidence),
          source_label: displayLabel,
          source_label_key: labelKey
        };
      }
      throw new CatalogLinkError(409, 'ALREADY_LINKED',
        `"${displayLabel}" on this IOC is already linked to ${linked.map((l) => l.name).join(', ') || 'another entry'}`,
        { linked_entities: linked.map(serializeCatalogEntity) });
    }

    let entityRow;
    let createdRow = null;
    if (entityId) {
      entityRow = await fetchCatalogEntity(client, cfg, entityId, { lock: true });
      if (!entityRow) throw new CatalogLinkError(404, 'ENTITY_NOT_FOUND', `${cfg.noun[0].toUpperCase()}${cfg.noun.slice(1)} not found`);
      if (entityRow.active === false) {
        throw new CatalogLinkError(400, 'ENTITY_INACTIVE', `${entityRow.name} is disabled in the catalog; enable it first`);
      }
      if (cfg.kind === ENTITY_KIND.THREAT_ACTOR && entityRow.slug === UNKNOWN_ACTOR_SLUG) {
        throw new CatalogLinkError(400, 'ENTITY_NOT_LINKABLE', 'The "unknown" placeholder cannot be linked');
      }
    } else {
      const collisions = await findCreateCollisions(client, cfg, createValue);
      if (collisions.exact.length) {
        throw new CatalogLinkError(409, 'DUPLICATE_ENTITY',
          `A ${cfg.noun} with this name, alias or slug already exists — link it instead`,
          { candidates: collisions.exact });
      }
      if (collisions.similar.length && input.confirmDistinct !== true) {
        throw new CatalogLinkError(409, 'POTENTIAL_DUPLICATES',
          `Similar ${cfg.noun} entries exist; confirm this is a distinct entity or link one of them`,
          { candidates: collisions.similar });
      }
      try {
        createdRow = await insertCatalogEntity(client, cfg, createValue, actorLabel);
      } catch (err) {
        // Slug unique constraint: a concurrent create through the catalog admin
        // page (which does not take this lock). The whole transaction rolls back.
        if (String(err?.code) === '23505') {
          throw new CatalogLinkError(409, 'DUPLICATE_ENTITY',
            `A ${cfg.noun} with this name or slug already exists — link it instead`, { candidates: [] });
        }
        throw err;
      }
      entityRow = createdRow;
    }

    const { rows: updated } = await client.query(
      `UPDATE ioc_source_attributions
       SET entity_id = $5::uuid,
           resolution_status = $6,
           resolution_method = $7,
           resolved_at = NOW(),
           resolved_by = $8,
           updated_at = NOW()
       WHERE ioc_id = $1
         AND ioc_observable_type = $2
         AND entity_kind = $3
         AND source_label_normalized = $4
         AND entity_id IS NULL
       RETURNING id, source_label, feed_key, source_name, evidence_ref_type, evidence_ref_id,
                 evidence_url, evidence_title, association_kind, assertion_status,
                 observed_at, first_ingested_at, last_ingested_at,
                 provider_metadata->>'field' AS provider_field`,
      [
        target.iocId,
        target.observableType,
        cfg.kind,
        labelKey,
        entityRow.id,
        RESOLUTION_STATUS.RESOLVED,
        ANALYST_RESOLUTION_METHOD,
        actorLabel
      ]
    );
    // Recorded with a newly created entry (audit): the same name already exists
    // in the other catalog. Informational; the analyst's choice stands.
    const crossCatalog = createdRow
      ? await findCrossCatalogMatches(client, cfg.kind, [createdRow.name, ...(createValue?.aliases || [])])
      : [];
    await client.query('COMMIT');

    return {
      outcome: createdRow ? CATALOG_LINK_OUTCOME.CREATED_AND_LINKED : CATALOG_LINK_OUTCOME.LINKED,
      cross_catalog_matches: crossCatalog,
      ioc,
      entity: serializeCatalogEntity(entityRow),
      created_entity: createdRow,
      linked_assertions: updated.length,
      evidence: updated.slice(0, MAX_EVIDENCE_ROWS).map(serializeEvidence),
      source_label: displayLabel,
      source_label_key: labelKey
    };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    throw err;
  } finally {
    client.release();
  }
}

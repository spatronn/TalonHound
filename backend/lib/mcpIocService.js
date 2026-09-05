/**
 * MCP IOC tools — thin adapter over existing TalonHound domain services.
 * No parallel IOC create/search/normalization logic.
 */

import {
  normalizeApiIocValue,
  parseApiIocType,
  toApiIocResponse,
  loadManualTags
} from './apiIocService.js';
import { getApiIoc, searchApiIocs, clampApiIocPageSize } from './apiIocReadService.js';
import { createManualIoc, inferObservableType } from './manualIocCreate.js';
import { isIocSourceSelectable, resolveIocSourceState } from './iocSourceLifecycle.js';
import { serializeIocSourceRow } from './iocSourceValidation.js';
import { fetchIocThreatClassificationSlugs } from './iocThreatClassifications.js';
import { API_SYSTEM_SOURCE_NAME } from './apiSystemSource.js';
import { getMcpConfig } from './mcpConfig.js';
import { effectiveMcpCapabilities } from './mcpPermissions.js';
import { API_ERROR_CODE } from './apiV1Errors.js';
import { parseSearchQuery, DslError } from './iocSearchDsl/index.js';
import {
  canonicalFieldName,
  TEXT_OPERATORS,
  LIST_OPERATORS,
  ENUM_OPERATORS,
  DATE_OPERATORS,
  HASH_OPERATORS
} from './iocSearchDsl/fields.js';

async function findExistingIoc(pool, type, value) {
  const { rows } = await pool.query(
    `SELECT *
     FROM ioc_items
     WHERE observable_type = $1 AND observable = $2
     ORDER BY created_at ASC, id ASC
     LIMIT 1`,
    [type, value]
  );
  return rows[0] || null;
}

function mcpActorAuditFields(mcpAuth, user) {
  return {
    actorUsername: user?.username || user?.email || (mcpAuth?.apiKeyName ? `api_key:${mcpAuth.apiKeyName}` : 'mcp'),
    actorEmail: user?.email || null,
    actorRole: user?.role || null,
    actorPublicId: user?.publicId || null,
    source: 'mcp',
    metadataExtras: {
      actor_type: 'mcp',
      channel: 'mcp',
      api_key_id: mcpAuth?.apiKeyId ?? null,
      api_key_name: mcpAuth?.apiKeyName || null,
      access_profile: mcpAuth?.keyType || null,
      owner_user_id: user?.id ?? null,
      via: 'mcp'
    }
  };
}

function truncateValue(raw, maxChars) {
  const s = String(raw ?? '');
  if (s.length > maxChars) {
    return { ok: false, error: `value exceeds maximum length of ${maxChars} characters` };
  }
  return { ok: true, value: s.trim() };
}

/**
 * Detect + normalize a single IOC value using TalonHound canonical rules.
 * Optional explicit type is accepted; otherwise inferObservableType is used.
 */
export function resolveMcpIocInput(rawValue, explicitType, config = getMcpConfig()) {
  const clipped = truncateValue(rawValue, config.valueMaxChars);
  if (!clipped.ok) {
    return { ok: false, code: API_ERROR_CODE.INVALID_IOC_VALUE, message: clipped.error };
  }
  if (!clipped.value) {
    return { ok: false, code: API_ERROR_CODE.INVALID_IOC_VALUE, message: 'value is required' };
  }

  let type = null;
  if (explicitType != null && String(explicitType).trim() !== '') {
    const parsed = parseApiIocType(explicitType);
    if (!parsed.ok) return parsed;
    type = parsed.value;
  } else {
    type = inferObservableType(clipped.value);
    if (!type) {
      return { ok: false, code: API_ERROR_CODE.INVALID_IOC_TYPE, message: 'Could not infer IOC type from value' };
    }
  }

  const norm = normalizeApiIocValue(type, clipped.value);
  if (!norm.ok) return norm;
  return { ok: true, type: norm.type, value: norm.value, input: clipped.value };
}

function serializeLookupHit(row, extras = {}) {
  return {
    found: true,
    id: Number(row.id),
    public_id: row.public_id || null,
    value: row.observable,
    normalized_value: row.observable,
    type: row.observable_type,
    status: row.status || null,
    classifications: row.classifications
      || row.threat_classifications
      || (row.threat_classification ? [row.threat_classification] : []),
    confidence: row.confidence ?? null,
    first_seen: row.created_at || null,
    last_seen: row.last_seen_at || row.created_at || null,
    note: row.note ?? null,
    tags: Array.isArray(row.tags)
      ? row.tags.map((t) => (typeof t === 'string' ? t : t?.name)).filter(Boolean)
      : [],
    sources: extras.sources || [],
    ...extras.rest
  };
}

async function loadIocSourcesForObservable(pool, type, value) {
  const { rows } = await pool.query(
    `SELECT i.id, i.ioc_source_id, i.source_name, i.status, i.created_at,
            s.name AS catalog_source_name, s.active AS source_active, s.archived_at
     FROM ioc_items i
     LEFT JOIN ioc_sources s ON s.id = i.ioc_source_id
     WHERE i.observable_type = $1 AND i.observable = $2
     ORDER BY i.created_at ASC, i.id ASC`,
    [type, value]
  );
  return rows.map((r) => ({
    ioc_id: Number(r.id),
    source_id: r.ioc_source_id != null ? Number(r.ioc_source_id) : null,
    name: r.catalog_source_name || r.source_name || null,
    status: r.status || null,
    first_seen: r.created_at || null
  }));
}

export async function mcpLookupIoc(pool, { value, type } = {}, opts = {}) {
  const resolved = resolveMcpIocInput(value, type, opts.config || getMcpConfig());
  if (!resolved.ok) {
    return { status: 400, error: { code: resolved.code || API_ERROR_CODE.VALIDATION_ERROR, message: resolved.message } };
  }

  const existing = await findExistingIoc(pool, resolved.type, resolved.value);
  if (!existing) {
    return {
      status: 200,
      body: {
        found: false,
        value: resolved.value,
        normalized_value: resolved.value,
        type: resolved.type
      }
    };
  }

  const [classifications, tags, sources] = await Promise.all([
    fetchIocThreatClassificationSlugs(pool, existing.id, existing.observable_type),
    loadManualTags(pool, existing.id, existing.observable_type),
    loadIocSourcesForObservable(pool, existing.observable_type, existing.observable)
  ]);

  return {
    status: 200,
    body: serializeLookupHit(
      {
        ...existing,
        classifications,
        tags: tags.map((t) => t.name)
      },
      { sources }
    )
  };
}

// Every DSL operator word, used only to detect a *broken DSL attempt* vs. plain text.
const DSL_OPERATOR_WORDS = new Set([
  ...TEXT_OPERATORS,
  ...LIST_OPERATORS,
  ...ENUM_OPERATORS,
  ...DATE_OPERATORS,
  ...HASH_OPERATORS,
  'and',
  'or',
  'not',
  'between'
]);

// Quote a raw value as a DSL string literal, matching the tokenizer's escape rules
// (\" and \\). The IOC Search DSL requires every value — even enum values — to be a
// double-quoted string, so all structured filters are emitted quoted.
function dslQuote(value) {
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

// The MCP/API `type` notion (ip|domain|url|hash) collapses several stored
// observable_types, so translate each to the exact valid DSL `type` predicate rather
// than emitting an invalid `type:value`. `ip` covers IPv4 + IPv6; `hash` covers the
// three identity hash types.
const MCP_TYPE_TO_DSL = Object.freeze({
  ip: `type in (${dslQuote('ip')}, ${dslQuote('ipv6')})`,
  domain: `type equals ${dslQuote('domain')}`,
  url: `type equals ${dslQuote('url')}`,
  hash: `type in (${dslQuote('md5')}, ${dslQuote('sha1')}, ${dslQuote('sha256')})`
});

// Heuristic: does this string look like an *attempted* DSL expression (a known field
// word next to a known operator word)? Used only to decide, when a query fails to
// parse, whether to surface the DSL error (broken DSL) or fall back to a plain-text
// value search (bare indicator / free text).
function looksLikeDslAttempt(raw) {
  const words = String(raw).toLowerCase().match(/[a-z_][a-z0-9_]*/g) || [];
  let hasField = false;
  let hasOperator = false;
  for (const w of words) {
    if (canonicalFieldName(w)) hasField = true;
    if (DSL_OPERATOR_WORDS.has(w)) hasOperator = true;
  }
  return hasField && hasOperator;
}

// Turn a free-form `query` into a single DSL clause.
//   - valid DSL            -> used verbatim (the real parser is the source of truth)
//   - broken DSL attempt   -> DSL error surfaced (validation is not weakened)
//   - plain text / bare IOC -> bounded `ioc contains "<value>"` value search
function queryToDslClause(rawQuery) {
  try {
    parseSearchQuery(rawQuery);
    return { clause: rawQuery };
  } catch (err) {
    if (err instanceof DslError) {
      if (looksLikeDslAttempt(rawQuery)) {
        return { error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: err.message } };
      }
      return { clause: `ioc contains ${dslQuote(rawQuery)}` };
    }
    throw err;
  }
}

/**
 * Build a valid TalonHound IOC Search DSL query from the MCP search_iocs arguments.
 * Reuses the single IOC search engine — this only assembles the DSL string that the
 * engine parses; there is no parallel search implementation.
 *
 * @returns {{ ok: true, query: string } | { ok: false, error: { code: string, message: string } }}
 */
export function buildMcpSearchDsl(args = {}, config = getMcpConfig()) {
  const rawQuery = args.query != null ? String(args.query).trim() : '';
  if (rawQuery.length > config.valueMaxChars) {
    return { ok: false, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'query is too long' } };
  }

  const clauses = [];

  if (rawQuery) {
    const q = queryToDslClause(rawQuery);
    if (q.error) return { ok: false, error: q.error };
    clauses.push(q.clause);
  }

  const typeFilter = args.type != null && String(args.type).trim() !== ''
    ? parseApiIocType(args.type)
    : null;
  if (typeFilter && !typeFilter.ok) {
    return { ok: false, error: { code: typeFilter.code || API_ERROR_CODE.VALIDATION_ERROR, message: typeFilter.message } };
  }
  if (typeFilter?.ok) clauses.push(MCP_TYPE_TO_DSL[typeFilter.value]);

  const classification = args.classification != null ? String(args.classification).trim() : '';
  if (classification) clauses.push(`classification equals ${dslQuote(classification.slice(0, 128))}`);

  const source = args.source != null ? String(args.source).trim() : '';
  if (source) clauses.push(`source equals ${dslQuote(source.slice(0, 128))}`);

  if (clauses.length === 0) {
    return {
      ok: false,
      error: {
        code: API_ERROR_CODE.VALIDATION_ERROR,
        message: 'Provide a query or at least one filter (type, classification, source)'
      }
    };
  }

  // Parenthesize each clause so the AND-combination is unambiguous regardless of any
  // OR/NOT inside a caller-supplied DSL query.
  const query = clauses.length === 1 ? clauses[0] : clauses.map((c) => `(${c})`).join(' AND ');
  return { ok: true, query };
}

export async function mcpSearchIocs(pool, args = {}, opts = {}) {
  const config = opts.config || getMcpConfig();
  const limit = clampApiIocPageSize(args.limit, Math.min(config.searchPageMax, 50));
  const cappedLimit = Math.min(limit, config.searchPageMax);

  const built = buildMcpSearchDsl(args, config);
  if (!built.ok) {
    return { status: 400, error: built.error };
  }

  const outcome = await searchApiIocs(pool, {
    query: built.query,
    cursor: args.cursor,
    limit: cappedLimit
  });
  return outcome;
}

export async function mcpGetIocContext(pool, { value, type, id } = {}, opts = {}) {
  const caps = effectiveMcpCapabilities({
    scopes: opts.mcpAuth?.scopes,
    ownerRole: opts.mcpAuth?.ownerRole || opts.user?.role
  });

  let rowOutcome;
  if (id != null && String(id).trim() !== '') {
    rowOutcome = await getApiIoc(pool, id);
  } else {
    const lookup = await mcpLookupIoc(pool, { value, type }, opts);
    if (lookup.error) return lookup;
    if (!lookup.body?.found) {
      return { status: 404, error: { code: API_ERROR_CODE.IOC_NOT_FOUND, message: 'IOC not found' } };
    }
    rowOutcome = await getApiIoc(pool, lookup.body.id);
  }
  if (rowOutcome.error) return rowOutcome;

  const body = rowOutcome.body;
  const sources = await loadIocSourcesForObservable(pool, body.type, body.value);

  let enrichment = undefined;
  if (caps.enrichment_read) {
    const { rows: enr } = await pool.query(
      `SELECT provider, status, normalized_summary, fetched_at, expires_at, error_message
       FROM ioc_enrichments
       WHERE ioc_id = $1
       ORDER BY provider ASC`,
      [body.id]
    );
    enrichment = enr.map((e) => ({
      provider: e.provider,
      status: e.status,
      summary: e.normalized_summary || null,
      fetched_at: e.fetched_at || null,
      expires_at: e.expires_at || null,
      error_message: e.error_message || null
    }));
  }

  return {
    status: 200,
    body: {
      id: body.id,
      public_id: body.public_id,
      value: body.value,
      type: body.type,
      status: body.status,
      confidence: body.confidence,
      classifications: body.classifications || [],
      tags: body.tags || [],
      note: body.note,
      first_seen: body.created_at,
      last_seen: body.created_at,
      sources,
      enrichment: enrichment === undefined ? undefined : enrichment,
      enrichment_included: caps.enrichment_read
    }
  };
}

export async function mcpBulkLookupIocs(pool, { iocs } = {}, opts = {}) {
  const config = opts.config || getMcpConfig();
  if (!Array.isArray(iocs)) {
    return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'iocs must be an array' } };
  }
  if (iocs.length === 0) {
    return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'iocs must not be empty' } };
  }
  if (iocs.length > config.bulkLookupMax) {
    return {
      status: 400,
      error: {
        code: API_ERROR_CODE.VALIDATION_ERROR,
        message: `Batch too large: maximum ${config.bulkLookupMax} IOCs per request`
      }
    };
  }

  const resolved = [];
  const invalid = [];
  const seen = new Set();
  for (let i = 0; i < iocs.length; i += 1) {
    const item = iocs[i];
    const raw = typeof item === 'string' ? item : item?.value;
    const type = typeof item === 'object' && item != null ? item.type : undefined;
    const r = resolveMcpIocInput(raw, type, config);
    if (!r.ok) {
      invalid.push({
        index: i,
        input: raw == null ? null : String(raw).slice(0, 200),
        error: r.message
      });
      continue;
    }
    const key = `${r.type}\0${r.value}`;
    if (seen.has(key)) {
      resolved.push({ ...r, index: i, duplicate_in_request: true });
      continue;
    }
    seen.add(key);
    resolved.push({ ...r, index: i, duplicate_in_request: false });
  }

  const uniquePairs = resolved.filter((r) => !r.duplicate_in_request);
  let foundRows = [];
  if (uniquePairs.length) {
    const types = uniquePairs.map((r) => r.type);
    const values = uniquePairs.map((r) => r.value);
    const { rows } = await pool.query(
      `SELECT DISTINCT ON (observable_type, observable)
              id, public_id, observable, observable_type, status, confidence,
              threat_classification, note, created_at, last_seen_at
       FROM ioc_items
       WHERE (observable_type, observable) IN (
         SELECT * FROM unnest($1::text[], $2::text[]) AS t(observable_type, observable)
       )
       ORDER BY observable_type, observable, created_at ASC, id ASC`,
      [types, values]
    );
    foundRows = rows;
  }

  const byKey = new Map(foundRows.map((r) => [`${r.observable_type}\0${r.observable}`, r]));
  const existing = [];
  const missing = [];

  for (const r of resolved) {
    if (r.duplicate_in_request) {
      const hit = byKey.get(`${r.type}\0${r.value}`);
      if (hit) {
        existing.push({
          index: r.index,
          value: r.value,
          type: r.type,
          found: true,
          id: Number(hit.id),
          duplicate_in_request: true
        });
      } else {
        missing.push({
          index: r.index,
          value: r.value,
          type: r.type,
          found: false,
          duplicate_in_request: true
        });
      }
      continue;
    }
    const hit = byKey.get(`${r.type}\0${r.value}`);
    if (hit) {
      existing.push({
        index: r.index,
        value: r.value,
        type: r.type,
        found: true,
        id: Number(hit.id),
        public_id: hit.public_id || null,
        status: hit.status || null,
        confidence: hit.confidence ?? null,
        classifications: hit.threat_classification ? [hit.threat_classification] : [],
        first_seen: hit.created_at || null
      });
    } else {
      missing.push({
        index: r.index,
        value: r.value,
        type: r.type,
        found: false
      });
    }
  }

  return {
    status: 200,
    body: {
      submitted: iocs.length,
      existing,
      missing,
      invalid,
      counts: {
        existing: existing.filter((e) => !e.duplicate_in_request).length,
        missing: missing.filter((m) => !m.duplicate_in_request).length,
        invalid: invalid.length,
        duplicate_in_request: resolved.filter((r) => r.duplicate_in_request).length
      }
    }
  };
}

export async function mcpListIocSources(pool, _args = {}, opts = {}) {
  const { rows } = await pool.query(
    `SELECT s.*,
            (SELECT COUNT(*)::int FROM ioc_items i WHERE i.ioc_source_id = s.id) AS ioc_count
     FROM ioc_sources s
     ORDER BY lower(s.name) ASC, s.id ASC`
  );

  const sources = rows
    .filter((row) => isIocSourceSelectable(row))
    .map((row) => {
      const serialized = serializeIocSourceRow(row);
      return {
        id: Number(row.id),
        name: row.name,
        description: row.description || null,
        active: row.active !== false && !row.archived_at,
        state: resolveIocSourceState(row),
        source_type: row.source_type || null,
        ioc_count: Number(row.ioc_count || 0),
        default_confidence: serialized.default_confidence ?? row.default_confidence ?? null
      };
    });

  return { status: 200, body: { sources, count: sources.length } };
}

async function resolveSelectableSource(pool, sourceId) {
  const id = Number(sourceId);
  if (!Number.isFinite(id) || id <= 0) {
    return { ok: false, code: API_ERROR_CODE.VALIDATION_ERROR, message: 'source_id is required' };
  }
  const { rows } = await pool.query(
    `SELECT id, name, description, default_confidence, default_threat_classification,
            default_expire_policy, default_expire_days, active, archived_at, source_type
     FROM ioc_sources WHERE id = $1`,
    [id]
  );
  const row = rows[0];
  if (!row) {
    return { ok: false, code: API_ERROR_CODE.VALIDATION_ERROR, message: 'IOC Source not found' };
  }
  if (String(row.name || '') === API_SYSTEM_SOURCE_NAME) {
    return { ok: false, code: API_ERROR_CODE.VALIDATION_ERROR, message: 'IOC Source not accessible' };
  }
  if (!isIocSourceSelectable(row)) {
    return { ok: false, code: API_ERROR_CODE.VALIDATION_ERROR, message: 'IOC Source is not active or not accessible' };
  }
  return { ok: true, source: row };
}

async function hasSourceMembership(pool, type, value, sourceId) {
  const { rows } = await pool.query(
    `SELECT id FROM ioc_items
     WHERE observable_type = $1 AND observable = $2 AND ioc_source_id = $3
     LIMIT 1`,
    [type, value, sourceId]
  );
  return rows[0] || null;
}

/**
 * Controlled IOC import into an existing IOC Source via createManualIoc.
 */
export async function mcpImportIocs(pool, args = {}, opts = {}) {
  const config = opts.config || getMcpConfig();
  const dryRun = Boolean(args.dry_run);
  const sourceResolved = await resolveSelectableSource(pool, args.source_id);
  if (!sourceResolved.ok) {
    return { status: 400, error: { code: sourceResolved.code, message: sourceResolved.message } };
  }
  const source = sourceResolved.source;

  if (!Array.isArray(args.iocs)) {
    return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'iocs must be an array' } };
  }
  if (args.iocs.length === 0) {
    return { status: 400, error: { code: API_ERROR_CODE.VALIDATION_ERROR, message: 'iocs must not be empty' } };
  }
  if (args.iocs.length > config.importMax) {
    return {
      status: 400,
      error: {
        code: API_ERROR_CODE.VALIDATION_ERROR,
        message: `Batch too large: maximum ${config.importMax} IOCs per import`
      }
    };
  }

  const note = args.note != null ? String(args.note).trim().slice(0, 2000) || null : null;

  const plan = {
    submitted: args.iocs.length,
    would_create: 0,
    already_existing: 0,
    source_membership_would_add: 0,
    invalid: [],
    items: []
  };

  const toCreate = [];
  const seen = new Set();
  /** @type {Array<{ index: number, type: string, value: string }>} */
  const candidates = [];

  for (let i = 0; i < args.iocs.length; i += 1) {
    const item = args.iocs[i];
    const raw = typeof item === 'string' ? item : item?.value;
    const type = typeof item === 'object' && item != null ? item.type : undefined;
    const r = resolveMcpIocInput(raw, type, config);
    if (!r.ok) {
      plan.invalid.push({ index: i, input: raw == null ? null : String(raw).slice(0, 200), error: r.message });
      plan.items.push({ index: i, outcome: 'invalid', error: r.message });
      continue;
    }
    const key = `${r.type}\0${r.value}`;
    if (seen.has(key)) {
      plan.items.push({
        index: i,
        outcome: 'duplicate_in_request',
        type: r.type,
        value: r.value
      });
      continue;
    }
    seen.add(key);
    candidates.push({ index: i, type: r.type, value: r.value });
  }

  const membershipByKey = new Map();
  const existingByKey = new Map();
  if (candidates.length) {
    const types = candidates.map((c) => c.type);
    const values = candidates.map((c) => c.value);
    const [memQ, anyQ] = await Promise.all([
      pool.query(
        `SELECT id, observable_type, observable
         FROM ioc_items
         WHERE ioc_source_id = $1
           AND (observable_type, observable) IN (
             SELECT * FROM unnest($2::text[], $3::text[]) AS t(observable_type, observable)
           )`,
        [source.id, types, values]
      ),
      pool.query(
        `SELECT DISTINCT ON (observable_type, observable)
                id, observable_type, observable
         FROM ioc_items
         WHERE (observable_type, observable) IN (
           SELECT * FROM unnest($1::text[], $2::text[]) AS t(observable_type, observable)
         )
         ORDER BY observable_type, observable, created_at ASC, id ASC`,
        [types, values]
      )
    ]);
    for (const row of memQ.rows) {
      membershipByKey.set(`${row.observable_type}\0${row.observable}`, row);
    }
    for (const row of anyQ.rows) {
      existingByKey.set(`${row.observable_type}\0${row.observable}`, row);
    }
  }

  for (const c of candidates) {
    const key = `${c.type}\0${c.value}`;
    const membership = membershipByKey.get(key);
    if (membership) {
      plan.already_existing += 1;
      plan.items.push({
        index: c.index,
        outcome: 'already_existing',
        type: c.type,
        value: c.value,
        id: Number(membership.id)
      });
      continue;
    }

    const anyExisting = existingByKey.get(key);
    if (anyExisting) {
      plan.source_membership_would_add += 1;
      toCreate.push({
        index: c.index,
        type: c.type,
        value: c.value,
        kind: 'source_membership_added',
        existing_id: Number(anyExisting.id)
      });
      plan.items.push({
        index: c.index,
        outcome: 'source_membership_would_add',
        type: c.type,
        value: c.value,
        existing_id: Number(anyExisting.id)
      });
    } else {
      plan.would_create += 1;
      toCreate.push({ index: c.index, type: c.type, value: c.value, kind: 'create' });
      plan.items.push({
        index: c.index,
        outcome: 'would_create',
        type: c.type,
        value: c.value
      });
    }
  }

  if (dryRun) {
    return {
      status: 200,
      body: {
        dry_run: true,
        submitted: plan.submitted,
        would_create: plan.would_create,
        already_existing: plan.already_existing,
        source_membership_would_add: plan.source_membership_would_add,
        invalid: plan.invalid.length,
        invalid_items: plan.invalid,
        source: { id: Number(source.id), name: source.name },
        items: plan.items
      }
    };
  }

  const result = {
    dry_run: false,
    submitted: plan.submitted,
    created: 0,
    already_existing: plan.already_existing,
    source_membership_added: 0,
    invalid: plan.invalid.length,
    failed: 0,
    invalid_items: plan.invalid,
    failed_items: [],
    source: { id: Number(source.id), name: source.name },
    items: plan.items.filter((it) => it.outcome === 'already_existing' || it.outcome === 'invalid' || it.outcome === 'duplicate_in_request')
  };

  const actor = mcpActorAuditFields(opts.mcpAuth, opts.user);
  const auditWrapper = opts.audit
    ? {
      auditSuccess: (event) => opts.audit.auditSuccess({
        ...event,
        actorUsername: actor.actorUsername,
        actorEmail: actor.actorEmail,
        actorRole: actor.actorRole,
        actorPublicId: actor.actorPublicId,
        source: actor.source,
        metadata: {
          ...(event.metadata || {}),
          ...actor.metadataExtras
        }
      })
    }
    : null;

  for (const item of toCreate) {
    try {
      const created = await createManualIoc(
        pool,
        {
          observable: item.value,
          ip: item.value,
          source_id: Number(source.id),
          note
        },
        {
          req: opts.req,
          user: opts.user,
          audit: auditWrapper,
          createdOrigin: 'manual_add'
        }
      );

      if (created.status === 200 && created.body?.skipped) {
        // Race / duplicate tuple — treat as already existing for this source.
        const membership = await hasSourceMembership(pool, item.type, item.value, source.id);
        result.already_existing += 1;
        result.items.push({
          index: item.index,
          outcome: 'already_existing',
          type: item.type,
          value: item.value,
          id: membership ? Number(membership.id) : null
        });
        continue;
      }

      if (created.status >= 400) {
        result.failed += 1;
        result.failed_items.push({
          index: item.index,
          value: item.value,
          error: created.body?.message || 'Create failed'
        });
        result.items.push({
          index: item.index,
          outcome: 'failed',
          type: item.type,
          value: item.value,
          error: created.body?.message || 'Create failed'
        });
        continue;
      }

      if (item.kind === 'source_membership_added') {
        result.source_membership_added += 1;
        result.items.push({
          index: item.index,
          outcome: 'source_membership_added',
          type: item.type,
          value: item.value,
          id: created.body?.id != null ? Number(created.body.id) : null,
          existing_id: item.existing_id
        });
      } else {
        result.created += 1;
        result.items.push({
          index: item.index,
          outcome: 'created',
          type: item.type,
          value: item.value,
          id: created.body?.id != null ? Number(created.body.id) : null,
          public_id: created.body?.public_id || null
        });
      }
    } catch {
      result.failed += 1;
      result.failed_items.push({ index: item.index, value: item.value, error: 'Internal error' });
      result.items.push({
        index: item.index,
        outcome: 'failed',
        type: item.type,
        value: item.value,
        error: 'Internal error'
      });
    }
  }

  return { status: 200, body: result };
}

export { toApiIocResponse, mcpActorAuditFields };

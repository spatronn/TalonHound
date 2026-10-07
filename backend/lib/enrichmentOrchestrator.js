// Canonical enrichment orchestration for explicit, automated triggers
// (MCP enrich_ioc / bulk_enrich_iocs / get_enrichment_job).
//
//   caller (already authorized)
//     → planEnrichment: resolve each IOC's applicable providers + lookup target
//       from the provider registry (never from caller input), drop fresh results
//       (non-force), refuse unavailable providers, enforce batch limits
//     → createEnrichmentJob: persist job + items, coalesce onto in-flight
//       identical operations (provider + target)
//     → in-process runner: per item re-check enabled/fresh/cooldown, take an
//       automation budget slot, run the provider's *registered executor* — the
//       exact function its UI/REST refresh route runs — and record the outcome
//     → provider stores / audit / IOC context, exactly as a UI refresh
//
// No provider names appear here: adding a provider to the registry (with
// resolveTarget/readFreshness) and registering its executor makes it available
// to every automated trigger.

import { randomUUID } from 'node:crypto';
import {
  listEnrichmentProviders,
  getEnrichmentProvider,
  getEnrichmentExecutor,
  observableCategory
} from './enrichmentProviderRegistry.js';
import { providerCooldownRemainingMs, tryAcquireAutomationSlot } from './enrichmentProviderGuard.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';

export const ITEM_STATUS = Object.freeze({
  QUEUED: 'queued',
  RUNNING: 'running',
  COMPLETED: 'completed',
  SKIPPED_FRESH: 'skipped_fresh',
  DEDUPLICATED: 'deduplicated',
  UNSUPPORTED: 'unsupported',
  UNKNOWN_PROVIDER: 'unknown_provider',
  PROVIDER_UNAVAILABLE: 'provider_unavailable',
  RATE_LIMITED: 'rate_limited',
  FORBIDDEN: 'forbidden',
  FAILED: 'failed',
  INTERRUPTED: 'interrupted'
});

export const JOB_STATUS = Object.freeze({
  QUEUED: 'queued',
  RUNNING: 'running',
  COMPLETED: 'completed',
  PARTIALLY_COMPLETED: 'partially_completed',
  FAILED: 'failed'
});

const ACTIVE_ITEM = new Set([ITEM_STATUS.QUEUED, ITEM_STATUS.RUNNING]);
const SUCCESS_ITEM = new Set([ITEM_STATUS.COMPLETED, ITEM_STATUS.SKIPPED_FRESH]);
// Coalesced items are being served by another job's in-flight operation.
const NEUTRAL_ITEM = new Set([ITEM_STATUS.DEDUPLICATED]);

export const ENRICHMENT_LIMITS = Object.freeze({
  /** IOCs per bulk request. */
  BULK_MAX_IOCS: 25,
  /** Provider operations (IOC × provider that would actually run) per request. */
  MAX_OPERATIONS: 100,
  /** Concurrently active (queued/running) jobs per API key. */
  MAX_ACTIVE_JOBS_PER_KEY: 5,
  /** Longest an item waits for an automation budget slot before giving up. */
  BUDGET_WAIT_MAX_MS: 120_000,
  /** Global in-process provider operations running at once. */
  CONCURRENCY: 2,
  /** Jobs older than this are pruned. */
  RETENTION_DAYS: 30
});

const RUNNER_INSTANCE = randomUUID();
const MESSAGE_MAX = 300;

/** Item fields for a provider whose stored result is reused (no external call). */
function freshItemFields(fresh) {
  const stored = fresh?.stored_status ? String(fresh.stored_status) : null;
  const okStored = !stored || ['success', 'not_found', 'listed', 'not_listed', 'unavailable'].includes(stored);
  return {
    status: ITEM_STATUS.SKIPPED_FRESH,
    result: stored,
    last_enriched_at: fresh?.last_enriched_at || null,
    message: okStored
      ? 'Fresh enrichment already exists'
      : `Stored result (${stored}) is still within the provider cache window; use force_refresh to retry`
  };
}

function safeMessage(raw) {
  if (raw == null) return null;
  const s = String(raw).replace(/\s+/g, ' ').trim();
  if (!s) return null;
  return s.length > MESSAGE_MAX ? `${s.slice(0, MESSAGE_MAX - 1)}…` : s;
}

function toIso(value) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isFinite(d.getTime()) ? d.toISOString() : null;
}

// ---------------------------------------------------------------------------
// Provider discovery
// ---------------------------------------------------------------------------

/** Registry entries automated triggers can actually run (capabilities + executor). */
function triggerableProviders() {
  return listEnrichmentProviders().filter(
    (p) => typeof p.resolveTarget === 'function' && getEnrichmentExecutor(p.key)
  );
}

async function loadProviderState(pool, entry) {
  try {
    const state = await entry.loadState(pool);
    return { enabled: state?.enabled === true, configured: state?.configured !== false };
  } catch {
    return { enabled: false, configured: false, error: true };
  }
}

/**
 * Safe provider inventory for list_enrichment_providers. Never includes keys,
 * tokens, base URLs or raw config — only booleans and capability metadata.
 */
export async function describeEnrichmentProviders(pool) {
  const out = [];
  for (const entry of listEnrichmentProviders()) {
    const state = await loadProviderState(pool, entry);
    const triggerable = typeof entry.resolveTarget === 'function' && Boolean(getEnrichmentExecutor(entry.key));
    out.push({
      id: entry.key,
      name: entry.displayName || entry.key,
      supported_observable_types: Array.isArray(entry.supportedObservableTypes) ? [...entry.supportedObservableTypes] : [],
      external: entry.external !== false,
      enabled: state.enabled,
      configured: state.configured,
      triggerable,
      available: triggerable && state.enabled && state.configured,
      automation_rate_per_min: Number(entry.automationRatePerMin) || null
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// IOC resolution (TalonHound is the source of truth for observable + type)
// ---------------------------------------------------------------------------

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Resolve IOC references (public UUIDs, or numeric ids) to stored IOCs.
 * @returns {Promise<{ found: Map<string, object>, invalid: string[] }>} keyed by the caller's reference
 */
export async function resolveEnrichmentIocs(pool, refs) {
  const found = new Map();
  const invalid = [];
  const uuids = [];
  const numeric = [];
  for (const raw of refs) {
    const ref = String(raw ?? '').trim();
    if (UUID_RE.test(ref)) uuids.push(ref.toLowerCase());
    else if (/^\d{1,18}$/.test(ref) && Number(ref) > 0) numeric.push(ref);
    else invalid.push(ref);
  }
  if (uuids.length) {
    const { rows } = await pool.query(
      `SELECT id, public_id, observable, observable_type
       FROM ioc_items WHERE public_id = ANY($1::uuid[])`,
      [uuids]
    );
    for (const r of rows) found.set(String(r.public_id).toLowerCase(), normalizeIocRow(r));
  }
  for (const ref of numeric) {
    const { rows } = await pool.query(
      `SELECT id, public_id, observable, observable_type FROM ioc_items WHERE id = $1 LIMIT 1`,
      [Number(ref)]
    );
    if (rows[0]) found.set(ref, normalizeIocRow(rows[0]));
  }
  return { found, invalid };
}

function normalizeIocRow(r) {
  return {
    id: Number(r.id),
    public_id: r.public_id ? String(r.public_id) : null,
    observable: String(r.observable || ''),
    observable_type: String(r.observable_type || '').toLowerCase()
  };
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/**
 * @param {import('pg').Pool} pool
 * @param {object[]} iocs  resolved IOCs
 * @param {{ providers: 'all'|string[], force?: boolean }} opts
 * @returns {Promise<{ items: object[], notApplicable: object[] }>}
 */
export async function planEnrichment(pool, iocs, { providers, force = false } = {}) {
  const all = providers === 'all';
  const requested = all
    ? triggerableProviders().map((p) => p.key)
    : [...new Set((providers || []).map((p) => String(p || '').trim().toLowerCase()).filter(Boolean))];

  const stateCache = new Map();
  const items = [];
  const notApplicable = [];

  for (const ioc of iocs) {
    for (const key of requested) {
      const base = {
        ioc,
        provider: key,
        force_refresh: Boolean(force),
        target_scope: null,
        target_type: null,
        target_value: null,
        last_enriched_at: null
      };
      const entry = getEnrichmentProvider(key);
      if (!entry) {
        items.push({ ...base, status: ITEM_STATUS.UNKNOWN_PROVIDER, error_code: 'unknown_provider', message: 'Unknown enrichment provider' });
        continue;
      }
      if (typeof entry.resolveTarget !== 'function') {
        items.push({ ...base, status: ITEM_STATUS.PROVIDER_UNAVAILABLE, error_code: 'provider_not_triggerable', message: 'Provider cannot be triggered automatically' });
        continue;
      }
      const target = entry.resolveTarget(ioc);
      if (!target?.applicable) {
        const reason = target?.reason || 'unsupported_type';
        if (all) {
          notApplicable.push({ ioc_id: ioc.public_id, provider: key, reason });
        } else {
          items.push({
            ...base,
            status: ITEM_STATUS.UNSUPPORTED,
            error_code: 'unsupported_observable',
            message: `${entry.displayName || key} does not apply to this ${observableCategory(ioc.observable_type)} IOC (${reason})`
          });
        }
        continue;
      }
      const withTarget = {
        ...base,
        target_scope: target.scope,
        target_type: target.target_type,
        target_value: target.target_value
      };

      if (!getEnrichmentExecutor(key)) {
        items.push({ ...withTarget, status: ITEM_STATUS.PROVIDER_UNAVAILABLE, error_code: 'provider_not_triggerable', message: 'Provider cannot be triggered automatically' });
        continue;
      }
      if (!stateCache.has(key)) stateCache.set(key, await loadProviderState(pool, entry));
      const state = stateCache.get(key);
      if (!state.enabled || !state.configured) {
        items.push({
          ...withTarget,
          status: ITEM_STATUS.PROVIDER_UNAVAILABLE,
          error_code: !state.enabled ? 'provider_disabled' : 'provider_not_configured',
          message: !state.enabled ? `${entry.displayName} is disabled` : `${entry.displayName} is not configured`
        });
        continue;
      }

      if (!force && typeof entry.readFreshness === 'function') {
        const fresh = await entry.readFreshness(pool, target, ioc).catch(() => null);
        if (fresh?.fresh) {
          items.push({ ...withTarget, ...freshItemFields(fresh) });
          continue;
        }
        withTarget.last_enriched_at = fresh?.last_enriched_at || null;
      }
      items.push({ ...withTarget, status: ITEM_STATUS.QUEUED });
    }
  }
  return { items, notApplicable };
}

export function countOperations(items) {
  return items.filter((i) => i.status === ITEM_STATUS.QUEUED).length;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export async function countActiveJobsForKey(pool, apiKeyId) {
  if (apiKeyId == null) return 0;
  const { rows } = await pool.query(
    `SELECT count(*)::int AS n FROM enrichment_jobs
     WHERE api_key_id = $1 AND status = ANY(ARRAY['queued','running'])`,
    [apiKeyId]
  );
  return rows[0]?.n || 0;
}

/**
 * Persist the job + items in one transaction. Queued items coalesce onto an
 * already-active identical operation (same provider + lookup target), and onto
 * each other within the request, so N concurrent agents enriching the same IOC
 * cost one provider call. A forced request only coalesces onto a forced
 * in-flight operation (a non-forced one may still end as "fresh, skipped").
 */
export async function createEnrichmentJob(pool, { items, providers, force, actor = {}, origin = 'mcp', requestId = null }) {
  const client = typeof pool.connect === 'function' ? await pool.connect() : pool;
  const release = () => { if (client !== pool && typeof client.release === 'function') client.release(); };
  try {
    await client.query('BEGIN');
    const { rows: jobRows } = await client.query(
      `INSERT INTO enrichment_jobs
         (origin, requested_by_user_id, api_key_id, requested_providers, force_refresh, status, runner_instance, request_id)
       VALUES ($1, $2, $3, $4::jsonb, $5, 'queued', $6, $7)
       RETURNING id, created_at`,
      [
        origin,
        actor.userId ?? null,
        actor.apiKeyId ?? null,
        JSON.stringify(providers === 'all' ? ['all'] : providers),
        Boolean(force),
        RUNNER_INSTANCE,
        requestId ? String(requestId).slice(0, 128) : null
      ]
    );
    const job = jobRows[0];
    const inRequest = new Map();
    const persisted = [];
    for (const item of items) {
      let status = item.status;
      let coalescedInto = null;
      if (status === ITEM_STATUS.QUEUED) {
        const dedupeKey = `${item.provider}|${item.target_value}`;
        const local = inRequest.get(dedupeKey);
        if (local && (local.force_refresh || !item.force_refresh)) {
          status = ITEM_STATUS.DEDUPLICATED;
          coalescedInto = local.id;
        } else {
          await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`enrichment:${dedupeKey}`]);
          const { rows: active } = await client.query(
            `SELECT id, force_refresh FROM enrichment_job_items
             WHERE provider = $1 AND target_value = $2 AND status = ANY(ARRAY['queued','running'])
             ORDER BY force_refresh DESC, id ASC LIMIT 1`,
            [item.provider, item.target_value]
          );
          const hit = active[0];
          if (hit && (hit.force_refresh || !item.force_refresh)) {
            status = ITEM_STATUS.DEDUPLICATED;
            coalescedInto = Number(hit.id);
          }
        }
      }
      const { rows } = await client.query(
        `INSERT INTO enrichment_job_items
           (job_id, ioc_id, ioc_public_id, observable, observable_type, provider,
            target_scope, target_type, target_value, force_refresh, status,
            error_code, message, coalesced_into_item_id, last_enriched_at, finished_at, result)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::timestamptz,
                 CASE WHEN $11 = ANY(ARRAY['queued','running']) THEN NULL ELSE now() END, $16)
         RETURNING id`,
        [
          job.id, item.ioc.id, item.ioc.public_id, item.ioc.observable, item.ioc.observable_type,
          item.provider, item.target_scope, item.target_type, item.target_value, item.force_refresh,
          status, item.error_code || null, safeMessage(item.message), coalescedInto, item.last_enriched_at || null,
          item.result || null
        ]
      );
      const id = Number(rows[0].id);
      if (status === ITEM_STATUS.QUEUED) {
        inRequest.set(`${item.provider}|${item.target_value}`, { id, force_refresh: item.force_refresh });
      }
      persisted.push({ ...item, id, status, coalesced_into_item_id: coalescedInto });
    }
    const hasWork = persisted.some((i) => i.status === ITEM_STATUS.QUEUED);
    if (!hasWork) {
      await client.query(
        `UPDATE enrichment_jobs SET status = $2, finished_at = now(), updated_at = now() WHERE id = $1`,
        [job.id, aggregateJobStatus(persisted.map((i) => i.status))]
      );
    }
    await client.query('COMMIT');
    return { jobId: String(job.id), items: persisted, hasWork };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    release();
  }
}

/**
 * Job status from item statuses: completed when every attempted operation
 * succeeded (or was fresh), partially_completed when some did, failed when none
 * did. Coalesced items are neutral (another job is doing that work).
 */
export function aggregateJobStatus(statuses) {
  const list = statuses.filter((s) => !NEUTRAL_ITEM.has(s));
  if (statuses.some((s) => ACTIVE_ITEM.has(s))) {
    return statuses.some((s) => s === ITEM_STATUS.RUNNING) || statuses.some((s) => !ACTIVE_ITEM.has(s))
      ? JOB_STATUS.RUNNING
      : JOB_STATUS.QUEUED;
  }
  if (!list.length) return JOB_STATUS.COMPLETED;
  const ok = list.filter((s) => SUCCESS_ITEM.has(s)).length;
  if (ok === list.length) return JOB_STATUS.COMPLETED;
  if (ok > 0) return JOB_STATUS.PARTIALLY_COMPLETED;
  return JOB_STATUS.FAILED;
}

// ---------------------------------------------------------------------------
// Execution outcome normalization (generic over every provider's route contract)
// ---------------------------------------------------------------------------

const UNAVAILABLE_BODY_STATUS = new Set(['disabled', 'not_configured', 'api_key_missing', 'dataset_not_synced']);

/**
 * Map a provider refresh function's `{ status: httpStatus, body }` to an item
 * outcome. Uses only the shared route vocabulary (HTTP status, `cached`,
 * `status` / `provider_status` / `rdap_status`), never provider names.
 */
export function classifyExecutorOutcome(out) {
  const http = Number(out?.status) || 500;
  const body = out?.body && typeof out.body === 'object' ? out.body : {};
  const message = safeMessage(body.message || body.error || body.error_message);
  const bodyStatus = String(body.provider_status || body.rdap_status || body.status || '').toLowerCase();

  if (http === 429) {
    return { status: ITEM_STATUS.RATE_LIMITED, error_code: 'provider_rate_limited', message, retry_after: body.retry_after ?? null };
  }
  if (http === 409) {
    return {
      status: ITEM_STATUS.PROVIDER_UNAVAILABLE,
      error_code: bodyStatus === 'not_configured' ? 'provider_not_configured' : 'provider_disabled',
      message
    };
  }
  if (http === 401 || http === 403) {
    return http === 403
      ? { status: ITEM_STATUS.FORBIDDEN, error_code: 'forbidden', message }
      : { status: ITEM_STATUS.FAILED, error_code: 'provider_auth_error', message };
  }
  // Precondition states (disabled / no key / dataset not synced) can arrive with
  // a 2xx or a 4xx depending on the provider route — they are never 'unsupported'.
  if (UNAVAILABLE_BODY_STATUS.has(bodyStatus)) {
    return { status: ITEM_STATUS.PROVIDER_UNAVAILABLE, error_code: `provider_${bodyStatus}`, message };
  }
  if (http === 400 || http === 422) {
    return { status: ITEM_STATUS.UNSUPPORTED, error_code: 'unsupported_observable', message };
  }
  if (http >= 200 && http < 300) {
    if (bodyStatus === 'not_applicable') {
      return { status: ITEM_STATUS.UNSUPPORTED, error_code: 'unsupported_observable', message };
    }
    if (body.cached === true) {
      return { status: ITEM_STATUS.SKIPPED_FRESH, result: bodyStatus || 'cached', message: 'Provider reused its stored result' };
    }
    return { status: ITEM_STATUS.COMPLETED, result: bodyStatus || 'success', message: null };
  }
  if (http === 404 && body.enriched === false) {
    // Completed lookup with no dataset match (e.g. IP not in the provider dataset).
    return { status: ITEM_STATUS.COMPLETED, result: bodyStatus || 'no_data', message };
  }
  if (http === 504) return { status: ITEM_STATUS.FAILED, error_code: 'provider_timeout', message };
  return { status: ITEM_STATUS.FAILED, error_code: 'provider_error', message };
}

// ---------------------------------------------------------------------------
// In-process runner
// ---------------------------------------------------------------------------

const pendingJobs = [];
/** jobId -> { pool, audit, providerAudit, principal } */
const jobContexts = new Map();
let activeLoops = 0;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Queue a persisted job for background execution in this process.
 * @param {{ pool, jobId, audit?, providerAudit?, principal?, requestId? }} ctx
 */
export function scheduleEnrichmentJob(ctx) {
  jobContexts.set(ctx.jobId, ctx);
  pendingJobs.push(ctx.jobId);
  setImmediate(pump);
}

function pump() {
  while (activeLoops < ENRICHMENT_LIMITS.CONCURRENCY && pendingJobs.length) {
    const jobId = pendingJobs.shift();
    activeLoops += 1;
    runJob(jobId)
      .catch((err) => console.error('[enrichment-job] runner failed', jobId, err?.message || err))
      .finally(() => {
        activeLoops -= 1;
        jobContexts.delete(jobId);
        setImmediate(pump);
      });
  }
}

/** Request-shaped principal for the provider refresh functions (audit attribution). */
function buildExecutionRequest(ctx, item) {
  return {
    user: ctx.principal || null,
    authVia: 'mcp',
    mcpAuth: ctx.mcpAuth || null,
    requestId: ctx.requestId || null,
    headers: { 'user-agent': 'TalonHound-MCP-Enrichment', ...(ctx.requestId ? { 'x-request-id': ctx.requestId } : {}) },
    ip: ctx.clientIp || null,
    params: {},
    query: {},
    body: {
      ioc_id: item.ioc_public_id || String(item.ioc_id),
      value: item.observable,
      ioc_type: item.observable_type
    }
  };
}

async function updateItem(pool, id, fields) {
  await pool.query(
    `UPDATE enrichment_job_items SET
       status = $2, result = $3, error_code = $4, message = $5,
       last_enriched_at = COALESCE($6::timestamptz, last_enriched_at),
       finished_at = CASE WHEN $2 = ANY(ARRAY['queued','running']) THEN NULL ELSE now() END,
       updated_at = now()
     WHERE id = $1`,
    [id, fields.status, fields.result || null, fields.error_code || null, safeMessage(fields.message), fields.last_enriched_at || null]
  );
}

async function executeItem(ctx, item) {
  const { pool } = ctx;
  const entry = getEnrichmentProvider(item.provider);
  const executor = getEnrichmentExecutor(item.provider);
  const ioc = { id: Number(item.ioc_id), public_id: item.ioc_public_id, observable: item.observable, observable_type: item.observable_type };
  const target = { applicable: true, scope: item.target_scope, target_type: item.target_type, target_value: item.target_value };
  if (!entry || !executor) {
    return { status: ITEM_STATUS.PROVIDER_UNAVAILABLE, error_code: 'provider_not_triggerable', message: 'Provider cannot be triggered automatically' };
  }

  const state = await loadProviderState(pool, entry);
  if (!state.enabled || !state.configured) {
    return {
      status: ITEM_STATUS.PROVIDER_UNAVAILABLE,
      error_code: !state.enabled ? 'provider_disabled' : 'provider_not_configured',
      message: !state.enabled ? `${entry.displayName} is disabled` : `${entry.displayName} is not configured`
    };
  }

  // Another job (or a UI refresh) may have refreshed it since planning.
  if (!item.force_refresh && typeof entry.readFreshness === 'function') {
    const fresh = await entry.readFreshness(pool, target, ioc).catch(() => null);
    if (fresh?.fresh) return freshItemFields(fresh);
  }

  const cooldownMs = providerCooldownRemainingMs(item.provider);
  if (cooldownMs > 0) {
    return {
      status: ITEM_STATUS.RATE_LIMITED,
      error_code: 'provider_cooldown',
      message: `${entry.displayName} recently rate-limited TalonHound; retry in ~${Math.ceil(cooldownMs / 1000)}s`
    };
  }

  let waited = 0;
  for (;;) {
    const slot = tryAcquireAutomationSlot(item.provider);
    if (slot.ok) break;
    if (waited + slot.waitMs > ENRICHMENT_LIMITS.BUDGET_WAIT_MAX_MS) {
      return {
        status: ITEM_STATUS.RATE_LIMITED,
        error_code: 'automation_budget_exhausted',
        message: `${entry.displayName} automation budget exhausted; retry later`
      };
    }
    await sleep(slot.waitMs);
    waited += slot.waitMs;
  }

  let out;
  try {
    out = await executor({
      pool,
      audit: ctx.providerAudit || ctx.audit,
      req: buildExecutionRequest(ctx, item),
      ioc,
      target,
      force: item.force_refresh === true
    });
  } catch (err) {
    console.error('[enrichment-job] provider execution failed', item.provider, err?.message || err);
    return { status: ITEM_STATUS.FAILED, error_code: 'internal_error', message: 'Enrichment provider execution failed' };
  }
  const outcome = classifyExecutorOutcome(out);
  if (typeof entry.readFreshness === 'function'
    && (outcome.status === ITEM_STATUS.COMPLETED || outcome.status === ITEM_STATUS.SKIPPED_FRESH)) {
    const after = await entry.readFreshness(pool, target, ioc).catch(() => null);
    if (after?.last_enriched_at) outcome.last_enriched_at = after.last_enriched_at;
  }
  return outcome;
}

async function runJob(jobId) {
  const ctx = jobContexts.get(jobId);
  if (!ctx) return;
  const { pool } = ctx;
  await pool.query(
    `UPDATE enrichment_jobs SET status = 'running', started_at = COALESCE(started_at, now()), updated_at = now()
     WHERE id = $1 AND status = 'queued'`,
    [jobId]
  );
  const { rows: items } = await pool.query(
    `SELECT * FROM enrichment_job_items WHERE job_id = $1 AND status = 'queued' ORDER BY id ASC`,
    [jobId]
  );
  for (const item of items) {
    const claimed = await pool.query(
      `UPDATE enrichment_job_items SET status = 'running', started_at = now(), updated_at = now()
       WHERE id = $1 AND status = 'queued' RETURNING id`,
      [item.id]
    );
    if (!claimed.rowCount) continue;
    let outcome;
    try {
      outcome = await executeItem(ctx, item);
    } catch (err) {
      console.error('[enrichment-job] item failed', item.id, err?.message || err);
      outcome = { status: ITEM_STATUS.FAILED, error_code: 'internal_error', message: 'Enrichment item failed' };
    }
    await updateItem(pool, item.id, outcome);
  }
  await finalizeJob(ctx, jobId);
}

async function finalizeJob(ctx, jobId) {
  const { pool } = ctx;
  const { rows } = await pool.query(
    `SELECT status, provider FROM enrichment_job_items WHERE job_id = $1`,
    [jobId]
  );
  const status = aggregateJobStatus(rows.map((r) => r.status));
  await pool.query(
    `UPDATE enrichment_jobs SET status = $2, finished_at = now(), updated_at = now() WHERE id = $1`,
    [jobId, status]
  );
  if (typeof ctx.onFinished === 'function') {
    const summary = {};
    for (const r of rows) summary[r.status] = (summary[r.status] || 0) + 1;
    await Promise.resolve(ctx.onFinished({ jobId, status, summary })).catch(() => {});
  }
}

/**
 * Wait (bounded) for a job to leave queued/running. Returns the final status or
 * null on timeout.
 */
export async function waitForEnrichmentJob(pool, jobId, timeoutMs) {
  const deadline = Date.now() + Math.max(0, timeoutMs);
  while (Date.now() < deadline) {
    const { rows } = await pool.query('SELECT status FROM enrichment_jobs WHERE id = $1', [jobId]);
    const status = rows[0]?.status;
    if (status && status !== JOB_STATUS.QUEUED && status !== JOB_STATUS.RUNNING) return status;
    await sleep(Math.min(500, Math.max(50, deadline - Date.now())));
  }
  return null;
}

/**
 * Startup / periodic maintenance: jobs this process does not own and that are
 * still queued/running were interrupted by a restart (the runner is in-process),
 * so close them honestly instead of leaving them "running" forever; prune old jobs.
 */
export async function sweepEnrichmentJobs(pool) {
  await pool.query(
    `UPDATE enrichment_job_items i SET status = 'interrupted', error_code = 'interrupted',
            message = 'Interrupted by a TalonHound restart; request it again',
            finished_at = now(), updated_at = now()
     FROM enrichment_jobs j
     WHERE i.job_id = j.id AND i.status = ANY(ARRAY['queued','running'])
       AND (j.runner_instance IS DISTINCT FROM $1)`,
    [RUNNER_INSTANCE]
  );
  const { rows } = await pool.query(
    `SELECT id FROM enrichment_jobs
     WHERE status = ANY(ARRAY['queued','running']) AND runner_instance IS DISTINCT FROM $1`,
    [RUNNER_INSTANCE]
  );
  for (const r of rows) {
    const { rows: items } = await pool.query('SELECT status FROM enrichment_job_items WHERE job_id = $1', [r.id]);
    await pool.query(
      `UPDATE enrichment_jobs SET status = $2, finished_at = now(), updated_at = now() WHERE id = $1`,
      [r.id, aggregateJobStatus(items.map((i) => i.status))]
    );
  }
  await pool.query(
    `DELETE FROM enrichment_jobs WHERE id IN (
       SELECT id FROM enrichment_jobs
       WHERE created_at < now() - make_interval(days => $1) LIMIT 5000)`,
    [ENRICHMENT_LIMITS.RETENTION_DAYS]
  );
}

// ---------------------------------------------------------------------------
// Read model
// ---------------------------------------------------------------------------

function itemView(row, coalescedStatus) {
  const view = {
    provider: row.provider,
    status: row.status,
    scope: row.target_scope || null,
    target_type: row.target_type || null,
    target_value: row.target_value || null,
    force_refresh: Boolean(row.force_refresh),
    last_enriched_at: toIso(row.last_enriched_at),
    started_at: toIso(row.started_at),
    finished_at: toIso(row.finished_at)
  };
  if (row.result) view.result = row.result;
  if (row.error_code) view.error_code = row.error_code;
  if (row.message) view.message = row.message;
  if (row.status === ITEM_STATUS.DEDUPLICATED) {
    view.coalesced_into_job_id = coalescedStatus?.job_id || null;
    view.coalesced_status = coalescedStatus?.status || null;
  }
  return view;
}

/**
 * Job view grouped by IOC. Returns null when the job does not exist or belongs
 * to another owner (no existence leak).
 */
export async function getEnrichmentJobView(pool, jobId, { ownerUserId = null } = {}) {
  if (!UUID_RE.test(String(jobId || ''))) return null;
  const { rows: jobs } = await pool.query('SELECT * FROM enrichment_jobs WHERE id = $1', [jobId]);
  const job = jobs[0];
  if (!job) return null;
  if (ownerUserId != null && Number(job.requested_by_user_id) !== Number(ownerUserId)) return null;
  const { rows: items } = await pool.query(
    `SELECT i.*, c.status AS coalesced_status, c.job_id AS coalesced_job_id
     FROM enrichment_job_items i
     LEFT JOIN enrichment_job_items c ON c.id = i.coalesced_into_item_id
     WHERE i.job_id = $1 ORDER BY i.id ASC`,
    [jobId]
  );
  return buildJobView(job, items);
}

export function buildJobView(job, items) {
  const byIoc = new Map();
  const summary = {};
  for (const row of items) {
    summary[row.status] = (summary[row.status] || 0) + 1;
    const key = String(row.ioc_public_id || row.ioc_id);
    if (!byIoc.has(key)) {
      byIoc.set(key, {
        ioc_id: row.ioc_public_id || null,
        ioc_numeric_id: row.ioc_id != null ? Number(row.ioc_id) : null,
        observable: row.observable,
        observable_type: row.observable_type,
        providers: []
      });
    }
    byIoc.get(key).providers.push(itemView(row, row.coalesced_status
      ? { status: row.coalesced_status, job_id: row.coalesced_job_id ? String(row.coalesced_job_id) : null }
      : null));
  }
  let requested = job.requested_providers;
  if (typeof requested === 'string') {
    try { requested = JSON.parse(requested); } catch { requested = []; }
  }
  return {
    job_id: String(job.id),
    status: job.status,
    origin: job.origin,
    force_refresh: Boolean(job.force_refresh),
    requested_providers: Array.isArray(requested) && requested.length === 1 && requested[0] === 'all' ? 'all' : (requested || []),
    created_at: toIso(job.created_at),
    started_at: toIso(job.started_at),
    finished_at: toIso(job.finished_at),
    summary,
    iocs: [...byIoc.values()]
  };
}

// ---------------------------------------------------------------------------
// One-call entry point for explicit triggers
// ---------------------------------------------------------------------------

/**
 * Plan, persist and schedule an enrichment job for already-authorized callers.
 * @returns {Promise<{ error?: { code, message }, view?: object, notApplicable?: object[], notFound?: string[] }>}
 */
export async function requestEnrichment(pool, {
  iocRefs,
  providers = 'all',
  force = false,
  actor = {},
  principal = null,
  mcpAuth = null,
  audit = null,
  providerAudit = null,
  requestId = null,
  clientIp = null,
  origin = 'mcp',
  maxIocs = ENRICHMENT_LIMITS.BULK_MAX_IOCS,
  maxOperations = ENRICHMENT_LIMITS.MAX_OPERATIONS,
  maxActiveJobs = ENRICHMENT_LIMITS.MAX_ACTIVE_JOBS_PER_KEY,
  auditFields = {}
}) {
  const refs = [...new Set((iocRefs || []).map((r) => String(r ?? '').trim()).filter(Boolean))];
  if (!refs.length) return { error: { code: 'VALIDATION_ERROR', message: 'At least one IOC id is required' } };
  if (refs.length > maxIocs) {
    return { error: { code: 'BATCH_TOO_LARGE', message: `At most ${maxIocs} IOCs per request; split the request into chunks` } };
  }
  if (providers !== 'all') {
    if (!Array.isArray(providers) || !providers.length) {
      return { error: { code: 'VALIDATION_ERROR', message: 'providers must be "all" or a non-empty list of provider ids' } };
    }
  }

  const { found, invalid } = await resolveEnrichmentIocs(pool, refs);
  const notFound = [...invalid, ...refs.filter((r) => !invalid.includes(r) && !found.has(r.toLowerCase()) && !found.has(r))];
  const iocs = [];
  const seenIds = new Set();
  for (const ioc of found.values()) {
    if (seenIds.has(ioc.id)) continue;
    seenIds.add(ioc.id);
    iocs.push(ioc);
  }
  if (!iocs.length) {
    return { error: { code: 'IOC_NOT_FOUND', message: 'No referenced IOC exists' }, notFound };
  }

  const { items, notApplicable } = await planEnrichment(pool, iocs, { providers, force });
  const operations = countOperations(items);
  if (operations > maxOperations) {
    return {
      error: {
        code: 'BATCH_TOO_LARGE',
        message: `Request needs ${operations} provider operations (max ${maxOperations}); reduce IOCs or providers`
      }
    };
  }
  if (operations > 0 && actor.apiKeyId != null) {
    const active = await countActiveJobsForKey(pool, actor.apiKeyId);
    if (active >= maxActiveJobs) {
      return {
        error: {
          code: 'TOO_MANY_ACTIVE_JOBS',
          message: `This credential already has ${active} active enrichment jobs (max ${maxActiveJobs}); poll get_enrichment_job and retry`
        }
      };
    }
  }

  const created = await createEnrichmentJob(pool, { items, providers, force, actor, origin, requestId });

  const requestedProviders = providers === 'all' ? 'all' : [...new Set(providers.map((p) => String(p).trim().toLowerCase()))];
  const auditMeta = {
    ...auditFields,
    origin,
    enrichment_job_id: created.jobId,
    requested_providers: requestedProviders,
    force_refresh: Boolean(force),
    ioc_count: iocs.length,
    operations,
    planned: created.items.reduce((acc, i) => { acc[i.status] = (acc[i.status] || 0) + 1; return acc; }, {}),
    providers_by_ioc: iocs.slice(0, 25).map((ioc) => ({
      ioc_id: ioc.public_id,
      observable: ioc.observable,
      providers: created.items.filter((i) => i.ioc.id === ioc.id).map((i) => `${i.provider}:${i.status}`)
    }))
  };
  const single = iocs.length === 1 ? iocs[0] : null;
  if (audit?.auditSuccess) {
    await audit.auditSuccess({
      action: AUDIT_ACTION.ENRICHMENT_JOB_REQUESTED,
      entityType: single ? AUDIT_ENTITY.IOC : AUDIT_ENTITY.ENRICHMENT,
      entityId: single ? single.public_id : created.jobId,
      entityDisplay: single ? single.observable : `${iocs.length} IOCs`,
      subjectIocId: single ? single.id : null,
      subjectIocType: single ? single.observable_type : null,
      subjectIocValue: single ? single.observable : null,
      severity: AUDIT_SEVERITY.INFO,
      metadata: auditMeta
    }).catch(() => {});
  }

  if (created.hasWork) {
    scheduleEnrichmentJob({
      pool,
      jobId: created.jobId,
      audit,
      providerAudit,
      principal,
      mcpAuth,
      requestId,
      clientIp,
      onFinished: audit?.auditSuccess
        ? ({ status, summary }) => (status === JOB_STATUS.FAILED ? audit.auditFailure : audit.auditSuccess)({
          action: AUDIT_ACTION.ENRICHMENT_JOB_COMPLETED,
          entityType: single ? AUDIT_ENTITY.IOC : AUDIT_ENTITY.ENRICHMENT,
          entityId: single ? single.public_id : created.jobId,
          entityDisplay: single ? single.observable : `${iocs.length} IOCs`,
          subjectIocId: single ? single.id : null,
          subjectIocType: single ? single.observable_type : null,
          subjectIocValue: single ? single.observable : null,
          severity: status === JOB_STATUS.COMPLETED ? AUDIT_SEVERITY.INFO : AUDIT_SEVERITY.WARNING,
          metadata: { ...auditFields, origin, enrichment_job_id: created.jobId, job_status: status, force_refresh: Boolean(force), summary }
        })
        : null
    });
  }

  const view = await getEnrichmentJobView(pool, created.jobId);
  return { view, notApplicable, notFound };
}

export const __test__ = { RUNNER_INSTANCE, pendingJobs, jobContexts };

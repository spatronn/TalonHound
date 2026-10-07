// In-memory stand-in for the SQL the enrichment orchestrator issues
// (ioc_items lookups, enrichment_jobs / enrichment_job_items). Pattern-matched on
// the statements in lib/enrichmentOrchestrator.js — tests fail loudly on any
// statement it does not recognise so query drift is caught.

import { randomUUID } from 'node:crypto';

const ACTIVE = new Set(['queued', 'running']);

export function createFakeEnrichmentPool({ iocs = [] } = {}) {
  const state = {
    iocs: iocs.map((r) => ({ ...r })),
    jobs: new Map(),
    items: [],
    nextItemId: 1,
    statements: [],
    /** advisory xact locks: key -> Promise resolved on release */
    locks: new Map()
  };

  function query(sqlRaw, params = []) {
    const sql = String(sqlRaw).replace(/\s+/g, ' ').trim();
    state.statements.push(sql);
    const res = (rows = [], rowCount = rows.length) => Promise.resolve({ rows, rowCount });

    if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK') return res();
    if (sql.startsWith('SELECT pg_advisory_xact_lock')) return res([{}]);

    if (sql.startsWith('SELECT id, public_id, observable, observable_type FROM ioc_items WHERE public_id = ANY')) {
      const wanted = new Set(params[0].map((x) => String(x).toLowerCase()));
      return res(state.iocs.filter((r) => wanted.has(String(r.public_id).toLowerCase())));
    }
    if (sql.startsWith('SELECT id, public_id, observable, observable_type FROM ioc_items WHERE id = $1')) {
      return res(state.iocs.filter((r) => Number(r.id) === Number(params[0])).slice(0, 1));
    }

    if (sql.startsWith('INSERT INTO enrichment_jobs')) {
      const id = randomUUID();
      const job = {
        id,
        origin: params[0],
        requested_by_user_id: params[1],
        api_key_id: params[2],
        requested_providers: JSON.parse(params[3]),
        force_refresh: params[4],
        status: 'queued',
        runner_instance: params[5],
        request_id: params[6],
        created_at: new Date(),
        started_at: null,
        finished_at: null
      };
      state.jobs.set(id, job);
      return res([{ id, created_at: job.created_at }]);
    }
    if (sql.startsWith('SELECT id, force_refresh FROM enrichment_job_items WHERE provider = $1 AND target_value = $2')) {
      const hit = state.items
        .filter((i) => i.provider === params[0] && i.target_value === params[1] && ACTIVE.has(i.status))
        .sort((a, b) => Number(b.force_refresh) - Number(a.force_refresh) || a.id - b.id)[0];
      return res(hit ? [{ id: hit.id, force_refresh: hit.force_refresh }] : []);
    }
    if (sql.startsWith('INSERT INTO enrichment_job_items')) {
      const id = state.nextItemId++;
      const [job_id, ioc_id, ioc_public_id, observable, observable_type, provider, target_scope, target_type,
        target_value, force_refresh, status, error_code, message, coalesced_into_item_id, last_enriched_at, result] = params;
      state.items.push({
        id, job_id, ioc_id, ioc_public_id, observable, observable_type, provider, target_scope, target_type,
        target_value, force_refresh, status, error_code, message, coalesced_into_item_id, last_enriched_at,
        result: result ?? null, started_at: null, finished_at: ACTIVE.has(status) ? null : new Date()
      });
      return res([{ id }]);
    }
    if (sql.startsWith('UPDATE enrichment_jobs SET status = $2, finished_at = now()')) {
      const job = state.jobs.get(params[0]);
      if (job) { job.status = params[1]; job.finished_at = new Date(); }
      return res([], job ? 1 : 0);
    }
    if (sql.startsWith("UPDATE enrichment_jobs SET status = 'running'")) {
      const job = state.jobs.get(params[0]);
      if (job && job.status === 'queued') { job.status = 'running'; job.started_at = new Date(); }
      return res();
    }
    if (sql.startsWith("SELECT * FROM enrichment_job_items WHERE job_id = $1 AND status = 'queued'")) {
      return res(state.items.filter((i) => i.job_id === params[0] && i.status === 'queued').map((i) => ({ ...i })));
    }
    if (sql.startsWith("UPDATE enrichment_job_items SET status = 'running'")) {
      const item = state.items.find((i) => i.id === Number(params[0]) && i.status === 'queued');
      if (!item) return res([], 0);
      item.status = 'running';
      item.started_at = new Date();
      return res([{ id: item.id }], 1);
    }
    if (sql.startsWith('UPDATE enrichment_job_items SET status = $2, result = $3')) {
      const item = state.items.find((i) => i.id === Number(params[0]));
      if (item) {
        item.status = params[1];
        item.result = params[2];
        item.error_code = params[3];
        item.message = params[4];
        if (params[5]) item.last_enriched_at = params[5];
        item.finished_at = ACTIVE.has(params[1]) ? null : new Date();
      }
      return res();
    }
    if (sql.startsWith('SELECT status, provider FROM enrichment_job_items WHERE job_id = $1')) {
      return res(state.items.filter((i) => i.job_id === params[0]).map((i) => ({ status: i.status, provider: i.provider })));
    }
    if (sql.startsWith('SELECT count(*)::int AS n FROM enrichment_jobs WHERE api_key_id = $1')) {
      const n = [...state.jobs.values()].filter((j) => j.api_key_id === params[0] && ACTIVE.has(j.status)).length;
      return res([{ n }]);
    }
    if (sql.startsWith('SELECT status FROM enrichment_jobs WHERE id = $1')) {
      const job = state.jobs.get(params[0]);
      return res(job ? [{ status: job.status }] : []);
    }
    if (sql.startsWith('SELECT * FROM enrichment_jobs WHERE id = $1')) {
      const job = state.jobs.get(params[0]);
      return res(job ? [{ ...job }] : []);
    }
    if (sql.startsWith('SELECT i.*, c.status AS coalesced_status')) {
      const rows = state.items.filter((i) => i.job_id === params[0]).map((i) => {
        const c = i.coalesced_into_item_id ? state.items.find((x) => x.id === i.coalesced_into_item_id) : null;
        return { ...i, coalesced_status: c?.status || null, coalesced_job_id: c?.job_id || null };
      });
      return res(rows);
    }
    throw new Error(`fakeEnrichmentPool: unrecognised SQL: ${sql.slice(0, 160)}`);
  }

  // Emulate pg_advisory_xact_lock: held until the owning client's COMMIT/ROLLBACK.
  function makeClient() {
    const held = [];
    const releaseAll = () => {
      for (const { key, release } of held.splice(0)) {
        state.locks.delete(key);
        release();
      }
    };
    return {
      async query(sqlRaw, params = []) {
        const sql = String(sqlRaw).replace(/\s+/g, ' ').trim();
        if (sql.startsWith('SELECT pg_advisory_xact_lock')) {
          const key = String(params[0]);
          while (state.locks.has(key)) await state.locks.get(key).promise;
          let release;
          const promise = new Promise((r) => { release = r; });
          state.locks.set(key, { promise });
          held.push({ key, release });
          state.statements.push(sql);
          return { rows: [{}], rowCount: 1 };
        }
        const out = await query(sqlRaw, params);
        if (sql === 'COMMIT' || sql === 'ROLLBACK') releaseAll();
        return out;
      },
      release() { releaseAll(); }
    };
  }

  return {
    query,
    connect: async () => makeClient(),
    state
  };
}

/** Resolve once the job leaves queued/running (fake pool), or throw after timeout. */
export async function waitForFakeJob(pool, jobId, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const job = pool.state.jobs.get(jobId);
    if (job && !ACTIVE.has(job.status)) return job;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(`job ${jobId} did not finish`);
}

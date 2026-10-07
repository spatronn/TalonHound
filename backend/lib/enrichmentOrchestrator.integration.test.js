import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {
  registerEnrichmentProvider,
  registerEnrichmentExecutor,
  getEnrichmentProvider
} from './enrichmentProviderRegistry.js';
import {
  requestEnrichment,
  getEnrichmentJobView,
  waitForEnrichmentJob,
  sweepEnrichmentJobs,
  countActiveJobsForKey
} from './enrichmentOrchestrator.js';

/**
 * Real-Postgres integration test for the enrichment job store (migration 037)
 * and the provider freshness hooks' SQL. Opt-in (ENRICHMENT_JOB_ITEST=1) because
 * it inserts IOC rows; run it only against a throwaway, migrated database —
 * never a live TalonHound database.
 */

const { Pool } = pg;
const enabled = process.env.ENRICHMENT_JOB_ITEST === '1';
const pool = enabled
  ? new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound',
    connectionTimeoutMillis: 3000,
    max: 6
  })
  : null;

let hasDb = false;
if (pool) {
  try {
    await pool.query('SELECT 1 FROM enrichment_jobs LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ENRICHMENT_JOB_ITEST=1 and DB_* for a migrated throwaway database' };

const calls = [];
let gate = null;
registerEnrichmentProvider({
  key: 'itest_ip',
  displayName: 'ITEST IP',
  external: true,
  supportedObservableTypes: ['ip'],
  loadState: async () => ({ enabled: true, configured: true }),
  resolveTarget: (ioc) => (ioc.observable_type === 'ip'
    ? { applicable: true, scope: 'direct', target_type: 'ip', target_value: ioc.observable }
    : { applicable: false, reason: 'unsupported_type' }),
  readFreshness: async () => ({ fresh: false, last_enriched_at: null }),
  automationRatePerMin: 1000
});
registerEnrichmentExecutor('itest_ip', async (ctx) => {
  calls.push(ctx.target.target_value);
  if (gate) await gate;
  return { status: 200, body: { status: 'success' } };
});

const created = [];
async function insertIoc(observable, type = 'ip') {
  const { rows } = await pool.query(
    `INSERT INTO ioc_items (observable, observable_type, source_name)
     VALUES ($1, $2, 'itest') RETURNING id, public_id`,
    [observable, type]
  );
  created.push({ id: rows[0].id, type });
  return { id: Number(rows[0].id), public_id: String(rows[0].public_id), observable, observable_type: type };
}

test.after(async () => {
  if (!hasDb) { await pool?.end().catch(() => {}); return; }
  await pool.query(`DELETE FROM enrichment_jobs WHERE origin = 'itest'`);
  for (const c of created) {
    await pool.query('DELETE FROM ioc_enrichments WHERE ioc_id = $1', [c.id]).catch(() => {});
    await pool.query('DELETE FROM ioc_items WHERE id = $1 AND observable_type = $2', [c.id, c.type]);
  }
  await pool.end();
});

test('job lifecycle on real Postgres: create → run → completed view', opts, async () => {
  calls.length = 0;
  const ioc = await insertIoc('203.0.113.10');
  const out = await requestEnrichment(pool, {
    iocRefs: [ioc.public_id], providers: ['itest_ip'], origin: 'itest', actor: { userId: null, apiKeyId: 900001 }
  });
  assert.ok(out.view.job_id);
  const status = await waitForEnrichmentJob(pool, out.view.job_id, 5000);
  assert.equal(status, 'completed');
  const view = await getEnrichmentJobView(pool, out.view.job_id);
  assert.equal(view.iocs[0].ioc_id, ioc.public_id);
  assert.equal(view.iocs[0].providers[0].status, 'completed');
  assert.ok(view.iocs[0].providers[0].finished_at);
  assert.deepEqual(calls, ['203.0.113.10']);
  // numeric id references resolve too
  const byId = await requestEnrichment(pool, { iocRefs: [String(ioc.id)], providers: ['itest_ip'], origin: 'itest' });
  assert.equal(byId.view.iocs[0].ioc_id, ioc.public_id);
  await waitForEnrichmentJob(pool, byId.view.job_id, 5000);
});

test('advisory-lock dedupe across concurrent requests (real transactions)', opts, async () => {
  calls.length = 0;
  const ioc = await insertIoc('203.0.113.11');
  let release;
  gate = new Promise((r) => { release = r; });
  const outs = await Promise.all(Array.from({ length: 4 }, (_, i) => requestEnrichment(pool, {
    iocRefs: [ioc.public_id], providers: ['itest_ip'], origin: 'itest', actor: { apiKeyId: 900010 + i }
  })));
  const statuses = outs.map((o) => o.view.iocs[0].providers[0].status).sort();
  assert.deepEqual(statuses.filter((s) => s === 'deduplicated').length, 3, statuses.join(','));
  // Only the job that owns the in-flight operation is active; coalesced jobs are done.
  const owner = outs.findIndex((o) => o.view.iocs[0].providers[0].status !== 'deduplicated');
  assert.equal(await countActiveJobsForKey(pool, 900010 + owner), 1);
  for (let i = 0; i < outs.length; i += 1) {
    if (i !== owner) assert.equal(await countActiveJobsForKey(pool, 900010 + i), 0);
  }
  release();
  gate = null;
  for (const o of outs) await waitForEnrichmentJob(pool, o.view.job_id, 5000);
  assert.equal(calls.length, 1);
});

test('sweep closes jobs left active by another runner instance', opts, async () => {
  const ioc = await insertIoc('203.0.113.12');
  const { rows } = await pool.query(
    `INSERT INTO enrichment_jobs (origin, requested_providers, status, runner_instance)
     VALUES ('itest', '["itest_ip"]', 'running', 'dead-instance') RETURNING id`
  );
  await pool.query(
    `INSERT INTO enrichment_job_items (job_id, ioc_id, ioc_public_id, observable, observable_type, provider, target_value, status)
     VALUES ($1, $2, $3, $4, 'ip', 'itest_ip', $4, 'running')`,
    [rows[0].id, ioc.id, ioc.public_id, ioc.observable]
  );
  await sweepEnrichmentJobs(pool);
  const view = await getEnrichmentJobView(pool, rows[0].id);
  assert.equal(view.status, 'failed');
  assert.equal(view.iocs[0].providers[0].status, 'interrupted');
});

test('real provider freshness hooks run against the real provider tables', opts, async () => {
  const ip = await insertIoc('198.51.100.7');
  const dom = await insertIoc('itest-example.org', 'domain');
  const hash = await insertIoc('8588d11874ab52a1637953dc5538984647023d00b529f695fbd0e40cf8e5e852', 'sha256');
  for (const [key, ioc] of [['ipinfo_lite', ip], ['abuseipdb', ip], ['spamhaus_drop', ip], ['rdap', dom], ['virustotal', hash]]) {
    const entry = getEnrichmentProvider(key);
    const target = entry.resolveTarget(ioc);
    assert.equal(target.applicable, true, key);
    const fresh = await entry.readFreshness(pool, target, ioc);
    assert.equal(fresh.fresh, false, `${key} has no stored result yet`);
  }
  // VirusTotal: an unexpired stored result is fresh; an expired one is not.
  const vt = getEnrichmentProvider('virustotal');
  await pool.query(
    `INSERT INTO ioc_enrichments (ioc_id, ioc_value, ioc_type, provider, status, fetched_at, expires_at, updated_at)
     VALUES ($1, $2, 'hash', 'virustotal', 'success', now(), now() + interval '1 hour', now())`,
    [hash.id, hash.observable]
  );
  const t = vt.resolveTarget(hash);
  assert.equal((await vt.readFreshness(pool, t, hash)).fresh, true);
  await pool.query(`UPDATE ioc_enrichments SET expires_at = now() - interval '1 minute' WHERE ioc_id = $1`, [hash.id]);
  assert.equal((await vt.readFreshness(pool, t, hash)).fresh, false);
});

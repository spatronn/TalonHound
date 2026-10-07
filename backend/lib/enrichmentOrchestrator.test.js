import test from 'node:test';
import assert from 'node:assert/strict';
import {
  registerEnrichmentProvider,
  registerEnrichmentExecutor,
  getEnrichmentProvider
} from './enrichmentProviderRegistry.js';
import {
  requestEnrichment,
  classifyExecutorOutcome,
  aggregateJobStatus,
  describeEnrichmentProviders,
  getEnrichmentJobView,
  ITEM_STATUS
} from './enrichmentOrchestrator.js';
import { noteProviderRateLimited, resetEnrichmentProviderGuardForTests } from './enrichmentProviderGuard.js';
import { AUDIT_ACTION } from './auditConstants.js';
import { createFakeEnrichmentPool, waitForFakeJob } from './fixtures/fakeEnrichmentPool.js';

// ---------------------------------------------------------------------------
// Test providers (registered through the same registry API as real providers).
// Real providers have no executor in this process (their route modules are not
// loaded), so `providers: "all"` only reaches these.
// ---------------------------------------------------------------------------

const calls = [];
const behaviour = new Map(); // provider -> (ctx) => { status, body }
const freshness = new Map(); // `${provider}:${target}` -> boolean
const providerEnabled = new Map();

function testProvider(key, types, { external = true } = {}) {
  registerEnrichmentProvider({
    key,
    displayName: key.toUpperCase(),
    external,
    supportedObservableTypes: types,
    loadState: async () => ({
      enabled: providerEnabled.get(key) !== false,
      configured: true,
      // A secret-shaped field a careless serializer could leak.
      apiKey: 'sk-test-SECRET-should-never-leak'
    }),
    resolveTarget: (ioc) => (types.includes(ioc.observable_type)
      ? { applicable: true, scope: 'direct', target_type: ioc.observable_type, target_value: ioc.observable }
      : { applicable: false, reason: 'unsupported_type' }),
    readFreshness: async (_pool, target) => ({
      fresh: freshness.get(`${key}:${target.target_value}`) === true,
      last_enriched_at: freshness.get(`${key}:${target.target_value}`) ? '2026-10-07T10:00:00.000Z' : null
    }),
    automationRatePerMin: 1000
  });
  registerEnrichmentExecutor(key, async (ctx) => {
    calls.push({ provider: key, target: ctx.target.target_value, force: ctx.force, req: ctx.req, audit: ctx.audit });
    const fn = behaviour.get(key);
    return fn ? fn(ctx) : { status: 200, body: { status: 'success' } };
  });
}

testProvider('t_ipa', ['ip']);
testProvider('t_ipb', ['ip']);
testProvider('t_dom', ['domain']);
testProvider('t_off', ['ip']);

const IOC_IP = { id: 11, public_id: '11111111-1111-4111-8111-111111111111', observable: '8.8.8.8', observable_type: 'ip' };
const IOC_IP2 = { id: 12, public_id: '22222222-2222-4222-8222-222222222222', observable: '1.1.1.1', observable_type: 'ip' };
const IOC_DOM = { id: 13, public_id: '33333333-3333-4333-8333-333333333333', observable: 'example.org', observable_type: 'domain' };

function reset() {
  calls.length = 0;
  behaviour.clear();
  freshness.clear();
  providerEnabled.clear();
  providerEnabled.set('t_off', false);
  resetEnrichmentProviderGuardForTests();
}

function pool() {
  return createFakeEnrichmentPool({ iocs: [IOC_IP, IOC_IP2, IOC_DOM] });
}

function providersOf(view) {
  return Object.fromEntries((view.iocs[0]?.providers || []).map((p) => [p.provider, p]));
}

async function run(p, opts) {
  const out = await requestEnrichment(p, { actor: { userId: 7, apiKeyId: 99 }, ...opts });
  if (out.error) return out;
  if (['queued', 'running'].includes(out.view.status)) await waitForFakeJob(p, out.view.job_id);
  await new Promise((r) => setImmediate(r));
  out.final = await getEnrichmentJobView(p, out.view.job_id);
  return out;
}

test('single explicit provider: only that provider executes', async () => {
  reset();
  const p = pool();
  const out = await run(p, { iocRefs: [IOC_IP.public_id], providers: ['t_ipa'] });
  assert.equal(out.final.status, 'completed');
  assert.deepEqual(calls.map((c) => c.provider), ['t_ipa']);
  assert.equal(providersOf(out.final).t_ipa.status, ITEM_STATUS.COMPLETED);
});

test('providers=all runs every enabled applicable provider; inapplicable listed, disabled reported', async () => {
  reset();
  const p = pool();
  const out = await run(p, { iocRefs: [IOC_IP.public_id], providers: 'all' });
  assert.deepEqual(calls.map((c) => c.provider).sort(), ['t_ipa', 't_ipb']);
  const byProvider = providersOf(out.final);
  assert.equal(byProvider.t_off.status, ITEM_STATUS.PROVIDER_UNAVAILABLE);
  assert.equal(byProvider.t_off.error_code, 'provider_disabled');
  assert.equal(byProvider.t_dom, undefined, 'domain-only provider is not an item for an IP IOC');
  assert.ok(out.notApplicable.some((n) => n.provider === 't_dom' && n.reason === 'unsupported_type'));
  // A disabled provider under "all" makes the job partial, never a silent success.
  assert.equal(out.final.status, 'partially_completed');
});

test('applicability comes from the IOC TalonHound resolved, not the caller: unsupported → no external call', async () => {
  reset();
  const p = pool();
  const out = await run(p, { iocRefs: [IOC_DOM.public_id], providers: ['t_ipa'] });
  assert.equal(calls.length, 0);
  assert.equal(providersOf(out.final).t_ipa.status, ITEM_STATUS.UNSUPPORTED);
  assert.equal(out.final.status, 'failed');
});

test('unknown provider id is a structured item, not an exception', async () => {
  reset();
  const out = await run(pool(), { iocRefs: [IOC_IP.public_id], providers: ['no_such_provider'] });
  assert.equal(providersOf(out.final).no_such_provider.status, ITEM_STATUS.UNKNOWN_PROVIDER);
  assert.equal(calls.length, 0);
});

test('freshness: fresh + force_refresh=false skips the external call', async () => {
  reset();
  freshness.set('t_ipa:8.8.8.8', true);
  const out = await run(pool(), { iocRefs: [IOC_IP.public_id], providers: ['t_ipa'] });
  assert.equal(calls.length, 0);
  const item = providersOf(out.final).t_ipa;
  assert.equal(item.status, ITEM_STATUS.SKIPPED_FRESH);
  assert.equal(item.last_enriched_at, '2026-10-07T10:00:00.000Z');
  assert.equal(out.final.status, 'completed');
});

test('freshness: fresh + force_refresh=true refreshes with force passed to the provider', async () => {
  reset();
  freshness.set('t_ipa:8.8.8.8', true);
  const out = await run(pool(), { iocRefs: [IOC_IP.public_id], providers: ['t_ipa'], force: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].force, true);
  assert.equal(providersOf(out.final).t_ipa.status, ITEM_STATUS.COMPLETED);
});

test('partial failure: one provider fails, the other result stands and the job is partial', async () => {
  reset();
  behaviour.set('t_ipb', () => ({ status: 502, body: { error: 'upstream exploded' } }));
  const out = await run(pool(), { iocRefs: [IOC_IP.public_id], providers: ['t_ipa', 't_ipb'] });
  const byProvider = providersOf(out.final);
  assert.equal(byProvider.t_ipa.status, ITEM_STATUS.COMPLETED);
  assert.equal(byProvider.t_ipb.status, ITEM_STATUS.FAILED);
  assert.equal(byProvider.t_ipb.error_code, 'provider_error');
  assert.equal(out.final.status, 'partially_completed');
});

test('provider 429 → rate_limited; recorded cooldown blocks the next automated call without spending quota', async () => {
  reset();
  behaviour.set('t_ipa', () => ({ status: 429, body: { message: 'slow down', retry_after: 30 } }));
  const first = await run(pool(), { iocRefs: [IOC_IP.public_id], providers: ['t_ipa'] });
  assert.equal(providersOf(first.final).t_ipa.status, ITEM_STATUS.RATE_LIMITED);
  assert.equal(providersOf(first.final).t_ipa.error_code, 'provider_rate_limited');

  // The shared refresh functions note 429s; emulate that here.
  noteProviderRateLimited('t_ipa', 30);
  calls.length = 0;
  const second = await run(pool(), { iocRefs: [IOC_IP2.public_id], providers: ['t_ipa'] });
  assert.equal(calls.length, 0);
  assert.equal(providersOf(second.final).t_ipa.error_code, 'provider_cooldown');
});

test('batch limits: too many IOCs and too many provider operations are rejected before any work', async () => {
  reset();
  const p = pool();
  const tooMany = await requestEnrichment(p, {
    iocRefs: [IOC_IP.public_id, IOC_IP2.public_id, IOC_DOM.public_id],
    providers: 'all',
    maxIocs: 2
  });
  assert.equal(tooMany.error.code, 'BATCH_TOO_LARGE');

  const tooManyOps = await requestEnrichment(p, {
    iocRefs: [IOC_IP.public_id, IOC_IP2.public_id],
    providers: ['t_ipa', 't_ipb'],
    maxOperations: 3
  });
  assert.equal(tooManyOps.error.code, 'BATCH_TOO_LARGE');
  assert.match(tooManyOps.error.message, /4 provider operations/);
  assert.equal(p.state.jobs.size, 0, 'rejected requests persist nothing');
  assert.equal(calls.length, 0);
});

test('active job cap per API key', async () => {
  reset();
  const p = pool();
  // Keep the first job's provider busy so it stays active.
  let release;
  behaviour.set('t_ipa', () => new Promise((r) => { release = () => r({ status: 200, body: {} }); }));
  const first = await requestEnrichment(p, { iocRefs: [IOC_IP.public_id], providers: ['t_ipa'], actor: { apiKeyId: 5 }, maxActiveJobs: 1 });
  assert.ok(first.view.job_id);
  const second = await requestEnrichment(p, { iocRefs: [IOC_IP2.public_id], providers: ['t_ipa'], actor: { apiKeyId: 5 }, maxActiveJobs: 1 });
  assert.equal(second.error.code, 'TOO_MANY_ACTIVE_JOBS');
  while (!release) await new Promise((r) => setImmediate(r));
  release();
  await waitForFakeJob(p, first.view.job_id);
});

test('dedupe: concurrent identical requests coalesce onto one provider operation', async () => {
  reset();
  const p = pool();
  const [a, b] = await Promise.all([
    requestEnrichment(p, { iocRefs: [IOC_IP.public_id], providers: ['t_ipa'], actor: { apiKeyId: 1 } }),
    requestEnrichment(p, { iocRefs: [IOC_IP.public_id], providers: ['t_ipa'], actor: { apiKeyId: 2 } })
  ]);
  const statuses = [providersOf(a.view).t_ipa.status, providersOf(b.view).t_ipa.status].sort();
  assert.deepEqual(statuses, [ITEM_STATUS.DEDUPLICATED, ITEM_STATUS.QUEUED]);
  for (const out of [a, b]) {
    if (['queued', 'running'].includes(out.view.status)) await waitForFakeJob(p, out.view.job_id);
  }
  assert.equal(calls.length, 1, 'one provider call for two requests');
  const dup = [a, b].find((o) => providersOf(o.view).t_ipa.status === ITEM_STATUS.DEDUPLICATED);
  const view = await getEnrichmentJobView(p, dup.view.job_id);
  assert.equal(providersOf(view).t_ipa.coalesced_status, ITEM_STATUS.COMPLETED);
  assert.equal(view.status, 'completed');
});

test('dedupe never swallows an explicit force refresh behind a non-forced in-flight request', async () => {
  reset();
  const p = pool();
  // Non-forced request first and still in flight → the forced one must run itself.
  const a = await requestEnrichment(p, { iocRefs: [IOC_IP.public_id], providers: ['t_ipa'] });
  const b = await requestEnrichment(p, { iocRefs: [IOC_IP.public_id], providers: ['t_ipa'], force: true });
  assert.equal(providersOf(a.view).t_ipa.status, ITEM_STATUS.QUEUED);
  assert.equal(providersOf(b.view).t_ipa.status, ITEM_STATUS.QUEUED);
  await waitForFakeJob(p, a.view.job_id);
  await waitForFakeJob(p, b.view.job_id);
  assert.equal(calls.filter((c) => c.force).length, 1);

  // Forced request in flight → a later non-forced request may join it.
  calls.length = 0;
  const c = await requestEnrichment(p, { iocRefs: [IOC_IP2.public_id], providers: ['t_ipa'], force: true });
  const d = await requestEnrichment(p, { iocRefs: [IOC_IP2.public_id], providers: ['t_ipa'] });
  assert.equal(providersOf(d.view).t_ipa.status, ITEM_STATUS.DEDUPLICATED);
  await waitForFakeJob(p, c.view.job_id);
  assert.equal(calls.length, 1);
});

test('same lookup target across IOCs in one request is executed once', async () => {
  reset();
  const p = createFakeEnrichmentPool({
    iocs: [IOC_IP, { ...IOC_IP2, observable: '8.8.8.8', id: 14, public_id: '44444444-4444-4444-8444-444444444444' }]
  });
  const out = await run(p, { iocRefs: [IOC_IP.public_id, '44444444-4444-4444-8444-444444444444'], providers: ['t_ipa'] });
  assert.equal(calls.length, 1);
  assert.equal(out.final.summary.deduplicated, 1);
});

test('missing / malformed IOC references are reported, never guessed', async () => {
  reset();
  const out = await requestEnrichment(pool(), {
    iocRefs: ['55555555-5555-4555-8555-555555555555', 'http://evil.example/'],
    providers: ['t_ipa']
  });
  assert.equal(out.error.code, 'IOC_NOT_FOUND');
  assert.deepEqual(out.notFound.sort(), ['55555555-5555-4555-8555-555555555555', 'http://evil.example/'].sort());
  assert.equal(calls.length, 0);
});

test('audit: one parent request event + one completion event with origin, job id and force flag', async () => {
  reset();
  const events = [];
  const audit = {
    auditSuccess: async (e) => { events.push({ ok: true, ...e }); },
    auditFailure: async (e) => { events.push({ ok: false, ...e }); }
  };
  const p = pool();
  const out = await run(p, { iocRefs: [IOC_IP.public_id], providers: ['t_ipa'], audit, providerAudit: audit, origin: 'mcp' });
  // completion hook runs right after the status flip
  await new Promise((r) => setTimeout(r, 10));
  const requested = events.filter((e) => e.action === AUDIT_ACTION.ENRICHMENT_JOB_REQUESTED);
  const completed = events.filter((e) => e.action === AUDIT_ACTION.ENRICHMENT_JOB_COMPLETED);
  assert.equal(requested.length, 1);
  assert.equal(completed.length, 1);
  assert.equal(requested[0].metadata.origin, 'mcp');
  assert.equal(requested[0].metadata.enrichment_job_id, out.view.job_id);
  assert.equal(requested[0].metadata.force_refresh, false);
  assert.equal(requested[0].entityId, IOC_IP.public_id);
  assert.equal(completed[0].metadata.job_status, 'completed');
  // Provider executors receive the provenance-stamping audit + an MCP principal request.
  assert.equal(calls[0].audit, audit);
  assert.equal(calls[0].req.authVia, 'mcp');
  assert.equal(calls[0].req.body.ioc_id, IOC_IP.public_id);
});

test('provider discovery exposes capability booleans only — never secrets', async () => {
  reset();
  const list = await describeEnrichmentProviders(pool());
  const json = JSON.stringify(list);
  assert.doesNotMatch(json, /SECRET/);
  assert.doesNotMatch(json, /api_?key|token/i);
  const ipa = list.find((p) => p.id === 't_ipa');
  assert.deepEqual(ipa.supported_observable_types, ['ip']);
  assert.equal(ipa.available, true);
  const off = list.find((p) => p.id === 't_off');
  assert.equal(off.enabled, false);
  assert.equal(off.available, false);
  // Real registry providers are listed but not triggerable without their executors.
  const vt = list.find((p) => p.id === 'virustotal');
  assert.ok(vt);
  assert.equal(vt.triggerable, false);
});

test('classifyExecutorOutcome maps the shared route vocabulary generically', () => {
  assert.equal(classifyExecutorOutcome({ status: 200, body: { status: 'success' } }).status, 'completed');
  assert.equal(classifyExecutorOutcome({ status: 200, body: { status: 'not_found' } }).result, 'not_found');
  assert.equal(classifyExecutorOutcome({ status: 200, body: { cached: true } }).status, 'skipped_fresh');
  assert.equal(classifyExecutorOutcome({ status: 200, body: { status: 'dataset_not_synced' } }).status, 'provider_unavailable');
  assert.equal(classifyExecutorOutcome({ status: 200, body: { status: 'not_applicable' } }).status, 'unsupported');
  assert.equal(classifyExecutorOutcome({ status: 404, body: { enriched: false, provider_status: 'unavailable' } }).status, 'completed');
  assert.equal(classifyExecutorOutcome({ status: 409, body: { provider_status: 'not_configured' } }).error_code, 'provider_not_configured');
  assert.equal(classifyExecutorOutcome({ status: 403, body: {} }).status, 'forbidden');
  assert.equal(classifyExecutorOutcome({ status: 400, body: { status: 'api_key_missing' } }).error_code, 'provider_api_key_missing');
  assert.equal(classifyExecutorOutcome({ status: 422, body: {} }).status, 'unsupported');
  assert.equal(classifyExecutorOutcome({ status: 429, body: { retry_after: 9 } }).retry_after, 9);
  assert.equal(classifyExecutorOutcome({ status: 504, body: {} }).error_code, 'provider_timeout');
  assert.equal(classifyExecutorOutcome({ status: 500, body: {} }).status, 'failed');
  const long = classifyExecutorOutcome({ status: 502, body: { message: 'x'.repeat(5000) } });
  assert.ok(long.message.length <= 300);
});

test('aggregateJobStatus', () => {
  assert.equal(aggregateJobStatus(['completed', 'skipped_fresh']), 'completed');
  assert.equal(aggregateJobStatus(['completed', 'failed']), 'partially_completed');
  assert.equal(aggregateJobStatus(['failed', 'rate_limited']), 'failed');
  assert.equal(aggregateJobStatus(['deduplicated']), 'completed');
  assert.equal(aggregateJobStatus(['queued', 'queued']), 'queued');
  assert.equal(aggregateJobStatus(['completed', 'queued']), 'running');
});

test('job view is owner-scoped (no existence leak to other owners)', async () => {
  reset();
  const p = pool();
  const out = await run(p, { iocRefs: [IOC_IP.public_id], providers: ['t_ipa'], actor: { userId: 7, apiKeyId: 1 } });
  assert.ok(await getEnrichmentJobView(p, out.view.job_id, { ownerUserId: 7 }));
  assert.equal(await getEnrichmentJobView(p, out.view.job_id, { ownerUserId: 8 }), null);
  assert.equal(await getEnrichmentJobView(p, 'not-a-uuid', { ownerUserId: 7 }), null);
});

test('registry: test providers did not displace the real provider entries', () => {
  for (const key of ['virustotal', 'ipinfo_lite', 'abuseipdb', 'rdap', 'spamhaus_drop']) {
    assert.ok(getEnrichmentProvider(key), key);
  }
});

test('a stored *failed* result inside the provider cache window is reported honestly, not as "fresh"', async () => {
  reset();
  registerEnrichmentProvider({
    key: 't_failcache',
    displayName: 'FAILCACHE',
    external: true,
    supportedObservableTypes: ['ip'],
    loadState: async () => ({ enabled: true, configured: true }),
    resolveTarget: (ioc) => ({ applicable: true, scope: 'direct', target_type: 'ip', target_value: ioc.observable }),
    readFreshness: async () => ({ fresh: true, stored_status: 'failed', last_enriched_at: '2026-10-07T09:00:00.000Z' }),
    automationRatePerMin: 1000
  });
  registerEnrichmentExecutor('t_failcache', async () => { calls.push({ provider: 't_failcache' }); return { status: 200, body: {} }; });
  const out = await run(pool(), { iocRefs: [IOC_IP.public_id], providers: ['t_failcache'] });
  const item = providersOf(out.final).t_failcache;
  assert.equal(item.status, ITEM_STATUS.SKIPPED_FRESH);
  assert.equal(item.result, 'failed');
  assert.match(item.message, /force_refresh/);
  assert.equal(calls.length, 0);
});

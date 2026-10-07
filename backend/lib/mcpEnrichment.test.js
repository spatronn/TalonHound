import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { authorizeMcpTool, effectiveMcpCapabilities, MCP_TOOL_SCOPES } from './mcpPermissions.js';
import { scopesForAccessProfile, API_SCOPE } from './apiKeyProfiles.js';
import { registerMcpTools } from './mcpTools.js';
import {
  listEnrichmentProviders,
  getEnrichmentProvider,
  registerEnrichmentExecutor,
  resetEnrichmentExecutorsForTests
} from './enrichmentProviderRegistry.js';
import { mcpEnrichIocs } from './mcpEnrichmentService.js';
import { AUDIT_ACTION } from './auditConstants.js';
import { createFakeEnrichmentPool, waitForFakeJob } from './fixtures/fakeEnrichmentPool.js';
import { resetEnrichmentProviderGuardForTests } from './enrichmentProviderGuard.js';

const here = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Authorization: mcp:enrichment:write is its own capability
// ---------------------------------------------------------------------------

test('MCP Read credential cannot trigger enrichment or import', () => {
  const scopes = scopesForAccessProfile('mcp_read');
  for (const tool of ['enrich_ioc', 'bulk_enrich_iocs']) {
    const gate = authorizeMcpTool(tool, { scopes, ownerRole: 'admin' });
    assert.equal(gate.ok, false, tool);
    assert.equal(gate.code, 'MISSING_SCOPE');
    assert.match(gate.message, /mcp:enrichment:write/);
  }
  assert.equal(authorizeMcpTool('import_iocs', { scopes, ownerRole: 'admin' }).code, 'MISSING_SCOPE');
  // Read-side enrichment tools stay available to read credentials.
  assert.equal(authorizeMcpTool('list_enrichment_providers', { scopes, ownerRole: 'readonly' }).ok, true);
  assert.equal(authorizeMcpTool('get_enrichment_job', { scopes, ownerRole: 'readonly' }).ok, true);
});

test('MCP Analyst profile bundles import + enrichment + tags on top of read (granular scopes kept)', () => {
  const scopes = scopesForAccessProfile('mcp_analyst');
  assert.deepEqual([...scopes].sort(), [
    API_SCOPE.MCP_ENRICHMENT_READ,
    API_SCOPE.MCP_ENRICHMENT_WRITE,
    API_SCOPE.MCP_IOC_CREATE,
    API_SCOPE.MCP_IOC_READ,
    API_SCOPE.MCP_SOURCES_READ,
    API_SCOPE.MCP_TAGS_WRITE
  ].sort());
  // Every MCP tool is available to an analyst-owned MCP Analyst key — through
  // each tool's own scope check, not a profile-name check.
  for (const tool of Object.keys(MCP_TOOL_SCOPES)) {
    assert.equal(authorizeMcpTool(tool, { scopes, ownerRole: 'analyst' }).ok, true, tool);
  }
});

test('the enrichment scopes still gate the action tools on their own (no profile coupling)', () => {
  const withoutWrite = scopesForAccessProfile('mcp_analyst').filter((s) => s !== API_SCOPE.MCP_ENRICHMENT_WRITE);
  const gate = authorizeMcpTool('enrich_ioc', { scopes: withoutWrite, ownerRole: 'admin' });
  assert.equal(gate.code, 'MISSING_SCOPE');
  assert.match(gate.message, /mcp:enrichment:write/);
  // Import keeps working for such a (pre-backfill) key.
  assert.equal(authorizeMcpTool('import_iocs', { scopes: withoutWrite, ownerRole: 'analyst' }).ok, true);
  // Granular grant still works without any profile.
  assert.equal(authorizeMcpTool('enrich_ioc', { scopes: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_ENRICHMENT_WRITE], ownerRole: 'analyst' }).ok, true);
  assert.equal(authorizeMcpTool('enrich_ioc', { scopes: [API_SCOPE.MCP_ENRICHMENT_WRITE], ownerRole: 'admin' }).code, 'MISSING_SCOPE');
});

test('a token never elevates a readonly owner: MCP Analyst key owned by readonly cannot enrich or import', () => {
  const scopes = scopesForAccessProfile('mcp_analyst');
  for (const tool of ['enrich_ioc', 'bulk_enrich_iocs', 'import_iocs']) {
    const gate = authorizeMcpTool(tool, { scopes, ownerRole: 'readonly' });
    assert.equal(gate.ok, false, tool);
    assert.equal(gate.code, 'RBAC_DENIED', tool);
  }
  assert.equal(effectiveMcpCapabilities({ scopes, ownerRole: 'readonly' }).enrichment_write, false);
  // Reads stay available.
  assert.equal(authorizeMcpTool('get_ioc_context', { scopes, ownerRole: 'readonly' }).ok, true);
});

test('only MCP Analyst carries the enrichment write scope', () => {
  assert.ok(scopesForAccessProfile('mcp_analyst').includes(API_SCOPE.MCP_ENRICHMENT_WRITE));
  for (const profile of ['mcp_read', 'ioc_management', 'ioc_read', 'published_feed', 'feed_access']) {
    assert.ok(!scopesForAccessProfile(profile).includes(API_SCOPE.MCP_ENRICHMENT_WRITE), profile);
  }
});

test('MCP Enrichment is not a profile any more', () => {
  assert.equal(scopesForAccessProfile('mcp_' + 'enrichment').length, 0);
});

// ---------------------------------------------------------------------------
// Tool registration + side-effect semantics in descriptions
// ---------------------------------------------------------------------------

function captureTools() {
  const tools = new Map();
  registerMcpTools({
    registerTool(name, def, handler) { tools.set(name, { def, handler }); }
  }, { pool: { query: async () => ({ rows: [] }) }, getRequestContext: () => ({ req: null }) });
  return tools;
}

test('every registered tool is scope-gated and enrichment tools are registered', () => {
  const tools = captureTools();
  for (const name of tools.keys()) assert.ok(MCP_TOOL_SCOPES[name], `${name} must be in MCP_TOOL_SCOPES`);
  for (const name of ['list_enrichment_providers', 'enrich_ioc', 'bulk_enrich_iocs', 'get_enrichment_job']) {
    assert.ok(tools.has(name), name);
  }
});

test('read tools say they never trigger enrichment; action tools say they do and cost quota', () => {
  const tools = captureTools();
  const readTools = ['lookup_ioc', 'search_iocs', 'get_ioc_context', 'get_threat_report', 'bulk_lookup_iocs',
    'list_ioc_sources', 'list_enrichment_providers', 'get_enrichment_job'];
  for (const name of readTools) {
    const { def } = tools.get(name);
    assert.equal(def.annotations.readOnlyHint, true, name);
    assert.match(def.description, /never triggers? (external\/paid )?enrichment|NEVER triggers external\/paid enrichment/i, name);
  }
  for (const name of ['enrich_ioc', 'bulk_enrich_iocs']) {
    const { def } = tools.get(name);
    assert.equal(def.annotations.readOnlyHint, false, name);
    assert.equal(def.annotations.openWorldHint, true, name);
    assert.match(def.description, /^ACTION:/, name);
    assert.match(def.description, /quota/i, name);
    assert.match(def.description, /mcp:enrichment:write/, name);
  }
});

test('enrichment tool inputs accept IOC ids and provider ids only — no URLs, endpoints or credentials', () => {
  const tools = captureTools();
  for (const name of ['enrich_ioc', 'bulk_enrich_iocs']) {
    const keys = Object.keys(tools.get(name).def.inputSchema).sort();
    assert.deepEqual(keys, name === 'enrich_ioc'
      ? ['force_refresh', 'ioc_id', 'providers', 'wait_seconds']
      : ['force_refresh', 'ioc_ids', 'providers', 'wait_seconds']);
  }
});

// ---------------------------------------------------------------------------
// Read purity: read tools never reach a provider executor
// ---------------------------------------------------------------------------

test('read tools never invoke an enrichment executor', async () => {
  resetEnrichmentExecutorsForTests();
  const invoked = [];
  for (const p of listEnrichmentProviders()) {
    registerEnrichmentExecutor(p.key, async () => { invoked.push(p.key); return { status: 200, body: {} }; });
  }
  const ioc = { id: 1, public_id: '11111111-1111-4111-8111-111111111111', observable: '8.8.8.8', observable_type: 'ip' };
  // Permissive pool: the IOC exists for any lookup; everything else is empty.
  const pool = {
    query: async (sql) => (/FROM ioc_items/i.test(String(sql)) ? { rows: [ioc], rowCount: 1 } : { rows: [], rowCount: 0 })
  };
  const req = {
    user: { id: 1, role: 'admin', username: 'a' },
    mcpAuth: { scopes: scopesForAccessProfile('mcp_analyst'), ownerRole: 'admin', apiKeyId: 1 }
  };
  const tools = new Map();
  registerMcpTools({ registerTool(name, def, handler) { tools.set(name, handler); } }, { pool, getRequestContext: () => ({ req }) });
  const calls = {
    lookup_ioc: { value: '8.8.8.8' },
    search_iocs: { query: '8.8.8.8' },
    get_ioc_context: { id: ioc.public_id },
    bulk_lookup_iocs: { iocs: ['8.8.8.8', 'example.org'] },
    get_threat_report: { id: '22222222-2222-4222-8222-222222222222' },
    list_ioc_sources: {},
    list_enrichment_providers: {},
    get_enrichment_job: { job_id: '33333333-3333-4333-8333-333333333333' }
  };
  for (const [name, args] of Object.entries(calls)) {
    await tools.get(name)(args);
  }
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(invoked, []);
  resetEnrichmentExecutorsForTests();
});

test('read-side modules do not import the enrichment executor / orchestrator', () => {
  for (const file of ['mcpIocService.js', 'iocEnrichmentAggregator.js', 'threatLibrary/mcpThreatReport.js', 'apiIocReadService.js']) {
    const src = readFileSync(path.join(here, file), 'utf8');
    assert.doesNotMatch(src, /enrichmentOrchestrator|getEnrichmentExecutor|registerEnrichmentExecutor|runVirusTotalRefresh/, file);
  }
});

// ---------------------------------------------------------------------------
// Registry: provider applicability mirrors the IOC Details UI matrix
// ---------------------------------------------------------------------------

function applies(key, observable, observable_type) {
  return getEnrichmentProvider(key).resolveTarget({ observable, observable_type });
}

test('provider applicability matrix (direct + URL-host derived)', () => {
  // VirusTotal: every IOC type, direct.
  for (const [v, t] of [['8.8.8.8', 'ip'], ['example.org', 'domain'], ['https://example.org/x', 'url'],
    ['8588d11874ab52a1637953dc5538984647023d00b529f695fbd0e40cf8e5e852', 'sha256'], ['d41d8cd98f00b204e9800998ecf8427e', 'md5']]) {
    const r = applies('virustotal', v, t);
    assert.equal(r.applicable, true, `${v}`);
    assert.equal(r.scope, 'direct');
  }
  // IP providers: public IPs and URL IP-literal hosts only.
  for (const key of ['ipinfo_lite', 'abuseipdb']) {
    assert.deepEqual(applies(key, '8.8.8.8', 'ip'), { applicable: true, scope: 'direct', target_type: 'ip', target_value: '8.8.8.8' });
    const derived = applies(key, 'http://45.143.130.195:8899/a/x', 'url');
    assert.equal(derived.scope, 'derived');
    assert.equal(derived.target_value, '45.143.130.195');
    assert.equal(applies(key, '10.0.0.1', 'ip').applicable, false, 'private IP never leaves TalonHound');
    assert.equal(applies(key, 'https://example.org/', 'url').applicable, false);
    assert.equal(applies(key, 'example.org', 'domain').applicable, false);
    assert.equal(applies(key, '8588d11874ab52a1637953dc5538984647023d00b529f695fbd0e40cf8e5e852', 'sha256').applicable, false);
  }
  // Spamhaus DROP: IP literal (local dataset).
  assert.equal(applies('spamhaus_drop', '8.8.8.8', 'ip').applicable, true);
  assert.equal(applies('spamhaus_drop', 'http://8.8.8.8/x', 'url').scope, 'derived');
  assert.equal(applies('spamhaus_drop', 'example.org', 'domain').applicable, false);
  // RDAP: registrable domain of domain IOCs / URL hosts, never IP hosts or hashes.
  assert.deepEqual(applies('rdap', 'www.example.co.uk', 'domain'), { applicable: true, scope: 'direct', target_type: 'domain', target_value: 'example.co.uk' });
  assert.equal(applies('rdap', 'https://login.example.org/a?b=c', 'url').target_value, 'example.org');
  assert.equal(applies('rdap', 'https://login.example.org/a', 'url').scope, 'derived');
  assert.equal(applies('rdap', 'http://45.143.130.195/x', 'url').applicable, false);
  assert.equal(applies('rdap', '8.8.8.8', 'ip').applicable, false);
});

test('every registry provider declares capabilities (new providers must too)', () => {
  for (const p of listEnrichmentProviders()) {
    if (p.key.startsWith('t_')) continue;
    assert.equal(typeof p.resolveTarget, 'function', p.key);
    assert.equal(typeof p.readFreshness, 'function', p.key);
    assert.ok(Array.isArray(p.supportedObservableTypes) && p.supportedObservableTypes.length, p.key);
    assert.equal(typeof p.external, 'boolean', p.key);
  }
});

// ---------------------------------------------------------------------------
// MCP provenance on audit + no secrets
// ---------------------------------------------------------------------------

test('MCP-triggered enrichment is audited with MCP provenance and no credentials', async () => {
  resetEnrichmentExecutorsForTests();
  resetEnrichmentProviderGuardForTests();
  const ioc = { id: 21, public_id: '21212121-2121-4121-8121-212121212121', observable: '9.9.9.9', observable_type: 'ip' };
  const pool = createFakeEnrichmentPool({ iocs: [ioc] });
  // Provider executor writes its own (provider-level) audit through the adapter, like the real refresh functions.
  registerEnrichmentExecutor('spamhaus_drop', async (ctx) => {
    await ctx.audit.auditSuccess({ req: ctx.req, action: AUDIT_ACTION.SPAMHAUS_DROP_ENRICHMENT_REFRESH, entityType: 'enrichment', metadata: { target_ip: '9.9.9.9', source_page: 'ioc_detail_intelligence' } });
    return { status: 200, body: { status: 'not_listed' } };
  });
  // Pretend spamhaus is enabled and has no stored result.
  const entry = getEnrichmentProvider('spamhaus_drop');
  const origLoad = entry.loadState;
  const origFresh = entry.readFreshness;
  entry.loadState = async () => ({ enabled: true, configured: true });
  entry.readFreshness = async () => ({ fresh: false, last_enriched_at: null });

  const events = [];
  const audit = {
    auditSuccess: async (e) => { events.push(e); },
    auditFailure: async (e) => { events.push(e); }
  };
  const secret = 'th_mcp_SUPERSECRETTOKENVALUE';
  const req = {
    user: { id: 3, publicId: '03030303-0303-4303-8303-030303030303', username: 'analyst1', role: 'analyst' },
    mcpAuth: { scopes: scopesForAccessProfile('mcp_analyst'), ownerRole: 'analyst', apiKeyId: 42, apiKeyName: 'agent-key', keyType: 'mcp_analyst' },
    requestId: 'req-123',
    headers: { authorization: `Bearer ${secret}`, 'user-agent': 'claude-code' }
  };
  try {
    const out = await mcpEnrichIocs(pool, { ioc_id: ioc.public_id, providers: ['spamhaus_drop'] }, { req, mcpAuth: req.mcpAuth, audit });
    assert.ok(out.body.job_id);
    assert.equal(out.body.ioc_id, ioc.public_id);
    assert.equal(out.body.providers[0].provider, 'spamhaus_drop');
    await waitForFakeJob(pool, out.body.job_id);
    await new Promise((r) => setTimeout(r, 20));

    const actions = events.map((e) => e.action);
    assert.ok(actions.includes(AUDIT_ACTION.ENRICHMENT_JOB_REQUESTED));
    assert.ok(actions.includes(AUDIT_ACTION.SPAMHAUS_DROP_ENRICHMENT_REFRESH));
    assert.ok(actions.includes(AUDIT_ACTION.ENRICHMENT_JOB_COMPLETED));
    for (const e of events) {
      assert.equal(e.source, 'mcp', e.action);
      assert.equal(e.req.authVia, 'mcp', e.action);
      assert.equal(e.actorUsername, 'analyst1');
      assert.equal(e.metadata.via, 'mcp');
      assert.equal(e.metadata.api_key_id, 42);
      assert.equal(e.metadata.api_key_name, 'agent-key');
      assert.equal(e.metadata.tool, 'enrich_ioc');
      assert.equal(e.metadata.force_refresh, false);
      assert.equal(e.req.requestId, 'req-123');
    }
    const provider = events.find((e) => e.action === AUDIT_ACTION.SPAMHAUS_DROP_ENRICHMENT_REFRESH);
    assert.equal(provider.metadata.target_ip, '9.9.9.9', 'provider metadata kept');
    assert.equal(provider.metadata.source_page, 'mcp', 'UI origin label never claimed for MCP triggers');
    const dump = JSON.stringify({ events: events.map(({ req: r, ...rest }) => ({ ...rest, req: r })), body: out.body });
    assert.doesNotMatch(dump, /SUPERSECRETTOKENVALUE/);
    assert.doesNotMatch(dump, /authorization/i);
  } finally {
    entry.loadState = origLoad;
    entry.readFreshness = origFresh;
    resetEnrichmentExecutorsForTests();
  }
});

test('mcpEnrichIocs validates providers and single-IOC shape', async () => {
  const pool = createFakeEnrichmentPool({ iocs: [] });
  const bad = await mcpEnrichIocs(pool, { ioc_id: 'x', providers: [] }, {});
  assert.equal(bad.error.code, 'VALIDATION_ERROR');
  const missing = await mcpEnrichIocs(pool, { ioc_id: '99999999-9999-4999-8999-999999999999' }, {});
  assert.equal(missing.error.code, 'IOC_NOT_FOUND');
  const tooMany = await mcpEnrichIocs(pool, {
    ioc_ids: Array.from({ length: 60 }, (_, i) => String(i + 1))
  }, {}, { bulk: true });
  assert.equal(tooMany.error.code, 'BATCH_TOO_LARGE');
});

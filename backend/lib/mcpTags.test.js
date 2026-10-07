import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizeMcpTool, effectiveMcpCapabilities, MCP_TAG_ACTION_TOOLS } from './mcpPermissions.js';
import { scopesForAccessProfile, listCreatableAccessProfiles, API_SCOPE } from './apiKeyProfiles.js';
import { registerMcpTools } from './mcpTools.js';
import { mcpAddIocTags, mcpRemoveIocTags, mcpListTags, normalizeRequestedTagNames } from './mcpTagService.js';
import { AUDIT_ACTION } from './auditConstants.js';

const IOC_UUID = '7bebdd6a-fad5-46dd-995d-f627ef854149';

// ---------------------------------------------------------------------------
// Fake pool: ioc_items + tags catalog + ioc_tags junction, matched by SQL shape.
// ---------------------------------------------------------------------------

function createFakeTagPool({ tags = [], assignments = [] } = {}) {
  const ioc = { id: 3562187, public_id: IOC_UUID, observable: 'www.wixconsulting.com', observable_type: 'domain' };
  const state = {
    ioc,
    tags: tags.map((t, i) => ({ id: i + 1, type: 'context', category: 'custom', description: null, enabled: true, ...t })),
    // { ioc_id, tag_id, origin, source_name, created_by }
    assignments: assignments.map((a) => ({ ioc_id: ioc.id, source_name: null, created_by: null, ...a })),
    queries: [],
    calls: []
  };
  const tagByName = (name) => state.tags.find((t) => t.name === name);

  async function query(sql, params = []) {
    const text = String(sql).replace(/\s+/g, ' ').trim();
    state.queries.push(text);
    state.calls.push({ text, params });
    if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(text)) return { rows: [] };
    if (/FROM ioc_items WHERE public_id = ANY/.test(text)) {
      return { rows: params[0].includes(ioc.public_id) ? [ioc] : [] };
    }
    if (/FROM ioc_items WHERE id = \$1 LIMIT 1/.test(text) && /SELECT id, public_id, observable, observable_type/.test(text)) {
      return { rows: Number(params[0]) === ioc.id ? [ioc] : [] };
    }
    if (/^SELECT id, name, type, category, enabled FROM tags WHERE name = ANY/.test(text)) {
      return { rows: state.tags.filter((t) => params[0].includes(t.name)) };
    }
    if (/^SELECT name, category, description FROM tags WHERE enabled = TRUE/.test(text)) {
      let rows = state.tags.filter((t) => t.enabled);
      if (params.length === 2) {
        const needle = params[0].replace(/^%|%$/g, '').replace(/\\(.)/g, '$1').toLowerCase();
        rows = rows.filter((t) => t.name.includes(needle));
      }
      rows = rows.sort((a, b) => a.name.localeCompare(b.name));
      return { rows: rows.slice(0, params[params.length - 1]) };
    }
    if (/^INSERT INTO ioc_tags .* 'manual'/.test(text)) {
      const [iocId, , tagId, createdBy] = params;
      const exists = state.assignments.some((a) => a.ioc_id === iocId && a.tag_id === tagId && a.origin === 'manual');
      if (exists) return { rows: [], rowCount: 0 };
      state.assignments.push({ ioc_id: iocId, tag_id: tagId, origin: 'manual', source_name: null, created_by: createdBy });
      return { rows: [{ tag_id: tagId }], rowCount: 1 };
    }
    if (/^DELETE FROM ioc_tags it USING tags t/.test(text)) {
      const [iocId, , names] = params;
      const removed = [];
      state.assignments = state.assignments.filter((a) => {
        const tag = state.tags.find((t) => t.id === a.tag_id);
        const hit = a.ioc_id === iocId && a.origin === 'manual' && names.includes(tag.name);
        if (hit) removed.push({ id: tag.id, name: tag.name, type: tag.type, category: tag.category });
        return !hit;
      });
      return { rows: removed, rowCount: removed.length };
    }
    // hydrateIocApiMetadata tag aggregate (enabled tags across every origin).
    if (/JOIN ioc_tags it ON it.ioc_id = s.ioc_id JOIN tags t ON t.id = it.tag_id/.test(text)) {
      const byName = new Map();
      for (const a of state.assignments.filter((x) => x.ioc_id === ioc.id)) {
        const tag = state.tags.find((t) => t.id === a.tag_id);
        if (!tag?.enabled) continue;
        const row = byName.get(tag.name) || { seed_id: ioc.id, name: tag.name, type: tag.type, origins: [], source_name: null };
        if (!row.origins.includes(a.origin)) row.origins.push(a.origin);
        row.source_name = row.source_name || a.source_name;
        byName.set(tag.name, row);
      }
      return { rows: [...byName.values()].sort((a, b) => a.name.localeCompare(b.name)) };
    }
    return { rows: [] };
  }

  const pool = {
    query,
    async connect() {
      return { query, release() { state.released = (state.released || 0) + 1; } };
    }
  };
  return { pool, state, tagByName };
}

function mcpCtx(overrides = {}) {
  const events = [];
  return {
    events,
    ctx: {
      req: {
        user: { id: 7, username: 'analyst1', email: 'analyst1@example.test', role: 'analyst', publicId: 'u-7' },
        mcpAuth: { apiKeyId: 42, apiKeyName: 'Claude analyst', keyType: 'mcp_analyst', scopes: scopesForAccessProfile('mcp_analyst'), ownerRole: 'analyst' },
        headers: {}
      },
      mcpAuth: { apiKeyId: 42, apiKeyName: 'Claude analyst', keyType: 'mcp_analyst', scopes: scopesForAccessProfile('mcp_analyst'), ownerRole: 'analyst' },
      audit: {
        auditSuccess: async (event) => { events.push(event); },
        auditFailure: async (event) => { events.push({ ...event, failed: true }); }
      },
      ...overrides
    }
  };
}

const CATALOG = [
  { name: 'clearfake' },
  { name: 'fake-update' },
  { name: 'compromised' },
  { name: 'etherhide' },
  { name: 'ransomware', enabled: false }
];

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

test('only MCP Analyst carries mcp:tags:write', () => {
  for (const profile of listCreatableAccessProfiles()) {
    assert.equal(
      profile.scopes.includes(API_SCOPE.MCP_TAGS_WRITE),
      profile.id === 'mcp_analyst',
      profile.id
    );
  }
});

test('MCP Read cannot change tags; it can read the catalog with an analyst/admin owner', () => {
  const scopes = scopesForAccessProfile('mcp_read');
  for (const tool of MCP_TAG_ACTION_TOOLS) {
    const gate = authorizeMcpTool(tool, { scopes, ownerRole: 'admin' });
    assert.equal(gate.code, 'MISSING_SCOPE', tool);
    assert.match(gate.message, /mcp:tags:write/);
  }
  assert.equal(authorizeMcpTool('list_tags', { scopes, ownerRole: 'analyst' }).ok, true);
});

test('tag scope is never implied by import or enrichment scopes', () => {
  const withoutTags = scopesForAccessProfile('mcp_analyst').filter((s) => s !== API_SCOPE.MCP_TAGS_WRITE);
  assert.equal(authorizeMcpTool('add_ioc_tags', { scopes: withoutTags, ownerRole: 'admin' }).code, 'MISSING_SCOPE');
  assert.equal(authorizeMcpTool('remove_ioc_tags', { scopes: withoutTags, ownerRole: 'admin' }).code, 'MISSING_SCOPE');
  // mcp:tags:write alone (without mcp:ioc:read) is not enough either.
  assert.equal(authorizeMcpTool('add_ioc_tags', { scopes: [API_SCOPE.MCP_TAGS_WRITE], ownerRole: 'admin' }).code, 'MISSING_SCOPE');
  assert.equal(
    authorizeMcpTool('add_ioc_tags', { scopes: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_TAGS_WRITE], ownerRole: 'analyst' }).ok,
    true
  );
});

test('a readonly owner can neither change tags nor list the catalog (GUI parity)', () => {
  const scopes = scopesForAccessProfile('mcp_analyst');
  for (const tool of [...MCP_TAG_ACTION_TOOLS, 'list_tags']) {
    const gate = authorizeMcpTool(tool, { scopes, ownerRole: 'readonly' });
    assert.equal(gate.code, 'RBAC_DENIED', tool);
  }
  const caps = effectiveMcpCapabilities({ scopes, ownerRole: 'readonly' });
  assert.equal(caps.tags_write, false);
  assert.equal(caps.tags_read, false);
  assert.equal(authorizeMcpTool('get_ioc_context', { scopes, ownerRole: 'readonly' }).ok, true);
});

// ---------------------------------------------------------------------------
// add_ioc_tags
// ---------------------------------------------------------------------------

test('add_ioc_tags writes analyst (manual) assignments of catalog tags and audits each one', async () => {
  const { pool, state } = createFakeTagPool({
    tags: CATALOG,
    assignments: [{ tag_id: 3, origin: 'integration', source_name: 'ThreatFox:abuse.ch' }]
  });
  const { ctx, events } = mcpCtx();
  const out = await mcpAddIocTags(pool, { ioc_id: IOC_UUID, tags: ['  ClearFake ', 'fake-update', 'clearfake'] }, ctx);
  assert.equal(out.error, undefined);
  assert.equal(out.body.ioc_id, IOC_UUID);
  assert.equal(out.body.observable, 'www.wixconsulting.com');
  assert.deepEqual(out.body.added, ['clearfake', 'fake-update']);
  assert.deepEqual(out.body.already_present, []);
  assert.deepEqual(out.body.tags, ['clearfake', 'compromised', 'fake-update']);
  const clearfake = out.body.tags_detail.find((t) => t.name === 'clearfake');
  assert.equal(clearfake.origin, 'manual');

  const manual = state.assignments.filter((a) => a.origin === 'manual');
  assert.equal(manual.length, 2);
  assert.ok(manual.every((a) => a.created_by === 7), 'created_by = owner user');
  assert.ok(state.queries.includes('BEGIN') && state.queries.includes('COMMIT'));
  assert.equal(state.released, 1);

  assert.equal(events.length, 2);
  for (const ev of events) {
    assert.equal(ev.action, AUDIT_ACTION.IOC_TAG_ADDED);
    assert.equal(ev.entityId, IOC_UUID);
    assert.equal(ev.subjectIocValue, 'www.wixconsulting.com');
    assert.equal(ev.source, 'mcp');
    assert.equal(ev.actorUsername, 'analyst1');
    assert.equal(ev.metadata.tool, 'add_ioc_tags');
    assert.equal(ev.metadata.channel, 'mcp');
    assert.equal(ev.metadata.api_key_id, 42);
    assert.equal(ev.metadata.api_key_name, 'Claude analyst');
    assert.ok(!JSON.stringify(ev).includes('th_mcp_'), 'never logs a token');
  }
  assert.deepEqual(events.map((e) => e.metadata.tag_name), ['clearfake', 'fake-update']);
});

test('add_ioc_tags is idempotent: an existing analyst tag is already_present and not re-audited', async () => {
  const { pool } = createFakeTagPool({ tags: CATALOG, assignments: [{ tag_id: 1, origin: 'manual' }] });
  const { ctx, events } = mcpCtx();
  const out = await mcpAddIocTags(pool, { ioc_id: 3562187, tags: ['clearfake', 'fake-update'] }, ctx);
  assert.deepEqual(out.body.added, ['fake-update']);
  assert.deepEqual(out.body.already_present, ['clearfake']);
  assert.equal(events.length, 1);
});

test('add_ioc_tags is all-or-nothing: unknown or disabled tags change nothing and are never created', async () => {
  const { pool, state } = createFakeTagPool({ tags: CATALOG });
  const { ctx, events } = mcpCtx();
  const out = await mcpAddIocTags(pool, { ioc_id: IOC_UUID, tags: ['clearfake', 'brand-new-tag', 'Ransomware'] }, ctx);
  assert.equal(out.error.code, 'TAG_NOT_ALLOWED');
  assert.match(out.error.message, /not in the TalonHound tag catalog: brand-new-tag/);
  assert.match(out.error.message, /disabled in the tag catalog: ransomware/);
  assert.match(out.error.message, /list_tags/);
  assert.equal(state.assignments.length, 0);
  assert.equal(state.tags.length, CATALOG.length, 'no catalog row created');
  assert.ok(!state.queries.some((q) => /INSERT INTO tags|UPDATE tags/.test(q)), 'catalog never written');
  assert.equal(events.length, 0);
});

test('add_ioc_tags validates input and resolves the IOC by public_id or numeric id only', async () => {
  const { pool } = createFakeTagPool({ tags: CATALOG });
  const { ctx } = mcpCtx({ config: { tagWriteMax: 2, tagListMax: 100 } });
  assert.equal((await mcpAddIocTags(pool, { ioc_id: IOC_UUID, tags: [] }, ctx)).error.code, 'VALIDATION_ERROR');
  assert.equal((await mcpAddIocTags(pool, { ioc_id: IOC_UUID, tags: ['   '] }, ctx)).error.code, 'VALIDATION_ERROR');
  const tooMany = await mcpAddIocTags(pool, { ioc_id: IOC_UUID, tags: ['clearfake', 'fake-update', 'etherhide'] }, ctx);
  assert.match(tooMany.error.message, /at most 2 tags/);
  // Values are never accepted as ioc_id — TalonHound resolves the stored record.
  assert.equal((await mcpAddIocTags(pool, { ioc_id: 'www.wixconsulting.com', tags: ['clearfake'] }, ctx)).error.code, 'VALIDATION_ERROR');
  assert.equal(
    (await mcpAddIocTags(pool, { ioc_id: '00000000-0000-4000-8000-000000000000', tags: ['clearfake'] }, ctx)).error.code,
    'IOC_NOT_FOUND'
  );
});

test('normalizeRequestedTagNames applies the catalog rule (case/whitespace only) and dedupes', () => {
  assert.deepEqual(normalizeRequestedTagNames([' Fake  Update ', 'fake update', 'fake-update'], 10), {
    ok: true,
    names: ['fake update', 'fake-update']
  });
  assert.equal(normalizeRequestedTagNames(['x'.repeat(101)], 10).ok, false);
  assert.equal(normalizeRequestedTagNames([42], 10).ok, false);
});

// ---------------------------------------------------------------------------
// remove_ioc_tags
// ---------------------------------------------------------------------------

test('remove_ioc_tags removes analyst tags only; source tags are not_removable, absent ones not_assigned', async () => {
  const { pool, state } = createFakeTagPool({
    tags: CATALOG,
    assignments: [
      { tag_id: 1, origin: 'manual' },
      { tag_id: 3, origin: 'integration', source_name: 'ThreatFox:abuse.ch' },
      // Same tag both analyst-added and feed-provided: the analyst assignment goes, the feed one stays.
      { tag_id: 4, origin: 'manual' },
      { tag_id: 4, origin: 'integration', source_name: 'ThreatFox:abuse.ch' }
    ]
  });
  const { ctx, events } = mcpCtx();
  const out = await mcpRemoveIocTags(pool, { ioc_id: IOC_UUID, tags: ['ClearFake', 'compromised', 'etherhide', 'fake-update'] }, ctx);
  assert.equal(out.error, undefined);
  assert.deepEqual(out.body.removed.sort(), ['clearfake', 'etherhide']);
  assert.deepEqual(out.body.not_assigned, ['fake-update']);
  assert.deepEqual(out.body.not_removable, [{
    tag: 'compromised',
    origins: ['integration'],
    reason: 'source/feed or Threat Library report tag — not an analyst tag'
  }]);
  assert.deepEqual(out.body.tags, ['compromised', 'etherhide']);
  assert.ok(!state.assignments.some((a) => a.origin === 'manual'), 'analyst assignments removed');
  assert.equal(state.assignments.filter((a) => a.origin === 'integration').length, 2, 'source assignments untouched');

  assert.equal(events.length, 2);
  for (const ev of events) {
    assert.equal(ev.action, AUDIT_ACTION.IOC_TAG_REMOVED);
    assert.equal(ev.source, 'mcp');
    assert.equal(ev.metadata.tool, 'remove_ioc_tags');
  }
});

test('remove_ioc_tags DELETE is scoped to this IOC, its partition and origin manual', async () => {
  const { pool, state } = createFakeTagPool({ tags: CATALOG });
  const { ctx } = mcpCtx();
  await mcpRemoveIocTags(pool, { ioc_id: IOC_UUID, tags: ['clearfake'] }, ctx);
  const del = state.queries.find((q) => q.startsWith('DELETE FROM ioc_tags'));
  assert.match(del, /it\.ioc_id = \$1/);
  assert.match(del, /it\.ioc_observable_type = \$2/);
  assert.match(del, /it\.origin = 'manual'/);
});

// ---------------------------------------------------------------------------
// list_tags
// ---------------------------------------------------------------------------

test('list_tags returns enabled catalog tags only, bounded, with a contains filter', async () => {
  const { pool } = createFakeTagPool({ tags: CATALOG });
  const all = await mcpListTags(pool, {}, { config: { tagListMax: 100 } });
  assert.deepEqual(all.body.tags.map((t) => t.name), ['clearfake', 'compromised', 'etherhide', 'fake-update']);
  assert.equal(all.body.truncated, false);
  const capped = await mcpListTags(pool, { limit: 2 }, { config: { tagListMax: 100 } });
  assert.equal(capped.body.tags.length, 2);
  assert.equal(capped.body.truncated, true);
  const filtered = await mcpListTags(pool, { query: 'FAKE' }, { config: { tagListMax: 100 } });
  assert.deepEqual(filtered.body.tags.map((t) => t.name), ['clearfake', 'fake-update']);
});

test('list_tags escapes LIKE wildcards in the query', async () => {
  const { pool, state } = createFakeTagPool({ tags: CATALOG });
  await mcpListTags(pool, { query: '100%_x' }, { config: { tagListMax: 100 } });
  const call = state.calls.find((c) => c.text.includes('name ILIKE $1'));
  assert.equal(call.params[0], '%100\\%\\_x%');
});

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

function captureTools() {
  const tools = new Map();
  const server = { registerTool: (name, def, handler) => tools.set(name, { def, handler }) };
  return { server, tools };
}

test('tag tools are registered as actions (writes) vs read, with honest descriptions', () => {
  const { server, tools } = captureTools();
  registerMcpTools(server, { pool: {}, getRequestContext: () => ({}) });
  const list = tools.get('list_tags').def;
  assert.equal(list.annotations.readOnlyHint, true);
  for (const name of ['add_ioc_tags', 'remove_ioc_tags']) {
    const { def } = tools.get(name);
    assert.equal(def.annotations.readOnlyHint, false, name);
    assert.equal(def.annotations.openWorldHint, false, name);
    assert.match(def.description, /^ACTION:/, name);
    assert.match(def.description, /mcp:tags:write/, name);
  }
  assert.equal(tools.get('remove_ioc_tags').def.annotations.destructiveHint, true);
  assert.match(tools.get('add_ioc_tags').def.description, /never creates catalog tags/);
  assert.match(tools.get('remove_ioc_tags').def.description, /never removed/);
});

test('tag tools write only their own ioc.tag.* events (no generic MCP tool-call event)', async () => {
  const { pool } = createFakeTagPool({ tags: CATALOG });
  const { ctx, events } = mcpCtx();
  const { server, tools } = captureTools();
  registerMcpTools(server, { pool, audit: ctx.audit, getRequestContext: () => ({ req: ctx.req }) });
  const res = await tools.get('add_ioc_tags').handler({ ioc_id: IOC_UUID, tags: ['clearfake'] });
  assert.equal(res.isError, undefined);
  assert.deepEqual(res.structuredContent.added, ['clearfake']);
  assert.deepEqual(events.map((e) => e.action), [AUDIT_ACTION.IOC_TAG_ADDED]);

  // Denied for a read-only credential before any query runs.
  const readCtx = mcpCtx().ctx;
  readCtx.req.mcpAuth = { ...readCtx.req.mcpAuth, scopes: scopesForAccessProfile('mcp_read') };
  const { server: s2, tools: t2 } = captureTools();
  const { pool: pool2, state: state2 } = createFakeTagPool({ tags: CATALOG });
  registerMcpTools(s2, { pool: pool2, getRequestContext: () => ({ req: readCtx.req }) });
  const denied = await t2.get('add_ioc_tags').handler({ ioc_id: IOC_UUID, tags: ['clearfake'] });
  assert.equal(denied.isError, true);
  assert.equal(denied.structuredContent.error.code, 'MISSING_SCOPE');
  assert.equal(state2.queries.length, 0);
});

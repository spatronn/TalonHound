import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { mcpGetIocContext, mcpLookupIoc } from './mcpIocService.js';
import { authorizeMcpTool } from './mcpPermissions.js';
import { API_SCOPE } from './apiKeyProfiles.js';
import { MCP_DEFAULTS } from './mcpConfig.js';

/**
 * Real-Postgres boundary for the MCP IOC read tools (lookup_ioc /
 * get_ioc_context). The unit suites answer SQL from a fake pool; this file
 * runs the same service code against the migrated schema so row-value
 * IN (VALUES …) pairs, uuid / bigint casts, LEFT JOIN catalog resolution,
 * partition-key joins and the attribution suppression / withdrawal filters are
 * executed by PostgreSQL itself.
 *
 * Rows are committed under a per-run token and deleted afterwards. Run only
 * against a DISPOSABLE migrated database (never production). Skips without one.
 */

const { Pool } = pg;
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 4
});

let hasDb = false;
try {
  await pool.query('SELECT 1 FROM ioc_source_attributions LIMIT 0');
  await pool.query('SELECT 1 FROM ioc_attribution_overrides LIMIT 0');
  await pool.query('SELECT 1 FROM threat_report_candidates LIMIT 0');
  hasDb = true;
} catch {
  hasDb = false;
}
const opts = { skip: hasDb ? false : 'no migrated database available (set DB_HOST/DB_PASSWORD to run)' };

const TOKEN = `mcp${process.pid}${Date.now().toString(36)}`;
const CONFIG = Object.freeze({ valueMaxChars: MCP_DEFAULTS.VALUE_MAX_CHARS, bulkLookupMax: 5, importMax: 5, searchPageMax: 50 });
const READ_AUTH = { scopes: [API_SCOPE.MCP_IOC_READ], ownerRole: 'analyst' };
const ENRICH_AUTH = { scopes: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_ENRICHMENT_READ], ownerRole: 'analyst' };
const created = { iocIds: [], actorIds: [], familyIds: [] };

async function insertIoc(type, value) {
  const { rows } = await pool.query(
    `INSERT INTO ioc_items (observable, observable_type, source_name)
     VALUES ($1, $2, 'itest') RETURNING id, public_id, observable, observable_type`,
    [value, type]
  );
  created.iocIds.push(rows[0].id);
  return rows[0];
}

async function insertActor(name) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const { rows } = await pool.query(
    `INSERT INTO threat_actors (name, slug, aliases, active, catalog_sources)
     VALUES ($1, $2, NULL, TRUE, ARRAY['manual']) RETURNING id, name`,
    [name, slug]
  );
  created.actorIds.push(rows[0].id);
  return rows[0];
}

async function insertFamily(name, aliases = []) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const { rows } = await pool.query(
    `INSERT INTO malware_families (name, slug, aliases, active, catalog_sources)
     VALUES ($1, $2, $3::text[], TRUE, ARRAY['manual']) RETURNING id, name`,
    [name, slug, aliases]
  );
  created.familyIds.push(rows[0].id);
  return rows[0];
}

async function linkActor(ioc, actor) {
  await pool.query(
    `INSERT INTO ioc_threat_actors (ioc_id, ioc_observable_type, threat_actor_id, source_type, created_by)
     VALUES ($1, $2, $3, 'analyst', 'itest')`,
    [ioc.id, ioc.observable_type, actor.id]
  );
}

async function assertSource(ioc, { label, entityId = null, ref, status = 'current' }) {
  await pool.query(
    `INSERT INTO ioc_source_attributions (
       ioc_id, ioc_observable_type, entity_kind, source_label, source_label_normalized,
       entity_id, resolution_status, feed_key, source_name, evidence_ref_type, evidence_ref_id,
       evidence_url, evidence_title, association_kind, assertion_status, observed_at,
       first_ingested_at, last_ingested_at, withdrawn_at, provider_metadata
     ) VALUES ($1, $2, 'malware_family', $3, lower($3), $4,
       CASE WHEN $4::uuid IS NULL THEN 'unresolved' ELSE 'resolved' END,
       $5, 'AlienVault OTX', 'otx_pulse', $6, 'https://otx.example/pulse/' || $6, 'Pulse ' || $6,
       'associated_via_source_pulse', $7, '2026-01-02T00:00:00Z', '2026-01-03T00:00:00Z', '2026-01-04T00:00:00Z',
       CASE WHEN $7 = 'current' THEN NULL ELSE '2026-01-05T00:00:00Z'::timestamptz END,
       jsonb_build_object('provider', 'alienvault_otx', 'field', 'malware_families'))`,
    [ioc.id, ioc.observable_type, label, entityId, `itest-otx-${TOKEN}`, ref, status]
  );
}

async function suppressLabel(ioc, label) {
  await pool.query(
    `INSERT INTO ioc_attribution_overrides (ioc_id, ioc_observable_type, entity_kind, source_label_normalized, action, created_by)
     VALUES ($1, $2, 'malware_family', lower($3), 'suppress', 'itest')`,
    [ioc.id, ioc.observable_type, label]
  );
}

test.after(async () => {
  if (!hasDb) return;
  try {
    // ioc_items deletes cascade to junctions, source attributions and overrides.
    await pool.query('DELETE FROM ioc_items WHERE id = ANY($1::bigint[])', [created.iocIds]);
    await pool.query('DELETE FROM malware_families WHERE id = ANY($1::uuid[])', [created.familyIds]);
    await pool.query('DELETE FROM threat_actors WHERE id = ANY($1::uuid[])', [created.actorIds]);
  } finally {
    await pool.end();
  }
});

test('get_ioc_context on real PostgreSQL: analyst ∪ source attribution, suppression, withdrawal, no cross-IOC leakage', opts, async () => {
  const ioc = await insertIoc('domain', `relay-${TOKEN}.example`);
  const other = await insertIoc('domain', `other-${TOKEN}.example`);
  const actor = await insertActor(`Actor ${TOKEN}`);
  const otherActor = await insertActor(`Other ${TOKEN}`);
  const family = await insertFamily(`Family ${TOKEN}`, [`Alias ${TOKEN}`]);
  await linkActor(ioc, actor);
  await linkActor(other, otherActor);
  await assertSource(ioc, { label: `Family ${TOKEN}`, entityId: family.id, ref: `p1-${TOKEN}` });
  await assertSource(ioc, { label: `Suppressed ${TOKEN}`, ref: `p2-${TOKEN}` });
  await assertSource(ioc, { label: `Withdrawn ${TOKEN}`, ref: `p3-${TOKEN}`, status: 'withdrawn' });
  await suppressLabel(ioc, `Suppressed ${TOKEN}`);

  const out = await mcpGetIocContext(pool, { value: ioc.observable, type: 'domain' }, { config: CONFIG, mcpAuth: READ_AUTH });
  assert.equal(out.status, 200, JSON.stringify(out.error));
  assert.equal(String(out.body.id), String(ioc.id)); // pg returns bigint as text; MCP serialises a number
  assert.deepEqual(out.body.threat_actors.map((a) => [a.id, a.attribution]), [[actor.id, 'analyst']]);
  assert.deepEqual(out.body.analyst_threat_actor_ids, [actor.id]);
  assert.deepEqual(out.body.malware_families.map((f) => [f.id, f.name, f.attribution]), [[family.id, family.name, 'source_reported']]);
  assert.deepEqual(out.body.malware_families[0].aliases, [`Alias ${TOKEN}`]);
  assert.deepEqual(out.body.malware_families[0].sources.map((s) => s.evidence_ref_id), [`p1-${TOKEN}`]);
  // Always-present Threat Context shape on an IOC with no linked report.
  assert.deepEqual(out.body.threat_context.claims, []);
  assert.deepEqual(out.body.threat_context.relationships, []);

  const byId = await mcpGetIocContext(pool, { id: ioc.public_id }, { config: CONFIG, mcpAuth: READ_AUTH });
  assert.equal(byId.status, 200);
  assert.deepEqual(byId.body.threat_actors, out.body.threat_actors);
  assert.deepEqual(byId.body.malware_families, out.body.malware_families);
});

test('get_ioc_context on real PostgreSQL: enrichment only with mcp:enrichment:read', opts, async () => {
  const ioc = await insertIoc('domain', `enrich-${TOKEN}.example`);
  const readOnly = await mcpGetIocContext(pool, { id: ioc.public_id }, { config: CONFIG, mcpAuth: READ_AUTH });
  assert.equal(readOnly.status, 200);
  assert.equal(readOnly.body.enrichment, undefined, 'no enrichment without the enrichment read scope');
  const withScope = await mcpGetIocContext(pool, { id: ioc.public_id }, { config: CONFIG, mcpAuth: ENRICH_AUTH });
  assert.equal(withScope.status, 200);
  assert.ok(Array.isArray(withScope.body.enrichment), 'stored-enrichment list (empty) with the scope');
});

test('lookup_ioc / get_ioc_context on real PostgreSQL: not found, invalid input', opts, async () => {
  const missing = await mcpLookupIoc(pool, { value: `absent-${TOKEN}.example` }, { config: CONFIG });
  assert.equal(missing.status, 200);
  assert.equal(missing.body.found, false);
  const ctx404 = await mcpGetIocContext(pool, { value: `absent-${TOKEN}.example`, type: 'domain' }, { config: CONFIG, mcpAuth: READ_AUTH });
  assert.equal(ctx404.status, 404);
  const bad = await mcpGetIocContext(pool, { value: '', type: 'domain' }, { config: CONFIG, mcpAuth: READ_AUTH });
  assert.equal(bad.status, 400);
});

test('get_ioc_context authorization is enforced before any read (scope-less key, read-only owner keeps read)', () => {
  assert.equal(authorizeMcpTool('get_ioc_context', { scopes: [], ownerRole: 'analyst' }).ok, false);
  assert.equal(authorizeMcpTool('get_ioc_context', { scopes: [API_SCOPE.MCP_IOC_READ], ownerRole: 'readonly' }).ok, true);
});

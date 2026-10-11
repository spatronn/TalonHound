import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import pg from 'pg';
import { applyDirectEvidence, directEvidenceAuditEvents, planDirectEvidence } from './directSourceEvidence.js';
import {
  fetchEffectiveIocAttributions,
  reconcileSourceAttributionsForEvidence,
  upsertSourceAttribution
} from './iocSourceAttributions.js';
import {
  countAssociatedIocsForFamilies,
  discoverIocs as discoverFamilyIocs
} from './malwareFamilies/iocDiscovery.js';
import {
  countAssociatedIocsForActors,
  discoverIocs as discoverActorIocs
} from './threatActors/iocDiscovery.js';
import { mcpListIocsByMalwareFamily, serializeMcpAttributionEntities } from './mcpMalwareFamilyService.js';

/**
 * Real-Postgres tests for direct source evidence and the Direct / Context /
 * Analyst relationship scopes. Rows are committed under a per-run token and
 * deleted afterwards. Run only against a DISPOSABLE migrated database (never
 * production). Skips without one.
 */

const { Pool } = pg;
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 8
});

let hasDb = false;
try {
  await pool.query('SELECT resolved_by FROM ioc_source_attributions LIMIT 0');
  hasDb = true;
} catch {
  hasDb = false;
}
const opts = { skip: hasDb ? false : 'no migrated database available (set DB_HOST/DB_PASSWORD to run)' };

const TOKEN = `de${process.pid}${Date.now().toString(36)}`;
const OTX_FEED = `itest-otx-${TOKEN}`;
const PULSE = `pulse-${TOKEN}`;
const REPORT_URL = `https://reports.example/${TOKEN}/inside-loader`;
const created = { iocIds: [], familyIds: [], actorIds: [] };

async function insertIoc(type, value) {
  const { rows } = await pool.query(
    `INSERT INTO ioc_items (observable, observable_type, source_name)
     VALUES ($1, $2, 'itest') RETURNING id, public_id, observable, observable_type`,
    [value, type]
  );
  created.iocIds.push(rows[0].id);
  return rows[0];
}

async function insertCatalog(table, name) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const { rows } = await pool.query(
    `INSERT INTO ${table} (name, slug, active, catalog_sources) VALUES ($1, $2, TRUE, ARRAY['manual']) RETURNING id, name`,
    [name, slug]
  );
  (table === 'threat_actors' ? created.actorIds : created.familyIds).push(rows[0].id);
  return rows[0];
}

/** OTX Pulse-context assertion, resolved to the catalog entity (as ingestion/backfill store it). */
async function pulseContext(ioc, kind, entity, { method = 'name' } = {}) {
  await pool.query(
    `INSERT INTO ioc_source_attributions (
       ioc_id, ioc_observable_type, entity_kind, source_label, source_label_normalized,
       entity_id, resolution_status, resolution_method, resolved_at, feed_key, source_name,
       evidence_ref_type, evidence_ref_id, evidence_url, evidence_title, association_kind,
       assertion_status, observed_at, first_ingested_at, last_ingested_at, provider_metadata
     ) VALUES ($1, $2, $3, $4, lower($4), $5::uuid, 'resolved', $6, '2026-01-04T00:00:00Z', $7, 'AlienVault OTX',
       'otx_pulse', $8, 'https://otx.example/pulse/' || $8, 'Pulse ' || $8, 'associated_via_source_pulse',
       'current', '2026-01-02T00:00:00Z', '2026-01-03T00:00:00Z', '2026-01-04T00:00:00Z',
       jsonb_build_object('provider', 'alienvault_otx', 'field', CASE WHEN $3 = 'threat_actor' THEN 'adversary' ELSE 'malware_families' END))`,
    [ioc.id, ioc.observable_type, kind, entity.name, entity.id, method, OTX_FEED, PULSE]
  );
}

async function otxSnapshot() {
  const { rows } = await pool.query(
    `SELECT ioc_id, entity_kind, source_label, entity_id, resolution_status, resolution_method, resolved_at,
            feed_key, evidence_ref_id, association_kind, assertion_status, observed_at,
            first_ingested_at, last_ingested_at, withdrawn_at, provider_metadata
     FROM ioc_source_attributions WHERE feed_key = $1 ORDER BY ioc_id, entity_kind, source_label`,
    [OTX_FEED]
  );
  return JSON.parse(JSON.stringify(rows));
}

const ids = (items) => items.map((i) => i.value).sort();

test.after(async () => {
  if (!hasDb) return;
  try {
    await pool.query('DELETE FROM ioc_items WHERE id = ANY($1::bigint[])', [created.iocIds]);
    await pool.query('DELETE FROM malware_families WHERE id = ANY($1::uuid[])', [created.familyIds]);
    await pool.query('DELETE FROM threat_actors WHERE id = ANY($1::uuid[])', [created.actorIds]);
    await pool.query("DELETE FROM audit_logs WHERE metadata->'source'->>'url' = $1", [REPORT_URL]).catch(() => {});
  } finally {
    await pool.end();
  }
});

test('direct source evidence: verified, idempotent, scoped separately from Pulse context and analyst attribution', opts, async () => {
  const loader = await insertCatalog('malware_families', `Loader${TOKEN}`);
  const stealer = await insertCatalog('malware_families', `Stealer${TOKEN}`);
  const actor = await insertCatalog('threat_actors', `Actor${TOKEN}`);

  const d1 = await insertIoc('domain', `d1.${TOKEN}.example`); // report: loader domain
  const d2 = await insertIoc('domain', `d2.${TOKEN}.example`); // pulse context only (families) + actor direct
  const h1 = await insertIoc('sha256', createHash('sha256').update(TOKEN).digest('hex'));
  const d3 = await insertIoc('domain', `d3.${TOKEN}.example`); // analyst attribution only
  const d4 = await insertIoc('domain', `d4.${TOKEN}.example`); // analyst + pulse context

  // OTX Pulse metadata names both families for every Pulse indicator.
  for (const ioc of [d1, d2, h1, d4]) {
    await pulseContext(ioc, 'malware_family', loader);
    await pulseContext(ioc, 'malware_family', stealer);
  }
  // Catalog identity confirmed by an analyst ("+"): still a source claim.
  await pool.query(
    `UPDATE ioc_source_attributions SET resolution_method = 'analyst', resolved_by = 'analyst@example.test'
     WHERE feed_key = $1 AND ioc_id = $2 AND source_label_normalized = lower($3)`,
    [OTX_FEED, d2.id, loader.name]
  );
  await pulseContext(d2, 'threat_actor', actor);
  // Analyst attribution (IOC Details Edit).
  for (const ioc of [d3, d4]) {
    await pool.query(
      `INSERT INTO ioc_malware_families (ioc_id, ioc_observable_type, malware_family_id, created_by)
       VALUES ($1, $2, $3::uuid, 'analyst@example.test')`,
      [ioc.id, ioc.observable_type, loader.id]
    );
  }
  await pool.query(
    `INSERT INTO ioc_threat_actors (ioc_id, ioc_observable_type, threat_actor_id, created_by)
     VALUES ($1, $2, $3::uuid, 'analyst@example.test')`,
    [d3.id, d3.observable_type, actor.id]
  );
  const otxBefore = await otxSnapshot();
  assert.equal(otxBefore.length, 9);

  const manifest = {
    source: { publisher: 'Example Labs', title: 'Inside the loader', url: REPORT_URL, published_at: '2026-10-07', section: 'Appendix B' },
    items: [
      { entity_kind: 'malware_family', entity_name: loader.name, row_label: `${loader.name} Domain`, observable_type: 'domain', value: d1.observable.replace(/\./g, '[.]') },
      { entity_kind: 'malware_family', entity_name: stealer.name, row_label: stealer.name, observable_type: 'sha256', value: h1.observable.toUpperCase(), association_kind: 'malware_sample_of' },
      { entity_kind: 'threat_actor', entity_name: actor.name, row_label: `${actor.name} infrastructure`, observable_type: 'domain', value: d2.observable },
      // Skipped: absent IOC, evidence mismatch, label of another entity, wrong hash type, unknown entity.
      { entity_kind: 'malware_family', entity_name: loader.name, row_label: `${loader.name} Domain`, observable_type: 'domain', value: `absent.${TOKEN}.example` },
      { entity_kind: 'malware_family', entity_name: loader.name, row_label: 'ClickFix URL', observable_type: 'domain', value: d2.observable },
      { entity_kind: 'malware_family', entity_name: loader.name, source_label: stealer.name, row_label: `${stealer.name} C2`, observable_type: 'domain', value: d2.observable },
      { entity_kind: 'malware_family', entity_name: stealer.name, row_label: stealer.name, observable_type: 'md5', value: h1.observable },
      { entity_kind: 'malware_family', entity_name: `Nope${TOKEN}`, row_label: `Nope${TOKEN} Domain`, observable_type: 'domain', value: d1.observable }
    ]
  };

  // Dry run writes nothing.
  const plan = await planDirectEvidence(pool, manifest);
  assert.equal(plan.ok, true);
  assert.deepEqual(plan.totals, { items: 8, create: 3, already_recorded: 0, skipped: 5 });
  assert.deepEqual(plan.items.slice(3).map((i) => i.reason), [
    'ioc_not_found', 'row_label_does_not_name_entity', 'label_resolves_to_other_entity', 'hash_type_mismatch', 'entity_not_found'
  ]);
  const { rows: [{ n: before }] } = await pool.query("SELECT COUNT(*)::int AS n FROM ioc_source_attributions WHERE evidence_ref_id = $1", [REPORT_URL]);
  assert.equal(before, 0);

  // Apply: exactly the three verified rows; Pulse context untouched.
  const applied = await applyDirectEvidence(pool, manifest, { recordedBy: 'itest-operator' });
  assert.equal(applied.created.length, 3);
  assert.deepEqual(await otxSnapshot(), otxBefore, 'OTX Pulse-context assertions are unchanged');
  const { rows: direct } = await pool.query(
    `SELECT ioc_id, entity_kind, entity_id, source_label, association_kind, resolution_status, resolution_method,
            resolved_by, feed_key, source_name, evidence_ref_type, evidence_url, evidence_title, observed_at,
            assertion_status, provider_metadata
     FROM ioc_source_attributions WHERE evidence_ref_id = $1 ORDER BY ioc_id`,
    [REPORT_URL]
  );
  assert.equal(direct.length, 3);
  const loaderRow = direct.find((r) => Number(r.ioc_id) === Number(d1.id));
  assert.equal(loaderRow.association_kind, 'directly_attributed_to');
  assert.equal(loaderRow.entity_id, loader.id);
  assert.equal(loaderRow.feed_key, 'publisher-report');
  assert.equal(loaderRow.source_name, 'Example Labs');
  assert.equal(loaderRow.evidence_ref_type, 'publisher_report');
  assert.equal(loaderRow.evidence_url, REPORT_URL);
  assert.equal(loaderRow.resolution_method, 'name');
  assert.equal(loaderRow.resolved_by, 'itest-operator');
  assert.equal(loaderRow.observed_at.toISOString(), '2026-10-07T00:00:00.000Z', 'publication time kept as the source observation');
  assert.equal(loaderRow.provider_metadata.row_label, `${loader.name} Domain`);
  assert.equal(loaderRow.provider_metadata.value_as_published, d1.observable.replace(/\./g, '[.]'));
  assert.equal(direct.find((r) => Number(r.ioc_id) === Number(h1.id)).association_kind, 'malware_sample_of');
  assert.equal(direct.find((r) => r.entity_kind === 'threat_actor').entity_id, actor.id);
  // Never analyst attribution.
  const { rows: [{ n: analystRows }] } = await pool.query(
    'SELECT COUNT(*)::int AS n FROM ioc_malware_families WHERE ioc_id = ANY($1::bigint[])', [[d1.id, h1.id]]
  );
  assert.equal(analystRows, 0);

  const events = directEvidenceAuditEvents(applied, { actorUsername: 'itest-operator' });
  assert.equal(events.length, 3);
  assert.ok(events.every((e) => e.metadata.attribution === 'source_reported' && e.metadata.relationship_scope === 'direct'));

  // Idempotent retry: nothing new, nothing to audit.
  const again = await applyDirectEvidence(pool, manifest, { recordedBy: 'itest-operator' });
  assert.equal(again.created.length, 0);
  assert.equal(again.totals.already_recorded, 3);
  assert.deepEqual(directEvidenceAuditEvents(again), []);

  // Feed refresh: OTX re-ingests d1 and withdraws the stealer label from its
  // Pulse; the publisher's direct rows are a different source and survive.
  await upsertSourceAttribution(pool, {
    iocId: d1.id, observableType: 'domain', entityKind: 'malware_family', sourceLabel: loader.name,
    feedKey: OTX_FEED, sourceName: 'AlienVault OTX', evidenceRefType: 'otx_pulse', evidenceRefId: PULSE,
    providerMetadata: { provider: 'alienvault_otx', field: 'malware_families' }
  });
  await reconcileSourceAttributionsForEvidence(pool, {
    iocId: d1.id, observableType: 'domain', feedKey: OTX_FEED, evidenceRefType: 'otx_pulse', evidenceRefId: PULSE,
    entityKinds: ['malware_family'], keepLabelKeysByKind: { malware_family: [loader.name] }
  });
  const { rows: afterRefresh } = await pool.query(
    "SELECT assertion_status FROM ioc_source_attributions WHERE evidence_ref_id = $1", [REPORT_URL]
  );
  assert.deepEqual(afterRefresh.map((r) => r.assertion_status), ['current', 'current', 'current']);

  // ---- Inventories: unique identities per scope, overlapping.
  const fam = (scope, extra = {}) => discoverFamilyIocs(pool, { familyId: loader.id }, { scope, ...extra });
  const all = await fam('all');
  assert.deepEqual(all.summary.scopes, { all: 5, direct: 1, context: 4, analyst: 2 });
  assert.notEqual(all.summary.scopes.all, 1 + 4 + 2, 'All counts unique IOCs, not the sum of scopes');
  assert.equal(all.items.length, 5);
  const directPage = await fam('direct');
  assert.deepEqual(ids(directPage.items), [d1.observable]);
  assert.equal(directPage.pagination.total, 1);
  assert.deepEqual(directPage.items[0].relationship_scopes, ['direct', 'context'], 'context kept when direct exists');
  assert.equal(directPage.items[0].evidence[0].association_kind, 'directly_attributed_to', 'direct evidence listed first');
  assert.ok(directPage.items[0].evidence.some((e) => e.association_kind === 'associated_via_source_pulse'));
  assert.deepEqual(ids((await fam('context')).items), [d1, d2, h1, d4].map((i) => i.observable).sort());
  const analystPage = await fam('analyst');
  assert.deepEqual(ids(analystPage.items), [d3, d4].map((i) => i.observable).sort());
  // Analyst catalog link on d2 is not analyst attribution.
  assert.ok(!analystPage.items.some((i) => i.value === d2.observable));
  assert.deepEqual(analystPage.items.find((i) => i.value === d4.observable).relationship_scopes, ['context', 'analyst']);
  // Paging + type filter keep the scope.
  const paged = await fam('context', { limit: 2, offset: 2, sort: 'value' });
  assert.equal(paged.pagination.total, 4);
  assert.equal(paged.items.length, 2);
  assert.equal(paged.pagination.has_more, false);
  assert.deepEqual(ids((await fam('context', { observable_type: 'hash' })).items), [h1.observable]);
  // Legacy filters still answer as before.
  const legacy = await discoverFamilyIocs(pool, { familyId: loader.id }, { origin: 'source' });
  assert.equal(legacy.options.scope, null);
  assert.equal(legacy.pagination.total, 4);

  // Stealer: sample from the report; the withdrawn Pulse label on d1 drops out of Context.
  const stealerAll = await discoverFamilyIocs(pool, { familyId: stealer.id }, {});
  assert.deepEqual(stealerAll.summary.scopes, { all: 3, direct: 1, context: 3, analyst: 0 });

  const counts = await countAssociatedIocsForFamilies(pool, [loader.id, stealer.id]);
  assert.deepEqual(counts.get(loader.id), { all_unique: 5, analyst_unique: 2, source_unique: 4, direct_unique: 1, context_unique: 4 });
  assert.equal(counts.get(stealer.id).direct_unique, 1);

  // Threat Actors use the same scopes.
  const act = await discoverActorIocs(pool, { actorId: actor.id }, { scope: 'all' });
  assert.deepEqual(act.summary.scopes, { all: 2, direct: 1, context: 1, analyst: 1 });
  assert.deepEqual(ids((await discoverActorIocs(pool, { actorId: actor.id }, { scope: 'direct' })).items), [d2.observable]);
  assert.deepEqual(ids((await discoverActorIocs(pool, { actorId: actor.id }, { scope: 'analyst' })).items), [d3.observable]);
  const actorCounts = await countAssociatedIocsForActors(pool, [actor.id]);
  assert.deepEqual(actorCounts.get(actor.id), { all_unique: 2, analyst_unique: 1, source_unique: 1, direct_unique: 1, context_unique: 1 });

  // ---- IOC Details: same classification as the inventories.
  const d1Attr = await fetchEffectiveIocAttributions(pool, d1.id, 'domain');
  const d1Loader = d1Attr.malware_families.find((f) => f.id === loader.id);
  assert.deepEqual(d1Loader.relationship_scopes, ['direct', 'context']);
  assert.equal(d1Loader.attribution, 'source_reported');
  assert.equal(d1Loader.association_kind, 'directly_attributed_to');
  assert.equal(d1Loader.sources[0].relationship_scope, 'direct');
  assert.equal(d1Loader.sources[0].evidence_row_label, `${loader.name} Domain`);
  assert.equal(d1Loader.sources[0].evidence_section, 'Appendix B');
  assert.ok(d1Loader.sources[0].source_published_at.startsWith('2026-10-07'));
  assert.equal(d1Loader.sources[1].relationship_scope, 'context');
  assert.deepEqual(d1Attr.analyst_malware_family_ids, []);
  const d4Attr = await fetchEffectiveIocAttributions(pool, d4.id, 'domain');
  assert.deepEqual(d4Attr.malware_families.find((f) => f.id === loader.id).relationship_scopes, ['context', 'analyst']);
  const d2Attr = await fetchEffectiveIocAttributions(pool, d2.id, 'domain');
  assert.deepEqual(d2Attr.malware_families.find((f) => f.id === loader.id).relationship_scopes, ['context']);
  assert.deepEqual(d2Attr.threat_actors.find((a) => a.id === actor.id).relationship_scopes, ['direct', 'context']);

  // ---- MCP: same membership + scopes as REST.
  for (const scope of ['all', 'direct', 'context', 'analyst']) {
    const rest = await fam(scope, { limit: 100 });
    const mcp = await mcpListIocsByMalwareFamily(pool, { malware_family_id: loader.id, scope, limit: 100 });
    assert.equal(mcp.status, 200);
    assert.equal(mcp.body.filters.scope, scope);
    assert.deepEqual(ids(mcp.body.iocs), ids(rest.items), `MCP = REST for scope ${scope}`);
    assert.deepEqual(mcp.body.summary.scopes, rest.summary.scopes);
  }
  const [mcpEntity] = serializeMcpAttributionEntities([d1Loader]);
  assert.deepEqual(mcpEntity.relationship_scopes, ['direct', 'context']);
  assert.equal(mcpEntity.sources[0].relationship_scope, 'direct');
  assert.equal(mcpEntity.sources[0].evidence_row_label, `${loader.name} Domain`);
});

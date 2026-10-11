import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {
  linkSourceLabelToCatalog,
  loadCatalogLinkContext
} from './attributionCatalogLinking.js';
import {
  fetchEffectiveIocAttributions,
  reconcileSourceAttributionsForEvidence,
  upsertSourceAttribution
} from './iocSourceAttributions.js';
import {
  countAssociatedIocsForFamilies,
  queryDiscoverySummary as familySummary
} from './malwareFamilies/iocDiscovery.js';
import {
  countAssociatedIocsForActors,
  queryDiscoverySummary as actorSummary
} from './threatActors/iocDiscovery.js';

/**
 * Real-Postgres tests for analyst catalog linking of source-reported labels.
 * The service manages its own transactions, so rows are committed under a
 * per-run token and deleted afterwards. Run only against a DISPOSABLE migrated
 * database (never production). Skips without one.
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

const TOKEN = `cl${process.pid}${Date.now().toString(36)}`;
const OTX = { feedKey: `itest-otx-${TOKEN}`, sourceName: 'AlienVault OTX' };
const OTHER = { feedKey: `itest-other-${TOKEN}`, sourceName: 'Other Feed' };
const ANALYST = 'analyst@example.test';

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

async function insertFamily(name, { aliases = [], active = true } = {}) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  const { rows } = await pool.query(
    `INSERT INTO malware_families (name, slug, aliases, active, catalog_sources)
     VALUES ($1, $2, $3::text[], $4, ARRAY['manual']) RETURNING id, name`,
    [name, slug, aliases, active]
  );
  created.familyIds.push(rows[0].id);
  return rows[0];
}

async function insertActor(name, { aliases = [] } = {}) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  const { rows } = await pool.query(
    `INSERT INTO threat_actors (name, slug, aliases, active, catalog_sources)
     VALUES ($1, $2, $3, TRUE, ARRAY['manual']) RETURNING id, name`,
    [name, slug, aliases.length ? aliases : null]
  );
  created.actorIds.push(rows[0].id);
  return rows[0];
}

/** Pre-catalog style source assertion (exactly as ingestion stores an unresolved label). */
async function assertSource(ioc, kind, label, src, ref, { status = 'current' } = {}) {
  await pool.query(
    `INSERT INTO ioc_source_attributions (
       ioc_id, ioc_observable_type, entity_kind, source_label, source_label_normalized,
       entity_id, resolution_status, feed_key, source_name, evidence_ref_type, evidence_ref_id,
       evidence_url, evidence_title, association_kind, assertion_status, observed_at,
       first_ingested_at, last_ingested_at, withdrawn_at, provider_metadata
     ) VALUES ($1, $2, $3, $4, lower($4), NULL, 'unresolved', $5, $6, 'otx_pulse', $7,
       'https://otx.example/pulse/' || $7, 'Pulse ' || $7, 'associated_via_source_pulse', $8,
       '2026-01-02T00:00:00Z', '2026-01-03T00:00:00Z', '2026-01-04T00:00:00Z',
       CASE WHEN $8 = 'current' THEN NULL ELSE '2026-01-05T00:00:00Z'::timestamptz END,
       '{"provider":"alienvault_otx"}'::jsonb)`,
    [ioc.id, ioc.observable_type, kind, label, src.feedKey, src.sourceName, ref, status]
  );
}

async function assertionRows(ioc, kind) {
  const { rows } = await pool.query(
    `SELECT source_label, source_label_normalized, entity_id, resolution_status, resolution_method,
            resolved_by, resolved_at, feed_key, source_name, evidence_ref_type, evidence_ref_id,
            evidence_url, evidence_title, association_kind, assertion_status, observed_at,
            first_ingested_at, last_ingested_at, withdrawn_at, is_backfill, provider_metadata
     FROM ioc_source_attributions
     WHERE ioc_id = $1 AND ioc_observable_type = $2 AND entity_kind = $3
     ORDER BY feed_key, evidence_ref_id, source_label_normalized`,
    [ioc.id, ioc.observable_type, kind]
  );
  return rows;
}

/** Fields owned by ingestion — the link must never change them. */
function provenanceOf(rows) {
  return rows.map((r) => ({
    source_label: r.source_label,
    feed_key: r.feed_key,
    source_name: r.source_name,
    evidence_ref_type: r.evidence_ref_type,
    evidence_ref_id: r.evidence_ref_id,
    evidence_url: r.evidence_url,
    evidence_title: r.evidence_title,
    association_kind: r.association_kind,
    assertion_status: r.assertion_status,
    observed_at: r.observed_at?.toISOString?.() || null,
    first_ingested_at: r.first_ingested_at?.toISOString?.() || null,
    last_ingested_at: r.last_ingested_at?.toISOString?.() || null,
    withdrawn_at: r.withdrawn_at?.toISOString?.() || null,
    is_backfill: r.is_backfill,
    provider_metadata: r.provider_metadata
  }));
}

const link = (ioc, kind, label, extra) => linkSourceLabelToCatalog(pool, {
  iocId: ioc.id,
  observableType: ioc.observable_type,
  entityKind: kind,
  sourceLabel: label,
  actorLabel: ANALYST,
  ...extra
});

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (err) => {
    assert.equal(err?.code, code, err?.message);
    return true;
  });
}

test.after(async () => {
  if (!hasDb) return;
  try {
    await pool.query('DELETE FROM ioc_items WHERE id = ANY($1::bigint[])', [created.iocIds]);
    await pool.query(
      `DELETE FROM malware_families WHERE id = ANY($1::uuid[]) OR name ILIKE $2`,
      [created.familyIds, `%${TOKEN}%`]
    );
    await pool.query(
      `DELETE FROM threat_actors WHERE id = ANY($1::uuid[]) OR name ILIKE $2`,
      [created.actorIds, `%${TOKEN}%`]
    );
  } finally {
    await pool.end();
  }
});

test('candidates: exact name, case-insensitive name, alias, similar (no merge), search', opts, async () => {
  const exact = await insertFamily(`PureRAT${TOKEN}`);
  const similar = await insertFamily(`Pure RAT ${TOKEN}`);
  const aliased = await insertFamily(`Sofacy Loader ${TOKEN}`, { aliases: [`SofLoad${TOKEN}`] });
  const ioc = await insertIoc('domain', `cand.${TOKEN}.example`);
  await assertSource(ioc, 'malware_family', `purerat${TOKEN}`, OTX, 'P1');
  await assertSource(ioc, 'malware_family', `SOFLOAD${TOKEN}`, OTX, 'P1');

  const ctx = await loadCatalogLinkContext(pool, {
    iocId: ioc.id, observableType: 'domain', entityKind: 'malware_family', sourceLabel: `PURERAT${TOKEN}`
  });
  assert.equal(ctx.link_state, 'unlinked');
  assert.equal(ctx.source_label, `purerat${TOKEN}`);
  assert.equal(ctx.evidence[0].source_name, 'AlienVault OTX');
  assert.equal(ctx.evidence[0].evidence_ref_id, 'P1');
  const byId = new Map(ctx.candidates.map((c) => [c.id, c]));
  assert.equal(byId.get(exact.id).match, 'name');
  assert.equal(byId.get(exact.id).exact, true);
  assert.equal(byId.get(similar.id).match, 'similar');
  assert.equal(byId.get(similar.id).exact, false);
  assert.deepEqual(ctx.exact_candidate_ids, [exact.id]);
  assert.equal(ctx.candidates[0].id, exact.id, 'exact match ranks first');

  const aliasCtx = await loadCatalogLinkContext(pool, {
    iocId: ioc.id, observableType: 'domain', entityKind: 'malware_family', sourceLabel: `SOFLOAD${TOKEN}`, q: 'Pure RAT'
  });
  const alias = aliasCtx.candidates.find((c) => c.id === aliased.id);
  assert.equal(alias.match, 'alias');
  assert.equal(alias.match_detail, `SofLoad${TOKEN}`);
  assert.ok(aliasCtx.candidates.some((c) => c.id === similar.id && c.match === 'search'), 'analyst search adds results');

  await rejectsCode(loadCatalogLinkContext(pool, {
    iocId: ioc.id, observableType: 'domain', entityKind: 'threat_actor', sourceLabel: `purerat${TOKEN}`
  }), 'SOURCE_LABEL_NOT_FOUND');
  await rejectsCode(loadCatalogLinkContext(pool, {
    iocId: ioc.id, observableType: 'ip', entityKind: 'malware_family', sourceLabel: `purerat${TOKEN}`
  }), 'IOC_NOT_FOUND');
});

test('link existing malware family: catalog identity only, provenance + analyst links intact, inventory consistent', opts, async () => {
  const fam = await insertFamily(`PureRAT-L${TOKEN}`);
  const other = await insertFamily(`Unrelated-L${TOKEN}`);
  const ioc = await insertIoc('domain', `link.${TOKEN}.example`);
  const label = `PureRAT_v2_${TOKEN}`; // resolver would never map this label to fam
  await assertSource(ioc, 'malware_family', label, OTX, 'P1');
  await assertSource(ioc, 'malware_family', label, OTX, 'P2');
  await assertSource(ioc, 'malware_family', label, OTHER, 'R1');
  // Existing analyst attribution for another family must survive untouched.
  await pool.query(
    `INSERT INTO ioc_malware_families (ioc_id, ioc_observable_type, malware_family_id, source_type, created_by)
     VALUES ($1, $2, $3, 'analyst', 'someone')`,
    [ioc.id, ioc.observable_type, other.id]
  );
  const before = await assertionRows(ioc, 'malware_family');

  const res = await link(ioc, 'malware_family', label, { mode: 'link', entityId: fam.id });
  assert.equal(res.outcome, 'linked');
  assert.equal(res.linked_assertions, 3);
  assert.equal(res.entity.id, fam.id);
  assert.deepEqual(res.evidence.map((e) => `${e.source_name}/${e.evidence_ref_id}`).sort(),
    ['AlienVault OTX/P1', 'AlienVault OTX/P2', 'Other Feed/R1']);

  const after = await assertionRows(ioc, 'malware_family');
  assert.deepEqual(provenanceOf(after), provenanceOf(before), 'ingestion-owned provenance unchanged');
  for (const r of after) {
    assert.equal(r.entity_id, fam.id);
    assert.equal(r.resolution_status, 'resolved');
    assert.equal(r.resolution_method, 'analyst');
    assert.equal(r.resolved_by, ANALYST);
    assert.ok(r.resolved_at instanceof Date);
  }
  // No analyst attribution was created for the linked family; the other stays.
  const { rows: analystRows } = await pool.query(
    `SELECT malware_family_id, created_by FROM ioc_malware_families WHERE ioc_id = $1 AND ioc_observable_type = $2`,
    [ioc.id, ioc.observable_type]
  );
  assert.deepEqual(analystRows.map((r) => [r.malware_family_id, r.created_by]), [[other.id, 'someone']]);

  // IOC Details: one chip for the family, still source-reported, both sources kept.
  const fields = await fetchEffectiveIocAttributions(pool, ioc.id, ioc.observable_type);
  const chip = fields.malware_families.find((f) => f.id === fam.id);
  assert.equal(chip.attribution, 'source_reported');
  assert.equal(chip.sources.length, 3);
  assert.ok(chip.sources.every((s) => s.resolution_method === 'analyst' && s.source_label === label));
  assert.equal(chip.source_label_key, undefined, 'linked chip has no unresolved label key');
  assert.deepEqual(fields.analyst_malware_family_ids, [other.id]);

  // Family inventory + catalog counter + summary agree (one identity, source origin).
  const counts = await countAssociatedIocsForFamilies(pool, [fam.id]);
  assert.deepEqual(counts.get(String(fam.id)), { all_unique: 1, analyst_unique: 0, source_unique: 1 });
  const summary = await familySummary(pool, { familyId: fam.id });
  assert.equal(summary.all_unique, 1);
  assert.equal(summary.source_unique, 1);
  assert.equal(summary.analyst_unique, 0);
  assert.equal(summary.source_references, 3);

  // Idempotent retry: no writes.
  const again = await link(ioc, 'malware_family', label, { mode: 'link', entityId: fam.id });
  assert.equal(again.outcome, 'already_linked');
  assert.equal(again.linked_assertions, 0);
  const afterRetry = await assertionRows(ioc, 'malware_family');
  assert.deepEqual(afterRetry.map((r) => r.resolved_at.toISOString()), after.map((r) => r.resolved_at.toISOString()));

  // A different target after resolution is refused with an explanation.
  await rejectsCode(link(ioc, 'malware_family', label, { mode: 'link', entityId: other.id }), 'ALREADY_LINKED');
});

test('re-ingestion and withdrawal never undo an analyst catalog link', opts, async () => {
  const fam = await insertFamily(`KeepMe${TOKEN}`);
  const ioc = await insertIoc('domain', `reingest.${TOKEN}.example`);
  const label = `keep_label_${TOKEN}`;
  await assertSource(ioc, 'malware_family', label, OTX, 'P1');
  await link(ioc, 'malware_family', label, { mode: 'link', entityId: fam.id });
  const [linked] = await assertionRows(ioc, 'malware_family');

  // Same pulse content re-ingested (resolver finds nothing for this label).
  const result = await upsertSourceAttribution(pool, {
    iocId: ioc.id, observableType: ioc.observable_type, entityKind: 'malware_family', sourceLabel: label,
    feedKey: OTX.feedKey, sourceName: OTX.sourceName, evidenceRefType: 'otx_pulse', evidenceRefId: 'P1',
    evidenceUrl: 'https://otx.example/pulse/P1', evidenceTitle: 'Pulse P1',
    observedAt: '2026-01-02T00:00:00Z', providerMetadata: { provider: 'alienvault_otx' }
  });
  assert.equal(result, 'updated');
  let [row] = await assertionRows(ioc, 'malware_family');
  assert.equal(row.entity_id, fam.id);
  assert.equal(row.resolution_method, 'analyst');
  assert.equal(row.resolved_by, ANALYST);
  assert.equal(row.resolved_at.toISOString(), linked.resolved_at.toISOString());
  assert.equal(row.last_ingested_at.toISOString(), linked.last_ingested_at.toISOString(),
    'unchanged source content + pinned link is not a source change');

  // Source withdraws the label: assertion historical, analyst link kept.
  await reconcileSourceAttributionsForEvidence(pool, {
    iocId: ioc.id, observableType: ioc.observable_type, feedKey: OTX.feedKey,
    evidenceRefType: 'otx_pulse', evidenceRefId: 'P1', keepLabelKeysByKind: { malware_family: [] }
  });
  [row] = await assertionRows(ioc, 'malware_family');
  assert.equal(row.assertion_status, 'withdrawn');
  assert.equal(row.entity_id, fam.id);
  assert.equal((await familySummary(pool, { familyId: fam.id }, { lifecycle: 'historical' })).all_unique, 1);
  assert.equal((await familySummary(pool, { familyId: fam.id })).all_unique, 0);

  // Source re-asserts: becomes current again, still linked by the analyst.
  await upsertSourceAttribution(pool, {
    iocId: ioc.id, observableType: ioc.observable_type, entityKind: 'malware_family', sourceLabel: label,
    feedKey: OTX.feedKey, sourceName: OTX.sourceName, evidenceRefType: 'otx_pulse', evidenceRefId: 'P1'
  });
  [row] = await assertionRows(ioc, 'malware_family');
  assert.equal(row.assertion_status, 'current');
  assert.equal(row.entity_id, fam.id);
  assert.equal(row.resolution_method, 'analyst');

  // Automatic resolution of other (non-analyst) rows still follows the catalog.
  const ioc2 = await insertIoc('domain', `reingest2.${TOKEN}.example`);
  await upsertSourceAttribution(pool, {
    iocId: ioc2.id, observableType: ioc2.observable_type, entityKind: 'malware_family', sourceLabel: `KeepMe${TOKEN}`,
    feedKey: OTX.feedKey, sourceName: OTX.sourceName, evidenceRefType: 'otx_pulse', evidenceRefId: 'P9'
  });
  const [auto] = await assertionRows(ioc2, 'malware_family');
  assert.equal(auto.entity_id, fam.id);
  assert.equal(auto.resolution_method, 'name');
  assert.equal(auto.resolved_by, null);
});

test('create + link threat actor; duplicates (name/alias/similar) are refused or need confirmation', opts, async () => {
  const apt = await insertActor(`APT28-${TOKEN}`, { aliases: [`Fancy Bear ${TOKEN}`, `Sofacy-${TOKEN}`] });
  const ioc = await insertIoc('domain', `actor.${TOKEN}.example`);
  await assertSource(ioc, 'threat_actor', `Storm-${TOKEN}`, OTX, 'P1');
  await assertSource(ioc, 'threat_actor', `fancy bear ${TOKEN}`, OTX, 'P1');

  // Analysts cannot create catalog entries.
  await rejectsCode(link(ioc, 'threat_actor', `Storm-${TOKEN}`, {
    mode: 'create', create: { name: `Storm-${TOKEN}` }, canCreate: false
  }), 'CATALOG_CREATE_FORBIDDEN');

  // Alias collision → link existing instead.
  await assert.rejects(link(ioc, 'threat_actor', `fancy bear ${TOKEN}`, {
    mode: 'create', create: { name: `Fancy Bear ${TOKEN}` }, canCreate: true
  }), (err) => err.code === 'DUPLICATE_ENTITY' && err.details.candidates[0].id === apt.id);
  // Name typed differently than the label but whose alias collides is refused too.
  await rejectsCode(link(ioc, 'threat_actor', `Storm-${TOKEN}`, {
    mode: 'create', create: { name: `Storm-${TOKEN}`, aliases: [`sofacy-${TOKEN}`] }, canCreate: true
  }), 'DUPLICATE_ENTITY');
  // Similar spelling needs explicit confirmation; never merged automatically.
  await assert.rejects(link(ioc, 'threat_actor', `Storm-${TOKEN}`, {
    mode: 'create', create: { name: `APT 28-${TOKEN}` }, canCreate: true
  }), (err) => err.code === 'POTENTIAL_DUPLICATES' && err.details.candidates.some((c) => c.id === apt.id));
  const { rows: none } = await pool.query(`SELECT 1 FROM threat_actors WHERE name = $1`, [`APT 28-${TOKEN}`]);
  assert.equal(none.length, 0, 'refused create leaves no catalog row');

  const res = await link(ioc, 'threat_actor', `Storm-${TOKEN}`, {
    mode: 'create', create: { name: `Storm-${TOKEN}`, aliases: [], description: '' }, canCreate: true
  });
  assert.equal(res.outcome, 'created_and_linked');
  created.actorIds.push(res.entity.id);
  assert.equal(res.created_entity.created_by, ANALYST);
  assert.deepEqual(res.created_entity.catalog_sources, ['manual']);
  assert.equal(res.created_entity.description, null, 'no invented description');
  assert.equal(res.created_entity.aliases, null);

  const [row] = (await assertionRows(ioc, 'threat_actor')).filter((r) => r.source_label === `Storm-${TOKEN}`);
  assert.equal(row.entity_id, res.entity.id);
  assert.equal(row.resolution_method, 'analyst');
  const { rows: analystLinks } = await pool.query(
    `SELECT 1 FROM ioc_threat_actors WHERE ioc_id = $1 AND ioc_observable_type = $2`, [ioc.id, ioc.observable_type]);
  assert.equal(analystLinks.length, 0, 'catalog linking is not analyst attribution');
  const counts = await countAssociatedIocsForActors(pool, [res.entity.id]);
  assert.deepEqual(counts.get(String(res.entity.id)), { all_unique: 1, analyst_unique: 0, source_unique: 1 });
  assert.equal((await actorSummary(pool, { actorId: res.entity.id })).source_unique, 1);

  // Retry of the same create → existing result, still exactly one catalog row.
  const retry = await link(ioc, 'threat_actor', `Storm-${TOKEN}`, {
    mode: 'create', create: { name: `Storm-${TOKEN}` }, canCreate: true
  });
  assert.equal(retry.outcome, 'already_linked');
  assert.equal(retry.entity.id, res.entity.id);
  const { rows: one } = await pool.query(`SELECT id FROM threat_actors WHERE lower(name) = lower($1)`, [`Storm-${TOKEN}`]);
  assert.equal(one.length, 1);

  // Linking the alias-reported label to the existing actor.
  const aliasLink = await link(ioc, 'threat_actor', `fancy bear ${TOKEN}`, { mode: 'link', entityId: apt.id });
  assert.equal(aliasLink.outcome, 'linked');
  const fields = await fetchEffectiveIocAttributions(pool, ioc.id, ioc.observable_type);
  assert.deepEqual(fields.threat_actors.map((a) => a.id).sort(), [apt.id, res.entity.id].sort());
  assert.ok(fields.threat_actors.every((a) => a.attribution === 'source_reported'));
});

test('concurrent create requests: one entity, one link, the other gets the resolved result', opts, async () => {
  const ioc = await insertIoc('domain', `race.${TOKEN}.example`);
  const label = `RaceRAT-${TOKEN}`;
  await assertSource(ioc, 'malware_family', label, OTX, 'P1');
  const req = () => link(ioc, 'malware_family', label, { mode: 'create', create: { name: label }, canCreate: true });
  const results = await Promise.allSettled([req(), req(), req()]);
  const ok = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  assert.equal(ok.length, 3, JSON.stringify(results.map((r) => r.reason?.message)));
  assert.deepEqual(ok.map((r) => r.outcome).sort(), ['already_linked', 'already_linked', 'created_and_linked']);
  assert.equal(new Set(ok.map((r) => r.entity.id)).size, 1);
  const { rows } = await pool.query(`SELECT id FROM malware_families WHERE lower(name) = lower($1)`, [label]);
  assert.equal(rows.length, 1);
  created.familyIds.push(rows[0].id);

  // Two IOCs creating the same new name at once: one creates, the other must link.
  const iocA = await insertIoc('domain', `race-a.${TOKEN}.example`);
  const iocB = await insertIoc('domain', `race-b.${TOKEN}.example`);
  const twin = `TwinRace-${TOKEN}`;
  await assertSource(iocA, 'malware_family', twin, OTX, 'PA');
  await assertSource(iocB, 'malware_family', twin, OTHER, 'PB');
  const pair = await Promise.allSettled([iocA, iocB].map((i) => link(i, 'malware_family', twin, {
    mode: 'create', create: { name: twin }, canCreate: true
  })));
  const won = pair.filter((r) => r.status === 'fulfilled');
  const lost = pair.filter((r) => r.status === 'rejected');
  assert.equal(won.length, 1);
  assert.equal(lost.length, 1);
  assert.equal(lost[0].reason.code, 'DUPLICATE_ENTITY');
  assert.equal(lost[0].reason.details.candidates[0].id, won[0].value.entity.id);
  created.familyIds.push(won[0].value.entity.id);
});

test('transaction failure rolls back the created entity and the link', opts, async () => {
  const ioc = await insertIoc('domain', `rollback.${TOKEN}.example`);
  const label = `RollbackRAT-${TOKEN}`;
  await assertSource(ioc, 'malware_family', label, OTX, 'P1');
  // Pool whose clients fail on the assertion UPDATE (after the catalog INSERT).
  const failing = {
    async connect() {
      const c = await pool.connect();
      return {
        query: (sql, params) => (String(sql).includes('UPDATE ioc_source_attributions')
          ? Promise.reject(new Error('simulated failure'))
          : c.query(sql, params)),
        release: () => c.release()
      };
    }
  };
  await assert.rejects(linkSourceLabelToCatalog(failing, {
    iocId: ioc.id, observableType: ioc.observable_type, entityKind: 'malware_family', sourceLabel: label,
    mode: 'create', create: { name: label }, canCreate: true, actorLabel: ANALYST
  }), /simulated failure/);
  const { rows } = await pool.query(`SELECT 1 FROM malware_families WHERE name = $1`, [label]);
  assert.equal(rows.length, 0);
  const [row] = await assertionRows(ioc, 'malware_family');
  assert.equal(row.entity_id, null);
  assert.equal(row.resolution_method, null);
});

test('invalid targets: inactive entity, unknown entity, suppressed/withdrawn-only label', opts, async () => {
  const inactive = await insertFamily(`Disabled-${TOKEN}`, { active: false });
  const ioc = await insertIoc('domain', `invalid.${TOKEN}.example`);
  await assertSource(ioc, 'malware_family', `Lbl-${TOKEN}`, OTX, 'P1');
  await assertSource(ioc, 'malware_family', `Gone-${TOKEN}`, OTX, 'P1', { status: 'withdrawn' });
  await rejectsCode(link(ioc, 'malware_family', `Lbl-${TOKEN}`, { mode: 'link', entityId: inactive.id }), 'ENTITY_INACTIVE');
  await rejectsCode(link(ioc, 'malware_family', `Lbl-${TOKEN}`, {
    mode: 'link', entityId: '00000000-0000-4000-8000-000000000000'
  }), 'ENTITY_NOT_FOUND');
  await rejectsCode(link(ioc, 'malware_family', `Gone-${TOKEN}`, { mode: 'link', entityId: inactive.id }), 'SOURCE_LABEL_NOT_FOUND');
  await rejectsCode(link(ioc, 'malware_family', `Missing-${TOKEN}`, { mode: 'link', entityId: inactive.id }), 'SOURCE_LABEL_NOT_FOUND');
  await rejectsCode(link({ id: ioc.id, observable_type: 'ip' }, 'malware_family', `Lbl-${TOKEN}`, {
    mode: 'link', entityId: inactive.id
  }), 'IOC_NOT_FOUND');
  // Wrong kind for a label that only exists as a malware family.
  await rejectsCode(link(ioc, 'threat_actor', `Lbl-${TOKEN}`, { mode: 'link', entityId: inactive.id }), 'SOURCE_LABEL_NOT_FOUND');

  await pool.query(
    `INSERT INTO ioc_attribution_overrides (ioc_id, ioc_observable_type, entity_kind, source_label_normalized, action, created_by)
     VALUES ($1, $2, 'malware_family', lower($3), 'suppress', 'itest')`,
    [ioc.id, ioc.observable_type, `Lbl-${TOKEN}`]
  );
  await rejectsCode(link(ioc, 'malware_family', `Lbl-${TOKEN}`, { mode: 'link', entityId: inactive.id }), 'SOURCE_LABEL_NOT_FOUND');
});

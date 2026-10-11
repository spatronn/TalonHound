import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerIocThreatMetadataRoutes } from './iocThreatMetadata.js';
import { AUDIT_ACTION, AUDIT_ENTITY } from '../lib/auditConstants.js';
import { CatalogLinkError, linkSourceLabelToCatalog } from '../lib/attributionCatalogLinking.js';
import { ROLES, rbacHttpPolicy } from '../lib/rbac.js';

const ADMIN = { role: ROLES.ADMIN, email: 'admin@example.com' };
const ANALYST = { role: ROLES.ANALYST, email: 'analyst@example.com' };
const READONLY = { role: ROLES.READONLY, email: 'ro@example.com' };

const IOC = { id: 42, public_id: '0f0e0d0c-0000-4000-8000-000000000042', observable: 'evil.example', observable_type: 'domain' };
const FAMILY = { id: '11111111-1111-4111-8111-111111111111', name: 'PureRAT', slug: 'purerat', aliases: [], active: true, attack_id: null };
const EVIDENCE = [
  { source_name: 'AlienVault OTX', feed_key: 'alienvault-otx', evidence_ref_type: 'otx_pulse', evidence_ref_id: 'p1', evidence_title: 'Pulse 1', assertion_status: 'current' },
  { source_name: 'Other Feed', feed_key: 'other', evidence_ref_type: 'report', evidence_ref_id: 'r9', evidence_title: null, assertion_status: 'current' }
];

function failingPool() {
  return {
    connect: async () => { throw new Error('pool must not be used'); },
    query: async () => { throw new Error('pool must not be used'); }
  };
}

async function withServer({ user, catalogLinking, pool = failingPool() }, fn) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.user = user; next(); });
  // Same global write policy as server.js (read-only role: GET only).
  app.use(rbacHttpPolicy);
  const audit = { events: [], auditSuccess: async (e) => { audit.events.push(e); } };
  const invalidated = [];
  registerIocThreatMetadataRoutes(app, pool, audit, {
    invalidateDetailsCache: (publicId) => invalidated.push(publicId),
    catalogLinking: {
      loadAttributionFields: async () => ({ malware_families: [{ id: FAMILY.id, name: FAMILY.name, attribution: 'source_reported' }] }),
      ...catalogLinking
    }
  });
  await new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        await fn(`http://127.0.0.1:${port}`, { audit, invalidated });
      } finally {
        server.close(resolve);
      }
    });
  });
}

function post(base, body) {
  return fetch(`${base}/api/ioc/${IOC.id}/source-attributions/catalog-link`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
}

const LINK_BODY = { observable_type: 'domain', entity_kind: 'malware_family', source_label: 'PureRAT', mode: 'link', entity_id: FAMILY.id };

test('read-only users cannot link or create (403) and the service is never called', async () => {
  let called = 0;
  await withServer({ user: READONLY, catalogLinking: { link: async () => { called += 1; } } }, async (base) => {
    assert.equal((await post(base, LINK_BODY)).status, 403);
    assert.equal((await post(base, { ...LINK_BODY, mode: 'create', create: { name: 'PureRAT' } })).status, 403);
  });
  assert.equal(called, 0);
});

test('analyst create is refused before any database work (catalog writes stay admin-only)', async () => {
  await withServer({ user: ANALYST, catalogLinking: { link: linkSourceLabelToCatalog } }, async (base, { audit }) => {
    const res = await post(base, { ...LINK_BODY, mode: 'create', create: { name: 'PureRAT' }, entity_id: undefined });
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.code, 'CATALOG_CREATE_FORBIDDEN');
    assert.equal(audit.events.length, 0);
  });
});

test('analyst link: passes verified identity to the service, audits once, invalidates details cache', async () => {
  let received = null;
  const link = async (_pool, input) => {
    received = input;
    return {
      outcome: 'linked', ioc: IOC, entity: FAMILY, created_entity: null, linked_assertions: 2,
      evidence: EVIDENCE, source_label: 'PureRAT', source_label_key: 'purerat'
    };
  };
  await withServer({ user: ANALYST, catalogLinking: { link } }, async (base, { audit, invalidated }) => {
    // Client-supplied provenance is ignored: only IOC, kind, label and target reach the service.
    const res = await post(base, { ...LINK_BODY, source_name: 'Forged Feed', evidence_ref_id: 'forged', create: { name: 'X' } });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.outcome, 'linked');
    assert.equal(body.entity.id, FAMILY.id);
    assert.equal(body.linked_assertions, 2);
    assert.equal(body.malware_families[0].attribution, 'source_reported');
    assert.equal(received.canCreate, false);
    assert.equal(received.create, null);
    assert.equal(received.actorLabel, 'analyst@example.com');
    assert.equal(received.sourceName, undefined);
    assert.deepEqual(invalidated, [IOC.public_id]);
    assert.equal(audit.events.length, 1);
    const ev = audit.events[0];
    assert.equal(ev.action, AUDIT_ACTION.IOC_MALWARE_FAMILY_CATALOG_LINKED);
    assert.equal(ev.entityType, AUDIT_ENTITY.IOC);
    assert.equal(ev.entityId, '42');
    assert.equal(ev.metadata.entity_id, FAMILY.id);
    assert.equal(ev.metadata.entity_name, 'PureRAT');
    assert.equal(ev.metadata.source_label, 'PureRAT');
    assert.equal(ev.metadata.operation, 'link');
    assert.equal(ev.metadata.resolution_method, 'analyst');
    assert.equal(ev.metadata.attribution, 'source_reported');
    // Independent provenance of every source is recorded.
    assert.deepEqual(ev.metadata.sources.map((s) => s.source_name), ['AlienVault OTX', 'Other Feed']);
  });
});

test('admin create-and-link: catalog created event + IOC event (threat actor)', async () => {
  const actor = { id: '22222222-2222-4222-8222-222222222222', name: 'Storm-9999', slug: 'storm-9999', aliases: [], active: true };
  const link = async (_pool, input) => {
    assert.equal(input.canCreate, true);
    assert.equal(input.mode, 'create');
    assert.equal(input.entityId, null);
    assert.deepEqual(input.create, { name: 'Storm-9999', aliases: [] });
    assert.equal(input.confirmDistinct, true);
    return {
      outcome: 'created_and_linked', ioc: IOC, entity: actor,
      created_entity: { ...actor, catalog_sources: ['manual'], description: null },
      linked_assertions: 1, evidence: EVIDENCE.slice(0, 1), source_label: 'Storm-9999', source_label_key: 'storm-9999'
    };
  };
  await withServer({ user: ADMIN, catalogLinking: { link } }, async (base, { audit }) => {
    const res = await post(base, {
      observable_type: 'domain', entity_kind: 'threat_actor', source_label: 'Storm-9999',
      mode: 'create', create: { name: 'Storm-9999', aliases: [] }, confirm_distinct: true
    });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).created, true);
    assert.deepEqual(audit.events.map((e) => e.action), [
      AUDIT_ACTION.THREAT_ACTOR_CREATED,
      AUDIT_ACTION.IOC_THREAT_ACTOR_CATALOG_CREATED_AND_LINKED
    ]);
    assert.equal(audit.events[0].entityType, AUDIT_ENTITY.THREAT_ACTOR);
    assert.equal(audit.events[0].metadata.origin, 'ioc_source_label_link');
    assert.equal(audit.events[1].metadata.operation, 'create_and_link');
  });
});

test('idempotent retry (already_linked): success, no audit, no cache churn', async () => {
  const link = async () => ({
    outcome: 'already_linked', ioc: IOC, entity: FAMILY, created_entity: null, linked_assertions: 0,
    evidence: EVIDENCE, source_label: 'PureRAT', source_label_key: 'purerat'
  });
  await withServer({ user: ANALYST, catalogLinking: { link } }, async (base, { audit, invalidated }) => {
    const res = await post(base, LINK_BODY);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).outcome, 'already_linked');
    assert.equal(audit.events.length, 0);
    assert.deepEqual(invalidated, []);
  });
});

test('service errors map to status + code + details (duplicates are actionable)', async () => {
  const link = async () => {
    throw new CatalogLinkError(409, 'DUPLICATE_ENTITY', 'exists', { candidates: [{ id: FAMILY.id, name: 'PureRAT', exact: true }] });
  };
  await withServer({ user: ADMIN, catalogLinking: { link } }, async (base, { audit }) => {
    const res = await post(base, { ...LINK_BODY, mode: 'create', create: { name: 'purerat' } });
    assert.equal(res.status, 409);
    const body = await res.json();
    assert.equal(body.success, false);
    assert.equal(body.code, 'DUPLICATE_ENTITY');
    assert.equal(body.candidates[0].id, FAMILY.id);
    assert.equal(audit.events.length, 0);
  });
});

test('GET catalog-candidates is readable by every role and reports permissions', async () => {
  const loadContext = async (_pool, input) => {
    assert.equal(input.entityKind, 'threat_actor');
    assert.equal(input.sourceLabel, 'Fancy Bear');
    assert.equal(input.q, 'apt');
    return {
      ioc: IOC, entity_kind: 'threat_actor', source_label: 'Fancy Bear', source_label_key: 'fancy bear',
      link_state: 'unlinked', linked_entities: [], evidence: EVIDENCE, evidence_total: 2,
      candidates: [], exact_candidate_ids: [], create_prefill: { name: 'Fancy Bear' }
    };
  };
  const url = (base) => `${base}/api/ioc/42/source-attributions/catalog-candidates?observable_type=domain&entity_kind=threat_actor&source_label=Fancy%20Bear&q=apt`;
  for (const [user, perms] of [
    [READONLY, { can_link: false, can_create: false }],
    [ANALYST, { can_link: true, can_create: false }],
    [ADMIN, { can_link: true, can_create: true }]
  ]) {
    await withServer({ user, catalogLinking: { loadContext } }, async (base) => {
      const res = await fetch(url(base));
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.deepEqual(body.permissions, perms);
      assert.equal(body.public_id, IOC.public_id);
      assert.equal(body.ioc, undefined);
    });
  }
});

test('GET catalog-candidates validates input (no DB access for invalid kind)', async () => {
  await withServer({ user: ANALYST, catalogLinking: {} }, async (base) => {
    const res = await fetch(`${base}/api/ioc/42/source-attributions/catalog-candidates?observable_type=domain&entity_kind=campaign&source_label=x`);
    assert.equal(res.status, 400);
    assert.equal((await res.json()).code, 'INVALID_ENTITY_KIND');
  });
});

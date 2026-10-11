import test from 'node:test';
import assert from 'node:assert/strict';
import {
  countAssociatedIocsForActors,
  resolveActorReference,
  serializeActorIdentity
} from './iocDiscovery.js';

test('countAssociatedIocsForActors returns empty map for no ids (no query)', async () => {
  let called = 0;
  const client = { query: async () => { called += 1; return { rows: [] }; } };
  const map = await countAssociatedIocsForActors(client, []);
  assert.equal(map.size, 0);
  assert.equal(called, 0);
});

test('countAssociatedIocsForActors ignores invalid ids and batches once', async () => {
  const captured = [];
  const a = '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6';
  const b = '364117ec-9e72-4531-956a-ba7f013f1b45';
  const client = {
    async query(sql, params) {
      captured.push({ sql: String(sql), params });
      return {
        rows: [
          { actor_id: a, all_unique: 34, analyst_unique: 2, source_unique: 33, direct_unique: 3, context_unique: 32 }
        ]
      };
    }
  };
  const map = await countAssociatedIocsForActors(client, [a, 'not-uuid', a, b]);
  assert.equal(captured.length, 1, 'single grouped query');
  assert.match(captured[0].sql, /ioc_threat_actors/);
  assert.match(captured[0].sql, /entity_kind = 'threat_actor'/);
  assert.match(captured[0].sql, /ANY\(\$1::uuid\[\]\)/);
  assert.deepEqual(captured[0].params[0].sort(), [a, b].sort());
  assert.deepEqual(map.get(a), { all_unique: 34, analyst_unique: 2, source_unique: 33, direct_unique: 3, context_unique: 32 });
  assert.match(captured[0].sql, /AS has_direct/);
  assert.match(captured[0].sql, /AS has_context/);
  assert.equal(map.has(b), false, 'actors with zero links omitted from SQL result');
});

test('resolveActorReference validates UUID and resolves by id', async () => {
  const actor = {
    id: '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6',
    name: 'APT28',
    slug: 'apt28',
    aliases: ['Fancy Bear'],
    description: null,
    active: false,
    catalog_sources: ['bundled']
  };
  const client = {
    async query(_sql, params) {
      assert.equal(params[0], actor.id);
      return { rows: [actor] };
    }
  };
  assert.equal((await resolveActorReference(client, { id: 'bad' })).code, 'INVALID_ID');
  const ok = await resolveActorReference(client, { id: actor.id });
  assert.equal(ok.ok, true);
  assert.equal(ok.actor.name, 'APT28');
  assert.equal(ok.actor.active, false);
});

test('resolveActorReference resolves exact alias and reports ambiguity', async () => {
  const rows = [
    { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: 'A', slug: 'a', aliases: ['Shared'], active: true },
    { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', name: 'B', slug: 'b', aliases: ['Shared'], active: true }
  ];
  const client = {
    async query() {
      return { rows };
    }
  };
  const ambiguous = await resolveActorReference(client, { name: 'Shared' });
  assert.equal(ambiguous.ok, false);
  assert.equal(ambiguous.code, 'AMBIGUOUS');

  const singleClient = {
    async query() {
      return { rows: [rows[0]] };
    }
  };
  const byAlias = await resolveActorReference(singleClient, { name: 'Shared' });
  assert.equal(byAlias.ok, true);
  assert.equal(byAlias.matched_by, 'alias');
});

test('serializeActorIdentity keeps inactive flag and aliases', () => {
  assert.equal(serializeActorIdentity(null), null);
  assert.deepEqual(serializeActorIdentity({
    id: '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6',
    name: 'APT28',
    slug: 'apt28',
    aliases: ['Fancy Bear'],
    description: 'desc',
    active: false,
    catalog_sources: ['bundled']
  }), {
    id: '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6',
    name: 'APT28',
    slug: 'apt28',
    aliases: ['Fancy Bear'],
    description: 'desc',
    active: false,
    catalog_sources: ['bundled']
  });
});

test('relationship scope: parsed, supersedes legacy filters, filters identities in HAVING', async () => {
  const { parseDiscoveryOptions, relationshipScopesOf, queryDiscoveryPage: familyPage } = await import('../malwareFamilies/iocDiscovery.js');
  const { queryDiscoveryPage: actorPage } = await import('./iocDiscovery.js');
  assert.equal(parseDiscoveryOptions({}).scope, 'all');
  assert.equal(parseDiscoveryOptions({ scope: 'DIRECT' }).scope, 'direct');
  assert.equal(parseDiscoveryOptions({ scope: 'bogus' }).scope, 'all');
  const scoped = parseDiscoveryOptions({ scope: 'context', origin: 'analyst', association: 'direct' });
  assert.equal(scoped.origin, 'all');
  assert.equal(scoped.association, 'all');
  // Legacy-only requests keep their meaning (no scope reported).
  assert.equal(parseDiscoveryOptions({ origin: 'analyst' }).scope, null);
  assert.deepEqual(relationshipScopesOf({ has_direct: true, has_context: true, has_analyst: false }), ['direct', 'context']);
  assert.deepEqual(relationshipScopesOf({ has_analyst: true }), ['analyst']);

  for (const [page, target, sampleKinds] of [
    [familyPage, { familyId: '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6' }, /malware_sample_of/],
    [actorPage, { actorId: '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6' }, null]
  ]) {
    const captured = [];
    await page({ async query(sql, params) { captured.push({ sql: String(sql), params }); return { rows: [] }; } },
      target, parseDiscoveryOptions({ scope: 'direct' }));
    assert.equal(captured[0].params[11], 'direct');
    assert.equal(captured[0].params[2], true, 'analyst links still loaded so a direct IOC keeps its analyst scope');
    assert.match(captured[0].sql, /HAVING[\s\S]*\$12::text = 'direct'/);
    assert.match(captured[0].sql, /AS has_direct/);
    if (sampleKinds) assert.match(captured[0].sql, sampleKinds);
    else assert.doesNotMatch(captured[0].sql, /malware_sample_of/);
  }
});

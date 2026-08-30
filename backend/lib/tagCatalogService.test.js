import test from 'node:test';
import assert from 'node:assert/strict';
import {
  aggregateTagSources,
  ensureCatalogTag,
  ensureIocTagAssignment,
  parseRawTagsFromNote,
  syncIntegrationTagsFromNote
} from './tagCatalogService.js';

function makeClient(handlers) {
  const queries = [];
  return {
    queries,
    async query(sql, params = []) {
      const norm = String(sql).replace(/\s+/g, ' ').trim();
      queries.push({ sql: norm, params: [...params] });
      for (const h of handlers) {
        if (h.match(norm, params)) return h.respond(norm, params);
      }
      throw new Error(`Unexpected query: ${norm.slice(0, 160)}`);
    }
  };
}

test('parseRawTagsFromNote extracts tags= CSV', () => {
  assert.deepEqual(
    parseRawTagsFromNote('Auto | tags=Mirai, elf ,C2 | signature=x'),
    ['Mirai', 'elf', 'C2']
  );
  assert.deepEqual(parseRawTagsFromNote('no tags here'), []);
  assert.deepEqual(parseRawTagsFromNote(null), []);
});

test('ensureCatalogTag creates new tag once and reuses canonical name', async () => {
  let existing = null;
  const client = makeClient([
    {
      match: (sql) => sql.includes('SELECT') && sql.includes('FROM tags WHERE name'),
      respond: () => ({ rows: existing ? [existing] : [] })
    },
    {
      match: (sql) => sql.includes('SELECT id FROM tags WHERE slug'),
      respond: () => ({ rows: [] })
    },
    {
      match: (sql) => sql.startsWith('INSERT INTO tags'),
      respond: (_sql, params) => {
        existing = {
          id: 11,
          name: params[0],
          slug: params[1],
          description: null,
          color: null,
          category: params[3],
          type: params[2],
          enabled: true,
          created_origin: params[7],
          created_at: 't0',
          updated_at: 't0'
        };
        return { rows: [existing], rowCount: 1 };
      }
    }
  ]);

  const first = await ensureCatalogTag(client, { name: '  Mirai ', createdOrigin: 'integration' });
  assert.equal(first.created, true);
  assert.equal(first.tag.name, 'mirai');

  const second = await ensureCatalogTag(client, { name: 'MIRAI', createdOrigin: 'manual' });
  assert.equal(second.created, false);
  assert.equal(second.existing, true);
  assert.equal(second.tag.id, 11);
  assert.equal(client.queries.filter((q) => q.sql.startsWith('INSERT INTO tags')).length, 1);
});

test('ensureCatalogTag applies internal "custom" default when category omitted', async () => {
  let inserted = null;
  const client = makeClient([
    {
      match: (sql) => sql.includes('FROM tags WHERE name'),
      respond: () => ({ rows: inserted ? [inserted] : [] })
    },
    {
      match: (sql) => sql.includes('SELECT id FROM tags WHERE slug'),
      respond: () => ({ rows: [] })
    },
    {
      match: (sql) => sql.startsWith('INSERT INTO tags'),
      respond: (_sql, params) => {
        inserted = {
          id: 21,
          name: params[0],
          slug: params[1],
          description: params[4],
          color: params[5],
          category: params[3],
          type: params[2],
          enabled: params[6],
          created_origin: params[7],
          created_at: 't',
          updated_at: 't'
        };
        return { rows: [inserted], rowCount: 1 };
      }
    }
  ]);

  // Simulates POST /admin/tags with only name/color/active — no category.
  const result = await ensureCatalogTag(client, { name: 'ransomware', color: '#ef4444' });
  assert.equal(result.created, true);
  assert.equal(result.tag.category, 'custom');
  const insert = client.queries.find((q) => q.sql.startsWith('INSERT INTO tags'));
  assert.equal(insert.params[3], 'custom'); // category column still populated
  assert.equal(insert.params[2], 'context'); // legacy type derived from custom
});

test('ensureCatalogTag coerces an invalid category to the internal default', async () => {
  let inserted = null;
  const client = makeClient([
    {
      match: (sql) => sql.includes('FROM tags WHERE name'),
      respond: () => ({ rows: inserted ? [inserted] : [] })
    },
    {
      match: (sql) => sql.includes('SELECT id FROM tags WHERE slug'),
      respond: () => ({ rows: [] })
    },
    {
      match: (sql) => sql.startsWith('INSERT INTO tags'),
      respond: (_sql, params) => {
        inserted = { id: 22, name: params[0], slug: params[1], category: params[3], type: params[2], enabled: params[6], created_origin: params[7] };
        return { rows: [inserted], rowCount: 1 };
      }
    }
  ]);

  const result = await ensureCatalogTag(client, { name: 'weird', category: 'not-a-real-category' });
  assert.equal(result.tag.category, 'custom');
});

test('ensureCatalogTag does not flip enabled on inactive reuse', async () => {
  const inactive = {
    id: 3,
    name: 'c2',
    slug: 'c2',
    description: 'legacy',
    color: null,
    category: 'malware',
    type: 'threat',
    enabled: false,
    created_origin: 'manual',
    created_at: 't0',
    updated_at: 't0'
  };
  const client = makeClient([
    {
      match: (sql) => sql.includes('FROM tags WHERE name'),
      respond: () => ({ rows: [inactive] })
    }
  ]);
  const result = await ensureCatalogTag(client, { name: 'C2', createdOrigin: 'integration' });
  assert.equal(result.existing, true);
  assert.equal(result.tag.enabled, false);
  assert.ok(!client.queries.some((q) => q.sql.includes('UPDATE tags')));
});

test('ensureIocTagAssignment allows manual and two integration sources', async () => {
  const inserts = [];
  const client = makeClient([
    {
      match: (sql) => sql.includes('INSERT INTO ioc_tags'),
      respond: (sql, params) => {
        inserts.push({ sql, params });
        return { rows: [{ tag_id: params[2] }], rowCount: 1 };
      }
    }
  ]);

  await ensureIocTagAssignment(client, {
    iocId: 1, observableType: 'ip', tagId: 9, origin: 'manual', createdBy: 5
  });
  await ensureIocTagAssignment(client, {
    iocId: 1, observableType: 'ip', tagId: 9, origin: 'integration', sourceName: 'URLhaus abuse.ch'
  });
  await ensureIocTagAssignment(client, {
    iocId: 1, observableType: 'ip', tagId: 9, origin: 'integration', sourceName: 'ThreatFox abuse.ch'
  });
  assert.equal(inserts.length, 3);
  assert.equal(inserts[0].params[3], 5);
  assert.equal(inserts[1].params[3], 'URLhaus abuse.ch');
});

test('ensureIocTagAssignment duplicate manual is no-op', async () => {
  const client = makeClient([
    {
      match: (sql) => sql.includes('INSERT INTO ioc_tags'),
      respond: () => ({ rows: [], rowCount: 0 })
    }
  ]);
  const res = await ensureIocTagAssignment(client, {
    iocId: 1, observableType: 'domain', tagId: 2, origin: 'manual'
  });
  assert.equal(res.inserted, false);
});

test('syncIntegrationTagsFromNote creates catalog links without reactivating', async () => {
  const tagsByName = new Map([
    ['c2', {
      id: 1, name: 'c2', slug: 'c2', description: null, color: null, category: 'malware',
      type: 'threat', enabled: false, created_origin: 'manual', created_at: 't', updated_at: 't'
    }]
  ]);
  const assignments = [];
  const client = makeClient([
    {
      match: (sql) => sql.includes('FROM tags WHERE name'),
      respond: (_sql, params) => ({ rows: tagsByName.has(params[0]) ? [tagsByName.get(params[0])] : [] })
    },
    {
      match: (sql) => sql.includes('SELECT id FROM tags WHERE slug'),
      respond: () => ({ rows: [] })
    },
    {
      match: (sql) => sql.startsWith('INSERT INTO tags'),
      respond: (_sql, params) => {
        const row = {
          id: 50 + tagsByName.size,
          name: params[0],
          slug: params[1],
          description: null,
          color: null,
          category: params[3],
          type: params[2],
          enabled: true,
          created_origin: params[7],
          created_at: 't',
          updated_at: 't'
        };
        tagsByName.set(row.name, row);
        return { rows: [row], rowCount: 1 };
      }
    },
    {
      match: (sql) => sql.includes('INSERT INTO ioc_tags'),
      respond: (_sql, params) => {
        assignments.push(params);
        return { rows: [{ tag_id: params[2] }], rowCount: 1 };
      }
    }
  ]);

  const res = await syncIntegrationTagsFromNote(client, {
    iocId: 42,
    observableType: 'url',
    sourceName: 'URLhaus abuse.ch',
    note: 'Auto-imported | tags=Mirai,C2,mirai | url_status=online'
  });

  // Raw list is Mirai,C2,mirai — each row is processed; catalog reuses mirai.
  assert.equal(res.synced, 3);
  assert.equal(assignments.length, 3);
  assert.equal(tagsByName.get('c2').enabled, false);
  assert.ok(tagsByName.get('mirai'));
  assert.equal(tagsByName.get('mirai').created_origin, 'integration');
});

test('filterFeedIntelligenceByDisabledTags drops disabled catalog names', async () => {
  const { filterFeedIntelligenceByDisabledTags } = await import('./tagCatalogService.js');
  const fi = {
    classifications: [],
    tags: [
      { tag: 'elf', normalized: 'elf', origin: 'feed', source_name: 'URLhaus' },
      { tag: 'c2', normalized: 'c2', origin: 'feed', source_name: 'URLhaus' }
    ]
  };
  const filtered = filterFeedIntelligenceByDisabledTags(fi, new Set(['c2']));
  assert.equal(filtered.tags.length, 1);
  assert.equal(filtered.tags[0].normalized, 'elf');
});

test('aggregateTagSources merges Manual and feed names', () => {
  assert.deepEqual(
    aggregateTagSources({
      created_origin: 'manual',
      assignment_origins: ['manual', 'integration'],
      assignment_sources: ['URLhaus abuse.ch', null, 'ThreatFox abuse.ch']
    }),
    ['Manual', 'ThreatFox abuse.ch', 'URLhaus abuse.ch']
  );
  assert.deepEqual(
    aggregateTagSources({
      created_origin: 'integration',
      assignment_origins: ['integration'],
      assignment_sources: ['MalwareBazaar abuse.ch']
    }),
    ['MalwareBazaar abuse.ch']
  );
});

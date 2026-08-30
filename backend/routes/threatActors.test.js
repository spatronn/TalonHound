import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerThreatActorRoutes } from './threatActors.js';
import { AUDIT_ACTION } from '../lib/auditConstants.js';
import { ROLES } from '../lib/rbac.js';

const ADMIN = { role: ROLES.ADMIN, id: 1, email: 'admin@example.com', username: 'admin@example.com' };
const VIEWER = { role: 'viewer', id: 2, email: 'viewer@example.com', username: 'viewer@example.com' };

function createMockPool(store) {
  async function query(sql, params = []) {
    const s = String(sql);

    if (s.includes('SELECT * FROM threat_actors WHERE id = $1::uuid')) {
      const row = store.find((item) => item.id === params[0]);
      return { rows: row ? [{ ...row }] : [] };
    }

    if (s.includes('SELECT id FROM threat_actors WHERE (lower(name) = lower($1) OR slug = $2)')) {
      const row = store.find((item) => (
        item.name.toLowerCase() === String(params[0]).toLowerCase()
        || item.slug === params[1]
      ) && item.id !== params[2]);
      return { rows: row ? [{ id: row.id }] : [] };
    }

    if (s.includes('UPDATE threat_actors') && s.includes('bundled_catalog_collision_pending')) {
      const row = store.find((item) => item.id === params[0]);
      row.name = params[1];
      row.slug = params[2];
      row.aliases = params[3];
      row.description = params[4];
      row.active = params[5];
      row.catalog_sources = params[6];
      row.bundled_catalog_collision_pending = params[7];
      row.updated_by = params[8];
      row.updated_at = new Date().toISOString();
      return { rows: [{ ...row }] };
    }

    if (s.includes('COUNT(*)::int AS total_items FROM threat_actors ta')) {
      let rows = [...store];
      if (s.includes('ta.active = TRUE')) rows = rows.filter((r) => r.active);
      const hasSearch = s.includes('unnest(COALESCE(ta.aliases');
      const search = hasSearch ? params[0] : null;
      if (search) {
        rows = rows.filter((r) => {
          const hay = [
            r.name,
            r.description || '',
            ...(r.aliases || [])
          ].join(' ').toLowerCase();
          return hay.includes(String(search).toLowerCase());
        });
      }
      return { rows: [{ total_items: rows.length }] };
    }

    if (s.includes('FROM threat_actors ta') && s.includes('LIMIT')) {
      let rows = [...store];
      if (s.includes('ta.active = TRUE')) rows = rows.filter((r) => r.active);
      const hasSearch = s.includes('unnest(COALESCE(ta.aliases');
      const search = hasSearch ? params[0] : null;
      const limit = Number(params[params.length - 2]);
      const offset = Number(params[params.length - 1]);
      if (search) {
        rows = rows.filter((r) => {
          const hay = [
            r.name,
            r.description || '',
            ...(r.aliases || [])
          ].join(' ').toLowerCase();
          return hay.includes(String(search).toLowerCase());
        });
      }
      rows.sort((a, b) => Number(b.active) - Number(a.active) || a.name.localeCompare(b.name));
      return { rows: rows.slice(offset, offset + limit) };
    }

    throw new Error(`Unhandled SQL in mock pool: ${s}`);
  }

  return { query };
}

async function withServer(store, fn, { user = ADMIN } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = user;
    next();
  });
  const audit = {
    events: [],
    auditSuccess: async (payload) => {
      audit.events.push(payload);
    }
  };
  registerThreatActorRoutes(app, createMockPool(store), audit);

  await new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        await fn(`http://127.0.0.1:${port}`, audit);
      } finally {
        server.close(resolve);
      }
    });
  });
}

test('GET /api/admin/threat-actors returns pagination metadata', async () => {
  const store = Array.from({ length: 30 }, (_, i) => ({
    id: `00000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}`,
    name: `Actor ${i + 1}`,
    slug: `actor-${i + 1}`,
    aliases: i === 0 ? ['Alias Zero'] : [],
    description: null,
    active: true,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
    created_by: null,
    updated_by: null
  }));

  await withServer(store, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/api/admin/threat-actors?page=2&page_size=10`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.threat_actors.length, 10);
    assert.equal(data.pagination.page, 2);
    assert.equal(data.pagination.total_items, 30);
    assert.equal(data.pagination.total_pages, 3);
  });
});

test('GET /api/admin/threat-actors searches aliases', async () => {
  const store = [
    {
      id: '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6',
      name: 'APT28',
      slug: 'apt28',
      aliases: ['Fancy Bear', 'Sofacy'],
      description: null,
      active: true,
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-01T00:00:00.000Z',
      created_by: null,
      updated_by: null
    },
    {
      id: '364117ec-9e72-4531-956a-ba7f013f1b45',
      name: 'Lazarus',
      slug: 'lazarus',
      aliases: ['Lazarus Group', 'HIDDEN COBRA'],
      description: null,
      active: true,
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-01T00:00:00.000Z',
      created_by: null,
      updated_by: null
    }
  ];

  await withServer(store, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/api/admin/threat-actors?search=hidden%20cobra`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.threat_actors.length, 1);
    assert.equal(data.threat_actors[0].name, 'Lazarus');
  });
});

const PENDING_XYZ = {
  id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  name: 'XYZ',
  slug: 'xyz',
  aliases: ['Internal Alias'],
  description: 'Internal/local description',
  active: false,
  catalog_sources: ['manual'],
  bundled_catalog_collision_pending: true,
  created_at: '2026-01-01T00:00:00.000Z',
  updated_at: '2026-01-01T00:00:00.000Z',
  created_by: 'analyst@example.com',
  updated_by: 'bundled-seed'
};

test('PATCH confirm_bundled_catalog confirms pending collision and writes audit entry', async () => {
  const store = [structuredClone(PENDING_XYZ)];
  await withServer(store, async (baseUrl, audit) => {
    const res = await fetch(`${baseUrl}/api/admin/threat-actors/${PENDING_XYZ.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ confirm_bundled_catalog: true })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.deepEqual(data.threat_actor.catalog_sources, ['manual', 'bundled']);
    assert.equal(data.threat_actor.bundled_catalog_collision_pending, false);
    assert.equal(data.threat_actor.aliases[0], 'Internal Alias');
    assert.equal(data.threat_actor.description, 'Internal/local description');
    assert.equal(data.threat_actor.active, false);
    assert.equal(audit.events.length, 1);
    assert.equal(audit.events[0].action, AUDIT_ACTION.THREAT_ACTOR_BUNDLED_IDENTITY_CONFIRMED);
    assert.deepEqual(audit.events[0].metadata.previous_catalog_sources, ['manual']);
    assert.deepEqual(audit.events[0].metadata.resulting_catalog_sources, ['manual', 'bundled']);
    assert.equal(audit.events[0].metadata.previous_collision_pending, true);
    assert.equal(audit.events[0].metadata.resulting_collision_pending, false);
  });
});

test('PATCH confirm_bundled_catalog rejects bundled-only actor without pending collision', async () => {
  const store = [{
    id: '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6',
    name: 'APT28',
    slug: 'apt28',
    aliases: [],
    description: null,
    active: true,
    catalog_sources: ['legacy-seed', 'bundled'],
    bundled_catalog_collision_pending: false,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
    created_by: null,
    updated_by: null
  }];
  await withServer(store, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/api/admin/threat-actors/${store[0].id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ confirm_bundled_catalog: true })
    });
    assert.equal(res.status, 400);
  });
});

test('PATCH confirm_bundled_catalog rejects Unknown sentinel', async () => {
  const store = [{
    id: '11111111-1111-4111-8111-111111111111',
    name: 'Unknown',
    slug: 'unknown',
    aliases: [],
    description: 'System default actor',
    active: true,
    catalog_sources: ['system'],
    bundled_catalog_collision_pending: false,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
    created_by: 'system-seed',
    updated_by: 'system-seed'
  }];
  await withServer(store, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/api/admin/threat-actors/${store[0].id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ confirm_bundled_catalog: true })
    });
    assert.equal(res.status, 400);
  });
});

test('PATCH confirm_bundled_catalog requires admin role', async () => {
  const store = [structuredClone(PENDING_XYZ)];
  await withServer(store, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/api/admin/threat-actors/${PENDING_XYZ.id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ confirm_bundled_catalog: true })
    });
    assert.equal(res.status, 403);
  }, { user: VIEWER });
});

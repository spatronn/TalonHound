import http from 'node:http';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createUsomApiClient, createUsomRunDetails } from './usomOfficialApi.js';
import { executeUsomImportPipeline } from './usomImportPipeline.js';

function payload(models) {
  return { totalCount: models.length, count: models.length, models, page: 0, pageCount: models.length ? 1 : 0 };
}

function createMemoryStore() {
  const production = new Map();
  let stage = new Map();
  return {
    production,
    store: {
      async createStage() {
        stage = new Map();
      },
      async stageEntries(_client, entries) {
        let staged = 0;
        for (const entry of entries) {
          const key = `${entry.observableType}|${entry.observable}`;
          if (stage.has(key)) continue;
          stage.set(key, structuredClone(entry));
          staged += 1;
        }
        return { staged, duplicate: entries.length - staged };
      },
      async finalize(_client, options = {}) {
        let inserted = 0;
        let updated = 0;
        let duplicate = 0;
        for (const [key, entry] of stage) {
          const current = production.get(key);
          if (!current) {
            production.set(key, { entry: structuredClone(entry), active: true });
            inserted += 1;
          } else if (!current.active || current.entry.providerFingerprint !== entry.providerFingerprint) {
            current.entry = structuredClone(entry);
            current.active = true;
            updated += 1;
          } else {
            duplicate += 1;
          }
        }
        let markedMissing = 0;
        if (options.mode === 'full_reconciliation') {
          for (const [key, current] of production) {
            if (current.active && !stage.has(key)) {
              current.active = false;
              markedMissing += 1;
            }
          }
        }
        return { inserted, updated, duplicate, suppressed: 0, markedMissing };
      },
      async dropStage() {
        stage.clear();
      }
    }
  };
}

test('mock official API supports two complete snapshot runs, dedup, metadata update and missing detection', async (t) => {
  let phase = 1;
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    res.setHeader('Content-Type', 'application/json');
    if (url.pathname !== '/api/address/index') {
      res.end(JSON.stringify(payload([])));
      return;
    }

    const type = url.searchParams.get('type');
    const common = { desc: 'PH', source: 'US', criticality_level: 9, connectiontype: 'BC' };
    const byType = {
      domain: phase === 1
        ? [
            { id: 1, type, url: 'Example.com', date: '2026-07-18 10:00:00', ...common },
            { id: 2, type, url: 'example.com', date: '2026-07-17 10:00:00', ...common }
          ]
        : [{ id: 1, type, url: 'example.com', date: '2026-07-19 10:00:00', ...common }],
      url: phase === 1 ? [{ id: 3, type, url: 'example.net/Login?q=1', ...common }] : [],
      ip: [{ id: 4, type, url: '203.0.113.4', ...common }],
      ip6: [{ id: 5, type, url: '2001:db8::4', ...common }],
      ip6net: [{ id: 6, type, url: '2001:db8::/32', ...common }]
    };
    res.end(JSON.stringify(payload(byType[type] || [])));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const baseUrl = `http://127.0.0.1:${server.address().port}/api`;
  const api = createUsomApiClient({
    baseUrl,
    allowNonOfficialBaseUrl: true,
    requestDelayMs: 0,
    maxRetries: 0
  });
  const memory = createMemoryStore();

  const firstStats = createUsomRunDetails();
  const first = await executeUsomImportPipeline({
    client: {},
    api,
    stats: firstStats,
    mode: 'full_reconciliation',
    seenAt: new Date('2026-07-20T00:00:00.000Z'),
    store: memory.store
  });
  assert.deepEqual(first.persistence, {
    inserted: 4,
    updated: 0,
    duplicate: 0,
    suppressed: 0,
    markedMissing: 0
  });
  assert.equal(first.inRunDuplicates, 1);
  assert.equal(firstStats.skipped_unsupported_ip_network, 1);
  assert.equal(memory.production.size, 4);

  phase = 2;
  const secondStats = createUsomRunDetails();
  const second = await executeUsomImportPipeline({
    client: {},
    api,
    stats: secondStats,
    mode: 'full_reconciliation',
    seenAt: new Date('2026-07-20T00:00:00.000Z'),
    store: memory.store
  });
  assert.deepEqual(second.persistence, {
    inserted: 0,
    updated: 1,
    duplicate: 2,
    suppressed: 0,
    markedMissing: 1
  });
  assert.equal(second.inRunDuplicates, 0);
  assert.equal(memory.production.get('url|example.net/Login?q=1').active, false);
  assert.equal(memory.production.get('domain|example.com').entry.providerMetadata.provider_date, '2026-07-19 10:00:00');
});

test('pipeline never finalizes persistent state when a required page fails', async () => {
  let finalized = false;
  let dropped = false;
  const store = {
    async createStage() {},
    async stageEntries() { return { staged: 0, duplicate: 0 }; },
    async finalize() {
      finalized = true;
      return {};
    },
    async dropStage() {
      dropped = true;
    }
  };
  const api = {
    async collect() {
      throw new Error('required ip6 page failed');
    }
  };
  await assert.rejects(
    executeUsomImportPipeline({
      client: {},
      api,
      stats: createUsomRunDetails(),
      mode: 'full_reconciliation',
      store
    }),
    /required ip6 page failed/
  );
  assert.equal(finalized, false);
  assert.equal(dropped, true);
});

test('incremental pipeline never reconciles unseen memberships as missing', async () => {
  const memory = createMemoryStore();
  memory.production.set('domain|unseen.example', {
    entry: { observable: 'unseen.example', observableType: 'domain', providerFingerprint: 'old' },
    active: true
  });
  memory.store.loadContext = async () => ({
    cursors: Object.fromEntries(['domain', 'url', 'ip', 'ip6'].map((type) => [
      type,
      { timestamp: '2026-07-20T10:00:00.000Z', providerId: '1' }
    ])),
    state: { full_snapshot_hash: 'prior' }
  });
  let collectedMode = null;
  const api = {
    async collect(options) {
      collectedMode = options.mode;
      await options.onEntries([{
        observable: 'seen.example',
        observableType: 'domain',
        providerFingerprint: 'new',
        providerMetadata: {
          provider_record_id: 2,
          provider_date_utc: '2026-07-20T11:00:00.000Z'
        }
      }], { apiType: 'domain' });
      return {
        highwaters: {
          domain: { timestamp: '2026-07-20T11:00:00.000Z', providerId: '2' }
        },
        queryWindows: {}
      };
    }
  };
  const result = await executeUsomImportPipeline({
    client: {},
    api,
    stats: createUsomRunDetails(),
    mode: 'incremental',
    seenAt: new Date('2026-07-20T12:00:00.000Z'),
    store: memory.store
  });
  assert.equal(collectedMode, 'incremental');
  assert.equal(result.persistence.markedMissing, 0);
  assert.equal(memory.production.get('domain|unseen.example').active, true);
});

test('incremental request without complete cursors requires explicit full bootstrap', async () => {
  const memory = createMemoryStore();
  memory.store.loadContext = async () => ({ cursors: {}, state: null });
  const api = {
    async collect() {
      assert.fail('incremental collection must not start without complete cursors');
    }
  };
  await assert.rejects(
    executeUsomImportPipeline({
      client: {},
      api,
      stats: createUsomRunDetails(),
      mode: 'incremental',
      store: memory.store
    }),
    (error) => error?.code === 'bootstrap_required'
  );
});

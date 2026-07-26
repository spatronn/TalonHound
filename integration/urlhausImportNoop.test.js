import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createImportMetrics } from './lib/import-metrics.js';
import { buildUrlhausNote, computeUrlhausProviderFingerprint, mapUrlhausRow, splitCsvLine } from './lib/urlhaus.js';
import {
  updateUrlhausExistingIocBySource,
  updateUrlhausObservableBySource,
  upsertUrlhausObservable
} from './importer.js';

function sampleEntry(overrides = {}) {
  const row = mapUrlhausRow(splitCsvLine(
    '3858192,2026-06-04 00:22:19,https://zkenezc.baccaratbazi.com/1cd153b6-68f9-451b-bb81-b8d7f4f263cb,offline,,malware_download,ClearFake,https://urlhaus.abuse.ch/url/3858192/,anonymous'
  ));
  return { ...row, ...overrides };
}

function makeUrlhausExistingClient({ row, membershipStatus = 'active' }) {
  const calls = [];
  const membershipRow = {
    id: 'bbbbbbbb-0000-0000-0000-000000000001',
    status: membershipStatus,
    missing_since: null,
    expired_at: membershipStatus === 'expired' ? new Date('2026-06-20T00:00:00Z') : null,
    purged_at: null,
    override_enabled: false,
    first_seen_in_feed: new Date('2026-06-01T00:00:00Z'),
    last_seen_in_feed: new Date('2026-06-20T00:00:00Z'),
    expiration_reason: membershipStatus === 'expired' ? 'policy_ttl' : null
  };
  return {
    calls,
    async query(sql, params = []) {
      const text = String(sql);
      calls.push({ sql: text, params });
      if (text.includes('FROM ioc_items')
        && text.includes('source_name = $3')
        && text.includes('LIMIT 1')) {
        return row ? { rowCount: 1, rows: [row] } : { rowCount: 0, rows: [] };
      }
      if (text.startsWith('UPDATE ioc_items')) {
        return { rowCount: 1, rows: [{ public_id: row?.public_id || '00000000-0000-0000-0000-000000000001' }] };
      }
      if (text.includes('FROM integration_feeds')) {
        return { rows: [{ key: 'urlhaus-abusech', integration_id: 'cccccccc-0000-0000-0000-000000000001', feed_id: 'cccccccc-0000-0000-0000-000000000001', name: 'URLhaus', feed_kind: 'builtin', feed_update_mode: 'incremental' }] };
      }
      if (text.includes('FROM ioc_items') && text.includes('WHERE observable = $1') && !text.includes('source_name = $3')) {
        return { rows: [{ id: 42, observable_type: row?.observable_type || 'url' }] };
      }
      if (text.includes('FROM threat_feed_expiration_policies')) return { rows: [] };
      if (text.includes('FROM ioc_feed_memberships') && text.includes('feed_id = $3')) {
        return { rowCount: 1, rows: [membershipRow] };
      }
      if (text.includes('SELECT * FROM ioc_feed_memberships WHERE id = $1')) {
        return { rows: [{ ...membershipRow, status: 'active' }] };
      }
      if (text.includes('FROM ioc_suppressions')) return { rows: [] };
      if (text.includes('INSERT INTO ioc_observables')) return { rowCount: 1, rows: [] };
      if (text.includes('analyst_confidence_override')) return { rows: [{ analyst_confidence_override: null }] };
      if (text.includes('UPDATE ioc_feed_memberships')) return { rowCount: 0, rows: [] };
      if (text.includes('SELECT m.status, m.purged_at')) return { rows: [{ status: 'active', purged_at: null }] };
      if (text.includes('SELECT MIN(m.expires_at)')) return { rows: [{ min_exp: null }] };
      if (text.includes('FROM ioc_items') && text.includes('WHERE id = $1')) {
        return { rows: [{ id: 42, observable_type: 'url', status: 'active', manual_status_override: false, manual_expires_at: null, expires_at: null, expired_at: null, expiration_reason: null }] };
      }
      throw new Error(`unexpected URLhaus mock query: ${text.slice(0, 160)}`);
    }
  };
}

function makeScriptedClient(handlers) {
  const calls = [];
  return {
    calls,
    async query(sql, params = []) {
      const text = String(sql);
      calls.push({ sql: text, params });
      const handler = handlers.find((h) => h.match(text, calls.length));
      if (!handler) throw new Error(`unexpected query: ${text.slice(0, 160)}`);
      return handler.result(text, params, calls.length);
    }
  };
}

const match = (needle) => (sql) => sql.includes(needle);
const nth = (n) => (_sql, callNo) => callNo === n;

describe('upsertUrlhausObservable unchanged metadata handling', () => {
  it('skips same-source URLhaus rows when metadata is unchanged and does not sync membership', async () => {
    const entry = sampleEntry();
    const note = buildUrlhausNote(entry);
    const client = makeUrlhausExistingClient({
      row: {
        public_id: '00000000-0000-0000-0000-000000000001',
        observable_type: 'url',
        note,
        category: entry.threat || 'malware-url',
        first_seen_at: entry.dateAdded,
        last_seen_at: null,
        provider_fingerprint: computeUrlhausProviderFingerprint(entry)
      }
    });
    const metrics = createImportMetrics();

    await upsertUrlhausObservable(client, entry, 'URLhaus:abuse.ch', null, metrics, 'high');

    assert.equal(metrics.records_updated, 0);
    assert.equal(metrics.records_unchanged, 1);
    assert.equal(metrics.records_skipped, 0);
    assert.ok(!client.calls.some((c) => c.sql.includes('UPDATE ioc_feed_memberships')), 'unchanged active URLhaus row must not rewrite feed membership');
    assert.ok(!client.calls.some((c) => c.sql.startsWith('UPDATE ioc_items')), 'unchanged row must not rewrite ioc_items');
  });

  it('updates URLhaus IOC observation when only last_online changes', async () => {
    const entry = sampleEntry({
      urlStatus: 'online',
      lastOnline: new Date('2026-06-28T17:40:00.000Z')
    });
    const note = buildUrlhausNote(entry);
    const priorNote = buildUrlhausNote(sampleEntry({ urlStatus: 'online', lastOnline: new Date('2026-06-27T11:52:06.000Z') }));
    const client = makeUrlhausExistingClient({
      row: {
        public_id: '00000000-0000-0000-0000-000000000002',
        observable_type: 'url',
        note: priorNote,
        category: entry.threat || 'malware-url',
        first_seen_at: entry.dateAdded,
        last_seen_at: new Date('2026-06-27T11:52:06.000Z')
      }
    });
    const metrics = createImportMetrics();

    await upsertUrlhausObservable(client, entry, 'URLhaus:abuse.ch', null, metrics, 'high');

    assert.equal(metrics.records_updated, 0);
    assert.equal(metrics.records_unchanged, 1);
    assert.equal(metrics.records_skipped, 0);
    assert.ok(client.calls.some((c) => c.sql.includes('SET note = $2') && c.sql.includes('last_seen_at = $4')));
    assert.ok(!client.calls.some((c) => c.sql.includes('UPDATE ioc_feed_memberships')), 'last_online-only row must not refresh active membership last_seen_in_feed');
  });

  it('counts url_status change as semantic updated with membership sync', async () => {
    const entry = sampleEntry({ urlStatus: 'online', lastOnline: new Date('2026-06-28T17:40:00.000Z') });
    const note = buildUrlhausNote(entry);
    const client = makeUrlhausExistingClient({
      row: {
        public_id: '00000000-0000-0000-0000-000000000003',
        observable_type: 'url',
        note: buildUrlhausNote(sampleEntry({ urlStatus: 'offline', lastOnline: null })),
        category: entry.threat || 'malware-url',
        first_seen_at: entry.dateAdded,
        last_seen_at: null
      }
    });
    const metrics = createImportMetrics();

    await upsertUrlhausObservable(client, entry, 'URLhaus:abuse.ch', null, metrics, 'high');

    assert.equal(metrics.records_updated, 1);
    assert.equal(metrics.records_skipped, 0);
    assert.ok(client.calls.some((c) => c.sql.includes('INSERT INTO ioc_observables')));
  });

  it('counts last_online plus url_status change as semantic updated', async () => {
    const entry = sampleEntry({ urlStatus: 'online', lastOnline: new Date('2026-06-28T17:40:00.000Z') });
    const client = makeUrlhausExistingClient({
      row: {
        public_id: '00000000-0000-0000-0000-000000000004',
        observable_type: 'url',
        note: buildUrlhausNote(sampleEntry({ urlStatus: 'offline', lastOnline: null })),
        category: entry.threat || 'malware-url',
        first_seen_at: entry.dateAdded,
        last_seen_at: null
      }
    });
    const result = await updateUrlhausObservableBySource(
      client,
      entry,
      'URLhaus:abuse.ch',
      buildUrlhausNote(entry),
      entry.threat || 'malware-url'
    );

    assert.equal(result.status, 'updated');
    assert.ok(client.calls.some((c) => c.sql.includes('INSERT INTO ioc_observables')));
  });

  it('classifies last_online-only change as observation_updated', async () => {
    const entry = sampleEntry({
      urlStatus: 'online',
      lastOnline: new Date('2026-06-28T17:40:00.000Z')
    });
    const note = buildUrlhausNote(entry);
    const result = await updateUrlhausExistingIocBySource({
      async query(sql) {
        const text = String(sql);
        if (text.includes('FROM ioc_items') && text.includes('source_name = $3')) {
          return {
            rowCount: 1,
            rows: [{
              public_id: '00000000-0000-0000-0000-000000000005',
              note: buildUrlhausNote(sampleEntry({ urlStatus: 'online', lastOnline: new Date('2026-06-27T11:52:06.000Z') })),
              category: 'malware_download',
              first_seen_at: entry.dateAdded,
              last_seen_at: new Date('2026-06-27T11:52:06.000Z')
            }]
          };
        }
        if (text.startsWith('UPDATE ioc_items')) {
          return { rowCount: 1, rows: [{ public_id: '00000000-0000-0000-0000-000000000005' }] };
        }
        throw new Error(`unexpected query: ${text.slice(0, 120)}`);
      }
    }, {
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName: 'URLhaus:abuse.ch',
      fullNote: note,
      category: entry.threat || 'malware-url',
      dateAddedAt: entry.dateAdded,
      lastOnlineAt: entry.lastOnline
    });

    assert.equal(result.status, 'observation_updated');
  });

  it('inserts a URLhaus row that is not already present', async () => {
    const entry = sampleEntry();
    const note = buildUrlhausNote(entry);
    const client = makeScriptedClient([
      { match: (sql) => sql.includes('FROM ioc_items') && sql.includes('source_name = $3'), result: () => ({ rowCount: 0, rows: [] }) },
      { match: match('FROM ioc_suppressions'), result: () => ({ rows: [] }) },
      { match: match('INSERT INTO ioc_items'), result: () => ({ rowCount: 1, rows: [{ public_id: '00000000-0000-0000-0000-000000000002' }] }) },
      { match: match('INSERT INTO ioc_observables'), result: () => ({ rowCount: 1, rows: [] }) },
      { match: match('FROM integration_feeds'), result: () => ({ rows: [] }) },
      {
        match: (sql, callNo) => callNo >= 6 && sql.includes('FROM ioc_items') && sql.includes('source_name = $3'),
        result: () => ({
          rowCount: 1,
          rows: [{
            public_id: '00000000-0000-0000-0000-000000000002',
            note,
            category: entry.threat || 'malware-url',
            first_seen_at: entry.dateAdded,
            last_seen_at: null
          }]
        })
      },
      { match: (sql) => sql.startsWith('UPDATE ioc_items'), result: () => ({ rowCount: 1, rows: [{ public_id: '00000000-0000-0000-0000-000000000002' }] }) },
      { match: match('INSERT INTO ioc_observables'), result: () => ({ rowCount: 1, rows: [] }) },
      { match: match('FROM integration_feeds'), result: () => ({ rows: [] }) }
    ]);
    const metrics = createImportMetrics();

    await upsertUrlhausObservable(client, entry, 'URLhaus:abuse.ch', null, metrics, 'high');

    assert.equal(metrics.records_inserted, 1);
    assert.equal(metrics.records_updated, 0);
    assert.equal(metrics.records_skipped, 0);
  });

  it('keeps duplicate handling when the same IOC exists only under a different source', async () => {
    const client = makeScriptedClient([
      { match: nth(1), result: () => ({ rowCount: 0, rows: [] }) },
      { match: match('FROM ioc_suppressions'), result: () => ({ rows: [] }) },
      { match: match('INSERT INTO ioc_items'), result: () => ({ rowCount: 0, rows: [] }) },
      { match: (sql) => sql.includes('FROM ioc_items') && sql.includes('source_name = $3'), result: () => ({ rowCount: 0, rows: [] }) },
      { match: match('FROM integration_feeds'), result: () => ({ rows: [] }) },
      { match: nth(6), result: () => ({ rowCount: 0, rows: [] }) }
    ]);
    const metrics = createImportMetrics();

    await upsertUrlhausObservable(client, sampleEntry(), 'URLhaus:abuse.ch', null, metrics, 'high');

    assert.equal(metrics.records_duplicate, 1);
    assert.equal(metrics.records_inserted, 0);
    assert.equal(metrics.records_updated, 0);
  });
});

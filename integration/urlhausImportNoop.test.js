import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createImportMetrics } from './lib/import-metrics.js';
import { mapUrlhausRow, splitCsvLine } from './lib/urlhaus.js';
import { upsertUrlhausObservable } from './importer.js';

function sampleEntry(overrides = {}) {
  const row = mapUrlhausRow(splitCsvLine(
    '3858192,2026-06-04 00:22:19,https://zkenezc.baccaratbazi.com/1cd153b6-68f9-451b-bb81-b8d7f4f263cb,offline,,malware_download,ClearFake,https://urlhaus.abuse.ch/url/3858192/,anonymous'
  ));
  return { ...row, ...overrides };
}

function makeClient(firstResult) {
  const calls = [];
  return {
    calls,
    async query(sql, params = []) {
      calls.push({ sql: String(sql), params });
      if (calls.length === 1) return firstResult;
      if (String(sql).includes('INSERT INTO ioc_observables')) return { rowCount: 1, rows: [] };
      if (String(sql).includes('FROM integration_feeds')) return { rows: [] };
      throw new Error(`unexpected query after URLhaus decision: ${String(sql).slice(0, 120)}`);
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
    const client = makeClient({
      rowCount: 1,
      rows: [{ status: 'unchanged', public_id: '00000000-0000-0000-0000-000000000001' }]
    });
    const metrics = createImportMetrics();

    await upsertUrlhausObservable(client, sampleEntry(), 'URLhaus:abuse.ch', null, metrics, 'high');

    assert.equal(metrics.records_updated, 0);
    assert.equal(metrics.records_inserted, 0);
    assert.equal(metrics.records_duplicate, 0);
    assert.equal(metrics.records_skipped, 1);
    assert.equal(client.calls.length, 1, 'unchanged row must not touch ioc_observables, confidence, or feed membership');
  });

  it('counts changed same-source URLhaus metadata as updated', async () => {
    const client = makeClient({
      rowCount: 1,
      rows: [{ status: 'updated', public_id: '00000000-0000-0000-0000-000000000001' }]
    });
    const metrics = createImportMetrics();

    await upsertUrlhausObservable(
      client,
      sampleEntry({ urlStatus: 'online', lastOnline: new Date('2026-06-28T17:40:00.000Z') }),
      'URLhaus:abuse.ch',
      null,
      metrics,
      'high'
    );

    assert.equal(metrics.records_updated, 1);
    assert.equal(metrics.records_skipped, 0);
  });

  it('inserts a URLhaus row that is not already present', async () => {
    const client = makeScriptedClient([
      { match: nth(1), result: () => ({ rowCount: 0, rows: [] }) },
      { match: match('FROM ioc_suppressions'), result: () => ({ rows: [] }) },
      { match: match('INSERT INTO ioc_items'), result: () => ({ rowCount: 1, rows: [{ public_id: '00000000-0000-0000-0000-000000000002' }] }) },
      { match: match('INSERT INTO ioc_observables'), result: () => ({ rowCount: 1, rows: [] }) },
      { match: match('FROM integration_feeds'), result: () => ({ rows: [] }) },
      { match: nth(6), result: () => ({ rowCount: 1, rows: [{ status: 'updated', public_id: '00000000-0000-0000-0000-000000000002' }] }) },
      { match: match('INSERT INTO ioc_observables'), result: () => ({ rowCount: 1, rows: [] }) },
      { match: match('FROM integration_feeds'), result: () => ({ rows: [] }) }
    ]);
    const metrics = createImportMetrics();

    await upsertUrlhausObservable(client, sampleEntry(), 'URLhaus:abuse.ch', null, metrics, 'high');

    assert.equal(metrics.records_inserted, 1);
    assert.equal(metrics.records_updated, 0);
    assert.equal(metrics.records_skipped, 0);
  });

  it('keeps duplicate handling when the same IOC exists only under a different source', async () => {
    const client = makeScriptedClient([
      { match: nth(1), result: () => ({ rowCount: 0, rows: [] }) },
      { match: match('FROM ioc_suppressions'), result: () => ({ rows: [] }) },
      { match: match('INSERT INTO ioc_items'), result: () => ({ rowCount: 0, rows: [] }) },
      { match: match('UPDATE ioc_items i'), result: () => ({ rowCount: 0, rows: [] }) },
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

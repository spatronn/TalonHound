import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createImportMetrics } from './lib/import-metrics.js';
import { buildMalwareBazaarNote, mapMalwareBazaarRecord } from './lib/malwarebazaar.js';
import { buildThreatFoxNote, mapThreatFoxApiRow } from './lib/threatfox.js';
import {
  batchInsertIocs,
  updateMalwareBazaarObservableBySource,
  updateThreatFoxObservableBySource
} from './importer.js';

function malwareEntry(overrides = {}) {
  return {
    ...mapMalwareBazaarRecord({
      first_seen_utc: '2026-06-28 04:00:01',
      sha256_hash: 'a'.repeat(64),
      md5_hash: 'b'.repeat(32),
      sha1_hash: 'c'.repeat(40),
      signature: 'ExampleFamily',
      file_type: 'exe',
      mime_type: 'application/x-dosexec',
      reporter: 'abuse_ch',
      tags: 'exe,malware',
      malwarebazaar_link: 'https://bazaar.abuse.ch/sample/' + 'a'.repeat(64) + '/'
    }),
    ...overrides
  };
}

function threatFoxEntry(overrides = {}) {
  return {
    ...mapThreatFoxApiRow({
      id: '12345',
      ioc: 'https://malicious.example.test/a',
      ioc_type: 'url',
      threat_type: 'payload_delivery',
      malware: 'win.example',
      malware_printable: 'Example Malware',
      malware_alias: 'ExampleAlias',
      confidence_level: 75,
      first_seen: '2026-06-28 04:00:01 UTC',
      last_seen: '2026-06-28 04:00:01 UTC',
      reporter: 'abuse_ch',
      reference: 'https://threatfox.abuse.ch/ioc/12345/',
      tags: ['malware', 'payload']
    }),
    ...overrides
  };
}

function makeUpdateClient(firstResult) {
  const calls = [];
  return {
    calls,
    async query(sql, params = []) {
      calls.push({ sql: String(sql), params });
      if (calls.length === 1) return firstResult;
      if (String(sql).includes('INSERT INTO ioc_observables')) return { rowCount: 1, rows: [] };
      if (String(sql).includes('FROM integration_feeds')) return { rows: [] };
      throw new Error(`unexpected side-effect query: ${String(sql).slice(0, 120)}`);
    }
  };
}

function makeBatchDuplicateClient(existingStatus = 'unchanged') {
  const calls = [];
  return {
    calls,
    async query(sql, params = []) {
      const text = String(sql);
      calls.push({ sql: text, params });
      if (text.includes('FROM ioc_suppressions')) return { rows: [] };
      if (text.includes('INSERT INTO ioc_items')) return { rowCount: 0, rows: [] };
      if (text.includes('WITH existing AS')) {
        if (existingStatus === 'not_found') return { rowCount: 0, rows: [] };
        return { rowCount: 1, rows: [{ status: existingStatus, public_id: '00000000-0000-0000-0000-000000000301' }] };
      }
      if (text.includes('FROM integration_feeds')) return { rows: [] };
      throw new Error(`unexpected count_only duplicate query: ${text.slice(0, 120)}`);
    }
  };
}

describe('built-in feed unchanged metadata no-op handling', () => {
  it('skips unchanged MalwareBazaar same-source rows without membership sync', async () => {
    const entry = malwareEntry();
    const client = makeUpdateClient({
      rowCount: 1,
      rows: [{ status: 'unchanged', public_id: '00000000-0000-0000-0000-000000000101' }]
    });
    const result = await updateMalwareBazaarObservableBySource(
      client,
      entry,
      'MalwareBazaar:abuse.ch',
      buildMalwareBazaarNote(entry),
      entry.category || 'malware'
    );

    assert.equal(result.status, 'unchanged');
    assert.ok(!client.calls.some((c) => c.sql.includes('UPDATE ioc_feed_memberships')), 'unchanged active MB row must not rewrite feed membership');
    assert.ok(!client.calls.some((c) => c.sql.includes('INSERT INTO ioc_observables')), 'unchanged active MB row must not touch observables index');
  });

  it('updates MalwareBazaar same-source rows when semantic metadata changes', async () => {
    const entry = malwareEntry({ signature: 'ChangedFamily', category: 'ChangedFamily' });
    const client = makeUpdateClient({
      rowCount: 1,
      rows: [{ status: 'updated', public_id: '00000000-0000-0000-0000-000000000102' }]
    });
    const result = await updateMalwareBazaarObservableBySource(
      client,
      entry,
      'MalwareBazaar:abuse.ch',
      buildMalwareBazaarNote(entry),
      entry.category || 'malware'
    );

    assert.equal(result.status, 'updated');
    assert.ok(client.calls.some((c) => c.sql.includes('INSERT INTO ioc_observables')));
  });

  it('skips unchanged ThreatFox same-source rows without membership sync', async () => {
    const entry = threatFoxEntry();
    const client = makeUpdateClient({
      rowCount: 1,
      rows: [{ status: 'unchanged', public_id: '00000000-0000-0000-0000-000000000201' }]
    });
    const result = await updateThreatFoxObservableBySource(
      client,
      entry,
      'ThreatFox:abuse.ch',
      buildThreatFoxNote(entry),
      entry.threatType || 'threat-intel'
    );

    assert.equal(result.status, 'unchanged');
    assert.ok(!client.calls.some((c) => c.sql.includes('UPDATE ioc_feed_memberships')), 'unchanged active ThreatFox row must not rewrite feed membership');
    assert.ok(!client.calls.some((c) => c.sql.includes('INSERT INTO ioc_observables')), 'unchanged active ThreatFox row must not touch observables index');
  });

  it('counts unchanged count_only batch duplicates as skipped without updating last_seen_at', async () => {
    const client = makeBatchDuplicateClient();
    const result = await batchInsertIocs(client, [{
      observable: '203.0.113.10',
      sourceName: 'EmergingThreats:compromised-ips.txt',
      sourceUrl: 'https://rules.example.test/compromised-ips.txt',
      category: 'compromised-host',
      note: 'Auto-imported from ET blockrules (compromised-ips.txt)'
    }], 'ip', null, null, { duplicateHandling: 'count_only' });

    assert.equal(result.inserted, 0);
    assert.equal(result.duplicate, 0);
    assert.equal(result.skipped, 1);
    assert.equal(client.calls.length, 3, 'count_only same-source duplicate should check suppression, attempt insert, and classify unchanged');
    assert.ok(client.calls[2].sql.includes('IS DISTINCT FROM'));
    assert.ok(!client.calls.some((c) => c.sql.includes('ioc_feed_memberships')));
  });

  it('records skipped metrics for count_only batch duplicates', async () => {
    const client = makeBatchDuplicateClient();
    const metrics = createImportMetrics();
    const result = await batchInsertIocs(client, [{
      observable: 'https://phishtank.example.test/phish',
      sourceName: 'PhishTank:open_dnsrr',
      sourceUrl: 'https://data.phishtank.com/data/online-valid.csv',
      category: 'phishing',
      note: 'Auto-imported from PhishTank online-valid.csv'
    }], 'url', null, null, { duplicateHandling: 'count_only' });
    metrics.records_inserted += result.inserted;
    metrics.records_duplicate += result.duplicate;
    metrics.records_skipped += result.skipped;

    assert.equal(metrics.records_inserted, 0);
    assert.equal(metrics.records_duplicate, 0);
    assert.equal(metrics.records_updated, 0);
    assert.equal(metrics.records_skipped, 1);
  });

  it('preserves same IOC different feed/source membership path for count_only batch duplicates', async () => {
    const client = makeBatchDuplicateClient('not_found');
    const result = await batchInsertIocs(client, [{
      observable: '198.51.100.44',
      sourceName: 'EmergingThreats:another-list.txt',
      sourceUrl: 'https://rules.example.test/another-list.txt',
      category: 'scanner',
      note: 'Auto-imported from ET blockrules (another-list.txt)'
    }], 'ip', null, null, { duplicateHandling: 'count_only' });

    assert.equal(result.inserted, 0);
    assert.equal(result.skipped, 0);
    assert.equal(result.duplicate, 1);
    assert.ok(client.calls.some((c) => c.sql.includes('FROM integration_feeds')), 'cross-source duplicate should attempt membership sync');
  });
});

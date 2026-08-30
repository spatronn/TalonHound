import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createImportMetrics } from './lib/import-metrics.js';
import { buildMalwareBazaarNote, mapMalwareBazaarRecord } from './lib/malwarebazaar.js';
import { buildThreatFoxNote, mapThreatFoxApiRow } from './lib/threatfox.js';
import {
  batchInsertIocs,
  updateMalwareBazaarObservableBySource,
  updateThreatFoxExistingIocBySource,
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

function makeThreatFoxExistingClient({ row, membershipStatus = 'active' }) {
  const calls = [];
  const membershipRow = {
    id: 'bbbbbbbb-0000-0000-0000-000000000002',
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
        return { rowCount: 1, rows: [{ public_id: row?.public_id || '00000000-0000-0000-0000-000000000201' }] };
      }
      if (text.includes('FROM integration_feeds')) {
        return { rows: [{ key: 'threatfox-abusech', integration_id: 'cccccccc-0000-0000-0000-000000000002', feed_id: 'cccccccc-0000-0000-0000-000000000002', name: 'ThreatFox abuse.ch', feed_kind: 'builtin', feed_update_mode: 'incremental' }] };
      }
      if (text.includes('FROM ioc_items') && text.includes('WHERE observable = $1') && !text.includes('source_name = $3')) {
        return { rows: [{ id: 42, observable_type: row?.observable_type || 'url' }] };
      }
      if (text.includes('FROM threat_feed_expiration_policies')) return { rows: [] };
      if (text.includes('FROM ioc_feed_memberships') && text.includes('feed_id = $3')) {
        return { rowCount: 1, rows: [membershipRow] };
      }
      if (text.includes('SELECT * FROM ioc_feed_memberships WHERE id = $1')) {
        return { rows: [{ ...membershipRow, status: 'active', expired_at: null, expiration_reason: null }] };
      }
      if (text.includes('FROM ioc_suppressions')) return { rows: [] };
      if (text.includes('INSERT INTO ioc_observables')) return { rowCount: 1, rows: [] };
      if (text.includes('analyst_confidence_override')) return { rows: [{ analyst_confidence_override: null }] };
      if (text.includes('UPDATE ioc_items') && text.includes('confidence')) return { rowCount: 1, rows: [] };
      if (text.includes('UPDATE ioc_feed_memberships') && text.includes('explicit_confidence')) {
        return { rowCount: 1, rows: [] };
      }
      if (text.includes('UPDATE ioc_feed_memberships')) {
        return { rowCount: 1, rows: [{ ...membershipRow, status: 'active' }] };
      }
      if (text.includes('SELECT m.status, m.purged_at')) return { rows: [{ status: 'active', purged_at: null }] };
      if (text.includes('SELECT MIN(m.expires_at)')) return { rows: [{ min_exp: null }] };
      if (text.includes('FROM ioc_items') && text.includes('WHERE id = $1')) {
        return { rows: [{ id: 42, observable: row?.observable || 'https://malicious.example.test/a', observable_type: row?.observable_type || 'url', status: 'expired', manual_status_override: false, manual_expires_at: null, expires_at: new Date('2026-06-20T00:00:00Z'), expired_at: new Date('2026-06-20T00:00:00Z'), expiration_reason: 'all_feed_memberships_expired' }] };
      }
      if (text.includes('UPDATE ioc_feed_memberships') && text.includes('policy_expires_at')) {
        return { rowCount: 0, rows: [] };
      }
      throw new Error(`unexpected ThreatFox mock query: ${text.slice(0, 160)}`);
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
    assert.equal(client.calls.length, 2, 'count_only same-source duplicate should attempt insert and classify unchanged (no suppression skip)');
    assert.ok(client.calls[1].sql.includes('IS DISTINCT FROM'));
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

  it('skips unchanged ThreatFox same-source rows without membership sync', async () => {
    const entry = threatFoxEntry();
    const note = buildThreatFoxNote(entry);
    const client = makeThreatFoxExistingClient({
      row: {
        public_id: '00000000-0000-0000-0000-000000000201',
        observable_type: 'url',
        note,
        category: entry.threatType || 'threat-intel',
        first_seen_at: entry.firstSeen,
        last_seen_at: entry.lastSeen
      }
    });
    const result = await updateThreatFoxObservableBySource(
      client,
      entry,
      'ThreatFox:abuse.ch',
      note,
      entry.threatType || 'threat-intel'
    );

    assert.equal(result.status, 'unchanged');
    assert.ok(!client.calls.some((c) => c.sql.startsWith('UPDATE ioc_items')), 'unchanged row must not rewrite ioc_items');
    assert.ok(!client.calls.some((c) => c.sql.includes('UPDATE ioc_feed_memberships')), 'unchanged active ThreatFox row must not rewrite feed membership');
  });

  it('updates ThreatFox IOC observation when only provider last_seen changes', async () => {
    const entry = threatFoxEntry({
      lastSeen: new Date('2026-06-28T19:25:13.000Z')
    });
    const note = buildThreatFoxNote(entry);
    const priorNote = buildThreatFoxNote(threatFoxEntry({
      lastSeen: new Date('2026-06-26T12:25:15.000Z')
    }));
    const client = makeThreatFoxExistingClient({
      row: {
        public_id: '00000000-0000-0000-0000-000000000202',
        observable_type: 'url',
        note: priorNote,
        category: entry.threatType || 'threat-intel',
        first_seen_at: entry.firstSeen,
        last_seen_at: new Date('2026-06-26T12:25:15.000Z')
      }
    });

    const result = await updateThreatFoxObservableBySource(
      client,
      entry,
      'ThreatFox:abuse.ch',
      note,
      entry.threatType || 'threat-intel'
    );

    assert.equal(result.status, 'observation_updated');
    assert.ok(client.calls.some((c) => c.sql.includes('SET note = $2') && c.sql.includes('last_seen_at = $4')));
    assert.ok(!client.calls.some((c) => c.sql.includes('UPDATE ioc_feed_memberships')), 'observation-only ThreatFox row must not refresh active membership last_seen_in_feed');
  });

  it('classifies ThreatFox existing-row update statuses', async () => {
    const entry = threatFoxEntry({ lastSeen: new Date('2026-06-28T19:25:13.000Z') });
    const note = buildThreatFoxNote(entry);
    const client = {
      calls: [],
      async query(sql, params = []) {
        this.calls.push({ sql: String(sql), params });
        if (String(sql).includes('FROM ioc_items') && String(sql).includes('source_name = $3')) {
          return {
            rowCount: 1,
            rows: [{
              public_id: '00000000-0000-0000-0000-000000000204',
              note: buildThreatFoxNote(threatFoxEntry({ lastSeen: new Date('2026-06-26T12:25:15.000Z') })),
              category: 'payload_delivery',
              first_seen_at: entry.firstSeen,
              last_seen_at: new Date('2026-06-26T12:25:15.000Z')
            }]
          };
        }
        if (String(sql).startsWith('UPDATE ioc_items')) {
          return { rowCount: 1, rows: [{ public_id: '00000000-0000-0000-0000-000000000204' }] };
        }
        throw new Error(`unexpected query: ${String(sql).slice(0, 120)}`);
      }
    };

    const result = await updateThreatFoxExistingIocBySource(client, {
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName: 'ThreatFox:abuse.ch',
      fullNote: note,
      category: entry.threatType || 'threat-intel',
      firstSeenAt: entry.firstSeen,
      lastSeenAt: entry.lastSeen
    });

    assert.equal(result.status, 'observation_updated');
  });

  it('marks semantic ThreatFox metadata changes as updated', async () => {
    const entry = threatFoxEntry({ threatType: 'botnet_cc' });
    const note = buildThreatFoxNote(entry);
    const priorNote = buildThreatFoxNote(threatFoxEntry({ threatType: 'payload_delivery' }));
    const client = {
      async query(sql) {
        const text = String(sql);
        if (text.includes('FROM ioc_items') && text.includes('source_name = $3')) {
          return {
            rowCount: 1,
            rows: [{
              public_id: '00000000-0000-0000-0000-000000000203',
              note: priorNote,
              category: 'payload_delivery',
              first_seen_at: entry.firstSeen,
              last_seen_at: entry.lastSeen
            }]
          };
        }
        if (text.startsWith('UPDATE ioc_items')) {
          return { rowCount: 1, rows: [{ public_id: '00000000-0000-0000-0000-000000000203' }] };
        }
        throw new Error(`unexpected query: ${text.slice(0, 120)}`);
      }
    };
    const result = await updateThreatFoxExistingIocBySource(client, {
      observable: entry.observable,
      observableType: entry.observableType,
      sourceName: 'ThreatFox:abuse.ch',
      fullNote: note,
      category: 'botnet_cc',
      firstSeenAt: entry.firstSeen,
      lastSeenAt: entry.lastSeen
    });
    assert.equal(result.status, 'updated');
  });

  it('reactivates expired ThreatFox membership when unchanged IOC reappears in feed', async () => {
    const entry = threatFoxEntry();
    const note = buildThreatFoxNote(entry);
    const client = makeThreatFoxExistingClient({
      membershipStatus: 'expired',
      row: {
        public_id: 'pub-2',
        observable: entry.observable,
        observable_type: entry.observableType,
        note,
        category: entry.threatType || 'threat-intel',
        first_seen_at: entry.firstSeen,
        last_seen_at: entry.lastSeen
      }
    });

    const result = await updateThreatFoxObservableBySource(
      client,
      entry,
      'ThreatFox:abuse.ch',
      note,
      entry.threatType || 'threat-intel'
    );

    assert.equal(result.status, 'unchanged');
    assert.ok(
      client.calls.some((c) => c.sql.includes('UPDATE ioc_feed_memberships') && c.sql.includes('last_seen_in_feed')),
      'expired membership must be reactivated via UPDATE ioc_feed_memberships'
    );
  });
});

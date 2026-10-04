import test from 'node:test';
import assert from 'node:assert/strict';
import { applyIocImportConfidence } from './iocConfidence.js';
import { recomputeIocGlobalStatus } from './iocExpiration.js';
import { upsertFeedSourceEvidence } from './iocFeedSourceEvidence.js';

test('applyIocImportConfidence skips UPDATE when confidence already matches', async () => {
  const updates = [];
  const client = {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('SELECT analyst_confidence_override')) {
        return {
          rows: [{
            analyst_confidence_override: null,
            source_confidence: 'high',
            confidence: 'high'
          }]
        };
      }
      if (s.startsWith('UPDATE ioc_items')) {
        updates.push({ sql: s, params });
        return { rowCount: 0 };
      }
      throw new Error(`unexpected: ${s.slice(0, 100)}`);
    }
  };

  const out = await applyIocImportConfidence(client, {
    observable: '1.2.3.4',
    observableType: 'ip',
    sourceName: 'ThreatFox:abuse.ch',
    parsedSourceConfidence: 'high'
  });

  assert.equal(out?.skipped, true);
  assert.equal(updates.length, 0);
});

test('applyIocImportConfidence repairs drifted confidence', async () => {
  const updates = [];
  const client = {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('SELECT analyst_confidence_override')) {
        return {
          rows: [{
            analyst_confidence_override: null,
            source_confidence: 'low',
            confidence: 'low'
          }]
        };
      }
      if (s.startsWith('UPDATE ioc_items')) {
        updates.push({ sql: s, params });
        assert.ok(s.includes('IS DISTINCT FROM'));
        return { rowCount: 1 };
      }
      throw new Error(`unexpected: ${s.slice(0, 100)}`);
    }
  };

  const out = await applyIocImportConfidence(client, {
    observable: '1.2.3.4',
    observableType: 'ip',
    sourceName: 'ThreatFox:abuse.ch',
    parsedSourceConfidence: 'high'
  });

  assert.equal(out?.source_confidence, 'high');
  assert.equal(updates.length, 1);
  assert.equal(updates[0].params[3], 'high');
});

test('recomputeIocGlobalStatus skips UPDATE when status/expires already match', async () => {
  const expires = new Date('2026-10-10T00:00:00.000Z');
  const updates = [];
  const client = {
    async query(sql) {
      const s = String(sql).replace(/\s+/g, ' ').trim();
      if (s.includes('FROM ioc_items') && s.includes('WHERE id = $1')) {
        return {
          rows: [{
            id: 1,
            observable: 'evil.test',
            observable_type: 'domain',
            status: 'active',
            manual_status_override: false,
            manual_status: null,
            manual_expires_at: null,
            expires_at: expires,
            expired_at: null,
            expiration_reason: null
          }]
        };
      }
      if (s.includes('SELECT 1 FROM ioc_suppressions') || s.includes('FROM ioc_suppressions')) {
        return { rows: [] };
      }
      if (s.includes('SELECT m.status, m.purged_at')) {
        return { rows: [{ status: 'active', purged_at: null }] };
      }
      if (s.includes('MIN(m.expires_at)')) {
        // Same instant, different Date instance — must not force a rewrite.
        return { rows: [{ min_exp: new Date(expires.getTime()) }] };
      }
      if (s.startsWith('UPDATE ioc_items')) {
        updates.push(s);
        return { rowCount: 0 };
      }
      throw new Error(`unexpected: ${s.slice(0, 120)}`);
    }
  };

  const res = await recomputeIocGlobalStatus(client, 1, 'domain');
  assert.equal(res.changed, false);
  assert.equal(res.status, 'active');
  assert.equal(updates.length, 0);
});

test('recomputeIocGlobalStatus writes when computed expires_at differs', async () => {
  const updates = [];
  const client = {
    async query(sql, params = []) {
      const s = String(sql).replace(/\s+/g, ' ').trim();
      if (s.includes('FROM ioc_items') && s.includes('WHERE id = $1')) {
        return {
          rows: [{
            id: 1,
            observable: 'evil.test',
            observable_type: 'domain',
            status: 'active',
            manual_status_override: false,
            manual_status: null,
            manual_expires_at: null,
            expires_at: new Date('2026-10-10T00:00:00.000Z'),
            expired_at: null,
            expiration_reason: null
          }]
        };
      }
      if (s.includes('FROM ioc_suppressions')) return { rows: [] };
      if (s.includes('SELECT m.status, m.purged_at')) {
        return { rows: [{ status: 'active', purged_at: null }] };
      }
      if (s.includes('MIN(m.expires_at)')) {
        return { rows: [{ min_exp: new Date('2026-11-01T00:00:00.000Z') }] };
      }
      if (s.startsWith('UPDATE ioc_items')) {
        updates.push({ sql: s, params });
        assert.ok(s.includes('IS DISTINCT FROM'));
        return { rowCount: 1 };
      }
      throw new Error(`unexpected: ${s.slice(0, 120)}`);
    }
  };

  const res = await recomputeIocGlobalStatus(client, 1, 'domain');
  assert.equal(res.changed, true);
  assert.equal(res.status, 'active');
  assert.equal(updates.length, 1);
});

test('upsertFeedSourceEvidence conflict no-op omits RETURNING and skips tag sync', async () => {
  let tagSync = 0;
  const client = {
    async query(sql) {
      const s = String(sql);
      if (s.includes('INSERT INTO ioc_feed_source_evidence')) {
        assert.ok(s.includes('IS DISTINCT FROM'));
        return { rows: [], rowCount: 0 };
      }
      if (s.includes('ioc_tags') || s.includes('tag')) {
        tagSync += 1;
      }
      return { rows: [], rowCount: 0 };
    }
  };

  const id = await upsertFeedSourceEvidence(client, {
    iocItemId: 9,
    observableType: 'domain',
    feedId: '11111111-1111-1111-1111-111111111111',
    sourceName: 'URLhaus:abuse.ch',
    sourceUrl: 'https://example.test',
    category: 'malware',
    note: 'same',
    confidence: null
  });

  assert.equal(id, null);
  assert.equal(tagSync, 0);
});

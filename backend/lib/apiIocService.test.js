import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeApiIocValue,
  parseApiIocType,
  createApiIoc,
  updateApiIoc
} from './apiIocService.js';
import { API_ERROR_CODE } from './apiV1Errors.js';

test('parseApiIocType rejects unknown types', () => {
  const r = parseApiIocType('email');
  assert.equal(r.ok, false);
  assert.equal(r.code, API_ERROR_CODE.INVALID_IOC_TYPE);
});

test('normalizeApiIocValue validates domain/ip/url/hash', () => {
  assert.equal(normalizeApiIocValue('domain', 'Evil.Example.COM').value, 'evil.example.com');
  assert.equal(normalizeApiIocValue('domain', 'not a domain').ok, false);
  assert.equal(normalizeApiIocValue('ip', '1.2.3.4').ok, true);
  assert.equal(normalizeApiIocValue('url', 'https://evil.example/x').ok, true);
  assert.equal(normalizeApiIocValue('url', 'ftp://x').ok, false);
  assert.equal(normalizeApiIocValue('hash', 'A'.repeat(32)).value, 'a'.repeat(32));
  assert.equal(normalizeApiIocValue('hash', 'zz').code, API_ERROR_CODE.INVALID_IOC_VALUE);
});

function makeCreatePool({ existing = null, inserted = null, sourceId = 9 } = {}) {
  const calls = [];
  return {
    calls,
    async query(sql, params = []) {
      const s = String(sql);
      calls.push({ sql: s, params });
      if (s.includes('FROM ioc_sources') && s.includes("name = $1")) {
        return {
          rows: [{
            id: sourceId,
            name: 'API',
            default_confidence: 'medium',
            default_threat_classification: null,
            default_expire_policy: 'never',
            default_expire_days: null,
            active: true,
            archived_at: null
          }]
        };
      }
      if (s.includes('FROM ioc_items') && s.includes('observable_type = $1') && s.includes('ORDER BY created_at')) {
        return { rows: existing ? [existing] : [] };
      }
      if (s.includes('INSERT INTO ioc_items')) {
        if (!inserted) return { rows: [] };
        return { rows: [inserted] };
      }
      if (s.includes('FROM ioc_sources WHERE id')) {
        return {
          rows: [{
            id: sourceId,
            name: 'API',
            default_confidence: 'medium',
            default_threat_classification: null,
            default_expire_policy: 'never',
            default_expire_days: null,
            active: true,
            archived_at: null
          }]
        };
      }
      if (s.includes('FROM ioc_threat_classifications') || s.includes('ioc_threat_classifications')) {
        return { rows: [] };
      }
      if (s.includes('FROM ioc_tags') || s.includes('JOIN tags')) {
        return { rows: [] };
      }
      if (s.includes('FROM tags')) {
        return { rows: [] };
      }
      if (s.includes('INSERT INTO ioc_observables') || s.includes('UPDATE ioc_items') || s.includes('recompute') || s.includes('SELECT * FROM ioc_items WHERE id')) {
        return { rows: inserted ? [inserted] : [], rowCount: 1 };
      }
      if (s.includes('BEGIN') || s.includes('COMMIT') || s.includes('ROLLBACK') || s.includes('DELETE FROM')) {
        return { rows: [], rowCount: 0 };
      }
      // createManualIoc may open a nested client via pool.connect in classification replace —
      // our mocked create path usually won't hit that when classifications empty.
      return { rows: [], rowCount: 0 };
    },
    async connect() {
      return {
        query: (...args) => this.query(...args),
        release() {}
      };
    }
  };
}

test('createApiIoc returns existing on duplicate type+value without inserting', async () => {
  const existing = {
    id: 55,
    public_id: 'p-55',
    observable: 'evil.example.com',
    observable_type: 'domain',
    confidence: 'high',
    threat_classification: 'malware_download',
    note: null,
    status: 'active',
    created_at: '2026-01-01T00:00:00.000Z'
  };
  const pool = makeCreatePool({ existing });
  const result = await createApiIoc(pool, {
    type: 'domain',
    value: 'Evil.Example.COM',
    confidence: 'low',
    source: 'ThreatFox'
  }, { apiKey: { id: 1, name: 'bot', key_type: 'ioc_management' } });

  assert.equal(result.status, 200);
  assert.equal(result.body.created, false);
  assert.equal(result.body.existing, true);
  assert.equal(result.body.id, 55);
  assert.equal(result.body.value, 'evil.example.com');
  assert.equal(pool.calls.some((c) => c.sql.includes('INSERT INTO ioc_items')), false);
});

test('updateApiIoc rejects type/value changes', async () => {
  const pool = {
    async query() {
      return {
        rows: [{
          id: 7,
          observable: 'evil.example.com',
          observable_type: 'domain',
          confidence: 'medium',
          note: null
        }]
      };
    }
  };
  const typeReject = await updateApiIoc(pool, 7, { type: 'ip' }, {});
  assert.equal(typeReject.status, 400);
  assert.match(typeReject.error.message, /immutable/i);

  const valueReject = await updateApiIoc(pool, 7, { value: 'other.com' }, {});
  assert.equal(valueReject.status, 400);
  assert.match(valueReject.error.message, /immutable/i);
});

test('updateApiIoc returns 404 for missing IOC', async () => {
  const pool = { async query() { return { rows: [] }; } };
  const result = await updateApiIoc(pool, 999, { note: 'x' }, {});
  assert.equal(result.status, 404);
  assert.equal(result.error.code, API_ERROR_CODE.IOC_NOT_FOUND);
});

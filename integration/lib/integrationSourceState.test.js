import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCompactCountPayload,
  upsertIntegrationSourceState
} from './integrationSourceState.js';

function recordingClient(handlers = []) {
  const calls = [];
  return {
    calls,
    async query(sql, params = []) {
      calls.push({ sql: String(sql), params });
      for (const h of handlers) {
        if (h.match(sql, params)) return h.result(sql, params);
      }
      return { rows: [], rowCount: 1 };
    }
  };
}

describe('buildCompactCountPayload', () => {
  it('stores only version + count', () => {
    assert.deepEqual(buildCompactCountPayload(6413), { v: 1, count: 6413 });
    assert.deepEqual(buildCompactCountPayload(null), { v: 1, count: 0 });
  });
});

describe('upsertIntegrationSourceState', () => {
  it('INSERTs on first write with JSON payload', async () => {
    const client = recordingClient();
    await upsertIntegrationSourceState(client, 'ThreatFox:abuse.ch', 'abc', { v: 1, count: 3 });
    assert.equal(client.calls.length, 1);
    assert.match(client.calls[0].sql, /INSERT INTO integration_source_state/);
    assert.equal(client.calls[0].params[0], 'ThreatFox:abuse.ch');
    assert.equal(client.calls[0].params[1], 'abc');
    assert.equal(client.calls[0].params[2], JSON.stringify({ v: 1, count: 3 }));
  });

  it('preserves items_json TOAST when content_hash is unchanged', async () => {
    const client = recordingClient();
    await upsertIntegrationSourceState(client, 'src', 'same-hash', { v: 1, count: 10 });
    const sql = client.calls[0].sql;
    assert.match(sql, /content_hash IS NOT DISTINCT FROM EXCLUDED\.content_hash/);
    assert.match(sql, /THEN integration_source_state\.items_json/);
    assert.match(sql, /ELSE EXCLUDED\.items_json/);
    assert.match(sql, /updated_at = NOW\(\)/);
  });

  it('accepts pre-stringified JSON', async () => {
    const client = recordingClient();
    await upsertIntegrationSourceState(client, 'src', 'h', '{"v":1,"count":2}');
    assert.equal(client.calls[0].params[2], '{"v":1,"count":2}');
  });

  it('stringifies arrays used by checkpoint feeds', async () => {
    const client = recordingClient();
    await upsertIntegrationSourceState(client, 'src', 'h', [{ a: 1 }]);
    assert.equal(client.calls[0].params[2], JSON.stringify([{ a: 1 }]));
  });
});

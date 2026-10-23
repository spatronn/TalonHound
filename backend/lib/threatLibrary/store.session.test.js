/**
 * Regression: fenced AI outcome persistence passes a raw pg.Client (has both
 * .connect and .release) into reconcileReportCandidates / replaceCandidates.
 * Detecting a Pool by `.connect` alone reconnects that client and throws
 * "Client has already been connected".
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { acquireDbSession, reconcileReportCandidates, replaceCandidates } from './store.js';

function checkedOutClient() {
  let connectCalls = 0;
  const queries = [];
  const client = {
    connect: async () => {
      connectCalls += 1;
      throw new Error('Client has already been connected. You cannot reuse a client.');
    },
    release() {},
    async query(sql, params) {
      queries.push(String(sql).slice(0, 80));
      if (/FROM threat_report_candidates WHERE report_id = \$1 ORDER BY id FOR UPDATE/.test(sql)) {
        return { rows: [] };
      }
      if (/INSERT INTO threat_report_candidates/.test(sql)) {
        return {
          rows: [{
            id: 1,
            report_id: params[0],
            candidate_type: params[2],
            normalized_value: params[3],
            role: params[6],
            assessment: params[5]
          }]
        };
      }
      return { rows: [] };
    }
  };
  return { client, connectCalls: () => connectCalls, queries };
}

test('acquireDbSession: Pool-like (connect, no release) checkouts a session', async () => {
  const inner = { query() {}, release() {} };
  const pool = { connect: async () => inner, query() {} };
  const { client, owned } = await acquireDbSession(pool);
  assert.equal(client, inner);
  assert.equal(owned, true);
});

test('acquireDbSession: checked-out client (connect + release) is reused', async () => {
  const { client: raw, connectCalls } = checkedOutClient();
  const { client, owned } = await acquireDbSession(raw);
  assert.equal(client, raw);
  assert.equal(owned, false);
  assert.equal(connectCalls(), 0);
});

test('acquireDbSession: query-only handle is reused without connect', async () => {
  const db = { async query() { return { rows: [] }; } };
  const { client, owned } = await acquireDbSession(db);
  assert.equal(client, db);
  assert.equal(owned, false);
});

test('reconcileReportCandidates inside a fenced transaction does not reconnect the client', async () => {
  const { client, connectCalls } = checkedOutClient();
  const out = await reconcileReportCandidates(client, 42, []);
  assert.equal(connectCalls(), 0);
  assert.equal(out.rows.length, 0);
  assert.equal(out.unchanged, 0);
});

test('replaceCandidates inside a fenced transaction does not reconnect the client', async () => {
  const { client, connectCalls } = checkedOutClient();
  const rows = await replaceCandidates(client, 42, [
    {
      candidate_type: 'domain',
      original_value: 'evil.example',
      normalized_value: 'evil.example',
      assessment: 'malicious',
      role: 'command_and_control'
    }
  ]);
  assert.equal(connectCalls(), 0);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].normalized_value, 'evil.example');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { acquireCreateIocsLock, createIocsInProgressError } from './createIocsLock.js';
import { applyCandidateReviewActions } from './reviewService.js';

test('createIocsInProgressError is a 409 conflict', () => {
  const err = createIocsInProgressError();
  assert.equal(err.ok, false);
  assert.equal(err.status, 409);
  assert.equal(err.code, 'create_iocs_in_progress');
});

test('fake pool without connect() acquires lock (unit-test path)', async () => {
  const lock = await acquireCreateIocsLock({}, 9);
  assert.equal(lock.acquired, true);
  await lock.release();
});

test('session advisory lock blocks a second acquire until release', async () => {
  let held = false;
  const clients = [];
  const pool = {
    async connect() {
      const client = {
        async query(sql) {
          if (/pg_try_advisory_lock/.test(sql)) {
            if (held) return { rows: [{ ok: false }] };
            held = true;
            return { rows: [{ ok: true }] };
          }
          if (/pg_advisory_unlock/.test(sql)) {
            held = false;
            return { rows: [{ ok: true }] };
          }
          return { rows: [] };
        },
        release() {
          /* noop */
        }
      };
      clients.push(client);
      return client;
    }
  };

  const first = await acquireCreateIocsLock(pool, 42);
  assert.equal(first.acquired, true);
  const second = await acquireCreateIocsLock(pool, 42);
  assert.equal(second.acquired, false);
  await first.release();
  const third = await acquireCreateIocsLock(pool, 42);
  assert.equal(third.acquired, true);
  await third.release();
});

test('confirmed create_iocs returns in_progress when lock is held', async () => {
  const report = {
    id: 9,
    public_id: 'rep-1',
    analysis_status: 'ready',
    source_url: null
  };
  const candidate = {
    id: 1,
    report_id: 9,
    candidate_type: 'ip',
    normalized_value: '203.0.113.10',
    original_value: '203.0.113.10',
    assessment: 'malicious',
    review_status: 'approved',
    match_state: 'new',
    matched_ioc_id: null,
    is_ioc: true,
    confidence: 0.9,
    role: 'c2',
    source_assertion: 'explicit_ioc',
    has_original_document_occurrence: true,
    evidence: {
      document_has_authoritative_scope: true,
      source_assertion: 'explicit_ioc',
      is_direct_source_observable: true,
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true }]
    },
    updated_at: '2026-10-10T00:00:00.000Z'
  };

  let held = true;
  const pool = {
    async connect() {
      return {
        async query(sql) {
          if (/pg_try_advisory_lock/.test(sql)) {
            return { rows: [{ ok: !held ? true : false }] };
          }
          if (/pg_advisory_unlock/.test(sql)) {
            held = false;
            return { rows: [{ ok: true }] };
          }
          return { rows: [] };
        },
        release() {}
      };
    },
    async query(sql, params) {
      if (/FROM threat_reports WHERE id/.test(sql)) return { rows: [report] };
      if (/FROM threat_report_candidates/.test(sql)) {
        if (/id = ANY/.test(sql)) return { rows: [candidate] };
        return { rows: [candidate] };
      }
      if (/FROM ioc_sources WHERE name/.test(sql)) return { rows: [{ id: 4 }] };
      return { rows: [], rowCount: 0 };
    }
  };

  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [1],
    confirm: true
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, 'create_iocs_in_progress');
  assert.equal(result.status, 409);
});

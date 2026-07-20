// No-op / dedup semantics for the USOM bulk import path.
//
// TEST HARNESS CAVEAT — READ THIS BEFORE TRUSTING THESE TESTS
// ----------------------------------------------------------
// This repository has no real-PostgreSQL test harness; every existing integration test
// mocks the pg client. These tests follow that convention, which means they verify:
//   * which statements are (and crucially are NOT) issued,
//   * the guard predicates present in the emitted SQL,
//   * the counter mapping derived from classification results,
//   * affected-row handling when the driver reports rowCount 0.
//
// They CANNOT prove PostgreSQL produces no physical UPDATE — that requires the live
// two-run verification (pg_stat_user_tables.n_tup_upd) documented in the task report.
// Treat these as guards against regression in importer logic, not as proof of DB
// behaviour.

import test from 'node:test';
import assert from 'node:assert/strict';
import { finalizeUsomImport } from './usomImportStore.js';

const FEED_ID = '7848ece4-ab84-44b9-a206-46826091c44c';
const SEEN_AT = new Date('2026-07-20T19:48:00.000Z');

/**
 * @param {object} opts
 * @param {{created:number,changed:number,unchanged:number,reactivated:number}} opts.classification
 * @param {string} opts.expirationMode policy mode returned for every observable type
 * @param {number} opts.missingRowCount rows the missing-marking UPDATE reports as affected
 */
function makeClient({
  classification = { created: 0, changed: 0, unchanged: 0, reactivated: 0 },
  expirationMode = 'never',
  enabled = false,
  missingRowCount = 0,
  newlyMissing = null,
  failOn = null
} = {}) {
  const calls = [];
  const client = {
    calls,
    async query(sql, params = []) {
      calls.push({ sql, params });
      if (failOn && sql.includes(failOn)) throw new Error('snapshot exploded');
      if (sql.includes('FROM integration_feeds')) {
        return {
          rows: [{
            integration_id: FEED_ID,
            key: 'usom-trcert',
            name: 'Siber Güvenlik Başkanlığı / USOM',
            default_confidence: 'medium',
            feed_update_mode: 'snapshot'
          }]
        };
      }
      if (sql.includes('AS created') && sql.includes('AS unchanged')) {
        return { rows: [classification] };
      }
      if (sql.includes('AS suppressed FROM removed')) return { rows: [{ suppressed: 0 }] };
      if (sql.includes('threat_feed_expiration_policies')) {
        return { rows: [{ enabled, expiration_mode: expirationMode, ttl_days: 30, grace_days: 7 }] };
      }
      if (sql.includes(`COUNT(*)::int AS count FROM usom_import_stage`)) {
        return { rows: [{ count: 5 }] };
      }
      if (sql.includes('AS newly_missing')) {
        // Defaults to the touched-row count so tests that don't care see them agree.
        return { rows: [{ newly_missing: newlyMissing ?? missingRowCount }] };
      }
      if (sql.includes('SET missing_since = COALESCE')) {
        return { rows: [], rowCount: missingRowCount };
      }
      // Default: statement affected nothing — the unchanged/no-op case.
      return { rows: [], rowCount: 0 };
    }
  };
  return client;
}

function find(calls, needle) {
  return calls.filter((c) => c.sql.includes(needle));
}

test('scenario 1: first import of a new IOC counts as created and seeds both timestamps', async () => {
  const client = makeClient({ classification: { created: 1, changed: 0, unchanged: 0, reactivated: 0 } });
  const result = await finalizeUsomImport(client, {
    stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 1
  });

  assert.equal(result.metrics.records_inserted, 1);
  assert.equal(result.metrics.records_unchanged, 0);
  assert.equal(result.metrics.records_reactivated, 0);

  const upsert = find(client.calls, 'INSERT INTO ioc_feed_memberships')[0];
  assert.ok(upsert, 'membership upsert must run');
  // New rows seed first_seen_in_feed, last_changed_in_source and the fingerprint together.
  assert.match(upsert.sql, /first_seen_in_feed, last_seen_in_feed/);
  assert.match(upsert.sql, /last_changed_in_source, content_fingerprint/);
  // No separate presence column exists; presence comes from the staging anti-join.
  assert.equal(/last_observed_in_source/.test(upsert.sql), false);
});

test('scenario 2: identical payload re-import is a pure no-op', async () => {
  const client = makeClient({ classification: { created: 0, changed: 0, unchanged: 4, reactivated: 0 } });
  const result = await finalizeUsomImport(client, {
    stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 2
  });

  assert.equal(result.metrics.records_unchanged, 4);
  assert.equal(result.metrics.records_updated, 0, 'unchanged must not leak into changed');
  assert.equal(result.metrics.records_reactivated, 0, 'unchanged is not a reactivation');
  assert.equal(result.metrics.records_removed, 0, 'unchanged is not a removal');

  // The membership upsert is still ISSUED (it must insert genuinely new rows), but its
  // DO UPDATE is gated so an unchanged row produces no physical UPDATE.
  const upsert = find(client.calls, 'INSERT INTO ioc_feed_memberships')[0];
  assert.match(
    upsert.sql,
    /WHERE ioc_feed_memberships\.content_fingerprint IS DISTINCT FROM EXCLUDED\.content_fingerprint/,
    'upsert must carry a fingerprint change guard'
  );
  // The mocked driver reports rowCount 0 for the upsert => nothing was updated.
  assert.equal(result.metrics.records_updated, 0);

  // On IOC-scoped tables, updated_at may only be written inside a guarded branch.
  // integration_source_state / integration_runs are deliberately excluded: those carry
  // the feed-level "last successfully checked" fact, which SHOULD advance on every
  // successful run. That is exactly the timestamp analysts should read instead of a
  // per-IOC one.
  const iocScoped = client.calls.filter((c) => (
    c.sql.includes('updated_at = NOW()')
    && (c.sql.includes('ioc_feed_memberships') || c.sql.includes('ioc_items'))
  ));
  for (const call of iocScoped) {
    assert.match(call.sql, /WHERE|AND \(/, 'every IOC-scoped updated_at write must be guarded');
  }
});

test('scenario 2b: unchanged run writes no audit and emits no run-level change event', async () => {
  const client = makeClient({ classification: { created: 0, changed: 0, unchanged: 3, reactivated: 0 } });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 3 });

  assert.equal(find(client.calls, 'audit_logs').length, 0, 'no audit rows may be written');
  assert.equal(find(client.calls, 'ioc_activity').length, 0);
  assert.equal(find(client.calls, 'NOTIFY').length, 0, 'no downstream notification');
});

test('scenario 3: changed source metadata counts as changed exactly once', async () => {
  const client = makeClient({ classification: { created: 0, changed: 2, unchanged: 0, reactivated: 0 } });
  const result = await finalizeUsomImport(client, {
    stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 4
  });

  assert.equal(result.metrics.records_updated, 2);
  assert.equal(result.metrics.records_unchanged, 0);
  // Changed rows advance the analyst-visible timestamp; unchanged ones cannot reach it
  // because the same statement is fingerprint-guarded.
  const upsert = find(client.calls, 'INSERT INTO ioc_feed_memberships')[0];
  assert.match(upsert.sql, /last_changed_in_source = EXCLUDED\.last_changed_in_source/);
});

test('scenario 4: fingerprint is canonical, so ordering-only differences never reach the DB', async () => {
  // Canonicalisation is the normalizer's job; assert it here so a regression in stable
  // key ordering surfaces as a dedup failure rather than silent churn.
  const { computeUsomProviderFingerprint } = await import('./usomNormalizer.js');
  const base = {
    observable: 'bumuhgudereteyse.lol',
    observableType: 'domain',
    category: 'threat-intel',
    note: 'n',
    providerMetadata: { provider_record_id: 5, provider_type: 'domain', provider_source_code: 'A' }
  };
  const reordered = {
    note: 'n',
    category: 'threat-intel',
    observableType: 'domain',
    observable: 'bumuhgudereteyse.lol',
    providerMetadata: { provider_source_code: 'A', provider_type: 'domain', provider_record_id: 5 }
  };
  assert.equal(
    computeUsomProviderFingerprint(base),
    computeUsomProviderFingerprint(reordered),
    'key order must not affect the fingerprint'
  );

  // Volatile run/import fields must be excluded from the fingerprint entirely.
  const withRunNoise = {
    ...base,
    providerMetadata: { ...base.providerMetadata, imported_at: new Date().toISOString(), run_id: 'abc' }
  };
  assert.equal(
    computeUsomProviderFingerprint(base),
    computeUsomProviderFingerprint(withRunNoise),
    'run/import metadata must not affect the fingerprint'
  );
});

test('scenario 5: removal only happens on a successful full snapshot', async () => {
  const client = makeClient({
    classification: { created: 0, changed: 0, unchanged: 2, reactivated: 0 },
    expirationMode: 'missing_from_feed_ttl',
    enabled: true,
    missingRowCount: 3
  });
  const result = await finalizeUsomImport(client, {
    stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', snapshotStable: true, runId: 5
  });

  // The mock reports 3 affected rows per observable type, and markMissingMemberships
  // iterates all four canonical types (domain, url, ip, ipv6) => 12.
  assert.equal(result.markedMissing, 12);
  assert.equal(result.metrics.records_removed, 12, 'removed must be its own counter');
  // The UPDATE scope is unchanged from before this work (see the dedicated
  // grace_days test); `removed` comes from the separate transition count.
  const missing = find(client.calls, 'SET missing_since = COALESCE')[0];
  assert.ok(missing, 'successful full snapshot must run absence reconciliation');
});

test('scenario 5b: incremental run never removes IOCs that simply were not in this batch', async () => {
  const client = makeClient({
    classification: { created: 0, changed: 0, unchanged: 2, reactivated: 0 },
    expirationMode: 'missing_from_feed_ttl',
    enabled: true,
    missingRowCount: 9
  });
  const result = await finalizeUsomImport(client, {
    stats: {}, seenAt: SEEN_AT, mode: 'incremental', runId: 6
  });

  assert.equal(find(client.calls, 'SET missing_since = COALESCE').length, 0,
    'incremental absence is not evidence of removal');
  assert.equal(result.metrics.records_removed, 0);
});

test('scenario 6: a failed snapshot rolls back and marks nothing missing', async () => {
  const client = makeClient({
    classification: { created: 0, changed: 0, unchanged: 1, reactivated: 0 },
    expirationMode: 'missing_from_feed_ttl',
    enabled: true,
    failOn: 'INSERT INTO ioc_feed_source_evidence'
  });

  await assert.rejects(
    finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 7 }),
    /snapshot exploded/
  );

  assert.equal(find(client.calls, 'SET missing_since = COALESCE').length, 0,
    'removal stage must not be reached when the snapshot fails');
  assert.equal(client.calls.at(-1).sql, 'ROLLBACK');
  assert.equal(find(client.calls, 'COMMIT').length, 0);
});

test('scenario 7: a returning inactive membership is reactivated, not counted as changed', async () => {
  const client = makeClient({ classification: { created: 0, changed: 0, unchanged: 0, reactivated: 2 } });
  const result = await finalizeUsomImport(client, {
    stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 8
  });

  assert.equal(result.metrics.records_reactivated, 2);
  assert.equal(result.metrics.records_updated, 0, 'reactivation must not inflate changed');
  assert.equal(result.metrics.records_unchanged, 0);

  // The guard must let inactive rows through even when the fingerprint is identical.
  const upsert = find(client.calls, 'INSERT INTO ioc_feed_memberships')[0];
  assert.match(upsert.sql, /OR ioc_feed_memberships\.status IS DISTINCT FROM 'active'/);
  assert.match(upsert.sql, /OR ioc_feed_memberships\.missing_since IS NOT NULL/);
});

test('scenario 9: analyst overrides survive an unchanged import', async () => {
  const client = makeClient({ classification: { created: 0, changed: 0, unchanged: 5, reactivated: 0 } });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 9 });

  const upsert = find(client.calls, 'INSERT INTO ioc_feed_memberships')[0];
  // Every lifecycle reset stays gated on override_enabled, and no override_* column is
  // ever assigned by the importer.
  assert.match(upsert.sql, /WHEN ioc_feed_memberships\.override_enabled THEN ioc_feed_memberships\.status/);
  assert.equal(/SET[\s\S]*override_(enabled|status|expires_at|reason) =/.test(upsert.sql), false,
    'importer must never write analyst override columns');

  const policy = find(client.calls, 'SET policy_expires_at')[0];
  assert.match(policy.sql, /m\.override_enabled AND m\.override_status/);
});

test('policy and status-refresh statements carry change guards', async () => {
  const client = makeClient({
    classification: { created: 0, changed: 0, unchanged: 2, reactivated: 0 },
    expirationMode: 'fixed_ttl',
    enabled: true
  });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 10 });

  const policy = find(client.calls, 'SET policy_expires_at')[0];
  assert.match(policy.sql, /m\.policy_expires_at IS DISTINCT FROM c\.policy_expiry/,
    'policy update must not rewrite identical values');

  const status = find(client.calls, 'UPDATE ioc_items i')[0];
  assert.match(status.sql, /i\.status IS DISTINCT FROM/,
    'global status refresh must not rewrite identical values');
});

test('no parallel presence column is introduced anywhere', async () => {
  // Design decision: full-snapshot presence is derived from the usom_import_stage
  // anti-join, which costs zero membership writes. A dedicated "observed at" column
  // would mean UPDATEing every membership row on every snapshot for no behaviour change.
  const client = makeClient({
    classification: { created: 0, changed: 0, unchanged: 2, reactivated: 0 },
    expirationMode: 'last_seen_ttl',
    enabled: true
  });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 11 });

  for (const call of client.calls) {
    assert.equal(/last_observed_in_source/.test(call.sql), false,
      'no parallel presence column may be written');
  }
});

test('records_duplicate is retained as a deprecated alias of records_unchanged', async () => {
  const client = makeClient({ classification: { created: 1, changed: 1, unchanged: 6, reactivated: 1 } });
  const result = await finalizeUsomImport(client, {
    stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 13, inRunDuplicates: 2
  });

  assert.equal(result.metrics.records_unchanged, 8, 'in-run duplicates fold into unchanged');
  assert.equal(result.metrics.records_duplicate, result.metrics.records_unchanged,
    'deprecated alias must mirror the canonical counter');

  // The run UPDATE must persist both, plus the new counters.
  const runUpdate = find(client.calls, 'UPDATE integration_runs')[0];
  assert.match(runUpdate.sql, /records_unchanged = \$6/);
  assert.match(runUpdate.sql, /records_duplicate = \$6/);
  assert.match(runUpdate.sql, /records_reactivated = \$7/);
  assert.match(runUpdate.sql, /records_removed = \$8/);
});

test('fingerprint adoption runs after classification and before the guarded upsert', async () => {
  const client = makeClient({ classification: { created: 0, changed: 0, unchanged: 2, reactivated: 0 } });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 14 });

  const classifyIdx = client.calls.findIndex((c) => c.sql.includes('AS created'));
  const adoptIdx = client.calls.findIndex((c) => c.sql.includes('SET content_fingerprint = s.provider_fingerprint'));
  const upsertIdx = client.calls.findIndex((c) => c.sql.includes('INSERT INTO ioc_feed_memberships'));

  assert.ok(classifyIdx >= 0 && adoptIdx > classifyIdx,
    'adoption must not distort classification of pre-migration rows');
  assert.ok(adoptIdx < upsertIdx, 'adoption must precede the guarded upsert');

  const adopt = client.calls[adoptIdx];
  assert.match(adopt.sql, /content_fingerprint IS NULL/, 'adoption is one-time only');
  assert.equal(/updated_at/.test(adopt.sql), false, 'adoption must not bump updated_at');
  assert.equal(/last_changed_in_source/.test(adopt.sql), false,
    'adoption must not move the analyst-visible timestamp');
});

// ---------------------------------------------------------------------------
// Fingerprint adoption (migration 121 one-time baseline)
// ---------------------------------------------------------------------------

test('adoption: active membership with NULL fingerprint and identical payload is unchanged', async () => {
  // Pre-migration-121 row: active, content_fingerprint IS NULL, payload identical.
  // classifyStageAgainstExisting resolves NULL fingerprints to 'unchanged' via its
  // `content_fingerprint IS NOT NULL AND ... IS DISTINCT FROM` branch.
  const client = makeClient({ classification: { created: 0, changed: 0, unchanged: 1, reactivated: 0 } });
  const result = await finalizeUsomImport(client, {
    stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 16
  });

  assert.equal(result.metrics.records_unchanged, 1);
  assert.equal(result.metrics.records_updated, 0, 'adoption must not look like a change');
  assert.equal(result.metrics.records_reactivated, 0);
  assert.equal(find(client.calls, 'audit_logs').length, 0, 'adoption must not audit');

  // The classification SQL must only treat a NON-NULL stored fingerprint as evidence of
  // change; a NULL one falls through to unchanged.
  const classify = find(client.calls, 'AS created')[0];
  assert.match(
    classify.sql,
    /m\.content_fingerprint IS NOT NULL\s*\n?\s*AND m\.content_fingerprint IS DISTINCT FROM/,
    'NULL fingerprint must not be classified as changed'
  );
});

test('adoption: fingerprint is populated without moving updated_at or last_changed_in_source', async () => {
  const client = makeClient({ classification: { created: 0, changed: 0, unchanged: 1, reactivated: 0 } });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 17 });

  const adopt = find(client.calls, 'SET content_fingerprint = s.provider_fingerprint')[0];
  assert.ok(adopt, 'adoption statement must run so NULL fingerprints converge');

  // This IS a physical write — a one-time technical adoption write, reported as such.
  // What matters is that it touches exactly one column.
  assert.match(adopt.sql, /content_fingerprint IS NULL/, 'scoped to unadopted rows only');
  assert.equal(/updated_at/.test(adopt.sql), false, 'must not bump updated_at');
  assert.equal(/last_changed_in_source/.test(adopt.sql), false, 'must not move analyst timestamp');
  assert.equal(/last_seen_in_feed/.test(adopt.sql), false, 'must not touch presence');
  assert.equal(/\bstatus\b/.test(adopt.sql), false, 'must not touch lifecycle status');

  // Exactly one SET assignment, before the FROM clause.
  const setClause = adopt.sql.slice(adopt.sql.indexOf('SET '), adopt.sql.indexOf('FROM '));
  const assignments = setClause.match(/\w+\s*=/g) || [];
  assert.equal(assignments.length, 1, `adoption must write one column, found: ${assignments.join(', ')}`);
});

// ---------------------------------------------------------------------------
// IPv6 canonical type (migration 120 follow-up)
// ---------------------------------------------------------------------------

test('ipv6: canonical stored type reaches policy application and absence reconciliation', async () => {
  const client = makeClient({
    classification: { created: 0, changed: 0, unchanged: 1, reactivated: 0 },
    expirationMode: 'missing_from_feed_ttl',
    enabled: true
  });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 18 });

  // Migration 120 renamed the stored type ip6 -> ipv6. Looking up 'ip6' matched zero
  // rows, silently skipping expiration for every USOM IPv6 membership.
  const missingTypes = find(client.calls, 'SET missing_since = COALESCE').map((c) => c.params[1]);
  assert.ok(missingTypes.includes('ipv6'), 'ipv6 memberships must enter missing reconciliation');
  assert.equal(missingTypes.includes('ip6'), false, 'stale pre-migration-120 type must not be used');

  const policyTypes = find(client.calls, 'SET policy_expires_at').map((c) => c.params[1]);
  assert.ok(policyTypes.includes('ipv6'), 'ipv6 memberships must have expiration policy applied');
  assert.equal(policyTypes.includes('ip6'), false);

  // All four canonical types must be covered, none dropped.
  assert.deepEqual([...new Set(policyTypes)].sort(), ['domain', 'ip', 'ipv6', 'url']);
});

test('ipv6: API stat keys keep the provider vocabulary and totals stay complete', async () => {
  // STORED_IOC_TYPES ('ipv6') and API_TOTAL_TYPES ('ip6') must not be conflated. The
  // USOM API names IPv6 'ip6', so the api_total_* lookup must keep that spelling —
  // renaming it to the canonical form silently drops the IPv6 count from the total.
  const client = makeClient({ classification: { created: 0, changed: 0, unchanged: 1, reactivated: 0 } });
  await finalizeUsomImport(client, {
    stats: {
      api_total_domain: 10,
      api_total_url: 20,
      api_total_ip: 30,
      api_total_ip6: 40,
      api_total_ip6net: 5
    },
    seenAt: SEEN_AT,
    mode: 'full_reconciliation',
    runId: 24
  });

  const stateWrite = find(client.calls, 'INSERT INTO integration_source_state')[0];
  const payload = JSON.parse(stateWrite.params[2]);
  assert.equal(payload.total, 105, 'total must include the ip6 bucket (10+20+30+40+5)');
  assert.equal(payload.totals.api_total_ip6, 40, 'provider stat key must survive verbatim');
});

test('ipv6: importer never writes the legacy ip6 type into new rows', async () => {
  const client = makeClient({ classification: { created: 1, changed: 0, unchanged: 0, reactivated: 0 } });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 19 });

  // Membership/IOC writes derive observable_type from the staging table, which the
  // normalizer already populates with 'ipv6'. No statement may hardcode 'ip6'.
  for (const call of client.calls) {
    assert.equal(
      /'ip6'/.test(call.sql), false,
      `no statement may reference the legacy ip6 type: ${call.sql.slice(0, 80)}`
    );
  }
  for (const call of client.calls) {
    assert.equal((call.params || []).includes('ip6'), false, 'no parameter may bind the legacy type');
  }
});

// ---------------------------------------------------------------------------
// IOC list recency sort
// ---------------------------------------------------------------------------

test('list sort: unchanged run does not advance last_seen_in_feed, so IOCs do not float up', async () => {
  // The IOC-list recency sort reads last_seen_in_feed (index-backed). If an unchanged
  // re-import advanced it, unchanged IOCs would climb the list on every poll — the same
  // bug in a different surface.
  const client = makeClient({ classification: { created: 0, changed: 0, unchanged: 3, reactivated: 0 } });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 20 });

  const writers = client.calls.filter((c) => /last_seen_in_feed\s*=/.test(c.sql));
  // Only the membership upsert may assign it, and only inside its guarded DO UPDATE.
  assert.equal(writers.length, 1, 'exactly one statement may assign last_seen_in_feed');
  assert.match(writers[0].sql, /INSERT INTO ioc_feed_memberships/);
  assert.match(
    writers[0].sql,
    /WHERE ioc_feed_memberships\.content_fingerprint IS DISTINCT FROM EXCLUDED\.content_fingerprint/,
    'the only writer must be fingerprint-guarded'
  );

  // With expiration off, the last_seen_ttl presence write must not run at all.
  assert.equal(find(client.calls, 'SET last_seen_in_feed = $3::timestamptz').length, 0);
});

test('list sort: last_seen_ttl feeds still record presence, but touch nothing else', async () => {
  const client = makeClient({
    classification: { created: 0, changed: 0, unchanged: 2, reactivated: 0 },
    expirationMode: 'last_seen_ttl',
    enabled: true
  });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 21 });

  const presence = find(client.calls, 'SET last_seen_in_feed = $3::timestamptz')[0];
  assert.ok(presence, 'last_seen_ttl expiry is computed from last_seen_in_feed, so it must be written');
  assert.equal(/updated_at/.test(presence.sql), false);
  assert.equal(/last_changed_in_source/.test(presence.sql), false);
  assert.match(presence.sql, /IS DISTINCT FROM \$3::timestamptz/, 'idempotent re-write guard');
});

// ---------------------------------------------------------------------------
// Expiration policy semantics must NOT change as a side effect of this work
// ---------------------------------------------------------------------------

test('missing reconciliation keeps re-evaluating already-missing rows (grace_days edits still apply)', async () => {
  const client = makeClient({
    classification: { created: 0, changed: 0, unchanged: 1, reactivated: 0 },
    expirationMode: 'missing_from_feed_ttl',
    enabled: true,
    missingRowCount: 4
  });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 22 });

  const missing = find(client.calls, 'SET missing_since = COALESCE')[0];
  // Deliberately NOT restricted to `missing_since IS NULL`: narrowing it would silently
  // change expiration-policy behaviour, which is out of scope for the no-op fix.
  assert.equal(
    /AND m\.missing_since IS NULL/.test(missing.sql), false,
    'absence UPDATE scope must stay as-is so grace_days changes keep applying'
  );

  // The exact "removed" count therefore comes from a separate pre-update transition
  // count, not from the UPDATE's rowCount.
  const transitionCount = find(client.calls, 'AS newly_missing')[0];
  assert.ok(transitionCount, 'removed must be counted from genuine transitions');
  assert.match(transitionCount.sql, /m\.missing_since IS NULL/);
});

test('records_removed counts transitions, not every touched row', async () => {
  const client = makeClient({
    classification: { created: 0, changed: 0, unchanged: 1, reactivated: 0 },
    expirationMode: 'missing_from_feed_ttl',
    enabled: true,
    missingRowCount: 10,
    newlyMissing: 2
  });
  const result = await finalizeUsomImport(client, {
    stats: {}, seenAt: SEEN_AT, mode: 'full_reconciliation', runId: 23
  });

  // 4 types x 10 touched rows = 40 touched, but only 4 x 2 = 8 real transitions.
  assert.equal(result.markedMissing, 40, 'touched rows include already-missing ones');
  assert.equal(result.metrics.records_removed, 8, 'removed must count only transitions');
});

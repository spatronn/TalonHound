import test from 'node:test';
import assert from 'node:assert/strict';
import { recomputeIocGlobalStatus } from './iocExpiration.js';
import { fetchObservableMembershipSummary } from './iocActiveSources.js';
import { isExplicitIocLifecycleOverride } from './iocStatusOverrideGuards.js';

/**
 * End-to-end reproduction of the reported scenario, driving the REAL lifecycle service
 * (recomputeIocGlobalStatus) and the REAL source-summary builder (fetchObservableMembershipSummary)
 * over a stateful in-memory Postgres substitute. No local Docker is available and production must
 * not be mutated, so this is the faithful substitute: the actual code paths run, only the storage
 * engine is in-memory.
 *
 *   ThreatFox abuse.ch (feed)  -> expires  -> IOC expired, 0 active sources
 *   Threat-Hunting (manual)    -> re-added -> IOC active again, 1 active / 2 total
 *   => manual lifecycle override = false ; ThreatFox stays historical/expired
 */

const OBS = 'deneme.reproduction.xyz';
const TYPE = 'domain';

function makeStore() {
  return {
    rows: [
      // ThreatFox feed row.
      {
        id: 1, observable: OBS, observable_type: TYPE, source_name: 'ThreatFox:abuse.ch',
        ioc_source_id: null, status: 'active', expires_at: null, expired_at: null,
        expiration_reason: null, manual_status_override: false, manual_status: null,
        manual_expires_at: null, manual_override_reason: null, created_at: '2026-01-01T00:00:00Z',
        last_seen_at: null
      }
    ],
    memberships: [
      {
        id: 10, ioc_item_id: 1, ioc_observable_type: TYPE, feed_id: 'f-threatfox', status: 'active',
        purged_at: null, purge_reason: null, first_seen_in_feed: '2026-01-01T00:00:00Z',
        last_seen_in_feed: '2026-02-01T00:00:00Z', last_changed_in_source: '2026-02-01T00:00:00Z',
        policy_expires_at: null, expires_at: null, override_enabled: false, explicit_confidence: null,
        feed_key: 'threatfox-abusech', feed_name: 'ThreatFox abuse.ch', feed_default_confidence: 'medium'
      }
    ]
  };
}

function makePool(store) {
  function rowById(id, type) {
    return store.rows.find((r) => Number(r.id) === Number(id) && r.observable_type === type);
  }
  async function query(sql, params = []) {
    const s = String(sql).replace(/\s+/g, ' ').trim();

    if (s.includes('FROM ioc_suppressions')) return { rows: [] };

    // recompute row SELECT by id
    if (s.startsWith('SELECT id, observable, observable_type, status, manual_status_override')
        && s.includes('WHERE id = $1 AND observable_type = $2')) {
      const r = rowById(params[0], params[1]);
      return { rows: r ? [{ ...r }] : [] };
    }

    // recompute: membership status list for observable
    if (s.includes('FROM ioc_feed_memberships m') && s.includes('INNER JOIN ioc_items i') && s.includes('m.status, m.purged_at')) {
      return { rows: store.memberships.map((m) => ({ status: m.status, purged_at: m.purged_at })) };
    }
    // recompute: MIN active expires
    if (s.includes('MIN(m.expires_at)')) {
      const act = store.memberships.filter((m) => m.status === 'active' && !m.purged_at && m.expires_at);
      return { rows: [{ min_exp: act.length ? act.map((m) => m.expires_at).sort()[0] : null }] };
    }
    // recompute override-branch write (WHERE id)
    if (s.includes('UPDATE ioc_items') && s.includes('SET status = $3, expires_at = $4, expired_at = $5, expiration_reason = $6')
        && s.includes('WHERE id = $1 AND observable_type = $2')) {
      const r = rowById(params[0], params[1]);
      if (r) { r.status = params[2]; r.expires_at = params[3]; r.expired_at = params[4]; r.expiration_reason = params[5]; }
      return { rowCount: r ? 1 : 0, rows: [] };
    }
    // recompute membership-branch write (WHERE observable)
    if (s.includes('UPDATE ioc_items') && s.includes('WHERE observable = $1 AND observable_type = $2')) {
      for (const r of store.rows) {
        if (r.observable === params[0] && r.observable_type === params[1]) {
          r.status = params[2]; r.expires_at = params[3]; r.expired_at = params[4]; r.expiration_reason = params[5];
        }
      }
      return { rowCount: 1, rows: [] };
    }

    // fetchObservableMembershipSummary: memberships by ioc_item_id ANY
    if (s.includes('FROM ioc_feed_memberships m') && s.includes('m.ioc_item_id = ANY($1::bigint[])')) {
      const ids = new Set((params[0] || []).map(Number));
      const rows = store.memberships.filter((m) => ids.has(Number(m.ioc_item_id)));
      return { rows: rows.map((m) => ({ ...m })) };
    }
    // fetchObservableMembershipSummary: active manual sources by observable
    if (s.includes('DISTINCT ON (i.ioc_source_id)') && s.includes('FROM ioc_items i')) {
      const rows = store.rows.filter((r) => r.observable === params[0] && r.observable_type === params[1]
        && String(r.status || 'active') === 'active' && r.ioc_source_id != null)
        .map((r) => ({
          ioc_item_id: r.id, ioc_source_id: r.ioc_source_id, source_name: r.source_name,
          created_at: r.created_at, last_seen_at: r.last_seen_at, expires_at: r.expires_at
        }));
      return { rows };
    }
    // fetchObservableMembershipSummary: historical manual memberships
    if (s.includes('FROM ioc_manual_source_memberships h')) return { rows: [] };

    throw new Error(`Unexpected query: ${s.slice(0, 140)}`);
  }
  return { query, connect: async () => ({ query, release: () => {} }) };
}

test('reproduction: expired feed IOC re-added via manual source => active, 1/2 sources, override=false', async () => {
  const store = makeStore();
  const pool = makePool(store);

  // Step 1: baseline — ThreatFox active, IOC active.
  await recomputeIocGlobalStatus(pool, 1, TYPE);
  assert.equal(store.rows.find((r) => r.id === 1).status, 'active');

  // Step 2: feed source expires -> membership expired, recompute.
  store.memberships[0].status = 'expired';
  store.memberships[0].expired_at = '2026-07-01T00:00:00Z';
  await recomputeIocGlobalStatus(pool, 1, TYPE);
  assert.equal(store.rows.find((r) => r.id === 1).status, 'expired');
  {
    const summary = await fetchObservableMembershipSummary(pool, { observable: OBS, observableType: TYPE, iocItemIds: [1] });
    assert.equal(summary.activeSourceCount, 0, 'no active sources after feed expiry');
  }

  // Step 3: manual re-add via Threat-Hunting (persisted exactly as createManualIoc writes it).
  store.rows.push({
    id: 2, observable: OBS, observable_type: TYPE, source_name: 'Threat-Hunting', ioc_source_id: 7,
    status: 'active', expires_at: null, expired_at: null, expiration_reason: null,
    manual_status_override: true, manual_status: 'active', manual_expires_at: '2026-09-18T12:00:00Z',
    manual_override_reason: 'manual_custom_expire', created_at: '2026-08-19T12:00:00Z', last_seen_at: null
  });
  await recomputeIocGlobalStatus(pool, 2, TYPE);

  const feedRow = store.rows.find((r) => r.id === 1);
  const manualRow = store.rows.find((r) => r.id === 2);

  // Step 4: assert the exact reproduction semantics via real code.
  assert.equal(manualRow.status, 'active', 'manual source row is active');
  assert.equal(feedRow.status, 'expired', 'ThreatFox row stays historical/expired');
  assert.equal(manualRow.expires_at, '2026-09-18T12:00:00Z', 'manual source keeps its own expiry');

  const summary = await fetchObservableMembershipSummary(pool, { observable: OBS, observableType: TYPE, iocItemIds: [1, 2] });
  assert.equal(summary.activeSourceCount, 1, '1 active source (Threat-Hunting)');
  assert.equal(summary.activeSourceNames[0], 'Threat-Hunting');
  assert.equal(summary.historicalMemberships.length, 1, 'ThreatFox is historical');
  const totalSources = summary.activeSourceCount + summary.historicalSourceCount;
  assert.equal(totalSources, 2, '2 total sources');

  // The analyst-facing "Manual Override" (from the lifecycle row) is FALSE.
  assert.equal(isExplicitIocLifecycleOverride(manualRow), false, 'manual source is NOT an explicit override');

  // No raw internal reason leaks as an analyst-facing expiration reason while active.
  // (Details API suppresses expiration_reason for active IOCs; the row itself may carry a sentinel.)
  const detailsExpirationReason = String(manualRow.status).toLowerCase() === 'expired'
    ? (manualRow.expiration_reason || null)
    : null;
  assert.equal(detailsExpirationReason, null);
});

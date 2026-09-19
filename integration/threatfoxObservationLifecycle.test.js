import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyThreatFoxObservable,
  computeThreatFoxSemanticFingerprint,
  mapThreatFoxApiRow,
  threatFoxObservedAt
} from './lib/threatfox.js';
import { updateThreatFoxObservableBySource } from './importer.js';
import { upsertMembershipOnImport, withImportOptimizationContext } from '../backend/lib/iocExpiration.js';

const IOC = '81.70.21.248';
const FEED_ID = '9f04b9f4-fc5b-4195-8802-0c99ac14b721';
const T1 = new Date('2026-06-03T00:00:00.000Z');
const T2 = new Date('2026-07-31T09:05:06.000Z');

function rowForPort(port, firstSeen, id) {
  return mapThreatFoxApiRow({
    id: String(id),
    ioc: `${IOC}:${port}`,
    ioc_type: 'ip:port',
    threat_type: 'botnet_cc',
    malware: 'win.cobalt_strike',
    malware_printable: 'Cobalt Strike',
    malware_alias: 'CobaltStrike',
    confidence_level: 75,
    first_seen: firstSeen,
    last_seen: firstSeen,
    reporter: 'abuse_ch',
    tags: ['c2']
  });
}

describe('ThreatFox IP:port observation lifecycle', () => {
  it('normalizes distinct ports to one base IP identity', () => {
    const a = classifyThreatFoxObservable(`${IOC}:443`, 'ip:port');
    const b = classifyThreatFoxObservable(`${IOC}:22`, 'ip:port');
    assert.equal(a.observable, IOC);
    assert.equal(b.observable, IOC);
    assert.equal(a.observableType, 'ip');
    assert.notEqual(`${IOC}:443`, a.observable);
  });

  it('treats later port observations as the same semantic membership fingerprint', () => {
    const first = rowForPort(443, '2026-06-03 00:00:00 UTC', 1001);
    const later = rowForPort(22, '2026-07-31 09:05:06 UTC', 1865994);
    assert.equal(first.observable, later.observable);
    assert.equal(computeThreatFoxSemanticFingerprint(first), computeThreatFoxSemanticFingerprint(later));
    assert.equal(threatFoxObservedAt(first).toISOString(), T1.toISOString());
    assert.equal(threatFoxObservedAt(later).toISOString(), T2.toISOString());
  });

  it('MIN first_seen and MAX last_seen across two port observations without last_changed', async () => {
    const first = rowForPort(443, '2026-06-03 00:00:00 UTC', 1001);
    const later = rowForPort(22, '2026-07-31 09:05:06 UTC', 1865994);
    const fp = computeThreatFoxSemanticFingerprint(first);
    const membership = {
      id: 10,
      ioc_item_id: 2216185,
      ioc_observable_type: 'ip',
      feed_id: FEED_ID,
      first_seen_in_feed: T1,
      last_seen_in_feed: T1,
      last_changed_in_source: T1,
      content_fingerprint: fp,
      missing_since: null,
      override_enabled: false,
      status: 'active',
      expired_at: null,
      expiration_reason: null,
      purged_at: null,
      policy_expires_at: new Date('2026-07-03T00:00:00Z'),
      expires_at: new Date('2026-07-03T00:00:00Z')
    };
    const writes = [];
    const client = {
      async query(sql, params = []) {
        const s = String(sql);
        if (s.includes('FROM threat_feed_expiration_policies')) {
          return { rows: [{ enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 30, feed_id: FEED_ID, observable_type: 'all' }] };
        }
        if (s.includes('FROM ioc_suppressions')) return { rows: [] };
        if (s.includes('FROM ioc_feed_memberships') && s.includes('ioc_item_id')) {
          return { rows: [membership], rowCount: 1 };
        }
        if (s.includes('GREATEST(last_seen_in_feed') && !s.includes('last_changed_in_source')) {
          writes.push({ sql: s, params });
          if (params[1] instanceof Date && membership.last_seen_in_feed < params[1]) {
            membership.last_seen_in_feed = params[1];
            return { rows: [{ ...membership }], rowCount: 1 };
          }
          return { rows: [], rowCount: 0 };
        }
        if (s.includes('last_changed_in_source')) {
          writes.push({ sql: s, params, kind: 'last_changed' });
          return { rows: [{ ...membership }], rowCount: 1 };
        }
        if (s.includes('policy_expires_at')) {
          membership.policy_expires_at = params[1];
          membership.expires_at = params[2];
          membership.status = params[3];
          return { rowCount: 1, rows: [] };
        }
        if (s.includes('FROM ioc_items') && s.includes('manual_status_override')) {
          return {
            rows: [{
              id: 2216185,
              observable: IOC,
              observable_type: 'ip',
              status: 'active',
              manual_status_override: false,
              expires_at: membership.expires_at,
              expired_at: null,
              expiration_reason: null
            }]
          };
        }
        if (s.includes('FROM ioc_feed_memberships m')) return { rows: [{ status: 'active', purged_at: null }] };
        if (s.includes('MIN(m.expires_at)')) return { rows: [{ min_exp: membership.expires_at }] };
        return { rows: [], rowCount: 0 };
      }
    };

    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 2216185,
      observableType: 'ip',
      feedId: FEED_ID,
      seenAt: new Date('2026-08-03T00:24:01Z'),
      firstSeenAt: later.firstSeen,
      observedAt: threatFoxObservedAt(later),
      contentFingerprint: computeThreatFoxSemanticFingerprint(later)
    }));

    assert.equal(first.observable, IOC);
    assert.equal(later.observable, IOC);
    assert.equal(result.outcome, 'reobserved');
    assert.equal(membership.first_seen_in_feed.toISOString(), T1.toISOString());
    assert.equal(membership.last_seen_in_feed.toISOString(), T2.toISOString());
    assert.equal(writes.some((w) => w.kind === 'last_changed'), false);
  });

  it('does not create a second IP identity when a later port observation updates an existing IOC', async () => {
    const first = rowForPort(443, '2026-06-03 00:00:00 UTC', 1001);
    const later = rowForPort(22, '2026-07-31 09:05:06 UTC', 1865994);
    let iocLookups = 0;
    const client = {
      calls: [],
      async query(sql, params = []) {
        const text = String(sql);
        this.calls.push({ sql: text, params });
        if (text.includes('FROM ioc_items') && text.includes('source_name = $3')) {
          iocLookups += 1;
          return {
            rowCount: 1,
            rows: [{
              public_id: '91af0591-e070-4e4c-9890-cbcc84c6f8c5',
              observable_type: 'ip',
              note: 'ioc_id=1001 first_seen=2026-06-03',
              category: 'botnet_cc',
              first_seen_at: T1,
              last_seen_at: T1,
              provider_fingerprint: null
            }]
          };
        }
        if (text.startsWith('UPDATE ioc_items')) {
          return { rowCount: 1, rows: [{ public_id: '91af0591-e070-4e4c-9890-cbcc84c6f8c5' }] };
        }
        if (text.includes('FROM integration_feeds')) {
          return {
            rows: [{
              key: 'threatfox-abusech',
              integration_id: FEED_ID,
              feed_id: FEED_ID,
              name: 'ThreatFox abuse.ch',
              feed_kind: 'builtin',
              feed_update_mode: 'incremental'
            }]
          };
        }
        if (text.includes('FROM ioc_items') && text.includes('WHERE observable = $1')) {
          return { rows: [{ id: 2216185, observable_type: 'ip' }] };
        }
        if (text.includes('FROM integration_feed_expiration_type_policies')) return { rows: [] };
        if (text.includes('FROM threat_feed_expiration_policies')) {
          return { rows: [{ enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 30, feed_id: FEED_ID, observable_type: 'all' }] };
        }
        if (text.includes('FROM ioc_feed_memberships')) {
          return {
            rowCount: 1,
            rows: [{
              id: 2164077,
              status: 'active',
              missing_since: null,
              expired_at: null,
              purged_at: null,
              override_enabled: false,
              first_seen_in_feed: T1,
              last_seen_in_feed: T1,
              last_changed_in_source: T1,
              content_fingerprint: computeThreatFoxSemanticFingerprint(first)
            }]
          };
        }
        if (text.includes('FROM ioc_suppressions')) return { rows: [] };
        if (text.includes('INSERT INTO ioc_observables')) return { rowCount: 1, rows: [] };
        if (text.includes('INSERT INTO ioc_items')) {
          throw new Error('must not insert a duplicate IP IOC');
        }
        if (text.includes('analyst_confidence_override')) return { rows: [{ analyst_confidence_override: null }] };
        if (text.includes('UPDATE ioc_feed_memberships')) {
          return { rowCount: 1, rows: [{ id: 2164077, status: 'active' }] };
        }
        if (text.includes('SELECT m.status, m.purged_at')) return { rows: [{ status: 'active', purged_at: null }] };
        if (text.includes('SELECT MIN(m.expires_at)')) return { rows: [{ min_exp: null }] };
        if (text.includes('FROM ioc_items') && text.includes('WHERE id = $1')) {
          return {
            rows: [{
              id: 2216185,
              observable: IOC,
              observable_type: 'ip',
              status: 'active',
              manual_status_override: false,
              expires_at: null,
              expired_at: null,
              expiration_reason: null
            }]
          };
        }
        throw new Error(`unexpected query: ${text.slice(0, 160)}`);
      }
    };

    const result = await updateThreatFoxObservableBySource(
      client,
      later,
      'ThreatFox:abuse.ch',
      'note',
      later.threatType
    );

    assert.equal(later.observable, first.observable);
    assert.ok(['updated', 'observation_updated'].includes(result.status));
    assert.ok(!client.calls.some((c) => c.sql.includes('INSERT INTO ioc_items')));
  });
});

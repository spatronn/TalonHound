import test from 'node:test';
import assert from 'node:assert/strict';
import { assembleFileIdentitySources, SOURCE_RELATIONSHIP } from './fileIdentitySources.js';

const SHA = 'c91183175ce77360006f964841eb4048cf37cb82103f2573e262927be4c7607f';
const MD5 = '7c396677848776f9824ebe408bbba943';
const SHA1 = 'd577c4a264fee27084ddf717441eb89f714972a5';

function feed(id, name, status = 'active') {
  return {
    id: `feed:${id}`,
    membership_id: id,
    name,
    source_type: 'feed',
    status,
    first_seen_at: '2026-03-08T00:00:00.000Z',
    expires_at: status === 'expired' ? '2026-06-28T00:00:00.000Z' : null,
    actions_enabled: status === 'active'
  };
}

function membership(id, status = 'active') {
  return { id, status, purged_at: null, first_seen_in_feed: '2026-03-08T00:00:00.000Z' };
}

test('canonical SHA256 keeps an expired MD5 source historical and an alias manual source active', () => {
  const summary = assembleFileIdentitySources([
    {
      ioc_id: 681960,
      public_id: 'ce27fd43-612f-402e-a66d-93d124ecf4ec',
      observable: SHA,
      observable_type: 'sha256',
      summary: {
        activeSources: [feed(1, 'MalwareBazaar abuse.ch')],
        historicalSources: [],
        membershipRows: [membership(1)]
      }
    },
    {
      ioc_id: 2200045,
      public_id: '33c877b0-55e0-4bcb-9e42-b961a4ee5826',
      observable: MD5,
      observable_type: 'md5',
      summary: {
        activeSources: [],
        historicalSources: [feed(2, 'ThreatFox abuse.ch', 'expired')],
        membershipRows: [membership(2, 'expired')]
      }
    },
    {
      ioc_id: 3820952,
      public_id: '4c366ab0-5eeb-4f3f-85a0-08482cff53f5',
      observable: SHA1,
      observable_type: 'sha1',
      summary: {
        activeSources: [{
          id: 'manual:19',
          name: 'Threat_Library',
          source_type: 'manual',
          ioc_source_id: 19,
          status: 'active',
          expires_at: '2027-10-29T13:59:51.476Z'
        }],
        historicalSources: [],
        membershipRows: []
      }
    }
  ], { canonicalIocId: 681960 });

  assert.deepEqual(summary.activeSourceNames, ['MalwareBazaar abuse.ch', 'Threat_Library']);
  assert.equal(summary.activeSourceCount, 2);
  assert.equal(summary.historicalSourceCount, 1);
  assert.equal(summary.historicalSources[0].name, 'ThreatFox abuse.ch');
  assert.equal(summary.historicalSources[0].relationship, SOURCE_RELATIONSHIP.VERIFIED_FILE_IDENTITY);
  assert.equal(summary.historicalSources[0].publisher_observable_type, 'md5');
  assert.equal(summary.historicalSources[0].publisher_observable, MD5);
  assert.equal(summary.historicalSources[0].status, 'expired');

  const mb = summary.activeSources.find((s) => s.name === 'MalwareBazaar abuse.ch');
  assert.equal(mb.relationship, SOURCE_RELATIONSHIP.DIRECT);
  assert.equal(mb.publisher_observable_type, 'sha256');
  assert.equal(mb.publisher_observable, SHA);

  const tl = summary.activeSources.find((s) => s.name === 'Threat_Library');
  assert.equal(tl.relationship, SOURCE_RELATIONSHIP.VERIFIED_FILE_IDENTITY);
  assert.equal(tl.publisher_observable_type, 'sha1');
  assert.equal(tl.publisher_ioc_id, 3820952);

  assert.equal(summary.activeSources.some((s) => /virustotal/i.test(s.name)), false);
  assert.equal(summary.historicalSources.some((s) => /virustotal/i.test(s.name)), false);
});

test('an expired alias of a provider that is still active is not a second source and is not reactivated', () => {
  const summary = assembleFileIdentitySources([
    {
      ioc_id: 1,
      public_id: 'p1',
      observable: SHA,
      observable_type: 'sha256',
      summary: {
        activeSources: [feed(10, 'MalwareBazaar abuse.ch')],
        historicalSources: [],
        membershipRows: [membership(10)]
      }
    },
    {
      ioc_id: 2,
      public_id: 'p2',
      observable: MD5,
      observable_type: 'md5',
      summary: {
        activeSources: [],
        historicalSources: [feed(11, 'MalwareBazaar abuse.ch', 'expired')],
        membershipRows: [membership(11, 'expired')]
      }
    }
  ], { canonicalIocId: 1 });

  assert.equal(summary.activeSourceCount, 1);
  assert.equal(summary.historicalSourceCount, 0);
  assert.equal(summary.activeSources[0].publisher_observable_type, 'sha256');
  assert.equal(summary.activeSources[0].observations.length, 2);
  assert.ok(summary.activeSources[0].observations.some((o) => o.observable_type === 'md5' && o.active === false));
});

test('repeated assembly of the same memberships does not duplicate providers', () => {
  const rows = [{
    ioc_id: 1,
    public_id: 'p1',
    observable: SHA,
    observable_type: 'sha256',
    summary: {
      activeSources: [feed(1, 'MalwareBazaar abuse.ch'), feed(1, 'MalwareBazaar abuse.ch')],
      historicalSources: [],
      membershipRows: [membership(1), membership(1)]
    }
  }];
  const a = assembleFileIdentitySources(rows, { canonicalIocId: 1 });
  const b = assembleFileIdentitySources(rows, { canonicalIocId: 1 });
  assert.equal(a.activeSourceCount, 1);
  assert.equal(b.activeSourceCount, 1);
  assert.equal(a.membershipRows.length, 1);
});

test('direct membership wins lifecycle when the same provider is active on two hashes', () => {
  const summary = assembleFileIdentitySources([
    {
      ioc_id: 2,
      public_id: 'md5-row',
      observable: MD5,
      observable_type: 'md5',
      summary: {
        activeSources: [{ ...feed(4, 'MalwareBazaar abuse.ch'), first_seen_at: '2026-01-01T00:00:00.000Z' }],
        historicalSources: [],
        membershipRows: []
      }
    },
    {
      ioc_id: 1,
      public_id: 'sha-row',
      observable: SHA,
      observable_type: 'sha256',
      summary: {
        activeSources: [{ ...feed(5, 'MalwareBazaar abuse.ch'), first_seen_at: '2026-09-01T00:00:00.000Z' }],
        historicalSources: [],
        membershipRows: []
      }
    }
  ], { canonicalIocId: 1 });

  assert.equal(summary.activeSources[0].publisher_observable_type, 'sha256');
  assert.equal(summary.activeSources[0].first_seen_at, '2026-09-01T00:00:00.000Z');
  assert.equal(summary.activeSources[0].membership_id, 5);
});

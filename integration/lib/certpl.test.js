import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  CERTPL_FEED_KEY,
  CERTPL_SOURCE_NAME,
  CERTPL_DOMAINS_URL,
  CertPlError,
  normalizeCertPlDomain,
  parseCertPlTimestamp,
  isCertPlRecordActive,
  mapCertPlRecord,
  preferCertPlEntry,
  parseCertPlDomainsPayload,
  buildCertPlNote,
  buildCertPlEvidenceMetadata,
  hashCertPlEntries,
  buildCertPlCheckpoint,
  buildCertPlPreviousKeySet,
  certPlDomainKeyHash,
  fetchCertPlDomains
} from './certpl.js';
import { FEED_SOURCE_RULES, sourceNameMatchesFeed, feedKeyForSourceName } from '../../backend/lib/iocExpiration.js';
import { INTEGRATION_FEED_JOBS } from '../../backend/lib/integrationFeedScheduleSync.js';
import { CERTPL_ADVISORY_LOCK } from '../../backend/lib/advisoryLocks.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

test('CERT.PL constants follow repository conventions', () => {
  assert.equal(CERTPL_FEED_KEY, 'certpl-warning-list');
  assert.equal(CERTPL_SOURCE_NAME, 'CERT.PL:CERT-Polska');
  assert.equal(CERTPL_DOMAINS_URL, 'https://hole.cert.pl/domains/v2/domains.json');
  assert.equal(INTEGRATION_FEED_JOBS[CERTPL_FEED_KEY], 'certpl-import');
  assert.equal(CERTPL_ADVISORY_LOCK, 942009);
  assert.equal(feedKeyForSourceName(CERTPL_SOURCE_NAME), CERTPL_FEED_KEY);
  assert.equal(sourceNameMatchesFeed(CERTPL_SOURCE_NAME, CERTPL_FEED_KEY), true);
  assert.ok(FEED_SOURCE_RULES.some((r) => r.key === CERTPL_FEED_KEY && r.exact === CERTPL_SOURCE_NAME));
});

test('normalizeCertPlDomain lowercases, strips trailing dot, validates labels', () => {
  assert.equal(normalizeCertPlDomain('Evil.Example.'), 'evil.example');
  assert.equal(normalizeCertPlDomain('  evil.example  '), 'evil.example');
  assert.equal(normalizeCertPlDomain('*.evil.example'), null);
  assert.equal(normalizeCertPlDomain('http://evil.example'), null);
  assert.equal(normalizeCertPlDomain('evil.example/path'), null);
  assert.equal(normalizeCertPlDomain('not a domain'), null);
  assert.equal(normalizeCertPlDomain(''), null);
  assert.equal(normalizeCertPlDomain(null), null);
  assert.equal(normalizeCertPlDomain('singlelabel'), null);
});

test('parseCertPlTimestamp accepts ISO and rejects garbage without throwing', () => {
  const ok = parseCertPlTimestamp('2026-08-29T15:22:25+00:00');
  assert.ok(ok instanceof Date);
  assert.equal(ok.toISOString(), '2026-08-29T15:22:25.000Z');
  assert.equal(parseCertPlTimestamp('not-a-date'), null);
  assert.equal(parseCertPlTimestamp(null), null);
  assert.equal(parseCertPlTimestamp(''), null);
});

test('mapCertPlRecord imports active record with InsertDate as firstSeen', () => {
  const mapped = mapCertPlRecord({
    RegisterPositionId: 100,
    DomainAddress: 'evil.example',
    InsertDate: '2026-08-29T15:22:25+00:00',
    DeleteDate: null
  });
  assert.equal(mapped.ok, true);
  assert.equal(mapped.entry.observable, 'evil.example');
  assert.equal(mapped.entry.observableType, 'domain');
  assert.equal(mapped.entry.registerPositionId, 100);
  assert.equal(mapped.entry.firstSeen.toISOString(), '2026-08-29T15:22:25.000Z');
  assert.notEqual(mapped.entry.firstSeen.toISOString(), new Date().toISOString());
});

test('mapCertPlRecord skips DeleteDate != null without treating as TalonHound deletion', () => {
  const mapped = mapCertPlRecord({
    RegisterPositionId: 101,
    DomainAddress: 'gone.example',
    InsertDate: '2026-08-29T15:22:25+00:00',
    DeleteDate: '2026-08-29T18:00:00+00:00'
  });
  assert.equal(mapped.ok, false);
  assert.equal(mapped.reason, 'upstream_deleted');
  assert.equal(isCertPlRecordActive({ DeleteDate: '2026-08-29T18:00:00+00:00' }), false);
});

test('mapCertPlRecord skips malformed DomainAddress', () => {
  assert.equal(mapCertPlRecord({
    RegisterPositionId: 1,
    DomainAddress: 'not a domain',
    InsertDate: null,
    DeleteDate: null
  }).reason, 'invalid_domain');
});

test('mapCertPlRecord tolerates malformed InsertDate', () => {
  const mapped = mapCertPlRecord({
    RegisterPositionId: 2,
    DomainAddress: 'ok.example',
    InsertDate: 'bogus',
    DeleteDate: null
  });
  assert.equal(mapped.ok, true);
  assert.equal(mapped.entry.firstSeen, null);
  assert.equal(mapped.entry.observable, 'ok.example');
});

test('parseCertPlDomainsPayload collapses duplicate normalized domains deterministically', () => {
  const { entries, stats } = parseCertPlDomainsPayload([
    {
      RegisterPositionId: 200,
      DomainAddress: 'DUPE.EXAMPLE',
      InsertDate: '2026-08-29T16:00:00+00:00',
      DeleteDate: null
    },
    {
      RegisterPositionId: 100,
      DomainAddress: 'dupe.example.',
      InsertDate: '2026-08-29T15:00:00+00:00',
      DeleteDate: null
    },
    {
      RegisterPositionId: 300,
      DomainAddress: 'deleted.example',
      InsertDate: '2026-08-29T15:00:00+00:00',
      DeleteDate: '2026-08-29T18:00:00+00:00'
    },
    {
      RegisterPositionId: 400,
      DomainAddress: 'bad domain',
      InsertDate: null,
      DeleteDate: null
    }
  ]);
  assert.equal(stats.fetched, 4);
  assert.equal(stats.active, 2);
  assert.equal(stats.upstream_deleted_skipped, 1);
  assert.equal(stats.invalid_skipped, 1);
  assert.equal(stats.duplicate_normalized_collapsed, 1);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].observable, 'dupe.example');
  assert.equal(entries[0].registerPositionId, 100);
  assert.equal(entries[0].firstSeen.toISOString(), '2026-08-29T15:00:00.000Z');
});

test('parseCertPlDomainsPayload empty array is safe (no destructive semantics)', () => {
  const { entries, stats } = parseCertPlDomainsPayload([]);
  assert.deepEqual(entries, []);
  assert.equal(stats.fetched, 0);
  assert.equal(stats.active, 0);
});

test('parseCertPlDomainsPayload rejects non-array JSON shape', () => {
  assert.throws(
    () => parseCertPlDomainsPayload({ domains: [] }),
    (err) => err instanceof CertPlError && err.code === 'invalid_schema'
  );
});

test('preferCertPlEntry picks earlier InsertDate', () => {
  const a = { insertDate: new Date('2026-01-01T00:00:00Z'), registerPositionId: 9 };
  const b = { insertDate: new Date('2026-02-01T00:00:00Z'), registerPositionId: 1 };
  assert.equal(preferCertPlEntry(a, b), a);
});

test('buildCertPlNote and evidence metadata preserve RegisterPositionId + InsertDate', () => {
  const entry = {
    registerPositionId: 100,
    insertDate: new Date('2026-08-29T15:22:25Z')
  };
  const note = buildCertPlNote(entry);
  assert.match(note, /external_id=100/);
  assert.match(note, /insert_date=2026-08-29T15:22:25.000Z/);
  assert.match(note, /CERT Polska \/ NASK/);
  const meta = buildCertPlEvidenceMetadata(entry);
  assert.equal(meta.provider_record_id, 100);
  assert.equal(meta.provider_insert_date, '2026-08-29T15:22:25.000Z');
});

test('hash + checkpoint are idempotent for the same active set', () => {
  const entries = [
    { observable: 'a.example' },
    { observable: 'b.example' }
  ];
  const h1 = hashCertPlEntries(entries);
  const h2 = hashCertPlEntries(entries);
  assert.equal(h1, h2);
  const cp = buildCertPlCheckpoint(entries);
  assert.equal(cp.count, 2);
  const set = buildCertPlPreviousKeySet(cp);
  assert.equal(set.has(certPlDomainKeyHash('a.example')), true);
  assert.equal(set.has(certPlDomainKeyHash('missing.example')), false);
});

test('fetchCertPlDomains validates JSON array and rejects HTML', async () => {
  await assert.rejects(
    () => fetchCertPlDomains({
      maxRetries: 0,
      fetchFn: async () => ({
        ok: true,
        status: 200,
        headers: { get: () => 'text/html' },
        text: async () => '<html>error</html>'
      })
    }),
    (err) => err instanceof CertPlError && err.code === 'unexpected_content_type'
  );

  const result = await fetchCertPlDomains({
    maxRetries: 0,
    fetchFn: async () => ({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      text: async () => JSON.stringify([
        {
          RegisterPositionId: 100,
          DomainAddress: 'evil.example',
          InsertDate: '2026-08-29T15:22:25+00:00',
          DeleteDate: null
        }
      ])
    })
  });
  assert.equal(result.entries.length, 1);
  assert.equal(result.stats.active, 1);
});

test('fetchCertPlDomains rejects non-HTTPS URL', async () => {
  await assert.rejects(
    () => fetchCertPlDomains({ url: 'http://hole.cert.pl/domains/v2/domains.json', maxRetries: 0 }),
    (err) => err instanceof CertPlError && err.code === 'https_required'
  );
});

test('CERT.PL importer source has no destructive reconciliation helpers', () => {
  const importerPath = join(__dirname, '..', 'importer.js');
  const src = readFileSync(importerPath, 'utf8');
  const certPlFn = src.slice(src.indexOf('export async function runCertPlImport'));
  assert.ok(certPlFn.includes('runCertPlImport'));
  assert.equal(certPlFn.includes('syncSnapshotFeedFromEntries'), false);
  assert.equal(/markMissing|mark_missing|missing_from_feed|removeMembership|DELETE FROM ioc_feed_memberships/.test(certPlFn), false);
  assert.ok(certPlFn.includes('Add-diff only'));
  assert.ok(certPlFn.includes('upstream_deleted_skipped'));
});

test('CERT.PL migration seeds feed idempotently', () => {
  const migration = readFileSync(
    join(__dirname, '..', '..', 'backend', 'migrations', '010_certpl_warning_list.sql'),
    'utf8'
  );
  assert.match(migration, /certpl-warning-list/);
  assert.match(migration, /ON CONFLICT \(key\) DO NOTHING/);
  assert.match(migration, /hole\.cert\.pl\/domains\/v2\/domains\.json/);
  assert.match(migration, /\*\/5 \* \* \* \*/);
  assert.match(migration, /incremental/);
  assert.equal(/DELETE FROM ioc_/i.test(migration), false);
});

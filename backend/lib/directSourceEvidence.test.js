import test from 'node:test';
import assert from 'node:assert/strict';
import { AUDIT_ACTION } from './auditConstants.js';
import {
  DIRECT_EVIDENCE_STATUS,
  canonicalObservable,
  directEvidenceAuditEvents,
  formatDirectEvidencePlan,
  refang,
  validateDirectEvidenceManifest
} from './directSourceEvidence.js';

const SOURCE = {
  publisher: 'LevelBlue SpiderLabs',
  title: 'Inside PhantomPolia',
  url: 'https://www.levelblue.com/blogs/spiderlabs-blog/inside-phantompolia',
  published_at: '2026-10-07',
  section: 'Appendix B: Indicators of Compromise (IoC)'
};
const item = (over = {}) => ({
  entity_kind: 'malware_family',
  entity_name: 'PhantomPolia',
  row_label: 'PhantomPolia Domain',
  observable_type: 'domain',
  value: 'voderlence[.]com',
  ...over
});

test('refang undoes report defanging only', () => {
  assert.equal(refang(' voderlence[.]com '), 'voderlence.com');
  assert.equal(refang('hxxps://cloudcheckic[.]com/check/update[.]ps1'), 'https://cloudcheckic.com/check/update.ps1');
  assert.equal(refang('a(.)b{.}c[dot]d'), 'a.b.c.d');
});

test('canonical observable: exact type rules, never guesses', () => {
  assert.deepEqual(canonicalObservable('domain', 'VoDerLence[.]com.'), { ok: true, value: 'voderlence.com' });
  assert.deepEqual(canonicalObservable('sha256', 'DC0A864F441F0237853B40217EDA577DEFB7C1DD15AF407C7241688B1B3A3B46'),
    { ok: true, value: 'dc0a864f441f0237853b40217eda577defb7c1dd15af407c7241688b1b3a3b46' });
  // A sha256 value declared as md5 (or vice versa) is rejected, not re-typed.
  assert.equal(canonicalObservable('md5', 'dc0a864f441f0237853b40217eda577defb7c1dd15af407c7241688b1b3a3b46').error, 'hash_type_mismatch');
  assert.equal(canonicalObservable('domain', 'not a domain').error, 'invalid_domain');
  // Scheme-less published URLs are not completed with a guessed scheme.
  assert.equal(canonicalObservable('url', 'workeslexamp[.]com/check/update[.]ps1').error, 'url_requires_scheme');
  assert.equal(canonicalObservable('url', 'hxxps://a[.]com/Check/Update[.]ps1').value, 'https://a.com/Check/Update.ps1');
  assert.equal(canonicalObservable('hash', 'abc').error, 'unsupported_observable_type');
});

test('manifest validation: source fields required, item errors kept per item', () => {
  const bad = validateDirectEvidenceManifest({ source: { publisher: 'X' }, items: [] });
  assert.ok(bad.errors.some((e) => /title/.test(e)));
  assert.ok(bad.errors.some((e) => /https URL/.test(e)));
  assert.ok(bad.errors.some((e) => /published_at/.test(e)));
  assert.ok(bad.errors.some((e) => /non-empty/.test(e)));

  const v = validateDirectEvidenceManifest({
    source: SOURCE,
    items: [
      item(),
      // Evidence mismatch: the publisher row does not name the entity.
      item({ row_label: 'ClickFix URL' }),
      // A sample relationship is only valid for a family hash.
      item({ association_kind: 'malware_sample_of' }),
      item({ entity_kind: 'campaign' }),
      item({ entity_name: 'Remus Stealer', row_label: 'Remus Stealer', observable_type: 'sha256', value: 'DC0A864F441F0237853B40217EDA577DEFB7C1DD15AF407C7241688B1B3A3B46', association_kind: 'malware_sample_of' })
    ]
  });
  assert.deepEqual(v.errors, []);
  assert.equal(v.source.published_at, '2026-10-07T00:00:00.000Z');
  assert.deepEqual(v.items[0].errors, []);
  assert.equal(v.items[0].value, 'voderlence.com');
  assert.equal(v.items[0].value_as_published, 'voderlence[.]com');
  assert.equal(v.items[0].association_kind, 'directly_attributed_to');
  assert.equal(v.items[0].source_label_normalized, 'phantompolia');
  assert.deepEqual(v.items[1].errors, ['row_label_does_not_name_entity']);
  assert.deepEqual(v.items[2].errors, ['malware_sample_of_requires_family_hash']);
  assert.deepEqual(v.items[3].errors, ['invalid_entity_kind']);
  assert.deepEqual(v.items[4].errors, []);
});

test('audit events: one per newly recorded assertion, source-reported, never analyst attribution', () => {
  const result = {
    source: { ...SOURCE, published_at: '2026-10-07T00:00:00.000Z' },
    created: [{
      ioc_id: 3491788, ioc_public_id: 'b21e', observable_type: 'domain', value: 'voderlence.com',
      value_as_published: 'voderlence[.]com', row_label: 'PhantomPolia Domain',
      entity_kind: 'malware_family', entity_id: 'f-1', entity_name: 'PhantomPolia', source_label: 'PhantomPolia',
      association_kind: 'directly_attributed_to', resolution_method: 'name', assertion_id: 'a-1'
    }]
  };
  const [ev] = directEvidenceAuditEvents(result, { actorUsername: 'operator' });
  assert.equal(ev.action, AUDIT_ACTION.IOC_MALWARE_FAMILY_DIRECT_SOURCE_EVIDENCE_RECORDED);
  assert.equal(ev.entityType, 'ioc');
  assert.equal(ev.entityId, '3491788');
  assert.equal(ev.actorUsername, 'operator');
  assert.equal(ev.metadata.attribution, 'source_reported');
  assert.equal(ev.metadata.relationship_scope, 'direct');
  assert.equal(ev.metadata.operation, 'direct_source_evidence');
  assert.equal(ev.metadata.source.row_label, 'PhantomPolia Domain');
  assert.equal(ev.metadata.source.published_at, '2026-10-07T00:00:00.000Z');
  // Idempotent retries create nothing and audit nothing.
  assert.deepEqual(directEvidenceAuditEvents({ ...result, created: [] }), []);
  const actorEv = directEvidenceAuditEvents({ ...result, created: [{ ...result.created[0], entity_kind: 'threat_actor' }] })[0];
  assert.equal(actorEv.action, AUDIT_ACTION.IOC_THREAT_ACTOR_DIRECT_SOURCE_EVIDENCE_RECORDED);
});

test('plan formatter lists every item with its outcome', () => {
  const lines = formatDirectEvidencePlan({
    ok: true,
    source: { ...SOURCE, published_at: '2026-10-07T00:00:00.000Z' },
    totals: { items: 2, create: 1, already_recorded: 0, skipped: 1 },
    items: [
      { status: DIRECT_EVIDENCE_STATUS.CREATE, entity_name: 'PhantomPolia', association_kind: 'directly_attributed_to', observable_type: 'domain', value: 'voderlence.com', row_label: 'PhantomPolia Domain', ioc_id: 1, ioc_rows: 1 },
      { status: DIRECT_EVIDENCE_STATUS.SKIP, entity_name: 'PhantomPolia', association_kind: 'directly_attributed_to', observable_type: 'domain', value: 'gone.example', row_label: 'PhantomPolia Domain', reason: 'ioc_not_found' }
    ]
  });
  assert.match(lines.join('\n'), /create=1 already_recorded=0 skipped=1/);
  assert.match(lines.join('\n'), /reason=ioc_not_found/);
  assert.deepEqual(formatDirectEvidencePlan({ ok: false, errors: ['x'] }), ['[direct-evidence] manifest rejected:', '  - x']);
});

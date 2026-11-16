import test from 'node:test';
import assert from 'node:assert/strict';
import { parseEmailObservable, normalizeEmailObservable, refangEmail } from './emailObservable.js';
import { inferObservableType, resolveIocStorageIdentity, resolveCreateStorageIdentity } from './manualIocCreate.js';
import { normalizeApiIocValue, parseApiIocType, API_IOC_TYPES } from './apiIocService.js';
import { normalizeObservable } from './observable-normalization.js';
import {
  FEED_IOC_TYPES,
  normalizeFeedIocTypes,
  observableTypesForFeedIocType,
  feedCategoryForObservableType,
  normalizeFeedLine
} from './feedFormatter.js';
import { stixPatternForIoc } from './publishedFeedStix.js';
import { parseIocExportQuery } from './iocExportHelpers.js';
import { getEnrichmentProvider, listEnrichmentProviders } from './enrichmentProviderRegistry.js';

test('email canonical identity: lower-cased, refanged, punycode domain, no mailto / brackets', () => {
  assert.equal(normalizeEmailObservable('Alex@ContactTrixauvex[.]ink'), 'alex@contacttrixauvex.ink');
  assert.equal(normalizeEmailObservable('alex[@]hr.pulsynk[.]org'), 'alex@hr.pulsynk.org');
  assert.equal(normalizeEmailObservable('brad [at] malware-traffic-analysis.net'), 'brad@malware-traffic-analysis.net');
  assert.equal(normalizeEmailObservable('recruiter[.]paloaltonetworks@gmail [.]com'), 'recruiter.paloaltonetworks@gmail.com');
  assert.equal(normalizeEmailObservable('mailto:ops@example-corp.com'), 'ops@example-corp.com');
  assert.equal(normalizeEmailObservable('<ops@example-corp.com>'), 'ops@example-corp.com');
  assert.equal(normalizeEmailObservable('kontakt@bücher.de'), 'kontakt@xn--bcher-kva.de');
  assert.equal(refangEmail('a (at) b (dot) com'), 'a@b.com');
});

test('email rejects shapes that are not addresses (package specifiers, remotes, reserved, redacted)', () => {
  for (const v of [
    'axios@1.14.1',
    'plain-crypto-js@4.2.1',
    '@qqbrowser/openclaw-qbot@0.0.130',
    'git@github.com:org/repo',
    'user@host',
    'user@[192.0.2.1]',
    '"quoted local"@example-corp.com',
    'a@@b.com',
    'pdf-para-texto@extensao.local',
    'admin@acmecloud.example',
    'x@test',
    'e*******7@proton.me',
    'emailaddress=admin@acmecloud.example'
  ]) {
    assert.equal(parseEmailObservable(v).ok, false, v);
  }
});

test('manual / API / MCP create: an address is an `email` IOC; any other "@" value is rejected, never a domain', () => {
  assert.equal(inferObservableType('Alex@x.ink'), 'email');
  assert.equal(inferObservableType('user@host'), null);
  assert.equal(inferObservableType('crest01.suncrest.in.net@80'), null);
  assert.deepEqual(resolveIocStorageIdentity('Alex@X[.]ink'), { ok: true, type: 'email', value: 'alex@x.ink' });
  assert.deepEqual(resolveCreateStorageIdentity('Alex@X.ink', 'email'), { ok: true, type: 'email', value: 'alex@x.ink' });
  assert.equal(resolveCreateStorageIdentity('axios@1.14.1', 'email').ok, false);
  // URLs carrying an address keep their URL identity.
  assert.equal(inferObservableType('https://hbjlxcl.com/?email=a@a.com'), 'url');
  assert.ok(API_IOC_TYPES.includes('email'));
  assert.deepEqual(parseApiIocType('email'), { ok: true, value: 'email' });
  assert.deepEqual(normalizeApiIocValue('email', 'Ops@Corp-Mail.com'), { ok: true, type: 'email', value: 'ops@corp-mail.com' });
  assert.equal(normalizeApiIocValue('email', 'axios@1.14.1').ok, false);
  assert.equal(normalizeApiIocValue('domain', 'ops@corp-mail.com').ok, false);
  assert.equal(normalizeObservable('email', 'Ops@Corp-Mail[.]com'), 'ops@corp-mail.com');
});

test('Published Feeds, STIX, export: email is a first-class category', () => {
  assert.deepEqual(FEED_IOC_TYPES, ['ip', 'domain', 'url', 'hash', 'email']);
  assert.deepEqual(normalizeFeedIocTypes(['email', 'ip']), { ok: true, value: ['ip', 'email'] });
  assert.deepEqual(observableTypesForFeedIocType('email'), ['email']);
  assert.equal(feedCategoryForObservableType('email'), 'email');
  assert.equal(normalizeFeedLine({ observable: 'Ops@Corp-Mail.com' }, 'email'), 'ops@corp-mail.com');
  assert.equal(stixPatternForIoc('email', "o'brien@corp-mail.com"), "[email-addr:value = 'o\\'brien@corp-mail.com']");
  assert.deepEqual(parseIocExportQuery({ type: 'email' }).ok, true);
});

test('enrichment: no provider claims an email IOC (explicit unsupported, never fabricated)', () => {
  const ioc = { public_id: 'x', observable_type: 'email', observable: 'ops@corp-mail.com' };
  const providers = listEnrichmentProviders();
  assert.ok(providers.length > 0);
  for (const p of providers) {
    const entry = getEnrichmentProvider(p.key || p.id || p);
    if (!entry || typeof entry.resolveTarget !== 'function') continue;
    const target = entry.resolveTarget(ioc);
    assert.equal(target?.applicable, false, `${p.key || p.id || p} must not apply to email`);
  }
});

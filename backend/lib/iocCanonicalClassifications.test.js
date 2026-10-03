/**
 * Pure canonical effective-classification semantics (no DB).
 *
 *   effective = (feed classifications − analyst suppressions) ∪ asserted classifications
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeCanonicalIocClassifications,
  CLASSIFICATION_PROVENANCE
} from './iocCanonicalClassifications.js';

function ctx(slug, sources) {
  return { classification: slug, sources };
}

test('feed proposal alone matches; provenance is feed', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      ioc_source_id: null,
      source_name: 'AlienVault OTX',
      feed: [{ value: 'credential_theft', source_name: 'AlienVault OTX', source_names: ['AlienVault OTX'] }],
      junction: [],
      suppressions: []
    }]
  });
  assert.deepEqual(out.classifications, ['credential_theft']);
  assert.deepEqual(out.classification_context, [
    ctx('credential_theft', [{ type: 'feed', source_name: 'AlienVault OTX' }])
  ]);
  assert.deepEqual(out.analyst, []);
});

test('feed suppression removes feed proposal with no analyst assertion', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      feed: [{ value: 'credential_theft', source_names: ['AlienVault OTX'] }],
      junction: [],
      suppressions: [{ classification_slug: 'credential_theft', source_name: null }]
    }]
  });
  assert.deepEqual(out.classifications, []);
  assert.deepEqual(out.classification_context, []);
});

test('analyst-only classification matches with analyst provenance', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      feed: [],
      junction: [{ slug: 'credential_theft', source_type: 'analyst' }],
      suppressions: []
    }]
  });
  assert.deepEqual(out.classifications, ['credential_theft']);
  assert.deepEqual(out.classification_context, [
    ctx('credential_theft', [{ type: 'analyst' }])
  ]);
  assert.deepEqual(out.analyst, ['credential_theft']);
});

test('feed + analyst different values both match', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      feed: [{ value: 'malware', source_names: ['URLhaus'] }],
      junction: [{ slug: 'credential_theft', source_type: 'analyst' }],
      suppressions: []
    }]
  });
  assert.deepEqual(out.classifications, ['credential_theft', 'malware']);
  assert.ok(out.classification_context.find((c) => c.classification === 'malware')
    .sources.some((s) => s.type === 'feed'));
  assert.ok(out.classification_context.find((c) => c.classification === 'credential_theft')
    .sources.some((s) => s.type === 'analyst'));
});

test('feed + analyst same value dedupes but keeps analyst provenance', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      feed: [{ value: 'credential_theft', source_names: ['AlienVault OTX'] }],
      junction: [{ slug: 'credential_theft', source_type: 'analyst' }],
      suppressions: []
    }]
  });
  assert.deepEqual(out.classifications, ['credential_theft']);
  assert.deepEqual(out.classification_context[0].sources, [
    { type: 'feed', source_name: 'AlienVault OTX' },
    { type: 'analyst' }
  ]);
  assert.deepEqual(out.analyst, ['credential_theft']);
});

test('suppression never hides an explicit analyst assertion', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      feed: [{ value: 'credential_theft', source_names: ['AlienVault OTX'] }],
      junction: [{ slug: 'credential_theft', source_type: 'analyst' }],
      suppressions: [{ classification_slug: 'credential_theft', source_name: null }]
    }]
  });
  assert.deepEqual(out.classifications, ['credential_theft']);
  assert.deepEqual(out.classification_context[0].sources, [{ type: 'analyst' }]);
  assert.equal(out.feed[0].value, 'credential_theft');
});

test('provider/importer legacy column on feed row is feed provenance, never analyst', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      threat_classification: 'dropper_downloader',
      ioc_source_id: null,
      source_name: 'ThreatFox:abuse.ch',
      junction: [],
      feed: [],
      suppressions: []
    }]
  });
  assert.deepEqual(out.classifications, ['dropper_downloader']);
  assert.deepEqual(out.classification_context, [
    ctx('dropper_downloader', [{ type: 'feed', source_name: 'ThreatFox:abuse.ch' }])
  ]);
  assert.deepEqual(out.analyst, []);
  assert.ok(!out.classification_context[0].sources.some((s) => s.type === 'analyst'));
});

test('manual junction source_type is analyst provenance', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      junction: [{ slug: 'phishing', source_type: 'manual' }],
      feed: [],
      suppressions: []
    }]
  });
  assert.deepEqual(out.analyst, ['phishing']);
  assert.deepEqual(out.classification_context[0].sources, [{ type: 'analyst' }]);
});

test('legacy junction source_type is legacy, not analyst', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      junction: [{ slug: 'malware', source_type: 'legacy' }],
      feed: [],
      suppressions: []
    }]
  });
  assert.deepEqual(out.classifications, ['malware']);
  assert.deepEqual(out.analyst, []);
  assert.deepEqual(out.legacy, ['malware']);
  assert.deepEqual(out.classification_context[0].sources, [{ type: CLASSIFICATION_PROVENANCE.LEGACY }]);
});

test('IOC-source legacy column without junction is legacy provenance', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      threat_classification: 'phishing',
      ioc_source_id: 7,
      source_name: 'manual-source',
      junction: [],
      feed: [],
      suppressions: []
    }]
  });
  assert.deepEqual(out.classifications, ['phishing']);
  assert.deepEqual(out.analyst, []);
  assert.deepEqual(out.legacy, ['phishing']);
});

test('source-scoped suppression only hides that feed source', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      feed: [{ value: 'phishing', source_names: ['Feed A', 'Feed B'] }],
      junction: [],
      suppressions: [{ classification_slug: 'phishing', source_name: 'Feed B' }]
    }]
  });
  assert.deepEqual(out.classifications, ['phishing']);
  assert.deepEqual(out.classification_context[0].sources, [
    { type: 'feed', source_name: 'Feed A' }
  ]);
});

test('same-observable sibling rows union into one identity', () => {
  const out = computeCanonicalIocClassifications({
    rows: [
      {
        threat_classification: 'malware',
        ioc_source_id: null,
        source_name: 'URLhaus',
        junction: [],
        feed: [],
        suppressions: []
      },
      {
        threat_classification: 'unknown',
        ioc_source_id: 3,
        junction: [{ slug: 'credential_theft', source_type: 'analyst' }],
        feed: [],
        suppressions: []
      }
    ]
  });
  assert.deepEqual(out.classifications, ['credential_theft', 'malware']);
});

test('importer legacy mirrored by analyst junction is not double-counted as feed', () => {
  const out = computeCanonicalIocClassifications({
    rows: [{
      threat_classification: 'credential_theft',
      ioc_source_id: null,
      source_name: 'AlienVault OTX',
      junction: [{ slug: 'credential_theft', source_type: 'analyst' }],
      feed: [],
      suppressions: []
    }]
  });
  // Legacy equals a junction slug → treated as the analyst mirror, not a feed proposal.
  assert.deepEqual(out.classifications, ['credential_theft']);
  assert.deepEqual(out.classification_context[0].sources, [{ type: 'analyst' }]);
  assert.deepEqual(out.feed, []);
});

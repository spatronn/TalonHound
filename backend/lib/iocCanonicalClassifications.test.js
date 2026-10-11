/**
 * Pure canonical effective-classification semantics (no DB).
 *
 *   effective = (feed classifications − analyst suppressions) ∪ asserted classifications
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeCanonicalIocClassifications,
  loadCanonicalIocClassifications,
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

test('loadCanonicalIocClassifications: empty input performs no SQL', async () => {
  let queries = 0;
  const pool = { async query() { queries += 1; return { rows: [] }; } };
  const map = await loadCanonicalIocClassifications(pool, []);
  assert.equal(map.size, 0);
  assert.equal(queries, 0);
});

test('loadCanonicalIocClassifications: mixed page never OR-joins pair and hash lookups', async () => {
  const sqls = [];
  const pool = {
    async query(sql, params = []) {
      const text = String(sql).replace(/\s+/g, ' ').trim();
      sqls.push({ text, params });
      if (text.includes('FROM ioc_items') && text.includes('unnest($1::text[], $2::bigint[])')) {
        return {
          rows: [{
            id: 10, observable_type: 'domain', observable: 'evil.test',
            threat_classification: null, ioc_source_id: null, source_name: null
          }]
        };
      }
      if (text.includes('FROM ioc_items') && text.includes('id = ANY($2::bigint[])')) {
        return {
          rows: [{
            id: 20, observable_type: 'sha256', observable: 'a'.repeat(64),
            threat_classification: null, ioc_source_id: null, source_name: null
          }]
        };
      }
      if (text.includes('FROM ioc_items') && text.includes('unnest($1::text[], $2::text[])')) {
        return { rows: [] }; // siblings
      }
      if (text.includes('FROM ioc_threat_classifications')) return { rows: [] };
      if (text.includes('FROM ioc_feed_source_evidence')) return { rows: [] };
      if (text.includes('FROM ioc_threat_classification_overrides')) return { rows: [] };
      return { rows: [] };
    }
  };

  const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
  process.env.FILE_ARTIFACTS_READ_ENABLED = '0';
  try {
    const map = await loadCanonicalIocClassifications(pool, [
      { id: 10, observable_type: 'domain' },
      { id: 20, observable_type: 'sha256' }
    ], { scopeBySeed: new Map([[10, [10]], [20, [20]]]) });
    assert.equal(map.size, 2);
    const baseSqls = sqls.filter((q) => q.text.includes('FROM ioc_items') && q.text.includes('threat_classification'));
    // Pair PK + hash-id branches are separate statements (and siblings is a third).
    assert.ok(baseSqls.length >= 2);
    assert.ok(!baseSqls.some((q) => /\bOR\b/.test(q.text) && q.text.includes('id = ANY')),
      'identity base lookup must not OR pair-PK with hash-id filter');
    assert.ok(baseSqls.some((q) => q.text.includes('unnest($1::text[], $2::bigint[])')));
    assert.ok(baseSqls.some((q) => q.text.includes('id = ANY($2::bigint[])') && !q.text.includes('OR')));
  } finally {
    if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
  }
});

test('loadCanonicalIocClassifications: hash-only page skips pair-PK branch', async () => {
  const sqls = [];
  const pool = {
    async query(sql) {
      const text = String(sql).replace(/\s+/g, ' ').trim();
      sqls.push(text);
      if (text.includes('FROM ioc_items') && text.includes('id = ANY($2::bigint[])')) {
        return {
          rows: [{
            id: 20, observable_type: 'sha256', observable: 'b'.repeat(64),
            threat_classification: null, ioc_source_id: null, source_name: null
          }]
        };
      }
      return { rows: [] };
    }
  };
  await loadCanonicalIocClassifications(pool, [{ id: 20, observable_type: 'sha256' }], {
    scopeBySeed: new Map([[20, [20]]])
  });
  const identity = sqls.filter((t) => t.includes('FROM ioc_items') && t.includes('threat_classification'));
  assert.equal(identity.filter((t) => t.includes('unnest($1::text[], $2::bigint[])')).length, 0);
  assert.equal(identity.filter((t) => t.includes('id = ANY($2::bigint[])')).length, 1);
});

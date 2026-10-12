import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  groundAiPublisherEntities,
  groundStoredPublisherEntities,
  groundSummaryPublisherEntities,
  publisherIdentity,
  sourceStatesThreatRole,
  unsupportedPublisherEntities
} from './publisherEntityGrounding.js';

const report = { source_url: 'https://hatching.io/blog/triage-insights-ep5-short/', source_name: 'hatching.io' };
const doc = (texts, meta = {}) => ({ title: 'x', meta, blocks: texts.map((text, i) => ({ id: `b${i}`, type: 'paragraph', text })) });
const body = doc([
  'A four-stage toolkit we call WinLol delivers a WebRTC remote desktop RAT.',
  'Hatching International B.V., The Netherlands'
]);

test('publisher identity: host label, source name and declared site names', () => {
  assert.deepEqual([...publisherIdentity(report, body)], ['hatching']);
  assert.deepEqual(
    [...publisherIdentity({ source_url: 'https://blog.talosintelligence.com/x', source_name: 'Cisco Talos' }, doc([], { site_names: ['Talos Intelligence'] }))].sort(),
    ['ciscotalos', 'talosintelligence']
  );
});

test('18651: the publisher promoted to a campaign is dropped, with its relationships and summary clause', () => {
  const aiValue = {
    summary: "The report details 'WinLol', a four-stage Rust/Go malware toolkit discovered in July 2026, associated with the 'Hatching' campaign. The toolkit employs anti-sandbox checks.",
    entities: [
      { name: 'WinLol', entity_type: 'malware' },
      { name: 'Hatching', entity_type: 'campaign', description: 'Automated malware analysis solutions campaign' },
      { name: 'Riot Games', entity_type: 'organization' }
    ],
    relationships: [
      { subject_ref: 'WinLol', relationship_type: 'attributed_to', object_ref: 'Hatching' },
      { subject_ref: 'WinLol', relationship_type: 'impersonates', object_ref: 'Riot Games' }
    ]
  };
  const { value, diagnostics } = groundAiPublisherEntities(aiValue, { report, document: body });
  assert.deepEqual(value.entities.map((e) => e.name), ['WinLol', 'Riot Games']);
  assert.deepEqual(value.relationships.map((r) => r.object_ref), ['Riot Games']);
  assert.equal(value.summary, "The report details 'WinLol', a four-stage Rust/Go malware toolkit discovered in July 2026. The toolkit employs anti-sandbox checks.");
  assert.deepEqual(diagnostics.entities_removed, [{ name: 'Hatching', entity_type: 'campaign' }]);
  assert.equal(diagnostics.relationships_removed, 1);
  assert.equal(diagnostics.summary_changed, true);
  // The input is not mutated.
  assert.equal(aiValue.entities.length, 3);
});

test('publisher named as threat actor is dropped too; as organization / tool it is kept', () => {
  const kept = unsupportedPublisherEntities([
    { name: 'Hatching', entity_type: 'threat_actor' },
    { name: 'Hatching International B.V.', entity_type: 'campaign' },
    { name: 'Hatching', entity_type: 'organization' },
    { name: 'Hatching Triage', entity_type: 'tool' }
  ], { report, document: body });
  assert.deepEqual(kept.map((e) => `${e.entity_type}:${e.name}`), ['threat_actor:Hatching', 'campaign:Hatching International B.V.']);
});

test('legitimate named campaigns and actors stay; a publisher name the source states as a campaign stays', () => {
  const entities = [
    { name: 'Operation Lantern', entity_type: 'campaign' },
    { name: 'Sandworm', entity_type: 'threat_actor' },
    { name: 'Hatching', entity_type: 'campaign' }
  ];
  const stated = doc(['Operators of the Hatching campaign reused the same loader.']);
  assert.deepEqual(unsupportedPublisherEntities(entities, { report, document: stated }), []);
  assert.deepEqual(unsupportedPublisherEntities(entities, { report, document: body }).map((e) => e.name), ['Hatching']);
  assert.equal(sourceStatesThreatRole('Foo', 'a cluster tracked as Foo'), true);
  assert.equal(sourceStatesThreatRole('Foo', 'Operation Foo targeted banks'), true);
  assert.equal(sourceStatesThreatRole('Hatching', 'Hatching International B.V., The Netherlands'), false);
});

test('no publisher identity (PDF / unknown source): nothing is removed', () => {
  const r = groundAiPublisherEntities({ entities: [{ name: 'Hatching', entity_type: 'campaign' }] }, { report: {}, document: doc([]) });
  assert.deepEqual(r.value.entities.map((e) => e.name), ['Hatching']);
});

test('summary grounding removes only threat-role clauses; other publisher mentions stay', () => {
  assert.deepEqual(groundSummaryPublisherEntities('Hatching researchers found WinLol, part of the Hatching operation.', ['Hatching']), {
    summary: 'Hatching researchers found WinLol.', changed: true, unresolved: []
  });
  assert.equal(groundSummaryPublisherEntities('WinLol was built by the Hatching group.', ['Hatching']).summary, 'WinLol was built.');
  const odd = groundSummaryPublisherEntities('The Hatching campaign uses WinLol.', ['Hatching']);
  assert.equal(odd.changed, false);
  assert.deepEqual(odd.unresolved, ['Hatching'], 'an unrewritable assertion is reported, never rephrased');
  assert.deepEqual(groundSummaryPublisherEntities(null, ['Hatching']), { summary: null, changed: false, unresolved: [] });
});

test('stored variant returns link ids only; the shared entity row is never deleted by the gate', () => {
  const stored = groundStoredPublisherEntities({
    summary: "WinLol, associated with the 'Hatching' campaign.",
    entities: [{ entity_id: 573, name: 'WinLol', entity_type: 'malware' }, { entity_id: 580, name: 'Hatching', entity_type: 'campaign' }]
  }, { report, document: body });
  assert.deepEqual(stored.entity_ids_removed, [580]);
  assert.equal(stored.summary, 'WinLol.');
  const store = fs.readFileSync(new URL('./store.js', import.meta.url), 'utf8');
  const fn = store.slice(store.indexOf('export async function removeReportEntityLinks('));
  assert.doesNotMatch(fn.slice(0, fn.indexOf('\n}\n')), /DELETE FROM threat_entities/);
});

test('pipeline applies the gate to every model result before persistence', () => {
  const src = fs.readFileSync(new URL('./pipeline.js', import.meta.url), 'utf8');
  const vuln = src.indexOf('groundAiVulnerabilities(ai.value, document)');
  const gate = src.indexOf('groundAiPublisherEntities(grounded.value, { report, document })');
  const assign = src.indexOf('aiValue = publisherGrounded.value;');
  assert.ok(vuln > 0 && gate > vuln && assign > gate, 'CVE gate -> publisher gate -> the grounded value becomes aiValue');
  // Nothing reads the model output between the model call and the gates.
  assert.equal(src.slice(src.lastIndexOf('if (!ai.ok)', vuln), vuln).includes('aiValue'), false);
  assert.match(src, /publisher_entity_grounding: publisherEntityGrounding/);
});

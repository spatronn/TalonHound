import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ASSOCIATION_KIND,
  ATTRIBUTION_PROVENANCE,
  ENTITY_KIND,
  MAX_SOURCE_LABEL_LENGTH,
  normalizeAdversaryLabels,
  normalizeAttributionLabel,
  normalizeAttributionLabelKey,
  normalizeMalwareFamilyLabels,
  emptyAttributionResponseFields
} from './iocSourceAttributions.js';

test('normalizeAttributionLabel trims and bounds length', () => {
  assert.equal(normalizeAttributionLabel('  UNC3569  '), 'UNC3569');
  assert.equal(normalizeAttributionLabel(''), null);
  assert.equal(normalizeAttributionLabel(null), null);
  const long = 'x'.repeat(MAX_SOURCE_LABEL_LENGTH + 20);
  assert.equal(normalizeAttributionLabel(long).length, MAX_SOURCE_LABEL_LENGTH);
});

test('normalizeAdversaryLabels handles string, array, objects, dedupe', () => {
  assert.deepEqual(normalizeAdversaryLabels('UNC3569'), ['UNC3569']);
  assert.deepEqual(normalizeAdversaryLabels(['UNC3569', 'unc3569', 'APT28']), ['UNC3569', 'APT28']);
  assert.deepEqual(normalizeAdversaryLabels([{ name: 'UNC3569' }, { value: 'APT28' }]), ['UNC3569', 'APT28']);
  assert.deepEqual(normalizeAdversaryLabels(''), []);
  assert.deepEqual(normalizeAdversaryLabels(null), []);
});

test('normalizeMalwareFamilyLabels mirrors adversary normalization', () => {
  assert.deepEqual(normalizeMalwareFamilyLabels(['GRAYRABBIT', 'grayrabbit', 'RABBITFUR']), [
    'GRAYRABBIT',
    'RABBITFUR'
  ]);
});

test('normalizeAttributionLabelKey is case-insensitive', () => {
  assert.equal(normalizeAttributionLabelKey('GrayRabbit'), 'grayrabbit');
});

test('emptyAttributionResponseFields shape', () => {
  const empty = emptyAttributionResponseFields();
  assert.deepEqual(empty.threat_actors, []);
  assert.deepEqual(empty.malware_families, []);
  assert.deepEqual(empty.analyst_threat_actor_ids, []);
  assert.equal(empty.threat_actor_id, null);
});

test('association / provenance constants are stable', () => {
  assert.equal(ASSOCIATION_KIND.ASSOCIATED_VIA_SOURCE_PULSE, 'associated_via_source_pulse');
  assert.equal(ATTRIBUTION_PROVENANCE.SOURCE_REPORTED, 'source_reported');
  assert.equal(ENTITY_KIND.MALWARE_FAMILY, 'malware_family');
});

test('upsert/reconcile/merge integration with mock client — single pulse', async () => {
  const {
    applyOtxPulseAttributions,
    loadEffectiveIocAttributions
  } = await import('./iocSourceAttributions.js');

  const store = new Map();
  const threatActors = new Map([
    ['unc3569', { id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', name: 'UNC3569', slug: 'unc3569', aliases: [], active: true }]
  ]);
  const malwareFamilies = new Map();

  const client = {
    async query(sql, params = []) {
      const text = String(sql).replace(/\s+/g, ' ').trim();

      if (text.includes('FROM threat_actors') && text.includes('lower(name)')) {
        const key = params[0];
        const hit = threatActors.get(key);
        return { rows: hit ? [hit] : [] };
      }
      if (text.includes('FROM malware_families') && text.includes('lower(name)')) {
        const key = params[0];
        const hit = malwareFamilies.get(key);
        return { rows: hit ? [hit] : [] };
      }

      if (text.startsWith('INSERT INTO ioc_source_attributions')) {
        const key = [
          params[0], params[1], params[2], params[7], params[9], params[10], params[4]
        ].join('|');
        const existing = store.get(key);
        if (!existing) {
          store.set(key, {
            ioc_id: params[0],
            ioc_observable_type: params[1],
            entity_kind: params[2],
            source_label: params[3],
            source_label_normalized: params[4],
            entity_id: params[5],
            resolution_status: params[6],
            feed_key: params[7],
            source_name: params[8],
            evidence_ref_type: params[9],
            evidence_ref_id: params[10],
            evidence_url: params[11],
            evidence_title: params[12],
            association_kind: params[13],
            assertion_status: 'current',
            observed_at: params[14],
            is_backfill: params[15],
            first_ingested_at: new Date(),
            last_ingested_at: new Date(),
            withdrawn_at: null,
            resolved_name: params[5] ? 'UNC3569' : null,
            resolved_slug: params[5] ? 'unc3569' : null,
            resolved_aliases: [],
            resolved_active: true
          });
          return { rows: [{ inserted: true }] };
        }
        existing.assertion_status = 'current';
        existing.withdrawn_at = null;
        return { rows: [{ inserted: false }] };
      }

      if (text.startsWith('UPDATE ioc_source_attributions') && text.includes("assertion_status = 'withdrawn'")) {
        let withdrawn = 0;
        const keep = new Set(params[6] || []);
        for (const [k, row] of store.entries()) {
          if (row.ioc_id !== params[0]) continue;
          if (row.ioc_observable_type !== params[1]) continue;
          if (row.feed_key !== params[2]) continue;
          if (row.evidence_ref_type !== params[3]) continue;
          if (String(row.evidence_ref_id) !== String(params[4])) continue;
          if (row.entity_kind !== params[5]) continue;
          if (row.assertion_status !== 'current') continue;
          if (!keep.has(row.source_label_normalized)) {
            row.assertion_status = 'withdrawn';
            row.withdrawn_at = new Date();
            withdrawn += 1;
          }
        }
        return { rowCount: withdrawn, rows: [] };
      }

      if (text.includes('FROM ioc_threat_actors')) return { rows: [] };
      if (text.includes('FROM ioc_malware_families')) return { rows: [] };
      if (text.includes('FROM ioc_attribution_overrides')) return { rows: [] };

      if (text.includes('FROM ioc_source_attributions a')) {
        const rows = [...store.values()].filter((r) => r.ioc_id === params[0] && r.ioc_observable_type === params[1]);
        // includeWithdrawn is last param in real query; mock returns current only unless true
        const includeWithdrawn = params[params.length - 1] === true;
        return {
          rows: rows
            .filter((r) => includeWithdrawn || r.assertion_status === 'current')
            .map((r) => ({
              ...r,
              resolved_name: r.entity_id ? (r.entity_kind === 'threat_actor' ? 'UNC3569' : r.source_label) : null,
              resolved_slug: r.entity_id ? 'unc3569' : null,
              resolved_aliases: [],
              resolved_active: true
            }))
        };
      }

      throw new Error(`Unexpected SQL in mock: ${text.slice(0, 120)}`);
    }
  };

  // Scenario A — single pulse
  const first = await applyOtxPulseAttributions(client, {
    iocId: 42,
    observableType: 'domain',
    pulseId: 'pulse-a',
    pulseName: 'Gray Rabbits',
    pulseUrl: 'https://otx.alienvault.com/pulse/pulse-a',
    adversary: 'UNC3569',
    malwareFamilies: ['GRAYRABBIT', 'RABBITFUR'],
    completeObservation: true
  });
  assert.equal(first.actors, 1);
  assert.equal(first.families, 2);
  assert.equal(first.withdrawn, 0);

  // Scenario B — repeated ingestion idempotent (no growth of store keys)
  const keysBefore = store.size;
  const second = await applyOtxPulseAttributions(client, {
    iocId: 42,
    observableType: 'domain',
    pulseId: 'pulse-a',
    pulseName: 'Gray Rabbits',
    pulseUrl: 'https://otx.alienvault.com/pulse/pulse-a',
    adversary: 'UNC3569',
    malwareFamilies: ['GRAYRABBIT', 'RABBITFUR'],
    completeObservation: true
  });
  assert.equal(store.size, keysBefore);
  assert.equal(second.withdrawn, 0);

  // Scenario C — second pulse adds another family for same actor
  await applyOtxPulseAttributions(client, {
    iocId: 42,
    observableType: 'domain',
    pulseId: 'pulse-b',
    pulseName: 'Other',
    pulseUrl: 'https://otx.alienvault.com/pulse/pulse-b',
    adversary: 'UNC3569',
    malwareFamilies: ['RABBITFUR'],
    completeObservation: true
  });

  const map = await loadEffectiveIocAttributions(client, [{ id: 42, observable_type: 'domain' }]);
  const fields = map.get('42|domain');
  assert.equal(fields.threat_actors.length, 1);
  assert.equal(fields.threat_actors[0].name, 'UNC3569');
  assert.equal(fields.threat_actors[0].attribution, ATTRIBUTION_PROVENANCE.SOURCE_REPORTED);
  assert.equal(fields.threat_actors[0].sources.length, 2);
  assert.equal(fields.malware_families.length, 2);
  assert.ok(fields.malware_families.some((f) => f.name === 'GRAYRABBIT'));
  assert.ok(fields.malware_families.some((f) => f.name === 'RABBITFUR'));
  assert.equal(
    fields.threat_actors[0].sources[0].association_kind,
    ASSOCIATION_KIND.ASSOCIATED_VIA_SOURCE_PULSE
  );

  // Scenario J — pulse update removes one family
  const updated = await applyOtxPulseAttributions(client, {
    iocId: 42,
    observableType: 'domain',
    pulseId: 'pulse-a',
    pulseName: 'Gray Rabbits',
    pulseUrl: 'https://otx.alienvault.com/pulse/pulse-a',
    adversary: 'UNC3569',
    malwareFamilies: ['GRAYRABBIT'],
    completeObservation: true
  });
  assert.ok(updated.withdrawn >= 1);

  const after = await loadEffectiveIocAttributions(client, [{ id: 42, observable_type: 'domain' }]);
  const afterFields = after.get('42|domain');
  const graySources = afterFields.malware_families.find((f) => f.name === 'GRAYRABBIT')?.sources || [];
  assert.ok(graySources.some((s) => s.evidence_ref_id === 'pulse-a' && s.assertion_status === 'current'));

  // Scenario F — empty metadata does not fabricate
  const emptyPulse = await applyOtxPulseAttributions(client, {
    iocId: 99,
    observableType: 'domain',
    pulseId: 'pulse-empty',
    adversary: null,
    malwareFamilies: [],
    completeObservation: true
  });
  assert.equal(emptyPulse.actors, 0);
  assert.equal(emptyPulse.families, 0);
});

test('incomplete observation must not withdraw (caller contract)', async () => {
  const { applyOtxPulseAttributions } = await import('./iocSourceAttributions.js');
  let updateCalled = false;
  const client = {
    async query(sql) {
      const text = String(sql);
      if (text.includes('FROM threat_actors') || text.includes('FROM malware_families')) {
        return { rows: [] };
      }
      if (text.startsWith('INSERT INTO ioc_source_attributions')) {
        return { rows: [{ inserted: true }] };
      }
      if (text.includes("assertion_status = 'withdrawn'")) {
        updateCalled = true;
        return { rowCount: 0, rows: [] };
      }
      return { rows: [] };
    }
  };
  await applyOtxPulseAttributions(client, {
    iocId: 1,
    observableType: 'domain',
    pulseId: 'p1',
    adversary: 'X',
    malwareFamilies: [],
    completeObservation: false
  });
  assert.equal(updateCalled, false);
});

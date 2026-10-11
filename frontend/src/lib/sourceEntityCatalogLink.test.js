import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCatalogLinkRequest,
  catalogLinkSuccessMessage,
  catalogLinkTarget,
  chipLinkAriaLabel,
  describeCandidateMatch,
  evidenceLine,
  formatCatalogLinkAuditSummary,
  interpretCatalogLinkError,
  isAnalystCatalogLink,
  mergeAttributionFields
} from './sourceEntityCatalogLink.js';

const OTX = {
  source_name: 'AlienVault OTX',
  assertion_status: 'current',
  source_label: 'PureRAT',
  evidence_ref_type: 'otx_pulse',
  evidence_ref_id: 'p1',
  evidence_title: 'PureRAT campaign',
  resolution_status: 'unresolved'
};

test('"+" is offered only for unlinked source-reported chips', () => {
  const unlinked = { id: null, name: 'PureRAT', attribution: 'source_reported', source_label_key: 'purerat', sources: [OTX] };
  assert.deepEqual(catalogLinkTarget(unlinked), { label: 'PureRAT' });
  // Already resolved (catalog id) → no "+".
  assert.equal(catalogLinkTarget({ ...unlinked, id: 'f1' }), null);
  // Analyst-only entity → no "+".
  assert.equal(catalogLinkTarget({ id: 'f1', name: 'X', attribution: 'analyst', sources: [] }), null);
  // Only withdrawn evidence → nothing current to resolve.
  assert.equal(catalogLinkTarget({ ...unlinked, sources: [{ ...OTX, assertion_status: 'withdrawn' }] }), null);
});

test('the original source label is sent, not the display name', () => {
  const entity = { id: null, name: 'Pure RAT', sources: [{ ...OTX, source_label: 'pure rat' }] };
  assert.equal(catalogLinkTarget(entity).label, 'pure rat');
});

test('accessible label names the entity and the catalog', () => {
  assert.equal(chipLinkAriaLabel('malware_family', { name: 'PureRAT' }), 'Link PureRAT to a local malware family');
  assert.equal(chipLinkAriaLabel('threat_actor', { name: 'APT28' }), 'Link APT28 to a local threat actor');
});

test('evidence lines keep source + pulse context', () => {
  assert.equal(evidenceLine(OTX), 'AlienVault OTX · Pulse: PureRAT campaign');
  assert.equal(evidenceLine({ source_name: 'Other', evidence_ref_type: 'report', evidence_ref_id: 'r9' }), 'Other · r9');
});

test('candidate match descriptions', () => {
  assert.equal(describeCandidateMatch({ match: 'name' }), 'Exact name');
  assert.equal(describeCandidateMatch({ match: 'alias', match_detail: 'Fancy Bear' }), 'Alias: Fancy Bear');
  assert.equal(describeCandidateMatch({ match: 'attack_id', match_detail: 'S0367' }), 'ATT&CK S0367');
  assert.equal(describeCandidateMatch({ match: 'similar' }), 'Similar spelling');
  assert.equal(describeCandidateMatch({ match: 'search' }), 'Search result');
});

test('request bodies: link sends the entity id; create sends the right kind + analyst fields only', () => {
  const summary = { id: 42, observable_type: 'domain' };
  assert.deepEqual(buildCatalogLinkRequest({ summary, kind: 'malware_family', label: 'PureRAT', mode: 'link', entityId: 'f1' }), {
    observable_type: 'domain', entity_kind: 'malware_family', source_label: 'PureRAT', mode: 'link', entity_id: 'f1'
  });
  assert.deepEqual(buildCatalogLinkRequest({
    summary, kind: 'threat_actor', label: 'Storm-1', mode: 'create',
    create: { name: ' Storm-1 ', aliases: 'S1, , Storm One', description: '  ' }, confirmDistinct: true
  }), {
    observable_type: 'domain', entity_kind: 'threat_actor', source_label: 'Storm-1', mode: 'create',
    create: { name: 'Storm-1', aliases: ['S1', 'Storm One'], description: null }, confirm_distinct: true
  });
});

test('errors: duplicates are actionable, retries are safe, nothing is claimed as saved', () => {
  const dup = interpretCatalogLinkError({ response: { status: 409, data: { code: 'DUPLICATE_ENTITY', error: 'exists', candidates: [{ id: 'f1' }] } } }, 'malware_family');
  assert.equal(dup.switchToLink, true);
  assert.equal(dup.candidates[0].id, 'f1');
  const similar = interpretCatalogLinkError({ response: { status: 409, data: { code: 'POTENTIAL_DUPLICATES', candidates: [{ id: 'f2' }] } } }, 'malware_family');
  assert.equal(similar.needsDistinctConfirmation, true);
  const raced = interpretCatalogLinkError({ response: { status: 409, data: { code: 'ALREADY_LINKED', linked_entities: [{ name: 'APT28' }] } } }, 'threat_actor');
  assert.match(raced.message, /Already linked to APT28/);
  assert.equal(raced.refresh, true);
  assert.match(interpretCatalogLinkError({}, 'threat_actor').message, /retry safely/);
  assert.match(interpretCatalogLinkError({ response: { status: 403, data: { error: 'Admins only' } } }, 'threat_actor').message, /Admins only/);
});

test('success messages per outcome', () => {
  assert.equal(catalogLinkSuccessMessage({ outcome: 'linked', entity: { name: 'PureRAT' } }, 'malware_family'), 'Linked to malware family "PureRAT"');
  assert.equal(catalogLinkSuccessMessage({ outcome: 'created_and_linked', entity: { name: 'PureRAT' } }, 'malware_family'), 'Created malware family "PureRAT" and linked it');
  assert.equal(catalogLinkSuccessMessage({ outcome: 'already_linked', entity: { name: 'APT28' } }, 'threat_actor'), 'Already linked to threat actor "APT28"');
});

test('link response updates only attribution fields of the summary (chip flips to linked)', () => {
  const summary = { id: 42, observable: 'x', malware_families: [{ id: null, name: 'PureRAT' }], threat_actors: [] };
  const next = mergeAttributionFields(summary, {
    success: true, outcome: 'linked', entity: { id: 'f1' },
    malware_families: [{ id: 'f1', name: 'PureRAT', attribution: 'source_reported', sources: [{ ...OTX, resolution_method: 'analyst' }] }],
    malware_family_ids: ['f1']
  });
  assert.equal(next.observable, 'x');
  assert.equal(next.malware_families[0].id, 'f1');
  assert.deepEqual(next.threat_actors, []);
  assert.equal(next.success, undefined);
  assert.equal(catalogLinkTarget(next.malware_families[0]), null);
  assert.equal(isAnalystCatalogLink(next.malware_families[0]), true);
});

test('audit summary text', () => {
  assert.equal(formatCatalogLinkAuditSummary({
    operation: 'link', entity_name: 'PureRAT', source_label: 'purerat',
    sources: [{ source_name: 'AlienVault OTX' }, { source_name: 'AlienVault OTX' }, { source_name: 'Other' }]
  }), '"purerat" (AlienVault OTX, Other) linked to PureRAT · source-reported');
  assert.equal(formatCatalogLinkAuditSummary({ operation: 'create_and_link', entity_name: 'X', source_label: 'x' }), '"x" created + linked to X · source-reported');
  assert.equal(formatCatalogLinkAuditSummary({ old_threat_actor: 'a' }), null);
});

test('provider classification is shown as the source said it, separate from the local catalog', async () => {
  const { providerClassificationLines, CLASSIFICATION_UNVERIFIED_NOTE } = await import('./sourceEntityCatalogLink.js');
  assert.deepEqual(providerClassificationLines([
    { source_name: 'AlienVault OTX', provider_field: 'malware_families', provider_entity_type: 'malware_family' },
    { source_name: 'AlienVault OTX', provider_field: 'malware_families', provider_entity_type: 'malware_family' },
    { source_name: 'Other Feed', provider_field: null, provider_entity_type: null }
  ]), [
    'AlienVault OTX: malware family (field “malware_families”)',
    'Other Feed: type not stated'
  ]);
  assert.deepEqual(providerClassificationLines([]), []);
  assert.match(CLASSIFICATION_UNVERIFIED_NOTE, /source-reported metadata and has not been independently verified/);
});

test('cross-catalog notice names the other catalog entry and never claims it is wrong', async () => {
  const { crossCatalogNotice } = await import('./sourceEntityCatalogLink.js');
  assert.equal(crossCatalogNotice([]), null);
  assert.equal(crossCatalogNotice(null), null);
  const text = crossCatalogNotice([{ entity_kind: 'threat_actor', name: 'BelialDemon', match: 'alias', match_detail: 'Matanbuchus', active: true }]);
  assert.match(text, /also a Threat Actor in the catalog: BelialDemon \(alias “Matanbuchus”\)/);
  assert.match(text, /can be legitimate/);
  assert.match(crossCatalogNotice([{ entity_kind: 'malware_family', name: 'GlassWorm', match: 'name', active: false }]), /Malware Family.*GlassWorm — disabled/);
});

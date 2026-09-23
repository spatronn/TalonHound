import test from 'node:test';
import assert from 'node:assert/strict';
import {
  planCandidateRoleRepair,
  planRelationshipRepair
} from '../../scripts/repair-threat-library-roles-relationships.js';
import { buildEvidenceIndex, publisherTokens } from './relationshipPolicy.js';

test('role repair: only hash rows with a file-incompatible role change', () => {
  assert.deepEqual(planCandidateRoleRepair({ candidate_type: 'sha256', role: 'command_and_control', assessment: 'malicious' }), {
    change: true,
    from: 'command_and_control',
    to: 'malware_sample'
  });
  assert.equal(planCandidateRoleRepair({ candidate_type: 'md5', role: 'payload_hosting', assessment: 'malicious' }).to, 'malware_sample');
  assert.equal(planCandidateRoleRepair({ candidate_type: 'sha256', role: 'malware_sample', assessment: 'malicious' }).change, false);
  assert.equal(planCandidateRoleRepair({ candidate_type: 'sha256', role: 'reference', assessment: 'context_only' }).change, false);
  assert.equal(planCandidateRoleRepair({ candidate_type: 'domain', role: 'command_and_control', assessment: 'malicious' }).change, false);
});

const vidarDoc = {
  meta: { source_host: 'www.zscaler.com' },
  blocks: [{ id: 'b075', text: 'Zscaler MDR detects Vidar using these detection analytics:' }]
};
const ctx = (doc, report) => ({ evidenceIndex: buildEvidenceIndex(doc), publisherTokens: publisherTokens(report, doc) });
const entityRow = (s, t, o, extra = {}) => ({
  relationship_type: t,
  subject_kind: 'entity',
  subject_entity_type: s[0],
  subject_names: [s[1]],
  object_kind: 'entity',
  object_entity_type: o[0],
  object_names: [o[1]],
  evidence_text: null,
  block_id: null,
  ...extra
});

test('relationship repair: deletes only rows the deterministic type policy rejects', () => {
  const report = { source_url: 'https://www.zscaler.com/blogs/x', source_name: 'www.zscaler.com' };
  const vidar = planRelationshipRepair(entityRow(['malware', 'Vidar'], 'uses', ['organization', 'Zscaler']), ctx(vidarDoc, report));
  assert.equal(vidar.decision, 'delete');

  // Co-mention cannot make an incompatible combination valid (production #32:
  // a figure credit "Source: Recorded Future" next to "InvisibleFerret").
  const doc = { blocks: [{ id: 'k1', text: 'Figure 10: InvisibleFerret system information data sent to C2 (Source: Recorded Future)' }] };
  const credit = planRelationshipRepair(
    entityRow(['malware', 'InvisibleFerret'], 'communicates_with', ['organization', 'Recorded Future'], { block_id: 'k1' }),
    ctx(doc, {})
  );
  assert.deepEqual(credit, { decision: 'delete', reason: 'incompatible_endpoint_types' });

  // A context-only indicator (a forum the actor sells on) is not delivery infrastructure.
  const forum = planRelationshipRepair(
    {
      ...entityRow(['malware', 'VectraRAT'], 'delivered_by', ['organization', 'x']),
      object_kind: 'candidate',
      object_candidate_type: 'domain',
      object_candidate_assessment: 'context_only',
      object_candidate_values: ['exploit.in']
    },
    ctx({ blocks: [{ id: 'f', text: 'VectraRAT has a parallel listing on Exploit.in.' }] }, {})
  );
  assert.equal(forum.decision, 'delete');

  // Type-valid without evidence → kept (only future analyses drop these).
  const noEvidence = planRelationshipRepair(entityRow(['threat_actor', 'Lazarus group'], 'uses', ['malware', 'DTrack']), ctx({ blocks: [] }, {}));
  assert.equal(noEvidence.decision, 'keep_type_valid_without_evidence');

  // Type-valid and evidenced → keep.
  const good = planRelationshipRepair(
    entityRow(['malware', 'InvisibleFerret'], 'uses', ['tool', 'PyObfuscate'], { block_id: 'g1' }),
    ctx({ blocks: [{ id: 'g1', text: 'InvisibleFerret uses PyObfuscate.' }] }, {})
  );
  assert.equal(good.decision, 'keep');
});

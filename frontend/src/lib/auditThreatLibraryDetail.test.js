import test from 'node:test';
import assert from 'node:assert/strict';
import {
  auditActorLabel,
  formatAuditStatusLabel,
  isThreatLibraryAuditRow,
  threatLibraryDetailRows,
  threatLibraryOutcomeSample
} from './auditThreatLibraryDetail.js';

const CREATE_IOCS_ROW = {
  id: 1,
  actor_user_id: '2f1c9d0e-5a6b-4c7d-8e9f-0a1b2c3d4e5f',
  actor_username: 'safa@safa.com',
  actor_email: 'safa@safa.com',
  action: 'threat_library.iocs.created',
  action_label: 'Threat Library › Create IOCs',
  entity_type: 'threat_report',
  entity_id: 'c9e28440-a25f-4149-a993-c78d8b458805',
  entity_display: 'PurpleBravo’s Targeting of the IT Software Supply Chain',
  status: 'success',
  source: 'web',
  metadata: {
    report_public_id: 'c9e28440-a25f-4149-a993-c78d8b458805',
    report_title: 'PurpleBravo’s Targeting of the IT Software Supply Chain',
    tlp: 'amber',
    initiated_by: 'safa@safa.com',
    executed_by: 'backend',
    selected: 120,
    eligible: 52,
    created: 52,
    already_existing: 61,
    not_approved: 5,
    unsupported: 2,
    failed: 0,
    candidate_types: { ip: 80, domain: 12, sha256: 20, cidr: 8 },
    results_total: 120,
    results_shown: 100,
    results_omitted: 20,
    results: [{ candidate_id: 101, type: 'ip', value: '23.106.70.154', outcome: 'created', ioc_id: 1234 }]
  }
};

test('actor label renders the user for attributed rows and "—" for legacy actor-null rows', () => {
  assert.equal(auditActorLabel(CREATE_IOCS_ROW), 'safa@safa.com');
  assert.equal(auditActorLabel({ actor_username: null, actor_email: null }), '—');
  assert.equal(auditActorLabel({ actor_username: null, actor_email: 'x@y' }), 'x@y');
});

test('Create IOCs event renders the operation summary from backend metadata', () => {
  assert.equal(isThreatLibraryAuditRow(CREATE_IOCS_ROW), true);
  const rows = Object.fromEntries(threatLibraryDetailRows(CREATE_IOCS_ROW));
  assert.equal(rows.Report, 'PurpleBravo’s Targeting of the IT Software Supply Chain');
  assert.equal(rows['Report ID'], 'c9e28440-a25f-4149-a993-c78d8b458805');
  assert.equal(rows.TLP, 'TLP:AMBER');
  assert.equal(rows['Initiated by'], 'safa@safa.com');
  assert.equal(rows.Selected, '120');
  assert.equal(rows.Created, '52');
  assert.equal(rows['Already existing'], '61');
  assert.equal(rows['Not approved'], '5');
  assert.equal(rows.Unsupported, '2');
  assert.equal(rows.Failed, '0');
  assert.equal(rows['Candidate types'], 'ip: 80 · sha256: 20 · domain: 12 · cidr: 8');
  assert.equal('Executed by' in rows, false, 'backend executor is implicit');
});

test('bounded outcome sample surfaces the omitted count explicitly', () => {
  const { rows, note } = threatLibraryOutcomeSample(CREATE_IOCS_ROW);
  assert.equal(rows.length, 1);
  assert.equal(note, 'Showing 100 of 120 outcomes · 20 omitted from the audit detail');
  const full = threatLibraryOutcomeSample({ metadata: { results: [{}], results_total: 1, results_shown: 1, results_omitted: 0 } });
  assert.equal(full.note, null);
});

test('non-Threat-Library rows produce no detail rows', () => {
  assert.deepEqual(threatLibraryDetailRows({ action: 'ioc.created', metadata: { created: 1 } }), []);
  assert.equal(isThreatLibraryAuditRow({ action: 'ioc.created' }), false);
});

test('worker-executed analysis event shows initiator and executor', () => {
  const rows = Object.fromEntries(threatLibraryDetailRows({
    action: 'threat_library.report.analysis.completed',
    entity_display: 'R',
    metadata: { initiated_by: 'safa@safa.com', executed_by: 'threat-library-worker', job_public_id: 'job-1', candidates_total: 12, result: 'completed' }
  }));
  assert.equal(rows['Initiated by'], 'safa@safa.com');
  assert.equal(rows['Executed by'], 'threat-library-worker');
  assert.equal(rows.Job, 'job-1');
  assert.equal(rows.Candidates, '12');
  assert.equal(rows.Result, 'completed');
});

test('legacy Threat Library rows with no metadata fall back to entity columns and "—" actor', () => {
  const rows = Object.fromEntries(threatLibraryDetailRows({
    action: 'threat_library.import.pdf', entity_id: 'abc', entity_display: null, actor_username: null, metadata: null
  }));
  assert.equal(rows['Report ID'], 'abc');
  assert.equal(rows['Initiated by'], '—' in rows ? rows['—'] : undefined);
  assert.equal('Initiated by' in rows, false);
});

test('finalize and review events render their summaries', () => {
  const fin = Object.fromEntries(threatLibraryDetailRows({
    action: 'threat_library.report.finalized',
    metadata: { total_candidates: 10, approved: 6, context_only: 2, ignored: 2, created: 4, already_existing: 1, unsupported: 1, failed: 0 }
  }));
  assert.equal(fin['Total candidates'], '10');
  assert.equal(fin['IOCs created'], '4');
  const rev = Object.fromEntries(threatLibraryDetailRows({
    action: 'threat_library.candidates.approved',
    metadata: { selected: 5, changed: 3, already_in_state: 2, target_state: 'approved', candidate_types: { ip: 5 } }
  }));
  assert.equal(rev.Changed, '3');
  assert.equal(rev['Already in state'], '2');
  assert.equal(rev['Target state'], 'approved');
});

test('status labels include Partial', () => {
  assert.equal(formatAuditStatusLabel('partial'), 'Partial');
  assert.equal(formatAuditStatusLabel('failed'), 'Failed');
  assert.equal(formatAuditStatusLabel('success'), 'Success');
});

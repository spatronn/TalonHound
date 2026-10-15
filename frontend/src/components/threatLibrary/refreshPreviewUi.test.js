import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  GUARD_REASON_COPY,
  REMOVAL_REASON_COPY,
  buildRefreshRequestBody,
  canSubmitAcceptance,
  describeBlockedRefresh,
  describeRefreshPreview
} from './refreshPreviewUi.js';
import { describeMaintenanceOutcome } from './reportRetryUi.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const FP = 'f'.repeat(64);

function preview({ decision = 'apply', reasons = [], removed = [], added = [], changes = [], deleted = [], counts = {} } = {}) {
  return {
    preview: true,
    ai_invoked: false,
    document_rebuilt: false,
    guard: { decision, reasons, material: reasons.some((r) => r.material), material_fingerprint: FP },
    membership_diff: {
      material_fingerprint: FP,
      indicators: { before: 26, after: 26 + added.length - removed.length },
      counts: {
        added_indicators: added.length,
        removed_indicators: removed.length,
        classification_changes: changes.length,
        reviewed_candidates_deleted: deleted.length,
        ...counts
      },
      added_indicators: added,
      removed_indicators: removed,
      classification_changes: changes,
      reviewed_candidates_deleted: deleted,
      newly_context_only: [],
      quality: { new_warning_codes: [] }
    }
  };
}

test('every backend guard reason and removal reason has analyst wording', () => {
  const src = fs.readFileSync(path.join(here, '..', '..', '..', '..', 'backend', 'lib', 'threatLibrary', 'refreshMembershipGuard.js'), 'utf8');
  const reasonsBlock = src.slice(src.indexOf('export const REFRESH_GUARD_REASONS'), src.indexOf('});', src.indexOf('export const REFRESH_GUARD_REASONS')));
  for (const [, code] of reasonsBlock.matchAll(/:\s*'([a-z_]+)'/g)) assert.ok(GUARD_REASON_COPY[code], `guard reason ${code}`);
  for (const code of ['identity_left_document', 'left_document_linked_source_kept', 'publisher_assertion_lost', 'became_context_only', 'excluded_by_type_gate', 'mode_changed', 'membership_rule']) {
    assert.ok(REMOVAL_REASON_COPY[code], `removal reason ${code}`);
    assert.ok(src.includes(`'${code}'`), `backend still emits ${code}`);
  }
});

test('unprotected preview: plain refresh, no acceptance sent', () => {
  const m = describeRefreshPreview(preview({ added: ['md5:aaaa'] }));
  assert.equal(m.blocked, false);
  assert.equal(m.indicatorsLine, 'Indicators 26 → 27');
  assert.deepEqual(m.added.map((a) => [a.typeLabel, a.value]), [['MD5', 'aaaa']]);
  assert.deepEqual(buildRefreshRequestBody(m, ''), {}, 'the server still re-checks the guard');
});

test('protected preview: reasons explained, reviewed / publisher-listed / linked rows highlighted', () => {
  const m = describeRefreshPreview(preview({
    decision: 'block',
    reasons: [
      { code: 'publisher_assertion_lost', count: 2, material: true },
      { code: 'reviewed_candidate_deleted', count: 1, material: true },
      { code: 'membership_mode_changed', count: 1, material: false }
    ],
    removed: [
      { identity: 'md5:aaaa', reason_code: 'publisher_assertion_lost', row_outcome: 'kept', publisher_asserted: true, reviewed: false, review_status: 'pending' },
      { identity: 'domain:kept.example', reason_code: 'left_document_linked_source_kept', row_outcome: 'original_occurrence_cleared', union_member_after: true, publisher_asserted: false, reviewed: true, review_status: 'approved' },
      { identity: 'domain:gone.example', reason_code: 'identity_left_document', row_outcome: 'deleted', publisher_asserted: false, reviewed: true, review_status: 'approved', matched_ioc_id: 9001 }
    ],
    deleted: [
      { identity: 'domain:gone.example', review_status: 'approved', matched_ioc_id: 9001 },
      { identity: 'domain:ignored.example', review_status: 'ignored', matched_ioc_id: null }
    ],
    changes: [{ identity: 'md5:aaaa', fields: ['source_assertion'], from: { source_assertion: 'explicit_ioc' }, to: { source_assertion: 'body_mention' } }]
  }));
  assert.equal(m.blocked, true);
  assert.equal(m.needsAcceptance, true);
  assert.match(m.headline, /accept these changes with a reason/);
  assert.deepEqual(m.blockingReasons.map((r) => r.title), ['Publisher-listed Indicators would be removed', 'Rows with analyst decisions would be deleted']);
  assert.deepEqual(m.advisoryReasons.map((r) => r.code), ['membership_mode_changed']);
  const byId = Object.fromEntries(m.removed.map((r) => [r.identity, r]));
  assert.equal(byId['md5:aaaa'].protected, true);
  assert.ok(byId['md5:aaaa'].badges.some((b) => b.label === 'Publisher-listed'));
  assert.equal(byId['domain:kept.example'].protected, false, 'decision kept through a linked IOC Source');
  assert.ok(byId['domain:kept.example'].badges.some((b) => b.label === 'Kept via IOC Source'));
  assert.equal(byId['domain:kept.example'].reason, 'No longer in the report text; kept through a linked IOC Source');
  assert.ok(byId['domain:gone.example'].badges.some((b) => b.label === 'Row deleted'));
  assert.ok(byId['domain:gone.example'].badges.some((b) => b.label === 'IOC record kept'));
  assert.deepEqual(m.deletedReviewed.map((d) => d.identity), ['domain:ignored.example'], 'deleted Indicators are not listed twice');
  assert.deepEqual(m.changed.map((c) => `${c.from} → ${c.to}`), ['Publisher IOC → Narrative mention']);
});

test('acceptance is never automatic: needs a reason and the preview fingerprint', () => {
  const m = describeRefreshPreview(preview({ decision: 'block', reasons: [{ code: 'publisher_assertion_lost', count: 1, material: true }] }));
  assert.equal(buildRefreshRequestBody(m, ''), null);
  assert.equal(buildRefreshRequestBody(m, 'ok'), null);
  assert.equal(canSubmitAcceptance('  short  '), false);
  assert.deepEqual(buildRefreshRequestBody(m, '  Verified against the publisher appendix  '), {
    membership_changes: 'accept',
    reason: 'Verified against the publisher appendix',
    preview_fingerprint: FP
  });
  const noFp = { ...m, fingerprint: null };
  assert.equal(buildRefreshRequestBody(noFp, 'Verified against the publisher appendix'), null);
});

test('a preview blocked only for acceptance problems cannot be accepted from the dialog', () => {
  const m = describeRefreshPreview(preview({ decision: 'block', reasons: [{ code: 'preview_stale', count: 1, material: true }] }));
  assert.equal(m.needsAcceptance, false);
  assert.equal(buildRefreshRequestBody(m, 'Verified against the publisher appendix'), null);
});

test('blocked refresh feedback names the reason (stale preview vs protected changes)', () => {
  const blocked = { job_type: 'refresh_extraction', status: 'failed', error_message: 'Refresh blocked…', progress: { failure_code: 'refresh_membership_loss_blocked', membership_guard: { reasons: [{ code: 'publisher_assertion_lost' }] } } };
  assert.match(describeMaintenanceOutcome(blocked).error, /not applied: it would remove protected Indicators/);
  const stale = { ...blocked, progress: { ...blocked.progress, membership_guard: { reasons: [{ code: 'preview_stale' }] } } };
  assert.match(describeMaintenanceOutcome(stale).error, /no longer match the preview/);
  assert.equal(describeBlockedRefresh({}).startsWith('Refresh extraction was not applied'), true);
  // Ordinary failures keep their message.
  assert.match(describeMaintenanceOutcome({ job_type: 'refresh_extraction', status: 'failed', error_message: 'no retained source' }).error, /Refresh extraction failed: no retained source/);
});

test('dialog and quality section never render parser internals or auto-accept', () => {
  const modal = fs.readFileSync(path.join(here, 'RefreshPreviewModal.jsx'), 'utf8');
  const section = fs.readFileSync(path.join(here, 'ExtractionQualitySection.jsx'), 'utf8');
  for (const src of [modal, section]) {
    assert.doesNotMatch(src, /block_ids|extractor_version|zone_reason|scope_opening_id|policy_decision/);
  }
  // The accept button is disabled until buildRefreshRequestBody returns a body.
  assert.match(modal, /disabled=\{submitting \|\| loading \|\| !body\}/);
  assert.match(modal, /buildRefreshRequestBody\(model, reason\)/);
});

test('RBAC: an admin-only acceptance is not offered to an analyst; an admin can accept the same preview', () => {
  const p = preview({ decision: 'block', reasons: [{ code: 'reviewed_indicator_removed', count: 1, material: true }] });
  p.guard.authorization = { required_role: 'admin', categories: [{ code: 'reviewed_indicator_removed', count: 1 }] };
  const analyst = describeRefreshPreview(p, { isAdmin: false });
  assert.equal(analyst.requiresAdmin, true);
  assert.equal(analyst.canAccept, false);
  assert.match(analyst.adminNotice, /requires an admin/);
  assert.equal(buildRefreshRequestBody(analyst, 'Verified against the publisher appendix'), null, 'no acceptance body for an analyst');
  assert.equal(buildRefreshRequestBody(describeRefreshPreview(p), 'Verified against the publisher appendix'), null, 'unknown viewer is not admin');
  const admin = describeRefreshPreview(p, { isAdmin: true });
  assert.equal(admin.canAccept, true);
  assert.equal(admin.adminNotice, null);
  assert.equal(buildRefreshRequestBody(admin, 'Verified against the publisher appendix').membership_changes, 'accept');
});

test('RBAC: analyst-level losses stay acceptable for an analyst; unblocked refreshes are unaffected', () => {
  const p = preview({ decision: 'block', reasons: [{ code: 'bulk_membership_loss', count: 6, material: true }] });
  p.guard.authorization = { required_role: 'analyst', categories: [] };
  const m = describeRefreshPreview(p, { isAdmin: false });
  assert.equal(m.canAccept, true);
  assert.equal(buildRefreshRequestBody(m, 'Verified against the publisher appendix').membership_changes, 'accept');
  assert.deepEqual(buildRefreshRequestBody(describeRefreshPreview(preview(), { isAdmin: false }), ''), {});
});

test('RBAC: a refresh refused for missing admin rights says so', () => {
  const job = { job_type: 'refresh_extraction', status: 'failed', progress: { failure_code: 'refresh_membership_loss_blocked', membership_guard: { reasons: [{ code: 'acceptance_requires_admin' }] } } };
  assert.match(describeMaintenanceOutcome(job).error, /requires an admin/);
});

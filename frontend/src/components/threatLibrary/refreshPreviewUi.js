/**
 * Refresh extraction preview → analyst view model (GET …/refresh-extraction/preview).
 *
 * The preview is read-only. The analyst sees which Indicators the refresh
 * would add / remove / reclassify, which of them were reviewed or
 * publisher-listed, and — when the membership guard would block — why. A
 * protected refresh is sent only with an explicit acceptance: a reason and
 * the fingerprint of THIS preview. The server re-evaluates the guard when the
 * job runs and refuses the acceptance if the losses changed in between.
 */

import { identityTypeLabel, splitIdentity } from './extractionQualityUi.js';

export const ACCEPTANCE_REASON_MIN_CHARS = 8;

/** Guard reason codes (backend refreshMembershipGuard.js) → analyst wording. */
export const GUARD_REASON_COPY = Object.freeze({
  acceptance_requires_admin: {
    title: 'Admin acceptance required',
    detail: 'These changes remove reviewed, publisher-listed or IOC-linked Indicators, or change global IOC links. Only an admin can accept them.'
  },
  acceptance_not_authorized: {
    title: 'Acceptance not authorized',
    detail: 'The account that accepted these changes is not an active analyst or admin.'
  },
  reviewed_indicator_removed: {
    title: 'Reviewed Indicators would be removed',
    detail: 'Indicators that already have an analyst decision would leave the Indicators list.'
  },
  reviewed_candidate_deleted: {
    title: 'Rows with analyst decisions would be deleted',
    detail: 'These values are no longer extracted, so their rows and the decisions on them would be removed.'
  },
  publisher_assertion_lost: {
    title: 'Publisher-listed Indicators would be removed',
    detail: 'Values the publisher lists as IOCs would no longer be Indicators. This is the typical sign of an extraction change losing part of an IOC section.'
  },
  ioc_link_changed: {
    title: 'Global IOC links would change',
    detail: 'Values already linked to a global IOC record would lose that link or point at a different IOC. The IOC records themselves are not deleted.'
  },
  bulk_membership_loss: {
    title: 'Large drop in Indicators',
    detail: 'A large share of the current Indicators would be removed.'
  },
  membership_mode_changed: {
    title: 'Indicator rules for this report change',
    detail: 'Whether the report has a publisher IOC section changes, which changes which values can be Indicators.'
  },
  new_quality_warnings: {
    title: 'New extraction warnings',
    detail: 'The refreshed extraction raises warnings the current one does not.'
  },
  acceptance_reason_missing: { title: 'A reason is required', detail: 'Explain why these changes are expected.' },
  preview_fingerprint_missing: { title: 'Preview required', detail: 'Accept from a current preview.' },
  preview_stale: {
    title: 'The preview is out of date',
    detail: 'The report changed since this preview. Review the new preview.'
  }
});

/** Per-row removal reason (diff `reason_code`) → analyst wording. */
export const REMOVAL_REASON_COPY = Object.freeze({
  identity_left_document: 'No longer extracted (row deleted)',
  left_document_linked_source_kept: 'No longer in the report text; kept through a linked IOC Source',
  publisher_assertion_lost: 'No longer read as publisher-listed',
  became_context_only: 'Becomes Context Only',
  excluded_by_type_gate: 'No longer an IOC type',
  mode_changed: 'Not an Indicator under the report’s new rules',
  membership_rule: 'No longer meets the Indicator rules'
});

const ASSERTION_LABELS = Object.freeze({
  explicit_ioc: 'Publisher IOC',
  explicit_c2: 'Publisher C2',
  explicit_operational_infrastructure: 'Publisher infrastructure',
  body_mention: 'Narrative mention',
  provider_service: 'Provider / service',
  reference_only: 'Reference',
  source_metadata: 'Source metadata',
  non_ioc: 'Not an IOC'
});

function assertionLabel(v) {
  return ASSERTION_LABELS[v] || (v ? String(v).replace(/_/g, ' ') : '—');
}

function display(identity) {
  const { type, value } = splitIdentity(identity);
  return { identity, type, typeLabel: identityTypeLabel(type), value };
}

function removalBadges(r) {
  const badges = [];
  if (r.publisher_asserted) badges.push({ label: 'Publisher-listed', tone: 'warning' });
  if (r.reviewed) badges.push({ label: r.review_status && r.review_status !== 'pending' ? `Reviewed · ${String(r.review_status).replace(/_/g, ' ')}` : 'IOC created', tone: 'warning' });
  if (r.row_outcome === 'original_occurrence_cleared') badges.push({ label: 'Kept via IOC Source', tone: 'info' });
  if (r.row_outcome === 'deleted') badges.push({ label: 'Row deleted', tone: 'danger' });
  if (r.matched_ioc_id != null) badges.push({ label: 'IOC record kept', tone: 'neutral' });
  return badges;
}

/**
 * @param {object|null|undefined} preview GET …/refresh-extraction/preview body
 * @param {{ isAdmin?: boolean }} [viewer] the session role decides whether the
 *   acceptance is offered (the server enforces it again, from the database role)
 */
export function describeRefreshPreview(preview, viewer = {}) {
  const diff = preview?.membership_diff || {};
  const guard = preview?.guard || {};
  const counts = diff.counts || {};
  const blocked = guard.decision === 'block';
  const reasons = (Array.isArray(guard.reasons) ? guard.reasons : []).map((r) => ({
    code: r.code,
    material: r.material === true,
    count: r.count ?? null,
    title: GUARD_REASON_COPY[r.code]?.title || String(r.code || '').replace(/_/g, ' '),
    detail: GUARD_REASON_COPY[r.code]?.detail || r.detail || ''
  }));
  const removed = (diff.removed_indicators || []).map((r) => ({
    ...display(r.identity),
    reason: REMOVAL_REASON_COPY[r.reason_code] || 'Removed',
    protected: Boolean(r.publisher_asserted || (r.reviewed && !r.union_member_after) || (r.reviewed && r.row_outcome === 'deleted')),
    badges: removalBadges(r)
  }));
  const deletedReviewed = (diff.reviewed_candidates_deleted || [])
    .filter((d) => !(diff.removed_indicators || []).some((r) => r.identity === d.identity))
    .map((d) => ({
      ...display(d.identity),
      reason: `Row with an analyst decision (${String(d.review_status || 'IOC created').replace(/_/g, ' ')}) would be deleted`,
      protected: true,
      badges: [
        { label: 'Row deleted', tone: 'danger' },
        ...(d.matched_ioc_id != null ? [{ label: 'IOC record kept', tone: 'neutral' }] : [])
      ]
    }));
  const iocLinks = (diff.ioc_link_changes || []).map((l) => ({
    ...display(l.identity),
    reason: l.change === 'moved' || l.to_ioc_id != null
      ? `Linked to IOC #${l.to_ioc_id} instead of #${l.from_ioc_id}`
      : `Link to IOC #${l.from_ioc_id} would be cleared`,
    protected: true,
    badges: [
      ...(l.reviewed ? [{ label: l.review_status && l.review_status !== 'pending' ? `Reviewed · ${String(l.review_status).replace(/_/g, ' ')}` : 'IOC created', tone: 'warning' }] : []),
      { label: 'IOC record kept', tone: 'neutral' }
    ]
  }));
  const changed = (diff.classification_changes || [])
    .filter((c) => (c.fields || []).includes('source_assertion'))
    .map((c) => ({
      ...display(c.identity),
      from: assertionLabel(c.from?.source_assertion),
      to: assertionLabel(c.to?.source_assertion)
    }));
  const before = diff.indicators?.before ?? null;
  const after = diff.indicators?.after ?? null;
  const material = reasons.filter((r) => r.material);
  const acceptanceProblems = new Set(['acceptance_reason_missing', 'preview_fingerprint_missing', 'preview_stale', 'acceptance_requires_admin', 'acceptance_not_authorized']);
  const requiresAdmin = blocked && guard.authorization?.required_role === 'admin';
  const canAccept = !requiresAdmin || viewer.isAdmin === true;
  return {
    available: Boolean(preview && preview.preview === true),
    blocked,
    needsAcceptance: blocked && material.some((r) => !acceptanceProblems.has(r.code)),
    requiresAdmin,
    canAccept,
    adminNotice: requiresAdmin && !canAccept
      ? 'Accepting these changes requires an admin: they remove reviewed, publisher-listed or IOC-linked Indicators, or change global IOC links. Ask an admin to review this preview.'
      : null,
    fingerprint: diff.material_fingerprint || guard.material_fingerprint || null,
    indicatorsLine: before != null && after != null ? `Indicators ${before} → ${after}` : null,
    headline: !blocked
      ? (counts.added_indicators || counts.removed_indicators || counts.classification_changes
          ? 'The refresh changes the report as listed below. No protected Indicator is affected.'
          : 'The refresh does not change any Indicator.')
      : 'This refresh would remove protected Indicators or analyst decisions. It runs only if you accept these changes with a reason.',
    counts: {
      added: counts.added_indicators || 0,
      removed: counts.removed_indicators || 0,
      changed: changed.length,
      newlyContextOnly: counts.newly_context_only || 0,
      deletedReviewed: counts.reviewed_candidates_deleted || 0,
      iocLinkChanges: counts.ioc_link_changes || 0,
      keptByLinkedSource: counts.original_occurrences_cleared || 0
    },
    reasons,
    blockingReasons: material,
    advisoryReasons: reasons.filter((r) => !r.material),
    removed,
    deletedReviewed,
    iocLinks,
    added: (diff.added_indicators || []).map(display),
    changed,
    newWarnings: diff.quality?.new_warning_codes || [],
    documentRebuilt: preview?.document_rebuilt === true
  };
}

export function canSubmitAcceptance(reason) {
  return String(reason || '').trim().length >= ACCEPTANCE_REASON_MIN_CHARS;
}

/**
 * Request body for POST …/refresh-extraction from a reviewed preview. An
 * unblocked preview sends no acceptance (the server still re-checks); a
 * blocked one sends the explicit acceptance only with a valid reason.
 * @returns {object|null} null when the acceptance is incomplete
 */
export function buildRefreshRequestBody(model, reason) {
  if (!model?.blocked) return {};
  if (!model.needsAcceptance || model.canAccept === false || !model.fingerprint || !canSubmitAcceptance(reason)) return null;
  return {
    membership_changes: 'accept',
    reason: String(reason).trim(),
    preview_fingerprint: model.fingerprint
  };
}

/** Feedback for a refresh job the guard blocked (job progress / error). */
export function describeBlockedRefresh(job) {
  const reasons = job?.progress?.membership_guard?.reasons || [];
  if (reasons.some((r) => r.code === 'acceptance_requires_admin' || r.code === 'acceptance_not_authorized')) {
    return 'Refresh extraction was not applied: accepting these changes requires an admin. Nothing was changed.';
  }
  if (reasons.some((r) => r.code === 'preview_stale')) {
    return 'Refresh extraction was not applied: the changes no longer match the preview you accepted. Open Refresh extraction again to review the current changes.';
  }
  return 'Refresh extraction was not applied: it would remove protected Indicators or analyst decisions. Open Refresh extraction to review the changes and accept them with a reason.';
}

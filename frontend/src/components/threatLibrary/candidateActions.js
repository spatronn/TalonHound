/**
 * State-aware review actions for one indicator (detail drawer action bar).
 *
 * Display gating only: mirrors the backend rules in
 * backend/lib/threatLibrary/reviewService.js + promotion.js so the drawer
 * never offers a transition the server would refuse or silently no-op:
 *   - approve updates only `is_ioc = true` rows; re-approving is a no-op
 *   - context_only / ignore apply to any row (hidden when already in state)
 *   - create_iocs needs approved + creatable type + malicious/suspicious
 *     assessment + no existing IOC record (classifyCreateEligibility)
 * The server remains the source of truth; this never rewrites a row.
 */

const CREATABLE_IOC_TYPES = new Set(['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256']);

function reviewOf(c) {
  return String(c?.review_status || 'pending').toLowerCase();
}

function isApproved(c) {
  const r = reviewOf(c);
  return r === 'approved' || r === 'created_ioc';
}

function isContextOrIgnored(c) {
  if (!c || c.is_ioc === false) return true;
  const review = reviewOf(c);
  const assessment = String(c.assessment || '').toLowerCase();
  const state = String(c.match_state || '').toLowerCase();
  if (review === 'ignored' || review === 'context_only') return true;
  if (assessment === 'context_only' || assessment === 'invalid') return true;
  if (state === 'context_only' || state === 'invalid') return true;
  return false;
}

function hasIocRecord(c) {
  if (c?.matched_ioc_id) return true;
  if (reviewOf(c) === 'created_ioc') return true;
  const outcome = String(c?.promotion_outcome || '').toLowerCase();
  if (outcome === 'created' || outcome === 'already_existing') return true;
  return String(c?.match_state || '').toLowerCase() === 'existing';
}

/** Frontend mirror of promotion.classifyCreateEligibility (outcome only). */
export function createEligibility(candidate) {
  const type = String(candidate?.candidate_type || '').toLowerCase();
  if (isContextOrIgnored(candidate)) return { eligible: false, outcome: 'not_applicable' };
  if (type === 'cidr' || !CREATABLE_IOC_TYPES.has(type)) return { eligible: false, outcome: 'unsupported' };
  if (!isApproved(candidate)) return { eligible: false, outcome: 'not_approved' };
  const assessment = String(candidate?.assessment || '').toLowerCase();
  if (!['malicious', 'suspicious'].includes(assessment)) return { eligible: false, outcome: 'not_applicable' };
  if (hasIocRecord(candidate)) return { eligible: false, outcome: 'already_existing' };
  return { eligible: true, outcome: 'will_create' };
}

/**
 * @param {object} candidate
 * @param {{ canWrite?: boolean, mutationAllowed?: boolean }} ctx
 * @returns {{ actions: { id: string, label: string, primary?: boolean }[], note: string|null }}
 */
export function describeCandidateActions(candidate, { canWrite = true, mutationAllowed = true } = {}) {
  if (!candidate || !canWrite || !mutationAllowed) return { actions: [], note: null };
  const review = reviewOf(candidate);
  const actions = [];
  const notes = [];

  if (candidate.is_ioc !== false && !isApproved(candidate)) {
    actions.push({ id: 'approve', label: 'Approve' });
  }
  if (review !== 'context_only') actions.push({ id: 'context_only', label: 'Context only' });
  if (review !== 'ignored') actions.push({ id: 'ignore', label: 'Ignore' });

  const create = createEligibility(candidate);
  if (create.eligible) {
    actions.push({ id: 'create_iocs', label: 'Create IOC', primary: true });
  }

  if (isApproved(candidate)) {
    const outcome = String(candidate.promotion_outcome || '').toLowerCase();
    if (outcome === 'created') notes.push('Approved · IOC record created');
    else if (outcome === 'already_existing' || hasIocRecord(candidate)) notes.push('Approved · IOC record already exists');
    else if (create.outcome === 'unsupported') notes.push('Approved · type cannot be stored as an IOC record');
    else if (create.outcome === 'not_applicable') notes.push('Approved · assessment is not malicious or suspicious');
    else notes.push('Approved');
  } else if (review === 'ignored') {
    notes.push('Ignored');
  } else if (review === 'context_only') {
    notes.push('Context only');
  } else if (candidate.is_ioc === false) {
    notes.push('Not an IOC candidate');
  }

  return { actions, note: notes.length ? notes.join(' · ') : null };
}

/**
 * Idempotency guards for IOC global status-override API (no DB write, no audit on noop).
 */

import { MANUAL_SOURCE_LIFECYCLE_REASONS } from './iocSourceValidation.js';

function normStatus(status) {
  return String(status || 'active').trim().toLowerCase();
}

/**
 * A manually-added IOC source (createManualIoc) and a moved manual source (iocSourceMove)
 * both set `manual_status_override = TRUE` on their ioc_items row. That flag is an internal
 * per-row lifecycle carrier that lets a manual source honour its OWN expiry
 * (`manual_expires_at`) independently of feed memberships — it is NOT an explicit analyst
 * override of the IOC lifecycle. Such bookkeeping rows are recognisable because they always
 * carry `manual_status = 'active'` together with one of the reserved source-lifecycle reason
 * sentinels. Everything else that sets the flag (Expire IOC now, reactivate, set custom
 * expiry, bulk expire) is a genuine explicit override and carries a free-text reason.
 *
 * `manual source` != `manual override`.
 *
 * @param {object|null|undefined} row ioc_items row exposing manual_status_override,
 *   manual_status, manual_override_reason.
 */
export function isManualSourceLifecycleBookkeeping(row) {
  if (!row || !row.manual_status_override) return false;
  if (normStatus(row.manual_status) !== 'active') return false;
  const reason = String(row.manual_override_reason || '').trim();
  return MANUAL_SOURCE_LIFECYCLE_REASONS.includes(reason);
}

/**
 * Canonical predicate for "an explicit analyst lifecycle override exists on this IOC row".
 * This is the value that should drive the analyst-facing "Manual Override" indicator and the
 * availability of the "Clear override" action — NOT the raw manual_status_override column,
 * which is overloaded to also carry manual-source lifecycle bookkeeping.
 *
 * @param {object|null|undefined} row
 */
export function isExplicitIocLifecycleOverride(row) {
  if (!row || !row.manual_status_override) return false;
  return !isManualSourceLifecycleBookkeeping(row);
}

/**
 * @param {object|null} prev Row from ioc_items
 * @param {object} body Request body
 * @returns {{ noop: boolean, message?: string }}
 */
export function evaluateIocStatusOverrideRequest(prev, body) {
  if (!prev) return { noop: false };

  const clear = body?.manual_status_override === false;
  if (clear) {
    // Only a genuine explicit override can be cleared. A manual SOURCE carries
    // manual_status_override as internal expiry bookkeeping — clearing that would destroy
    // the source's lifecycle, so treat it as a noop (defence in depth; the UI already
    // hides "Clear override" for these rows).
    if (!isExplicitIocLifecycleOverride(prev)) {
      return { noop: true, message: 'No manual override is set.' };
    }
    return { noop: false };
  }

  const manualStatus = normStatus(body?.manual_status);
  if (!['active', 'expired'].includes(manualStatus)) {
    return { noop: false };
  }

  if (manualStatus === 'expired') {
    if (normStatus(prev.status) === 'expired') {
      return { noop: true, message: 'IOC is already expired.' };
    }
    return { noop: false };
  }

  // manual_status === 'active'
  const manualExpiresAt = body?.manual_expires_at;
  if (manualExpiresAt != null && manualExpiresAt !== '') {
    return { noop: false };
  }
  if (body?.expiration_policy) {
    return { noop: false };
  }

  if (normStatus(prev.status) === 'active') {
    return { noop: true, message: 'IOC is already active.' };
  }

  return { noop: false };
}

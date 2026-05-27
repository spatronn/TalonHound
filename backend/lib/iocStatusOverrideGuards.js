/**
 * Idempotency guards for IOC global status-override API (no DB write, no audit on noop).
 */

function normStatus(status) {
  return String(status || 'active').trim().toLowerCase();
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
    if (!prev.manual_status_override) {
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

  if (normStatus(prev.status) === 'active') {
    return { noop: true, message: 'IOC is already active.' };
  }

  return { noop: false };
}

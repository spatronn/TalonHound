function isoOrNull(value) {
  if (value == null) return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export function formatIocEntityDisplay(observableType, observable) {
  const type = String(observableType || '').trim();
  const value = String(observable || '').trim();
  if (type && value) return `${type} · ${value}`;
  return value || type || null;
}

export function formatMembershipEntityDisplay({ observableType, observable, feedName, membershipId }) {
  const iocPart = formatIocEntityDisplay(observableType, observable);
  const parts = [iocPart];
  if (feedName) parts.push(String(feedName).trim());
  const label = parts.filter(Boolean).join(' · ');
  if (label) return label;
  return membershipId != null ? `membership ${membershipId}` : null;
}

export function normalizeExpirationAuditReason(reason) {
  const r = String(reason || '').trim();
  if (!r) return 'expires_at_reached';
  if (r === 'policy_ttl') return 'expires_at_reached';
  return r;
}

/**
 * @param {{
 *   iocId: number,
 *   observable: string,
 *   observableType: string,
 *   oldStatus: string,
 *   newStatus: string,
 *   oldExpiresAt?: unknown,
 *   expiredAt?: unknown,
 *   reason?: string|null,
 *   actor?: { actor_type?: string, source?: string },
 *   feed?: { feed_id?: string|null, feed_name?: string|null }|null,
 *   membershipId?: number|null,
 * }} input
 */
function iocSnapshotFields(iocId, observable, observableType) {
  return {
    ioc_id: Number(iocId),
    observable: String(observable || '').trim(),
    observable_type: String(observableType || '').trim()
  };
}

export function buildIocExpirationAuditPayload(input) {
  const snapshot = iocSnapshotFields(input.iocId, input.observable, input.observableType);
  const metadata = {
    actor_type: input.actor?.actor_type || 'system',
    reason: normalizeExpirationAuditReason(input.reason),
    ioc_id: snapshot.ioc_id,
    ioc_value: snapshot.observable,
    ioc_observable_type: snapshot.observable_type,
    old_status: input.oldStatus,
    new_status: input.newStatus,
    old_expires_at: isoOrNull(input.oldExpiresAt),
    expired_at: isoOrNull(input.expiredAt),
    source: input.actor?.source || 'expiration-worker'
  };

  if (input.feed?.feed_id) metadata.feed_id = String(input.feed.feed_id);
  if (input.feed?.feed_name) metadata.feed_name = input.feed.feed_name;
  if (input.membershipId != null) metadata.membership_id = Number(input.membershipId);

  const before = {
    ...snapshot,
    status: input.oldStatus,
    expires_at: isoOrNull(input.oldExpiresAt)
  };
  const after = {
    ...snapshot,
    status: input.newStatus,
    expired_at: isoOrNull(input.expiredAt),
    expires_at: input.newExpiresAt !== undefined ? isoOrNull(input.newExpiresAt) : null
  };

  return {
    entityDisplay: formatIocEntityDisplay(input.observableType, input.observable),
    metadata,
    before,
    after
  };
}

/**
 * @param {{
 *   membershipId: number,
 *   iocId: number,
 *   observable: string,
 *   observableType: string,
 *   feedId?: string|null,
 *   feedName?: string|null,
 *   oldStatus?: string,
 *   newStatus?: string,
 *   oldExpiresAt?: unknown,
 *   expiredAt?: unknown,
 *   reason?: string|null,
 *   actor?: { actor_type?: string, source?: string },
 * }} input
 */
export function buildMembershipExpirationAuditPayload(input) {
  const snapshot = iocSnapshotFields(input.iocId, input.observable, input.observableType);
  const membershipId = Number(input.membershipId);
  const oldStatus = input.oldStatus || 'active';
  const newStatus = input.newStatus || 'expired';
  const metadata = {
    actor_type: input.actor?.actor_type || 'system',
    reason: normalizeExpirationAuditReason(input.reason),
    ioc_id: snapshot.ioc_id,
    ioc_value: snapshot.observable,
    ioc_observable_type: snapshot.observable_type,
    membership_id: membershipId,
    old_status: oldStatus,
    new_status: newStatus,
    old_expires_at: isoOrNull(input.oldExpiresAt),
    expired_at: isoOrNull(input.expiredAt),
    source: input.actor?.source || 'expiration-worker'
  };

  if (input.feedId) metadata.feed_id = String(input.feedId);
  if (input.feedName) metadata.feed_name = input.feedName;

  const feedFields = {};
  if (input.feedId) feedFields.feed_id = String(input.feedId);
  if (input.feedName) feedFields.feed_name = input.feedName;

  return {
    entityDisplay: formatMembershipEntityDisplay({
      observableType: input.observableType,
      observable: input.observable,
      feedName: input.feedName,
      membershipId: input.membershipId
    }),
    metadata,
    before: {
      membership_id: membershipId,
      ...snapshot,
      ...feedFields,
      status: oldStatus,
      expires_at: isoOrNull(input.oldExpiresAt)
    },
    after: {
      membership_id: membershipId,
      ...snapshot,
      ...feedFields,
      status: newStatus,
      expired_at: isoOrNull(input.expiredAt),
      expires_at: null
    }
  };
}

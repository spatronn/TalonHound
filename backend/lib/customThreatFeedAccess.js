import { ROLES } from './rbac.js';
import { CUSTOM_FEED_KEY_PREFIX } from './customThreatFeedUtils.js';

export function isCustomThreatFeedKey(feedKey) {
  return String(feedKey || '').trim().startsWith(CUSTOM_FEED_KEY_PREFIX);
}

export function isAdminRequest(req) {
  return String(req.user?.role || 'admin').trim().toLowerCase() === ROLES.ADMIN;
}

/** Custom feed settings mutations are admin-only; vendor feeds keep existing analyst write access. */
export function assertCustomFeedSettingsAllowed(req, feedKey, res) {
  if (!isCustomThreatFeedKey(feedKey)) return true;
  if (isAdminRequest(req)) return true;
  res.status(403).json({ message: 'Forbidden' });
  return false;
}

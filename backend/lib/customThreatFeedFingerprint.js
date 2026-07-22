import { createHash } from 'node:crypto';

/**
 * Canonical membership content fingerprint for Custom Threat Feeds.
 *
 * Includes only source-controlled fields that should drive last_changed_in_source.
 * Excludes run/presence noise (seenAt, feed id, import counters).
 */
export function computeCustomThreatFeedContentFingerprint({
  observable,
  observableType,
  confidence = null
} = {}) {
  const conf = confidence == null || confidence === ''
    ? null
    : String(confidence).trim().toLowerCase();
  const payload = JSON.stringify({
    provider: 'custom_threat_feed',
    observable: String(observable ?? ''),
    observable_type: String(observableType ?? '').toLowerCase(),
    confidence: conf && ['low', 'medium', 'high'].includes(conf) ? conf : null
  });
  return createHash('sha256').update(payload).digest('hex');
}

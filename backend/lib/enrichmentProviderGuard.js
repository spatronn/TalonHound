// Shared, process-local protection for enrichment provider calls.
//
// Two independent signals:
//
//   1. Provider cooldown — set by the canonical refresh functions (UI, REST and
//      automation alike) whenever a provider answers 429. Until it expires an
//      automated trigger does not spend another request on that provider.
//   2. Automation budget — a per-provider sliding window that bounds how many
//      provider operations automated triggers (MCP enrich_ioc / bulk_enrich_iocs)
//      may start per minute. Defaults come from the provider registry
//      (`automationRatePerMin`), overridable per provider with
//      ENRICHMENT_AUTOMATION_RATE_PER_MIN_<PROVIDER_KEY>. Human UI clicks are not
//      budgeted here (they are already human-paced and keep their behavior).

import { getEnrichmentProvider } from './enrichmentProviderRegistry.js';

const DEFAULT_COOLDOWN_MS = 60_000;
const MAX_COOLDOWN_MS = 15 * 60_000;
const WINDOW_MS = 60_000;

/** providerKey -> epoch ms until which the provider is cooling down */
const cooldowns = new Map();
/** providerKey -> start timestamps (ms) inside the current window */
const windows = new Map();

let nowFn = () => Date.now();

/**
 * Record a provider-side rate limit. `retryAfter` may be seconds (number/string)
 * from a Retry-After header; falls back to one minute, capped at 15 minutes.
 */
export function noteProviderRateLimited(providerKey, retryAfter = null) {
  const key = String(providerKey || '');
  if (!key) return;
  const secs = Number(retryAfter);
  const ms = Number.isFinite(secs) && secs > 0
    ? Math.min(secs * 1000, MAX_COOLDOWN_MS)
    : DEFAULT_COOLDOWN_MS;
  const until = nowFn() + ms;
  cooldowns.set(key, Math.max(cooldowns.get(key) || 0, until));
}

/** @returns {number} ms remaining in the provider cooldown (0 when none) */
export function providerCooldownRemainingMs(providerKey) {
  const until = cooldowns.get(String(providerKey || '')) || 0;
  const left = until - nowFn();
  if (left <= 0) {
    cooldowns.delete(String(providerKey || ''));
    return 0;
  }
  return left;
}

export function automationRatePerMin(providerKey, env = process.env) {
  const key = String(providerKey || '');
  const envName = `ENRICHMENT_AUTOMATION_RATE_PER_MIN_${key.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;
  const fromEnv = Number(env[envName]);
  if (Number.isFinite(fromEnv) && fromEnv >= 1) return Math.min(Math.trunc(fromEnv), 10_000);
  const fromRegistry = Number(getEnrichmentProvider(key)?.automationRatePerMin);
  return Number.isFinite(fromRegistry) && fromRegistry >= 1 ? Math.trunc(fromRegistry) : 10;
}

/**
 * Try to take one automation slot for the provider.
 * @returns {{ ok: true } | { ok: false, waitMs: number }}
 */
export function tryAcquireAutomationSlot(providerKey) {
  const key = String(providerKey || '');
  const now = nowFn();
  const limit = automationRatePerMin(key);
  const stamps = (windows.get(key) || []).filter((t) => now - t < WINDOW_MS);
  if (stamps.length >= limit) {
    windows.set(key, stamps);
    return { ok: false, waitMs: Math.max(1, WINDOW_MS - (now - stamps[0])) };
  }
  stamps.push(now);
  windows.set(key, stamps);
  return { ok: true };
}

/** Test helpers. */
export function resetEnrichmentProviderGuardForTests({ now } = {}) {
  cooldowns.clear();
  windows.clear();
  nowFn = typeof now === 'function' ? now : () => Date.now();
}

/**
 * Recovery of quarantined AI inference capacity (inferenceScheduler.js).
 *
 * A quarantined slot is released only by proof that the provider is idle (a
 * probe served promptly inside the slot) or by an audited administrator
 * release — never by time. Waiters probe while they wait; this module lets
 * the worker's safety net probe even when nobody is waiting (every analysis
 * failed fast with ai_capacity_quarantined), so a recovered provider frees
 * its capacity without manual action.
 */

import { getAiSettings } from '../store.js';
import { assertAiReady } from './settings.js';
import { resolveAiTimeoutPolicy, inferenceResourceKey } from './timeouts.js';
import { verifyProviderIdle } from './client.js';

function readySettings(settings) {
  if (!settings || settings.enabled !== true) return null;
  try {
    assertAiReady(settings);
    return settings;
  } catch {
    return null;
  }
}

/**
 * Probe one due quarantined slot of the configured provider endpoint.
 * @param {import('pg').Pool} pool
 * @param {{ snapshot: Function, verifyQuarantine: Function }} scheduler
 * @param {{ transport?: Function, policy?: object }} [deps]
 * @returns {Promise<'released'|'still_busy'|'none'|'not_configured'>}
 */
export async function probeQuarantinedCapacity(pool, scheduler, deps = {}) {
  const settings = readySettings(await getAiSettings(pool));
  if (!settings) return 'not_configured';
  const resourceKey = inferenceResourceKey(settings);
  const snap = await scheduler.snapshot(resourceKey);
  if (!snap.quarantined) return 'none';
  const policy = deps.policy || resolveAiTimeoutPolicy(settings);
  return scheduler.verifyQuarantine(resourceKey, () => verifyProviderIdle(settings, policy, deps.transport));
}

/**
 * Capacity view of the configured endpoint for the AI Settings page.
 * @param {object|null} settings threat_library_ai_settings row
 * @param {{ snapshot: Function }} scheduler
 */
export async function describeInferenceCapacity(settings, scheduler) {
  const ready = readySettings(settings);
  if (!ready) return null;
  const policy = resolveAiTimeoutPolicy(ready);
  const resourceKey = inferenceResourceKey(ready);
  const snap = await scheduler.snapshot(resourceKey);
  return {
    capacity: policy.max_concurrent_ai_requests,
    holding: snap.holding,
    waiting: snap.waiting,
    quarantined: snap.quarantined,
    unverified: snap.unverified,
    oldest_quarantined_at: snap.oldest_quarantined_at
  };
}

/**
 * Administrator release of every quarantined slot of the configured endpoint.
 * @param {object|null} settings
 * @param {{ releaseQuarantined: Function }} scheduler
 */
export async function releaseQuarantinedCapacity(settings, scheduler) {
  const ready = readySettings(settings);
  if (!ready) return { released: 0, resource_key: null };
  const resourceKey = inferenceResourceKey(ready);
  return { released: await scheduler.releaseQuarantined(resourceKey), resource_key: resourceKey };
}

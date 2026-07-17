/**
 * Import-scoped caches and deferred IOC recompute batching (reduces PG churn).
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { buildSuppressionIndex, isPairSuppressed } from './ioc-suppression.js';

const importContextStorage = new AsyncLocalStorage();

export function getImportOptimizationContext() {
  return importContextStorage.getStore() || null;
}

function policyCacheKey(feedId, observableType) {
  return `${String(feedId)}:${String(observableType || 'all')}`;
}

/** Mirrors getFeedPolicy SQL precedence (specific observable_type over 'all'). */
export function pickFeedPolicyFromRows(rows, feedId, observableType = 'all') {
  const feedIdStr = String(feedId);
  const type = String(observableType || 'all');
  const matches = (rows || []).filter(
    (r) => String(r.feed_id) === feedIdStr
      && (String(r.observable_type) === type || String(r.observable_type) === 'all')
  );
  if (!matches.length) return null;
  matches.sort((a, b) => {
    const aSpec = String(a.observable_type) === type ? 0 : 1;
    const bSpec = String(b.observable_type) === type ? 0 : 1;
    return aSpec - bSpec;
  });
  return matches[0];
}

export async function loadAllFeedPolicies(client) {
  const { rows } = await client.query('SELECT * FROM threat_feed_expiration_policies');
  return rows || [];
}

export async function loadAllExpirationTypePolicies(client) {
  const { rows } = await client.query(
    'SELECT feed_id, ioc_type, mode, ttl_days FROM integration_feed_expiration_type_policies'
  );
  return rows || [];
}

/** Find the type override row for a feed + normalized policy IOC type. */
export function pickTypePolicyFromRows(rows, feedId, policyType) {
  if (!policyType) return null;
  const feedIdStr = String(feedId);
  return (rows || []).find(
    (r) => String(r.feed_id) === feedIdStr && String(r.ioc_type) === policyType
  ) || null;
}

export async function loadActiveSuppressionIndex(client) {
  const { rows } = await client.query(
    `SELECT lower(ioc_value) AS ioc_value,
            lower(ioc_type) AS ioc_type,
            scope,
            lower(source_name) AS source_name
     FROM ioc_suppressions
     WHERE active = TRUE
       AND deleted_at IS NULL
       AND (expires_at IS NULL OR expires_at > NOW())`
  );
  return buildSuppressionIndex(rows || []);
}

export function isIocSuppressedFromIndex(index, observable, observableType) {
  if (!index?.size) return false;
  const hit = isPairSuppressed(index, { iocValue: observable, iocType: observableType });
  return Boolean(hit?.suppressed);
}

export async function createImportOptimizationContext(client) {
  const [policyRows, typePolicyRows, suppressionIndex] = await Promise.all([
    loadAllFeedPolicies(client),
    loadAllExpirationTypePolicies(client),
    loadActiveSuppressionIndex(client)
  ]);

  return {
    policyRows,
    typePolicyRows,
    suppressionIndex,
    deferredRecomputes: new Map()
  };
}

export function resolveTypePolicyFromContext(ctx, feedId, policyType) {
  if (!ctx || !policyType) return null;
  if (!ctx._typePolicyByKey) ctx._typePolicyByKey = new Map();
  const key = `${String(feedId)}:${policyType}`;
  if (ctx._typePolicyByKey.has(key)) return ctx._typePolicyByKey.get(key);
  const row = pickTypePolicyFromRows(ctx.typePolicyRows, feedId, policyType);
  ctx._typePolicyByKey.set(key, row);
  return row;
}

export function resolveFeedPolicyFromContext(ctx, feedId, observableType = 'all') {
  if (!ctx?.policyRows) return undefined;
  if (!ctx._policyByKey) ctx._policyByKey = new Map();
  const key = policyCacheKey(feedId, observableType);
  if (ctx._policyByKey.has(key)) return ctx._policyByKey.get(key);
  const policy = pickFeedPolicyFromRows(ctx.policyRows, feedId, observableType);
  ctx._policyByKey.set(key, policy);
  return policy;
}

export function scheduleDeferredIocRecompute(ctx, { iocItemId, observableType, audit = null, actor = null }) {
  if (!ctx?.deferredRecomputes || !iocItemId || !observableType) return;
  const key = `${observableType}|${iocItemId}`;
  const prev = ctx.deferredRecomputes.get(key);
  ctx.deferredRecomputes.set(key, {
    iocItemId,
    observableType,
    audit: audit || prev?.audit || null,
    actor: actor || prev?.actor || { actor_type: 'feed_import', source: 'integration' }
  });
}

export function runWithImportOptimizationContext(ctx, fn) {
  return importContextStorage.run(ctx, fn);
}

export function enterImportOptimizationContext(ctx, fn) {
  const active = getImportOptimizationContext();
  if (active) return fn();
  return importContextStorage.run(ctx, fn);
}

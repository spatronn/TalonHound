// Read-only Enrichment Usage analytics API.
//
//   GET /api/enrichment-usage?range=&from=&to=&provider=&iocType=
//
// Auth: none added here on purpose. The global apiAuthGate authenticates and
// rbacHttpPolicy already allows GET/HEAD for every authenticated role (readonly
// included) — matching the existing Enrichment Providers read behavior. Adding a
// requireRole here would REGRESS readonly access, so we intentionally do not.
//
// Data source: only the pre-aggregated enrichment_usage_daily table. A small, fixed
// number of grouped queries per request (provider breakdown + series + type
// breakdown + collection start), plus bounded provider-state lookups from the
// registry. No scans of ioc_items / ioc_enrichments / audit_logs; no per-provider
// N+1 over usage data.

import { createServiceLogger } from '../lib/appLogger.js';
import { listEnrichmentProviders } from '../lib/enrichmentProviderRegistry.js';
import {
  parseUsageQuery,
  buildProviderBreakdownQuery,
  buildSeriesQuery,
  buildTypeBreakdownQuery,
  buildCollectionStartQuery,
  summarizeProviderRows,
  shapeProviderBreakdown,
  shapeTypeBreakdown,
  shapeSeries,
  normalizeProviderQuota,
  MAX_RANGE_DAYS
} from '../lib/enrichmentUsageQuery.js';

const logger = createServiceLogger('enrichment-usage-api');

/**
 * Resolve the provider registry into display + live enabled/configured state + any
 * configured quota. Bounded (one entry per registered provider). Each provider's
 * state loader and quota lookup is guarded so a single provider failure degrades to
 * "state unknown" instead of failing the whole page.
 * @returns {Promise<Array<{key,displayName,enabled,configured,quota}>>}
 */
export async function buildProviderRegistryState(pool) {
  const entries = listEnrichmentProviders();

  // Single query for all configured quotas (future: config->'quota').
  const quotaByProvider = new Map();
  try {
    const { rows } = await pool.query('SELECT provider, config FROM threat_intel_provider_configs');
    for (const row of rows || []) {
      const cfg = row?.config && typeof row.config === 'object' ? row.config : null;
      quotaByProvider.set(String(row.provider), normalizeProviderQuota(cfg?.quota));
    }
  } catch (err) {
    logger.warn('failed to load provider quota config', { error: String(err?.message || err) });
  }

  const resolved = await Promise.all(entries.map(async (entry) => {
    let enabled = null;
    let configured = null;
    try {
      const state = await entry.loadState(pool);
      enabled = state?.enabled !== false;
      configured = state?.configured !== false;
    } catch (err) {
      logger.warn('failed to load provider state', { provider: entry.key, error: String(err?.message || err) });
    }
    return {
      key: entry.key,
      displayName: entry.displayName || entry.key,
      enabled,
      configured,
      quota: quotaByProvider.get(entry.key) || null
    };
  }));
  return resolved;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 */
export function registerEnrichmentUsageRoutes(app, pool) {
  app.get('/api/enrichment-usage', async (req, res) => {
    try {
      // Resolve provider state and "today" together. `today` comes from the DB
      // session (SELECT CURRENT_DATE), so it is expressed in the canonical System
      // Timezone the pool runs in — the exact same clock the telemetry write buckets
      // on (CURRENT_DATE). This keeps write, read-range, and (via the returned range)
      // the frontend all anchored to the same system-tz "today".
      const [registry, todayRes] = await Promise.all([
        buildProviderRegistryState(pool),
        pool.query('SELECT CURRENT_DATE::text AS today')
      ]);
      const knownProviders = registry.map((p) => p.key);
      const today = todayRes.rows?.[0]?.today || null;

      const parsed = parseUsageQuery(req.query || {}, { knownProviders, today });
      if (!parsed.ok) {
        return res.status(parsed.status || 400).json({ error: parsed.error, message: parsed.error });
      }
      const { from, to, preset, provider, iocType } = parsed.params;

      const providerQ = buildProviderBreakdownQuery({ from, to, iocType });
      const seriesQ = buildSeriesQuery({ from, to, provider, iocType });
      const typeQ = buildTypeBreakdownQuery({ from, to, provider });
      const startQ = buildCollectionStartQuery();

      const [providerRes, seriesRes, typeRes, startRes] = await Promise.all([
        pool.query(providerQ.sql, providerQ.params),
        pool.query(seriesQ.sql, seriesQ.params),
        pool.query(typeQ.sql, typeQ.params),
        pool.query(startQ.sql, startQ.params)
      ]);

      // Provider breakdown is filtered by ioc type only; when a provider filter is
      // active the summary must reflect just that provider, so summarize the filtered
      // subset while still returning the full breakdown for the table.
      const providerRows = providerRes.rows || [];
      const summaryRows = provider
        ? providerRows.filter((r) => String(r.provider_key) === provider)
        : providerRows;

      const providers = shapeProviderBreakdown(providerRows, registry);
      const providersForResponse = provider
        ? providers.filter((p) => p.provider_key === provider)
        : providers;

      return res.json({
        range: { from, to, preset, max_days: MAX_RANGE_DAYS },
        filters: { provider: provider || null, ioc_type: iocType || null },
        collection_started_on: startRes.rows?.[0]?.started_on || null,
        summary: summarizeProviderRows(summaryRows),
        series: shapeSeries(seriesRes.rows || []),
        providers: providersForResponse,
        ioc_types: shapeTypeBreakdown(typeRes.rows || [])
      });
    } catch (err) {
      logger.error?.('enrichment usage query failed', { error: String(err?.message || err) });
      return res.status(500).json({ error: 'Failed to load enrichment usage', message: 'Failed to load enrichment usage' });
    }
  });
}

import { SPAMHAUS_DROP_PROVIDER } from '../lib/spamhausDropSync.js';

/**
 * @param {import('pg').Pool} pool
 * @param {string} lookupIp
 */
export async function getSpamhausDropEnrichmentByIp(pool, lookupIp) {
  const ip = String(lookupIp || '').trim();
  if (!ip) return null;
  const { rows } = await pool.query(
    `SELECT * FROM ioc_spamhaus_drop_enrichment WHERE lookup_ip = $1 LIMIT 1`,
    [ip]
  );
  return rows[0] || null;
}

/**
 * Persist a completed Spamhaus DROP IOC lookup (listed / not_listed / failed).
 * @param {import('pg').Pool} pool
 * @param {object} record
 */
export async function upsertSpamhausDropEnrichment(pool, record) {
  const now = new Date().toISOString();
  const status = String(record.provider_status || 'failed');
  const persistable = status === 'listed' || status === 'not_listed' || status === 'failed';
  if (!persistable) {
    return null;
  }

  const listed = status === 'listed' ? true : (status === 'not_listed' ? false : null);
  const { rows } = await pool.query(
    `INSERT INTO ioc_spamhaus_drop_enrichment (
       lookup_ip, lookup_type, observable_value, ioc_type,
       provider_status, listed, matched_cidr, list_type, sblid, rir,
       dataset_status, last_sync_at, error_code, error_message, raw_json,
       enriched_at, last_attempt_at
     ) VALUES (
       $1, 'ip', $2, $3,
       $4, $5, $6, $7, $8, $9,
       $10, $11::timestamptz, $12, $13, $14::jsonb,
       $15::timestamptz, $16::timestamptz
     )
     ON CONFLICT (lookup_ip) DO UPDATE SET
       observable_value = EXCLUDED.observable_value,
       ioc_type = EXCLUDED.ioc_type,
       provider_status = EXCLUDED.provider_status,
       listed = EXCLUDED.listed,
       matched_cidr = EXCLUDED.matched_cidr,
       list_type = EXCLUDED.list_type,
       sblid = EXCLUDED.sblid,
       rir = EXCLUDED.rir,
       dataset_status = EXCLUDED.dataset_status,
       last_sync_at = EXCLUDED.last_sync_at,
       error_code = EXCLUDED.error_code,
       error_message = EXCLUDED.error_message,
       raw_json = EXCLUDED.raw_json,
       enriched_at = EXCLUDED.enriched_at,
       last_attempt_at = EXCLUDED.last_attempt_at,
       updated_at = NOW()
     RETURNING *`,
    [
      String(record.lookup_ip).trim(),
      record.observable_value || null,
      record.ioc_type || null,
      status,
      listed,
      record.matched_cidr || null,
      record.list_type || null,
      record.sblid || null,
      record.rir || null,
      record.dataset_status || null,
      record.last_sync_at || null,
      record.error_code || null,
      record.error_message || null,
      record.raw_json != null ? JSON.stringify(record.raw_json) : null,
      status === 'failed' ? null : now,
      now
    ]
  );
  return rows[0] || null;
}

/**
 * Map a persisted row to the same shape as live lookup responses.
 * @param {object|null} row
 * @param {{ providerDisabled?: boolean }} [opts]
 */
export function rowToSpamhausApiPayload(row, opts = {}) {
  if (opts.providerDisabled) {
    return { provider: SPAMHAUS_DROP_PROVIDER, status: 'disabled', listed: null };
  }
  if (!row) {
    return { provider: SPAMHAUS_DROP_PROVIDER, status: 'not_run', listed: null };
  }

  const status = String(row.provider_status || 'failed');
  if (status === 'failed') {
    return {
      provider: SPAMHAUS_DROP_PROVIDER,
      status: 'error',
      listed: null,
      target_ip: row.lookup_ip || null,
      error_message: row.error_message || 'Spamhaus DROP lookup failed',
      last_enriched_at: row.last_attempt_at || row.enriched_at || null
    };
  }

  const base = {
    provider: SPAMHAUS_DROP_PROVIDER,
    status,
    listed: row.listed,
    target_ip: row.lookup_ip || null,
    last_sync_at: row.last_sync_at || null,
    dataset_status: row.dataset_status || null,
    last_enriched_at: row.enriched_at || row.last_attempt_at || null
  };

  if (status === 'listed') {
    return {
      ...base,
      listed: true,
      matched_cidr: row.matched_cidr || null,
      sblid: row.sblid || null,
      rir: row.rir || null,
      list_type: row.list_type || null
    };
  }

  return {
    ...base,
    listed: false
  };
}

/**
 * Upsert from a live buildSpamhausLookupResponse payload.
 */
export async function persistSpamhausLookupResult(pool, {
  targetIp,
  iocValue,
  iocType,
  response
}) {
  const status = String(response?.status || '');
  if (status !== 'listed' && status !== 'not_listed' && status !== 'error' && status !== 'failed') {
    return null;
  }
  const providerStatus = (status === 'error' || status === 'failed') ? 'failed' : status;
  return upsertSpamhausDropEnrichment(pool, {
    lookup_ip: targetIp,
    observable_value: iocValue,
    ioc_type: iocType,
    provider_status: providerStatus,
    matched_cidr: response.matched_cidr,
    list_type: response.list_type,
    sblid: response.sblid,
    rir: response.rir,
    dataset_status: response.dataset_status,
    last_sync_at: response.last_sync_at,
    error_message: response.error_message || response.message || null,
    raw_json: response
  });
}

/** System IOC source used exclusively by the REST API create path. */

export const API_SYSTEM_SOURCE_NAME = 'API';

/**
 * Resolve the durable system "API" IOC source row.
 * @param {import('pg').Pool} pool
 * @returns {Promise<{ id: number, name: string, default_confidence: string|null, default_threat_classification: string|null, default_expire_policy: string|null, default_expire_days: number|null, active: boolean, archived_at: Date|null }>}
 */
export async function resolveApiSystemSource(pool) {
  const { rows } = await pool.query(
    `SELECT id, name, default_confidence, default_threat_classification,
            default_expire_policy, default_expire_days, active, archived_at
     FROM ioc_sources
     WHERE name = $1
     LIMIT 1`,
    [API_SYSTEM_SOURCE_NAME]
  );
  const row = rows[0];
  if (!row) {
    const err = new Error('System API IOC source is missing; run migrations');
    err.code = 'API_SYSTEM_SOURCE_MISSING';
    throw err;
  }
  if (row.active === false || row.archived_at) {
    const err = new Error('System API IOC source is inactive');
    err.code = 'API_SYSTEM_SOURCE_INACTIVE';
    throw err;
  }
  return row;
}

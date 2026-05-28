import pg from 'pg';
import { config } from '../config.js';

const LOG_PREFIX = '[integration-worker]';

function formatPgTimeoutMs(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return '0';
  return `${Math.floor(n)}ms`;
}

export function buildPgSessionSettings(dbConfig = config.db) {
  return {
    application_name: dbConfig.application_name || 'integration-worker',
    statement_timeout: formatPgTimeoutMs(dbConfig.statement_timeout ?? 120000),
    lock_timeout: formatPgTimeoutMs(dbConfig.lock_timeout ?? 5000),
    idle_in_transaction_session_timeout: formatPgTimeoutMs(
      dbConfig.idle_in_transaction_session_timeout ?? 120000
    )
  };
}

export async function applyPgSessionSettings(client, dbConfig = config.db) {
  const settings = buildPgSessionSettings(dbConfig);
  await client.query(
    `SELECT
       set_config('application_name', $1, false),
       set_config('statement_timeout', $2, false),
       set_config('lock_timeout', $3, false),
       set_config('idle_in_transaction_session_timeout', $4, false)`,
    [
      settings.application_name,
      settings.statement_timeout,
      settings.lock_timeout,
      settings.idle_in_transaction_session_timeout
    ]
  );
  return settings;
}

export function createIntegrationPool(dbConfig = config.db) {
  const pool = new pg.Pool(dbConfig);
  pool.on('connect', (client) => {
    applyPgSessionSettings(client, dbConfig).catch((err) => {
      console.error(
        `${LOG_PREFIX} Failed to apply PG session settings message=${err?.message || err}`
      );
    });
  });
  return pool;
}

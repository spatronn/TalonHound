import pg from 'pg';
import { config } from '../config.js';

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

/**
 * Create a PG pool with session guard rails applied at connection startup.
 * Avoids pool.on('connect') async SET — that races with pg checkout and breaks clients.
 */
export function createIntegrationPool(dbConfig = config.db) {
  const settings = buildPgSessionSettings(dbConfig);
  const {
    idle_in_transaction_session_timeout: _idle,
    application_name: _app,
    statement_timeout: stmtMs,
    lock_timeout: lockMs,
    ...rest
  } = dbConfig;

  return new pg.Pool({
    ...rest,
    application_name: settings.application_name,
    statement_timeout: Number(stmtMs ?? 120000),
    lock_timeout: Number(lockMs ?? 5000),
    // Fail fast under pool starvation instead of waiting forever (pg default 0).
    connectionTimeoutMillis: Math.max(Number(dbConfig.connectionTimeoutMillis || 10000), 1000),
    options: [
      `-c idle_in_transaction_session_timeout=${settings.idle_in_transaction_session_timeout}`,
      `-c statement_timeout=${settings.statement_timeout}`,
      `-c lock_timeout=${settings.lock_timeout}`
    ].join(' ')
  });
}

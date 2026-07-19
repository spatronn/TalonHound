import './ensure-db-password.js';
import { getRedisUrl } from './redis-url.js';

export const config = {
  redisUrl: getRedisUrl(),
  queueName: process.env.QUEUE_NAME || 'integration-imports',
  schedulerCron: process.env.SCHEDULER_CRON || '0 * * * *',
  db: {
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'demo',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'demo',
    application_name: process.env.PG_APPLICATION_NAME || 'integration-worker',
    statement_timeout: Number(process.env.PG_STATEMENT_TIMEOUT_MS || 120000),
    lock_timeout: Number(process.env.PG_LOCK_TIMEOUT_MS || 5000),
    idle_in_transaction_session_timeout: Number(process.env.PG_IDLE_IN_TX_TIMEOUT_MS || 120000)
  },
  sourceName: process.env.SOURCE_NAME || 'EmergingThreats:blockrules',
  sourceIndexUrl: process.env.SOURCE_INDEX_URL || 'http://rules.emergingthreats.net/blockrules/',
  // USOM:TR-CERT is a stable database identity, not a display label.
  usomSourceName: 'USOM:TR-CERT',
  usomApiBaseUrl: process.env.USOM_API_BASE_URL || 'https://siberguvenlik.gov.tr/api',
  usomApiPerPage: Number(process.env.USOM_API_PER_PAGE || 5000),
  usomApiTimeoutMs: Number(process.env.USOM_API_TIMEOUT_MS || 30000),
  usomApiMaxRetries: Number(process.env.USOM_API_MAX_RETRIES || 5),
  usomApiRequestDelayMs: Number(process.env.USOM_API_REQUEST_DELAY_MS || 250),
  usomImportMode: process.env.USOM_IMPORT_MODE || 'incremental',
  usomIncrementalEnabled: !['0', 'false', 'no', 'off'].includes(
    String(process.env.USOM_INCREMENTAL_ENABLED || 'true').trim().toLowerCase()
  ),
  usomCursorOverlapHours: Number(
    process.env.USOM_INCREMENTAL_OVERLAP_HOURS
      || process.env.USOM_CURSOR_OVERLAP_HOURS
      || 24
  ),
  usomIncrementalMaxRecords: Number(process.env.USOM_INCREMENTAL_MAX_RECORDS || 100000),
  usomLookupCacheTtlHours: Number(process.env.USOM_LOOKUP_CACHE_TTL_HOURS || 24),
  usomDbStatementTimeoutMs: Number(process.env.USOM_DB_STATEMENT_TIMEOUT_MS || 1800000),
  usomDbIdleInTxTimeoutMs: Number(process.env.USOM_DB_IDLE_IN_TX_TIMEOUT_MS || 600000),
  urlhausSourceName: process.env.URLHAUS_SOURCE_NAME || 'URLhaus:abuse.ch',
  urlhausAuthKey: process.env.URLHAUS_AUTH_KEY || '',
  threatfoxSourceName: process.env.THREATFOX_SOURCE_NAME || 'ThreatFox:abuse.ch',
  threatfoxAuthKey: process.env.THREATFOX_AUTH_KEY || '',
  threatfoxApiUrl: process.env.THREATFOX_API_URL || 'https://threatfox-api.abuse.ch/api/v1/',
  threatfoxRecentDays: process.env.THREATFOX_RECENT_DAYS || '3',
  malwareBazaarSourceName: process.env.MALWARE_BAZAAR_SOURCE_NAME || 'MalwareBazaar:abuse.ch',
  malwareBazaarAuthKey: process.env.MALWAREBAZAAR_AUTH_KEY || '',
  phishTankSourceName: process.env.PHISHTANK_SOURCE_NAME || 'PhishTank:open_dnsrr',
  phishTankCsvUrl: process.env.PHISHTANK_CSV_URL || 'https://data.phishtank.com/data/online-valid.csv',
  alienvaultOtxSourceName: process.env.ALIENVAULT_OTX_SOURCE_NAME || 'AlienVault OTX',
  alienvaultOtxApiBase: process.env.ALIENVAULT_OTX_API_BASE || 'https://otx.alienvault.com',
  alienvaultOtxApiKey: process.env.ALIENVAULT_OTX_API_KEY || '',
  alienvaultOtxPageLimit: Number(process.env.ALIENVAULT_OTX_PAGE_LIMIT || 50),
  alienvaultOtxInitialLookbackDays: Number(process.env.OTX_INITIAL_LOOKBACK_DAYS || 30),
  alienvaultOtxMaxPagesPerRun: Number(process.env.OTX_MAX_PAGES_PER_RUN || 200)
};

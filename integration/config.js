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
  usomSourceName: process.env.USOM_SOURCE_NAME || 'USOM:TR-CERT',
  usomApiUrl: process.env.USOM_API_URL || 'https://www.usom.gov.tr/url-list.txt',
  urlhausSourceName: process.env.URLHAUS_SOURCE_NAME || 'URLhaus:abuse.ch',
  urlhausAuthKey: process.env.URLHAUS_AUTH_KEY || '',
  threatfoxSourceName: process.env.THREATFOX_SOURCE_NAME || 'ThreatFox:abuse.ch',
  threatfoxAuthKey: process.env.THREATFOX_AUTH_KEY || '',
  threatfoxApiUrl: process.env.THREATFOX_API_URL || 'https://threatfox-api.abuse.ch/api/v1/',
  threatfoxRecentDays: process.env.THREATFOX_RECENT_DAYS || '3',
  malwareBazaarSourceName: process.env.MALWARE_BAZAAR_SOURCE_NAME || 'MalwareBazaar:abuse.ch',
  malwareBazaarAuthKey: process.env.MALWAREBAZAAR_AUTH_KEY || '',
  phishTankSourceName: process.env.PHISHTANK_SOURCE_NAME || 'PhishTank:open_dnsrr',
  phishTankCsvUrl: process.env.PHISHTANK_CSV_URL || 'https://data.phishtank.com/data/online-valid.csv'
};

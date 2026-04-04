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
    database: process.env.DB_NAME || 'demo'
  },
  sourceName: process.env.SOURCE_NAME || 'EmergingThreats:blockrules',
  sourceIndexUrl: process.env.SOURCE_INDEX_URL || 'http://rules.emergingthreats.net/blockrules/',
  usomSourceName: process.env.USOM_SOURCE_NAME || 'USOM:TR-CERT',
  usomApiUrl: process.env.USOM_API_URL || 'https://www.usom.gov.tr/url-list.txt',
  urlhausSourceName: process.env.URLHAUS_SOURCE_NAME || 'URLhaus:abuse.ch',
  urlhausUrl: process.env.URLHAUS_URL || 'https://urlhaus.abuse.ch/downloads/text/',
  threatfoxSourceName: process.env.THREATFOX_SOURCE_NAME || 'ThreatFox:abuse.ch',
  threatfoxCsvUrl: process.env.THREATFOX_CSV_URL || 'https://threatfox.abuse.ch/export/csv/full/',
  malwareBazaarSourceName: process.env.MALWARE_BAZAAR_SOURCE_NAME || 'MalwareBazaar:abuse.ch',
  malwareBazaarCsvUrl: process.env.MALWARE_BAZAAR_CSV_URL || 'https://bazaar.abuse.ch/export/csv/full/',
  phishTankSourceName: process.env.PHISHTANK_SOURCE_NAME || 'PhishTank:open_dnsrr',
  phishTankCsvUrl: process.env.PHISHTANK_CSV_URL || 'https://data.phishtank.com/data/online-valid.csv'
};

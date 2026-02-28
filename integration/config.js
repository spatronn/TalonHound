export const config = {
  redisUrl: process.env.REDIS_URL || 'redis://redis:6379',
  queueName: process.env.QUEUE_NAME || 'integration-imports',
  schedulerCron: process.env.SCHEDULER_CRON || '0 * * * *',
  db: {
    host: process.env.DB_HOST || 'db',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'demo',
    password: process.env.DB_PASSWORD || 'demo123',
    database: process.env.DB_NAME || 'demo'
  },
  sourceName: process.env.SOURCE_NAME || 'EmergingThreats:blockrules',
  sourceIndexUrl: process.env.SOURCE_INDEX_URL || 'http://rules.emergingthreats.net/blockrules/'
};

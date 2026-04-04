const isProduction = process.env.NODE_ENV === 'production';
const logStorage = (process.env.LOG_STORAGE || 'postgres').toLowerCase();
const needsClickhouse = logStorage === 'clickhouse';

if (needsClickhouse && !process.env.CLICKHOUSE_PASSWORD) {
  if (isProduction) {
    throw new Error('CLICKHOUSE_PASSWORD is required when LOG_STORAGE is clickhouse');
  }
  console.warn('[config] WARNING: CLICKHOUSE_PASSWORD is not set; ClickHouse connections may fail.');
}

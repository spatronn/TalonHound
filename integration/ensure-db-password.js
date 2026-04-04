const isProduction = process.env.NODE_ENV === 'production';

if (!process.env.DB_PASSWORD) {
  if (isProduction) {
    throw new Error('DB_PASSWORD is required');
  }
  console.warn('[config] WARNING: DB_PASSWORD is not set; PostgreSQL connections may fail.');
}

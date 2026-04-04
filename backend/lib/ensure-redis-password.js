const isProduction = process.env.NODE_ENV === 'production';
const hasLegacyUrl = Boolean(process.env.REDIS_URL?.trim());

if (!hasLegacyUrl && !process.env.REDIS_PASSWORD) {
  if (isProduction) {
    throw new Error('REDIS_PASSWORD is required (or set REDIS_URL with credentials)');
  }
  console.warn('[config] REDIS_PASSWORD not set; using dev-insecure-redis (align with compose default)');
  process.env.REDIS_PASSWORD = 'dev-insecure-redis';
}

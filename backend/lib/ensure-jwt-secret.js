const isProduction = process.env.NODE_ENV === 'production';

if (!process.env.JWT_SECRET) {
  if (isProduction) {
    throw new Error('JWT_SECRET is required');
  }
  console.warn('[config] JWT_SECRET not set; using insecure dev default (set JWT_SECRET for real use)');
  process.env.JWT_SECRET = 'dev-insecure-jwt-secret';
}

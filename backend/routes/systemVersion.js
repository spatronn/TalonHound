import { getProductVersionInfo } from '../lib/productVersion.js';

/**
 * @param {import('express').Express} app
 */
export function registerSystemVersionRoutes(app) {
  app.get('/api/system/version', (_req, res) => {
    return res.json(getProductVersionInfo());
  });
}

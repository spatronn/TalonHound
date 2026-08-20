import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import express from 'express';
import { buildOpenApiDocument } from '../lib/openapiDocument.js';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Absolute path to TalonHound Swagger UI theme overrides (not from swagger-ui-dist). */
export function getTalonhoundSwaggerThemePath() {
  return path.resolve(__dirname, '../assets/api-docs/swagger-ui-talonhound.css');
}

/**
 * Short cache-busting token for the theme file. The link is served with a long
 * max-age, so without a version query browsers keep a stale theme after a deploy.
 * Derived from size+mtime so it changes exactly when the file does; falls back to
 * a timestamp if the file can't be stat-ed.
 */
export function getThemeAssetVersion(themePath = getTalonhoundSwaggerThemePath()) {
  try {
    const s = fs.statSync(themePath);
    return crypto.createHash('sha1').update(`${s.size}-${s.mtimeMs}`).digest('hex').slice(0, 10);
  } catch {
    return String(Date.now());
  }
}

/** Absolute directory for locally installed swagger-ui-dist assets. */
export function getSwaggerUiDistPath() {
  return path.dirname(require.resolve('swagger-ui-dist/package.json'));
}

/**
 * Self-contained docs HTML — all JS/CSS/favicon URLs are same-origin under /api/docs/static/.
 * No CDN / unpkg / Google Fonts references.
 */
export function buildApiDocsHtml(themeVersion = '') {
  const themeQuery = themeVersion ? `?v=${encodeURIComponent(themeVersion)}` : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TalonHound API Documentation</title>
  <link rel="icon" type="image/png" href="/api/docs/static/favicon-32x32.png" sizes="32x32" />
  <link rel="icon" type="image/png" href="/api/docs/static/favicon-16x16.png" sizes="16x16" />
  <link rel="stylesheet" href="/api/docs/static/swagger-ui.css" />
  <link rel="stylesheet" href="/api/docs/static/talonhound.css${themeQuery}" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/api/docs/static/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: '/api/openapi.json',
      dom_id: '#swagger-ui',
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis],
      layout: 'BaseLayout'
    });
  </script>
</body>
</html>`;
}

/** True when HTML (or other text) still points at known external CDN hosts. */
export function hasExternalCdnReferences(html) {
  const text = String(html || '');
  return /https?:\/\/(?:unpkg\.com|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|fonts\.googleapis\.com|fonts\.gstatic\.com)/i.test(text);
}

/**
 * OpenAPI contract + locally served Swagger UI (offline-capable).
 * @param {import('express').Express} app
 */
export function registerApiDocsRoutes(app) {
  const distPath = getSwaggerUiDistPath();
  const themePath = getTalonhoundSwaggerThemePath();

  // Theme override must win over swagger-ui-dist filenames; register before static.
  app.get('/api/docs/static/talonhound.css', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=86400');
    res.type('css');
    return res.sendFile(themePath);
  });

  // Only expose the dist bundle directory; do not enable directory listing or path escape.
  app.use(
    '/api/docs/static',
    express.static(distPath, {
      fallthrough: false,
      index: false,
      dotfiles: 'deny',
      maxAge: '1d'
    })
  );

  app.get('/api/openapi.json', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=60');
    return res.json(buildOpenApiDocument());
  });

  app.get('/api/docs', (_req, res) => {
    const html = buildApiDocsHtml(getThemeAssetVersion(themePath));
    res.set('Cache-Control', 'public, max-age=60');
    res.type('html');
    return res.send(html);
  });
}

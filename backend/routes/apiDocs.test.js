import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import {
  registerApiDocsRoutes,
  buildApiDocsHtml,
  hasExternalCdnReferences,
  getSwaggerUiDistPath,
  getTalonhoundSwaggerThemePath
} from './apiDocs.js';
import { buildOpenApiDocument } from '../lib/openapiDocument.js';

function makeApp() {
  const app = express();
  registerApiDocsRoutes(app);
  return app;
}

async function http(app, method, urlPath) {
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}${urlPath}`, { method });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* html/binary */ }
    return { status: res.status, text, json, headers: res.headers };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test('buildApiDocsHtml has no external CDN references', () => {
  const html = buildApiDocsHtml();
  assert.equal(hasExternalCdnReferences(html), false);
  assert.doesNotMatch(html, /https?:\/\//i);
  assert.match(html, /\/api\/docs\/static\/swagger-ui\.css/);
  assert.match(html, /\/api\/docs\/static\/talonhound\.css/);
  assert.match(html, /\/api\/docs\/static\/swagger-ui-bundle\.js/);
  assert.match(html, /url:\s*'\/api\/openapi\.json'/);
  // Theme override must load after stock Swagger CSS.
  assert.ok(
    html.indexOf('/api/docs/static/swagger-ui.css') < html.indexOf('/api/docs/static/talonhound.css')
  );
});

test('GET /api/docs returns 200 with local asset references only', async () => {
  const res = await http(makeApp(), 'GET', '/api/docs');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') || '', /html/i);
  assert.equal(hasExternalCdnReferences(res.text), false);
  assert.doesNotMatch(res.text, /unpkg\.com|jsdelivr|cdnjs|fonts\.googleapis/i);
  assert.match(res.text, /\/api\/docs\/static\/talonhound\.css/);
});

test('local Swagger UI static assets are reachable', async () => {
  const app = makeApp();
  const css = await http(app, 'GET', '/api/docs/static/swagger-ui.css');
  assert.equal(css.status, 200);
  assert.ok(css.text.includes('{') || css.text.length > 100);

  const theme = await http(app, 'GET', '/api/docs/static/talonhound.css');
  assert.equal(theme.status, 200);
  assert.match(theme.headers.get('content-type') || '', /css/i);
  assert.match(theme.text, /--th-bg/);
  assert.match(theme.text, /\.scheme-container/);
  assert.equal(hasExternalCdnReferences(theme.text), false);
  assert.doesNotMatch(theme.text, /https?:\/\//i);

  const js = await http(app, 'GET', '/api/docs/static/swagger-ui-bundle.js');
  assert.equal(js.status, 200);
  assert.match(js.text, /SwaggerUIBundle/);

  const fav = await http(app, 'GET', '/api/docs/static/favicon-32x32.png');
  assert.equal(fav.status, 200);
});

test('TalonHound Swagger theme file exists outside node_modules', () => {
  const themePath = getTalonhoundSwaggerThemePath();
  assert.ok(fs.existsSync(themePath));
  assert.doesNotMatch(themePath.replace(/\\/g, '/'), /node_modules\//);
});

test('swagger-ui-dist resolves from node_modules (offline package)', () => {
  const dist = getSwaggerUiDistPath();
  assert.ok(fs.existsSync(path.join(dist, 'swagger-ui-bundle.js')));
  assert.ok(fs.existsSync(path.join(dist, 'swagger-ui.css')));
  assert.match(dist.replace(/\\/g, '/'), /node_modules\/swagger-ui-dist$/);
});

test('GET /api/openapi.json returns valid OpenAPI 3.1', async () => {
  const res = await http(makeApp(), 'GET', '/api/openapi.json');
  assert.equal(res.status, 200);
  assert.equal(res.json.openapi, '3.1.0');
  assert.ok(res.json.paths['/api/v1/iocs']?.post);
  assert.ok(res.json.paths['/api/v1/iocs']?.get);
  assert.ok(res.json.paths['/api/v1/iocs/{id}']?.patch);
  assert.ok(res.json.paths['/api/v1/iocs/{id}']?.get);
  assert.ok(res.json.paths['/api/v1/iocs/search']?.post);
  assert.ok(res.json.paths['/api/v1/iocs/export']?.post);
  assert.ok(res.json.paths['/taxii2/']?.get);
  assert.ok(res.json.paths['/taxii2/talonhound/collections/{id}/objects/']?.get);
  assert.ok(res.json.components.securitySchemes.ApiKeyBearer);
  // Canonical doc helper stays in sync with the HTTP response.
  assert.equal(buildOpenApiDocument().openapi, '3.1.0');
});

test('openapi.json contains no secret-like key material fields', async () => {
  const res = await http(makeApp(), 'GET', '/api/openapi.json');
  const blob = JSON.stringify(res.json);
  assert.doesNotMatch(blob, /th_pf_[A-Za-z0-9_-]{20,}/);
  assert.doesNotMatch(blob, /th_ioc_[A-Za-z0-9_-]{20,}/);
  assert.doesNotMatch(blob, /th_read_[A-Za-z0-9_-]{20,}/);
  assert.doesNotMatch(blob, /"token_hash"\s*:/);
  assert.doesNotMatch(blob, /secret_ciphertext/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import express from 'express';
import { registerSystemTlsCertificateRoutes } from './systemTlsCertificate.js';
import {
  validateTlsMaterial,
  parseCertificatePem,
  readActiveTlsCertificate,
  classifyCertificateStatus,
  TLS_PUBLIC_DOWNLOAD_NAME
} from '../lib/tlsCertificateService.js';
import { activateTlsCertificate } from '../lib/tlsCertificateActivate.js';
import { GOOD_CERT, GOOD_KEY, OTHER_KEY } from '../lib/tlsTestFixtures.js';
import { ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION } from '../lib/auditConstants.js';

function makePool({ systemAdmins = new Set() } = {}) {
  return {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM users') && s.includes('is_system_admin')) {
        const id = Number(params[0]);
        return { rows: [{ is_system_admin: systemAdmins.has(id) }] };
      }
      throw new Error(`unexpected sql: ${s}`);
    }
  };
}

function request(app, { method, path: urlPath, user, body, headers = {} }) {
  return new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${port}${urlPath}`, {
          method,
          headers: {
            'Content-Type': 'application/json',
            ...(user ? { 'x-test-user': JSON.stringify(user) } : {}),
            ...headers
          },
          body: body == null ? undefined : JSON.stringify(body)
        });
        const contentType = res.headers.get('content-type') || '';
        const text = await res.text();
        let parsed = text;
        if (contentType.includes('application/json')) {
          try { parsed = JSON.parse(text); } catch { parsed = text; }
        }
        resolve({
          status: res.status,
          body: parsed,
          headers: Object.fromEntries(res.headers.entries()),
          text
        });
      } finally {
        server.close();
      }
    });
  });
}

function buildApp(pool, auditEvents = []) {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use((req, _res, next) => {
    const raw = req.headers['x-test-user'];
    if (raw) {
      const u = JSON.parse(String(raw));
      req.user = u;
    }
    next();
  });
  registerSystemTlsCertificateRoutes(app, {
    pool,
    audit: {
      auditSuccess: async (event) => { auditEvents.push(event); }
    }
  });
  return app;
}

function startFakeReloadWatcher(certDir) {
  const requestPath = path.join(certDir, '.reload_request');
  const resultPath = path.join(certDir, '.reload_result');
  let stopped = false;
  const loop = (async () => {
    while (!stopped) {
      if (fs.existsSync(requestPath)) {
        try { fs.unlinkSync(requestPath); } catch { /* ignore */ }
        fs.writeFileSync(resultPath, 'ok\n', { mode: 0o644 });
      }
      await delay(50);
    }
  })();
  return {
    stop: async () => {
      stopped = true;
      await loop;
    }
  };
}

test('validateTlsMaterial accepts matching cert/key and parses metadata', () => {
  const out = validateTlsMaterial({
    certificatePem: GOOD_CERT,
    privateKeyPem: GOOD_KEY
  });
  assert.equal(out.ok, true);
  assert.equal(out.metadata.subject_cn, 'test.talonhound.local');
  assert.ok(out.metadata.fingerprint_sha256.includes(':'));
  assert.ok(out.metadata.dns_names.includes('test.talonhound.local'));
  assert.ok(out.metadata.ip_addresses.includes('127.0.0.1'));
  assert.equal(out.metadata.status, 'active');
});

test('validateTlsMaterial rejects mismatched key', () => {
  const out = validateTlsMaterial({
    certificatePem: GOOD_CERT,
    privateKeyPem: OTHER_KEY
  });
  assert.equal(out.ok, false);
  assert.match(out.message, /do not match/i);
});

test('validateTlsMaterial rejects malformed certificate and key', () => {
  assert.equal(validateTlsMaterial({
    certificatePem: 'not-a-cert',
    privateKeyPem: GOOD_KEY
  }).ok, false);
  assert.equal(validateTlsMaterial({
    certificatePem: GOOD_CERT,
    privateKeyPem: 'not-a-key'
  }).ok, false);
});

test('validateTlsMaterial rejects expired certificate', () => {
  const out = validateTlsMaterial({
    certificatePem: GOOD_CERT,
    privateKeyPem: GOOD_KEY
  }, { now: new Date('2099-01-01T00:00:00Z') });
  assert.equal(out.ok, false);
  assert.match(out.message, /expired/i);
});

test('classifyCertificateStatus and parseCertificatePem helpers', () => {
  const parsed = parseCertificatePem(GOOD_CERT);
  assert.equal(parsed.ok, true);
  assert.equal(classifyCertificateStatus(parsed.cert, new Date('2099-01-01T00:00:00Z')), 'expired');
  assert.equal(classifyCertificateStatus(parsed.cert), 'active');
});

test('activateTlsCertificate writes files, reloads, never exposes private key', async () => {
  const certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'th-tls-act-'));
  const watcher = startFakeReloadWatcher(certDir);
  try {
    // seed prior generated cert
    fs.writeFileSync(path.join(certDir, 'cert.pem'), GOOD_CERT, { mode: 0o644 });
    fs.writeFileSync(path.join(certDir, 'key.pem'), GOOD_KEY, { mode: 0o600 });
    fs.writeFileSync(path.join(certDir, '.cert_source'), 'generated\n', { mode: 0o644 });

    const result = await activateTlsCertificate({
      certificate_pem: GOOD_CERT,
      private_key_pem: GOOD_KEY
    }, { certDir });
    assert.equal(result.ok, true);
    assert.equal(result.metadata.source, 'custom');
    assert.equal(fs.readFileSync(path.join(certDir, '.cert_source'), 'utf8').trim(), 'custom');
    const blob = JSON.stringify(result);
    assert.doesNotMatch(blob, /BEGIN PRIVATE KEY/);
    assert.doesNotMatch(fs.readFileSync(path.join(certDir, 'cert.pem'), 'utf8'), /PRIVATE KEY/);
  } finally {
    await watcher.stop();
    fs.rmSync(certDir, { recursive: true, force: true });
  }
});

test('GET metadata and public download; POST replace authz', async () => {
  const certDir = fs.mkdtempSync(path.join(os.tmpdir(), 'th-tls-api-'));
  const watcher = startFakeReloadWatcher(certDir);
  const previous = process.env.TLS_CERT_DIR;
  process.env.TLS_CERT_DIR = certDir;
  fs.writeFileSync(path.join(certDir, 'cert.pem'), GOOD_CERT, { mode: 0o644 });
  fs.writeFileSync(path.join(certDir, 'key.pem'), GOOD_KEY, { mode: 0o600 });
  fs.writeFileSync(path.join(certDir, '.cert_source'), 'generated\n');

  const auditEvents = [];
  const pool = makePool({ systemAdmins: new Set([1]) });
  const app = buildApp(pool, auditEvents);
  const systemAdmin = { id: 1, role: ROLES.ADMIN, username: 'sysadmin@example.com', publicId: '11111111-1111-4111-8111-111111111111' };
  const normalAdmin = { id: 2, role: ROLES.ADMIN, username: 'admin@example.com', publicId: '22222222-2222-4222-8222-222222222222' };

  try {
    const meta = await request(app, {
      method: 'GET',
      path: '/api/system/tls-certificate',
      user: normalAdmin
    });
    assert.equal(meta.status, 200);
    assert.equal(meta.body.can_edit, false);
    assert.equal(meta.body.subject_cn, 'test.talonhound.local');
    assert.equal(meta.body.source, 'generated');
    assert.equal(meta.body.has_private_key_file, true);
    assert.doesNotMatch(JSON.stringify(meta.body), /BEGIN PRIVATE KEY/);

    const sysMeta = await request(app, {
      method: 'GET',
      path: '/api/system/tls-certificate',
      user: systemAdmin
    });
    assert.equal(sysMeta.body.can_edit, true);

    const dl = await request(app, {
      method: 'GET',
      path: '/api/system/tls-certificate/public',
      user: normalAdmin
    });
    assert.equal(dl.status, 200);
    assert.match(dl.headers['content-disposition'] || '', new RegExp(TLS_PUBLIC_DOWNLOAD_NAME));
    assert.match(dl.text, /BEGIN CERTIFICATE/);
    assert.doesNotMatch(dl.text, /PRIVATE KEY/);
    assert.ok(auditEvents.some((e) => e.action === AUDIT_ACTION.TLS_CERTIFICATE_DOWNLOADED));

    const denied = await request(app, {
      method: 'POST',
      path: '/api/system/tls-certificate',
      user: normalAdmin,
      body: { certificate_pem: GOOD_CERT, private_key_pem: GOOD_KEY }
    });
    assert.equal(denied.status, 403);

    const allowed = await request(app, {
      method: 'POST',
      path: '/api/system/tls-certificate',
      user: systemAdmin,
      body: { certificate_pem: GOOD_CERT, private_key_pem: GOOD_KEY }
    });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.body.source, 'custom');
    assert.ok(auditEvents.some((e) => e.action === AUDIT_ACTION.TLS_CERTIFICATE_REPLACED));
    assert.doesNotMatch(JSON.stringify(auditEvents), /BEGIN PRIVATE KEY/);

    const bad = await request(app, {
      method: 'POST',
      path: '/api/system/tls-certificate',
      user: systemAdmin,
      body: { certificate_pem: GOOD_CERT, private_key_pem: OTHER_KEY }
    });
    assert.equal(bad.status, 400);
    assert.match(bad.body.message, /do not match/i);

    // Active read still works after failed replace attempt
    const still = readActiveTlsCertificate(certDir);
    assert.equal(still.ok, true);
  } finally {
    await watcher.stop();
    if (previous === undefined) delete process.env.TLS_CERT_DIR;
    else process.env.TLS_CERT_DIR = previous;
    fs.rmSync(certDir, { recursive: true, force: true });
  }
});

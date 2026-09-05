/**
 * Atomic TLS certificate activation with backup + proxy reload handshake.
 * Never logs or returns private key material.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import {
  getTlsCertDir,
  tlsPaths,
  TLS_SOURCE_FILE,
  validateTlsMaterial,
  readActiveTlsCertificate,
  TLS_CERT_FILE,
  TLS_KEY_FILE
} from './tlsCertificateService.js';

const RELOAD_TIMEOUT_MS = Number(process.env.TLS_RELOAD_TIMEOUT_MS || 15000);
const RELOAD_POLL_MS = 250;

function secureWriteFile(filePath, contents, mode) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
  const tmp = path.join(dir, `.tmp-${path.basename(filePath)}-${process.pid}-${Date.now()}`);
  const fd = fs.openSync(tmp, 'w', mode);
  try {
    fs.writeFileSync(fd, contents, { encoding: 'utf8' });
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, filePath);
  try {
    fs.chmodSync(filePath, mode);
  } catch {
    /* best effort on platforms that ignore chmod */
  }
}

function copyFileIfExists(src, dest, mode) {
  if (!fs.existsSync(src)) return false;
  const data = fs.readFileSync(src);
  secureWriteFile(dest, data, mode);
  return true;
}

async function requestProxyReload(paths) {
  try {
    fs.unlinkSync(paths.reloadResult);
  } catch {
    /* none */
  }
  secureWriteFile(paths.reloadRequest, `${Date.now()}\n`, 0o644);
  const deadline = Date.now() + RELOAD_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (fs.existsSync(paths.reloadResult)) {
      const body = fs.readFileSync(paths.reloadResult, 'utf8').trim();
      try {
        fs.unlinkSync(paths.reloadResult);
      } catch {
        /* ignore */
      }
      if (body.startsWith('ok')) return { ok: true };
      return { ok: false, message: body.replace(/^fail:?\s*/i, '') || 'Proxy reload failed' };
    }
    await delay(RELOAD_POLL_MS);
  }
  return { ok: false, message: 'Timed out waiting for proxy TLS reload' };
}

function restoreBackup(paths, backupDir) {
  const bakCert = path.join(backupDir, TLS_CERT_FILE);
  const bakKey = path.join(backupDir, TLS_KEY_FILE);
  const bakSource = path.join(backupDir, TLS_SOURCE_FILE);
  if (fs.existsSync(bakCert)) secureWriteFile(paths.cert, fs.readFileSync(bakCert), 0o644);
  if (fs.existsSync(bakKey)) secureWriteFile(paths.key, fs.readFileSync(bakKey), 0o600);
  if (fs.existsSync(bakSource)) {
    secureWriteFile(paths.source, fs.readFileSync(bakSource, 'utf8'), 0o644);
  }
}

/**
 * Validate and activate a new TLS certificate for the edge proxy.
 */
export async function activateTlsCertificate(input = {}, opts = {}) {
  const baseDir = opts.certDir || getTlsCertDir();
  const paths = tlsPaths(baseDir);

  const validated = validateTlsMaterial({
    certificatePem: input.certificate_pem ?? input.certificatePem,
    privateKeyPem: input.private_key_pem ?? input.privateKeyPem,
    chainPem: input.chain_pem ?? input.chainPem
  });
  if (!validated.ok) {
    return { ok: false, code: 'VALIDATION_ERROR', message: validated.message };
  }

  const previous = readActiveTlsCertificate(baseDir);
  const oldFingerprint = previous.ok ? previous.metadata.fingerprint_sha256 : null;

  const backupDir = fs.mkdtempSync(path.join(os.tmpdir(), 'talonhound-tls-bak-'));
  const candidateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'talonhound-tls-cand-'));

  try {
    // Stage candidates outside active dir first.
    secureWriteFile(path.join(candidateDir, TLS_CERT_FILE), validated.fullchainPem, 0o644);
    secureWriteFile(path.join(candidateDir, TLS_KEY_FILE), String(input.private_key_pem ?? input.privateKeyPem).trim() + '\n', 0o600);
    secureWriteFile(path.join(candidateDir, TLS_SOURCE_FILE), 'custom\n', 0o644);

    // Backup current active material.
    fs.mkdirSync(paths.dir, { recursive: true, mode: 0o755 });
    copyFileIfExists(paths.cert, path.join(backupDir, TLS_CERT_FILE), 0o644);
    copyFileIfExists(paths.key, path.join(backupDir, TLS_KEY_FILE), 0o600);
    copyFileIfExists(paths.source, path.join(backupDir, TLS_SOURCE_FILE), 0o644);

    // Atomic-ish replace into active directory.
    secureWriteFile(paths.cert, fs.readFileSync(path.join(candidateDir, TLS_CERT_FILE)), 0o644);
    secureWriteFile(paths.key, fs.readFileSync(path.join(candidateDir, TLS_KEY_FILE)), 0o600);
    secureWriteFile(paths.source, 'custom\n', 0o644);

    const reload = await requestProxyReload(paths);
    if (!reload.ok) {
      restoreBackup(paths, backupDir);
      const rollbackReload = await requestProxyReload(paths);
      return {
        ok: false,
        code: 'TLS_ACTIVATION_FAILED',
        message: reload.message || 'Failed to activate TLS certificate',
        rolled_back: true,
        rollback_reload_ok: rollbackReload.ok
      };
    }

    // Persist a host-side backup under certs/backup-* for operator recovery (no key in API).
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const hostBackup = path.join(paths.dir, `backup-${stamp}`);
    try {
      fs.mkdirSync(hostBackup, { mode: 0o700 });
      copyFileIfExists(path.join(backupDir, TLS_CERT_FILE), path.join(hostBackup, TLS_CERT_FILE), 0o644);
      copyFileIfExists(path.join(backupDir, TLS_KEY_FILE), path.join(hostBackup, TLS_KEY_FILE), 0o600);
    } catch {
      /* non-fatal */
    }

    return {
      ok: true,
      metadata: validated.metadata,
      previous_fingerprint_sha256: oldFingerprint,
      fingerprint_sha256: validated.fingerprint
    };
  } finally {
    try {
      fs.rmSync(candidateDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
    try {
      fs.rmSync(backupDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}

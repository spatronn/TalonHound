/**
 * TLS certificate metadata, validation, and filesystem paths for the edge proxy.
 * Private key material is never returned by these helpers.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto, { X509Certificate, createPrivateKey } from 'node:crypto';

export const TLS_CERT_FILE = 'cert.pem';
export const TLS_KEY_FILE = 'key.pem';
export const TLS_SOURCE_FILE = '.cert_source';
export const TLS_RELOAD_REQUEST = '.reload_request';
export const TLS_RELOAD_RESULT = '.reload_result';
export const TLS_PUBLIC_DOWNLOAD_NAME = 'talonhound-certificate.pem';

const EXPIRING_SOON_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Resolve the directory that holds active nginx TLS files.
 * Override with TLS_CERT_DIR (compose mounts ./proxy/certs here).
 */
export function getTlsCertDir() {
  const raw = String(process.env.TLS_CERT_DIR || '/etc/talonhound/certs').trim();
  return path.resolve(raw || '/etc/talonhound/certs');
}

export function tlsPaths(baseDir = getTlsCertDir()) {
  return {
    dir: baseDir,
    cert: path.join(baseDir, TLS_CERT_FILE),
    key: path.join(baseDir, TLS_KEY_FILE),
    source: path.join(baseDir, TLS_SOURCE_FILE),
    reloadRequest: path.join(baseDir, TLS_RELOAD_REQUEST),
    reloadResult: path.join(baseDir, TLS_RELOAD_RESULT)
  };
}

export function readCertSource(baseDir = getTlsCertDir()) {
  const p = tlsPaths(baseDir).source;
  try {
    const v = fs.readFileSync(p, 'utf8').trim().toLowerCase();
    if (v === 'custom' || v === 'generated') return v;
  } catch {
    /* missing */
  }
  return 'generated';
}

/**
 * Split a PEM blob into certificate blocks (leaf + optional chain).
 * @param {string} pem
 * @returns {string[]}
 */
export function splitPemCertificates(pem) {
  const text = String(pem || '');
  const blocks = [];
  const re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let m;
  while ((m = re.exec(text)) != null) {
    blocks.push(m[0].trim());
  }
  return blocks;
}

/**
 * @param {string} pem
 * @returns {{ ok: true, key: import('node:crypto').KeyObject } | { ok: false, message: string }}
 */
export function parsePrivateKeyPem(pem) {
  const text = String(pem || '').trim();
  if (!text.includes('BEGIN') || !text.includes('PRIVATE KEY')) {
    return { ok: false, message: 'Invalid PEM private key' };
  }
  try {
    const key = createPrivateKey(text);
    const type = String(key.asymmetricKeyType || '');
    if (!['rsa', 'ec', 'ed25519', 'ed448'].includes(type)) {
      return { ok: false, message: 'Unsupported private key algorithm' };
    }
    return { ok: true, key };
  } catch {
    return { ok: false, message: 'Invalid PEM private key' };
  }
}

/**
 * @param {string} certPem
 * @returns {{ ok: true, cert: X509Certificate, pem: string } | { ok: false, message: string }}
 */
export function parseCertificatePem(certPem) {
  const blocks = splitPemCertificates(certPem);
  if (!blocks.length) {
    return { ok: false, message: 'Invalid PEM certificate' };
  }
  try {
    const cert = new X509Certificate(blocks[0]);
    return { ok: true, cert, pem: blocks[0], chainPems: blocks.slice(1) };
  } catch {
    return { ok: false, message: 'Invalid PEM certificate' };
  }
}

/**
 * @param {string} chainPem
 * @returns {{ ok: true, pems: string[] } | { ok: false, message: string }}
 */
export function parseChainPem(chainPem) {
  if (chainPem == null || String(chainPem).trim() === '') {
    return { ok: true, pems: [] };
  }
  const blocks = splitPemCertificates(chainPem);
  if (!blocks.length) {
    return { ok: false, message: 'Invalid certificate chain' };
  }
  try {
    for (const b of blocks) {
      // eslint-disable-next-line no-new
      new X509Certificate(b);
    }
    return { ok: true, pems: blocks };
  } catch {
    return { ok: false, message: 'Invalid certificate chain' };
  }
}

/**
 * @param {X509Certificate} cert
 */
export function certificateSha256Fingerprint(cert) {
  const der = cert.raw;
  const hex = crypto.createHash('sha256').update(der).digest('hex').toUpperCase();
  return hex.match(/.{2}/g).join(':');
}

/**
 * @param {X509Certificate} cert
 */
export function classifyCertificateStatus(cert, now = new Date()) {
  const notBefore = new Date(cert.validFrom);
  const notAfter = new Date(cert.validTo);
  if (Number.isNaN(notBefore.getTime()) || Number.isNaN(notAfter.getTime())) {
    return 'invalid';
  }
  if (now < notBefore) return 'invalid';
  if (now > notAfter) return 'expired';
  if (notAfter.getTime() - now.getTime() <= EXPIRING_SOON_MS) return 'expiring_soon';
  return 'active';
}

function parseSanList(cert) {
  const san = cert.subjectAltName || '';
  const dns = [];
  const ips = [];
  for (const part of san.split(',').map((s) => s.trim()).filter(Boolean)) {
    const dnsMatch = /^DNS:(.+)$/i.exec(part);
    const ipMatch = /^IP(?: Address)?:(.+)$/i.exec(part);
    if (dnsMatch) dns.push(dnsMatch[1].trim());
    else if (ipMatch) ips.push(ipMatch[1].trim());
  }
  return { dns_names: dns, ip_addresses: ips };
}

function subjectCn(cert) {
  const s = String(cert.subject || '');
  const m = /(?:^|\n)CN\s*=\s*(.+)$/im.exec(s);
  return m ? m[1].trim() : (s.split('\n')[0] || null);
}

function issuerCn(cert) {
  const s = String(cert.issuer || '');
  const m = /(?:^|\n)CN\s*=\s*(.+)$/im.exec(s);
  return m ? m[1].trim() : (s.split('\n')[0] || null);
}

/**
 * @param {X509Certificate} cert
 */
export function serializeCertificateMetadata(cert, extras = {}) {
  const status = classifyCertificateStatus(cert);
  const sans = parseSanList(cert);
  let keyAlgorithm = null;
  try {
    keyAlgorithm = cert.publicKey?.asymmetricKeyType || null;
  } catch {
    keyAlgorithm = null;
  }
  return {
    status,
    subject: cert.subject || null,
    subject_cn: subjectCn(cert),
    issuer: cert.issuer || null,
    issuer_cn: issuerCn(cert),
    serial_number: cert.serialNumber || null,
    valid_from: new Date(cert.validFrom).toISOString(),
    valid_until: new Date(cert.validTo).toISOString(),
    dns_names: sans.dns_names,
    ip_addresses: sans.ip_addresses,
    fingerprint_sha256: certificateSha256Fingerprint(cert),
    key_algorithm: keyAlgorithm,
    ...extras
  };
}

function hasServerTlsUsage(cert) {
  // Node exposes extKeyUsage as an array of OIDs or names when present.
  const eku = cert.extKeyUsage;
  if (!Array.isArray(eku) || eku.length === 0) {
    // Many self-signed installs omit EKU; allow when unconstrained.
    return true;
  }
  const normalized = eku.map((x) => String(x).toLowerCase());
  return normalized.some((x) =>
    x.includes('serverauth')
    || x === '1.3.6.1.5.5.7.3.1'
    || x.includes('any')
  );
}

/**
 * Full validation of a candidate cert/key/chain before activation.
 * @returns {{ ok: true, leafPem: string, fullchainPem: string, fingerprint: string, metadata: object }
 *   | { ok: false, message: string }}
 */
export function validateTlsMaterial({ certificatePem, privateKeyPem, chainPem } = {}, { now = new Date() } = {}) {
  const leaf = parseCertificatePem(certificatePem);
  if (!leaf.ok) return leaf;

  const key = parsePrivateKeyPem(privateKeyPem);
  if (!key.ok) return key;

  const chain = parseChainPem(chainPem);
  if (!chain.ok) return chain;

  try {
    if (typeof leaf.cert.checkPrivateKey === 'function') {
      if (!leaf.cert.checkPrivateKey(key.key)) {
        return { ok: false, message: 'Certificate and private key do not match' };
      }
    }
  } catch {
    return { ok: false, message: 'Certificate and private key do not match' };
  }

  const status = classifyCertificateStatus(leaf.cert, now);
  if (status === 'expired') {
    return { ok: false, message: 'Certificate has expired' };
  }
  if (status === 'invalid') {
    return { ok: false, message: 'Certificate is not yet valid or is invalid' };
  }

  if (!hasServerTlsUsage(leaf.cert)) {
    return { ok: false, message: 'Certificate is not suitable for server TLS' };
  }

  // Prefer chain from dedicated field; also accept multi-cert leaf upload.
  const chainBlocks = chain.pems.length ? chain.pems : (leaf.chainPems || []);
  const fullchainPem = [leaf.pem, ...chainBlocks].join('\n') + '\n';
  const metadata = serializeCertificateMetadata(leaf.cert, {
    source: 'custom',
    chain_count: chainBlocks.length
  });

  return {
    ok: true,
    leafPem: leaf.pem + '\n',
    fullchainPem,
    fingerprint: metadata.fingerprint_sha256,
    metadata
  };
}

/**
 * Read active public certificate metadata (never includes private key).
 */
export function readActiveTlsCertificate(baseDir = getTlsCertDir()) {
  const paths = tlsPaths(baseDir);
  if (!fs.existsSync(paths.cert)) {
    return {
      ok: false,
      code: 'TLS_CERT_MISSING',
      message: 'No active TLS certificate is configured'
    };
  }
  let pem;
  try {
    pem = fs.readFileSync(paths.cert, 'utf8');
  } catch {
    return { ok: false, code: 'TLS_CERT_UNREADABLE', message: 'Unable to read TLS certificate' };
  }
  const parsed = parseCertificatePem(pem);
  if (!parsed.ok) {
    return { ok: false, code: 'TLS_CERT_INVALID', message: parsed.message };
  }
  const source = readCertSource(baseDir);
  const chainCount = Math.max(0, splitPemCertificates(pem).length - 1);
  return {
    ok: true,
    pem,
    metadata: serializeCertificateMetadata(parsed.cert, {
      source,
      chain_count: chainCount,
      has_private_key_file: fs.existsSync(paths.key)
    })
  };
}

import { requireRole, ROLES } from '../lib/rbac.js';
import { requireSystemAdmin, isCallerSystemAdmin } from '../lib/systemAdminAuth.js';
import {
  readActiveTlsCertificate,
  TLS_PUBLIC_DOWNLOAD_NAME
} from '../lib/tlsCertificateService.js';
import { activateTlsCertificate } from '../lib/tlsCertificateActivate.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';

const FORBIDDEN_MESSAGE = 'Only the System Administrator can replace the TLS certificate';

function actorFields(req) {
  return {
    actorUsername: req.user?.username || req.user?.email || null,
    actorEmail: req.user?.email || null,
    actorRole: req.user?.role || null,
    actorPublicId: req.user?.publicId || null
  };
}

/**
 * @param {import('express').Express} app
 * @param {{ pool: import('pg').Pool, audit?: { auditSuccess?: Function } }} deps
 */
export function registerSystemTlsCertificateRoutes(app, deps = {}) {
  const pool = deps.pool;
  const audit = deps.audit;
  const admin = requireRole(ROLES.ADMIN);
  const systemAdmin = requireSystemAdmin(pool, FORBIDDEN_MESSAGE);

  app.get('/api/system/tls-certificate', admin, async (req, res) => {
    const canEdit = await isCallerSystemAdmin(pool, req);
    const active = readActiveTlsCertificate();
    if (!active.ok) {
      return res.status(active.code === 'TLS_CERT_MISSING' ? 404 : 500).json({
        code: active.code || 'TLS_CERT_ERROR',
        message: active.message,
        can_edit: canEdit
      });
    }
    return res.json({
      ...active.metadata,
      can_edit: canEdit
    });
  });

  app.get('/api/system/tls-certificate/public', admin, async (req, res) => {
    const active = readActiveTlsCertificate();
    if (!active.ok) {
      return res.status(active.code === 'TLS_CERT_MISSING' ? 404 : 500).json({
        code: active.code || 'TLS_CERT_ERROR',
        message: active.message
      });
    }
    // Defense-in-depth: never stream key material even if misconfigured.
    if (/BEGIN .*PRIVATE KEY/i.test(active.pem)) {
      return res.status(500).json({
        code: 'TLS_CERT_INVALID',
        message: 'Public certificate file is invalid'
      });
    }
    if (audit?.auditSuccess) {
      await audit.auditSuccess({
        action: AUDIT_ACTION.TLS_CERTIFICATE_DOWNLOADED,
        entityType: AUDIT_ENTITY.SETTINGS,
        entityId: null,
        entityDisplay: 'TLS certificate',
        severity: AUDIT_SEVERITY.INFO,
        ...actorFields(req),
        source: 'ui',
        metadata: {
          fingerprint_sha256: active.metadata.fingerprint_sha256,
          source: active.metadata.source
        }
      }).catch(() => {});
    }
    res.setHeader('Content-Type', 'application/x-pem-file');
    res.setHeader('Content-Disposition', `attachment; filename="${TLS_PUBLIC_DOWNLOAD_NAME}"`);
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).send(active.pem);
  });

  app.post('/api/system/tls-certificate', admin, systemAdmin, async (req, res) => {
    const certificatePem = req.body?.certificate_pem ?? req.body?.certificate;
    const privateKeyPem = req.body?.private_key_pem ?? req.body?.private_key;
    const chainPem = req.body?.chain_pem ?? req.body?.chain;

    const result = await activateTlsCertificate({
      certificate_pem: certificatePem,
      private_key_pem: privateKeyPem,
      chain_pem: chainPem
    });

    if (!result.ok) {
      const status = result.code === 'VALIDATION_ERROR' ? 400 : 500;
      return res.status(status).json({
        code: result.code || 'TLS_ACTIVATION_FAILED',
        message: result.message,
        rolled_back: result.rolled_back === true
      });
    }

    if (audit?.auditSuccess) {
      await audit.auditSuccess({
        action: AUDIT_ACTION.TLS_CERTIFICATE_REPLACED,
        entityType: AUDIT_ENTITY.SETTINGS,
        entityId: null,
        entityDisplay: 'TLS certificate',
        severity: AUDIT_SEVERITY.WARNING,
        ...actorFields(req),
        source: 'ui',
        metadata: {
          previous_fingerprint_sha256: result.previous_fingerprint_sha256,
          fingerprint_sha256: result.fingerprint_sha256,
          subject_cn: result.metadata?.subject_cn || null,
          valid_until: result.metadata?.valid_until || null
        }
      }).catch(() => {});
    }

    const canEdit = true;
    return res.json({
      ...result.metadata,
      can_edit: canEdit,
      previous_fingerprint_sha256: result.previous_fingerprint_sha256
    });
  });
}

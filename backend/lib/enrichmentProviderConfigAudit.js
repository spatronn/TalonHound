import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './auditConstants.js';

// Shared audit for enrichment provider config updates. One place so every
// provider that goes through the common enable/disable toggle flow records the
// same shape: provider id, previous vs new enabled, and the actor (derived by
// auditLogService from req). Extra `after` fields and `metadata` (e.g. reason)
// are merged per provider.
//
// This audits deliberate admin config changes only. Execution requests rejected
// because a provider is disabled are NOT audited here (that path lives in the
// guard, which intentionally records nothing to avoid audit spam).
export async function auditProviderConfigUpdate(audit, req, {
  provider,
  displayName,
  previousEnabled,
  newEnabled,
  after = {},
  metadata = {}
} = {}) {
  if (!audit?.auditSuccess) return;
  await audit.auditSuccess({
    req,
    action: AUDIT_ACTION.ENRICHMENT_PROVIDER_CONFIG_UPDATED,
    entityType: AUDIT_ENTITY.ENRICHMENT,
    entityId: provider,
    entityDisplay: displayName,
    severity: AUDIT_SEVERITY.INFO,
    before: { enabled: previousEnabled ?? null },
    after: { enabled: newEnabled, ...after },
    metadata: { provider, ...metadata }
  }).catch(() => {});
}

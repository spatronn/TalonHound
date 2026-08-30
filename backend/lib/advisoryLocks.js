/**
 * Session advisory-lock key registry for fixed integer locks.
 *
 * PostgreSQL session advisory locks share one 64-bit (or two 32-bit) namespace.
 * Unrelated jobs MUST use distinct keys. Prefer appending the next free id in
 * the 94200x feed-import series rather than reusing values.
 *
 * hashtext(...) namespaced locks (migrations, feed-sync, published feeds, …)
 * live in a different derivation path and are listed separately for inventory.
 */

/** EmergingThreats blockrules import */
export const ET_ADVISORY_LOCK = 942001;
/** USOM import */
export const USOM_ADVISORY_LOCK = 942002;
/** URLhaus import */
export const URLHAUS_ADVISORY_LOCK = 942003;
/** ThreatFox import */
export const THREATFOX_ADVISORY_LOCK = 942004;
/** MalwareBazaar recent/csv import */
export const MALWAREBAZAAR_IMPORT_ADVISORY_LOCK = 942005;
/** PhishTank import */
export const PHISHTANK_ADVISORY_LOCK = 942006;
/** AlienVault OTX import */
export const OTX_ADVISORY_LOCK = 942007;
/** MalwareBazaar historical recovery (must NOT collide with OTX) */
export const MALWAREBAZAAR_RECOVERY_ADVISORY_LOCK = 942008;
/** CERT.PL Dangerous Websites Warning List import */
export const CERTPL_ADVISORY_LOCK = 942009;

/**
 * Named fixed-integer locks used by feed/import workers.
 * Keep identities unique — the uniqueness test fails the suite on collision.
 */
export const FIXED_INTEGER_ADVISORY_LOCKS = Object.freeze([
  { id: ET_ADVISORY_LOCK, name: 'emergingthreats-import' },
  { id: USOM_ADVISORY_LOCK, name: 'usom-import' },
  { id: URLHAUS_ADVISORY_LOCK, name: 'urlhaus-import' },
  { id: THREATFOX_ADVISORY_LOCK, name: 'threatfox-import' },
  { id: MALWAREBAZAAR_IMPORT_ADVISORY_LOCK, name: 'malwarebazaar-import' },
  { id: PHISHTANK_ADVISORY_LOCK, name: 'phishtank-import' },
  { id: OTX_ADVISORY_LOCK, name: 'alienvault-otx-import' },
  { id: MALWAREBAZAAR_RECOVERY_ADVISORY_LOCK, name: 'malwarebazaar-historical-recovery' },
  { id: CERTPL_ADVISORY_LOCK, name: 'certpl-warning-list-import' }
]);

/** hashtext()-namespaced session locks (inventory only; uniqueness is by string). */
export const HASHTEXT_ADVISORY_LOCK_NAMES = Object.freeze([
  'talonhound:migrations',
  'talonhound:system-admin-bootstrap',
  'talonhound:default-admin-bootstrap',
  'enrichment-health-probe',
  'talonhound:system-backup',
  'talonhound:ioc-list-stats-refresh'
  // Dynamic: manual_ioc:\\0-joined identity via manualIocDuplicateLockKey()
  // Dynamic: published_feed_snapshots:... via feedPublisherService
  // Dynamic: talonhound:feed-sync:* via feedSyncLock
]);

export function findDuplicateFixedAdvisoryLocks(entries = FIXED_INTEGER_ADVISORY_LOCKS) {
  const byId = new Map();
  const duplicates = [];
  for (const entry of entries) {
    const id = Number(entry.id);
    const prev = byId.get(id);
    if (prev) {
      duplicates.push({ id, names: [prev, entry.name] });
    } else {
      byId.set(id, entry.name);
    }
  }
  return duplicates;
}

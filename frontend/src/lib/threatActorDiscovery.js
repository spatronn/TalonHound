/**
 * Threat Actor → associated IOC discovery (pure helpers for the UI).
 * URL state / filter helpers match Malware Families discovery.
 */

export const THREAT_ACTOR_DETAIL_BASE = '/threat-intelligence/threat-actors';
export const THREAT_ACTOR_DISCOVERY_PAGE_SIZE = 25;

export function threatActorDetailHref(id) {
  const v = String(id ?? '').trim();
  return v ? `${THREAT_ACTOR_DETAIL_BASE}/${encodeURIComponent(v)}` : null;
}

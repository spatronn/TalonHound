import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_MITRE_REFERENCE_PATH = path.resolve(__dirname, '../../data/mitre-attack-reference.json');

/** @typedef {{ id: string, name: string, type: 'tactic'|'technique'|'sub-technique', url: string }} MitreReferenceRecord */

/** @type {Map<string, MitreReferenceRecord> | null} */
let referenceCache = null;

export function invalidateMitreReferenceCache() {
  referenceCache = null;
}

/** @param {unknown} record */
function normalizeReferenceRecord(record) {
  if (!record || typeof record !== 'object') return null;
  const id = String(record.id || '').trim();
  const name = String(record.name || '').trim();
  const type = String(record.type || '').trim();
  const url = String(record.url || '').trim();
  if (!id || !name || !url) return null;
  if (!['tactic', 'technique', 'sub-technique'].includes(type)) return null;
  return { id, name, type, url };
}

export async function loadMitreReference(referencePath = DEFAULT_MITRE_REFERENCE_PATH) {
  if (referenceCache) return referenceCache;
  const raw = JSON.parse(await readFile(referencePath, 'utf8'));
  const map = new Map();
  for (const record of raw?.records || []) {
    const normalized = normalizeReferenceRecord(record);
    if (normalized) map.set(normalized.id, normalized);
  }
  referenceCache = map;
  return map;
}

export function isValidMitreAttackId(id) {
  const s = String(id || '').trim();
  if (/^TA\d{4}$/.test(s)) return true;
  if (/^T\d{4}$/.test(s)) return true;
  if (/^T\d{4}\.\d{3}$/.test(s)) return true;
  return false;
}

export function resolveMitreAttackRecord(reference, attackId) {
  const id = String(attackId || '').trim();
  if (!isValidMitreAttackId(id)) {
    throw new Error(`Invalid MITRE ATT&CK id format: ${attackId}`);
  }
  const record = reference.get(id);
  if (!record) {
    throw new Error(`MITRE ATT&CK id not found in bundled reference: ${attackId}`);
  }
  return record;
}

/**
 * @param {Array<{ id?: string }>} mappings
 * @param {Map<string, MitreReferenceRecord>} reference
 */
export function resolveBundledMitreMappings(mappings = [], reference) {
  const resolved = [];
  const seen = new Set();
  for (let i = 0; i < mappings.length; i++) {
    const attackId = String(mappings[i]?.id || '').trim();
    if (!attackId) continue;
    if (seen.has(attackId)) {
      throw new Error(`Duplicate MITRE ATT&CK mapping in bundled record: ${attackId}`);
    }
    seen.add(attackId);
    const record = resolveMitreAttackRecord(reference, attackId);
    resolved.push({
      attack_id: record.id,
      attack_name: record.name,
      attack_type: record.type,
      attack_url: record.url,
      sort_order: i * 10
    });
  }
  return resolved;
}

/**
 * @param {Array<{ attack_id: string }>} bundledMappings
 * @param {Array<{ attack_id: string, attack_name: string, attack_type: string, attack_url: string, sort_order: number }>} existingMappings
 */
export function mitreMappingSetsEqual(bundledMappings, existingMappings) {
  const a = [...(bundledMappings || [])].map((m) => `${m.attack_id}|${m.attack_name}|${m.attack_type}|${m.attack_url}|${m.sort_order}`).sort();
  const b = [...(existingMappings || [])].map((m) => `${m.attack_id}|${m.attack_name}|${m.attack_type}|${m.attack_url}|${m.sort_order}`).sort();
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * Rebuild backend/data/mitre-attack-reference.json from official MITRE ATT&CK
 * STIX (offline-consumable compact catalog). Runtime never contacts MITRE.
 *
 * Usage:
 *   node scripts/build-mitre-attack-reference.js
 *   node scripts/build-mitre-attack-reference.js --source /path/to/enterprise-attack.json
 */
import { writeFile, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT = path.resolve(__dirname, '../data/mitre-attack-reference.json');
const DEFAULT_STIX_URL =
  'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json';

function mitreExt(obj) {
  const refs = Array.isArray(obj?.external_references) ? obj.external_references : [];
  return refs.find((r) => r?.source_name === 'mitre-attack' && r.external_id) || null;
}

function officialUrl(type, id) {
  if (type === 'tactic') return `https://attack.mitre.org/tactics/${id}/`;
  const [tech, sub] = String(id).split('.');
  return sub
    ? `https://attack.mitre.org/techniques/${tech}/${sub}/`
    : `https://attack.mitre.org/techniques/${tech}/`;
}

function isWithdrawn(obj) {
  return obj?.revoked === true || obj?.x_mitre_deprecated === true;
}

export function buildMitreAttackReference(stix, { version, source } = {}) {
  const objects = Array.isArray(stix?.objects) ? stix.objects : [];
  const tacticsByShortname = new Map();
  const records = [];

  for (const obj of objects) {
    if (obj?.type !== 'x-mitre-tactic' || isWithdrawn(obj)) continue;
    const ext = mitreExt(obj);
    if (!ext || !/^TA\d{4}$/.test(ext.external_id)) continue;
    const shortname = String(obj.x_mitre_shortname || '').trim();
    const rec = {
      id: ext.external_id,
      name: String(obj.name || '').trim(),
      type: 'tactic',
      url: officialUrl('tactic', ext.external_id),
      tactics: []
    };
    if (!rec.name) continue;
    records.push(rec);
    if (shortname) tacticsByShortname.set(shortname, rec.id);
  }

  for (const obj of objects) {
    if (obj?.type !== 'attack-pattern' || isWithdrawn(obj)) continue;
    const ext = mitreExt(obj);
    if (!ext) continue;
    const id = String(ext.external_id || '').trim();
    const isSub = obj.x_mitre_is_subtechnique === true || /^\d{4}\.\d{3}$/.test(id.slice(1));
    if (isSub) {
      if (!/^T\d{4}\.\d{3}$/.test(id)) continue;
    } else if (!/^T\d{4}$/.test(id)) {
      continue;
    }
    const tacticIds = [];
    for (const phase of obj.kill_chain_phases || []) {
      if (phase?.kill_chain_name && phase.kill_chain_name !== 'mitre-attack') continue;
      const tid = tacticsByShortname.get(String(phase?.phase_name || '').trim());
      if (tid && !tacticIds.includes(tid)) tacticIds.push(tid);
    }
    const rec = {
      id,
      name: String(obj.name || '').trim(),
      type: isSub ? 'sub-technique' : 'technique',
      url: officialUrl(isSub ? 'sub-technique' : 'technique', id),
      tactics: tacticIds
    };
    if (!rec.name) continue;
    records.push(rec);
  }

  records.sort((a, b) => a.id.localeCompare(b.id, 'en'));
  return {
    version: version || stix?.spec_version || 'enterprise-attack',
    source: source || 'MITRE ATT&CK Enterprise matrix (bundled snapshot for TalonHound)',
    license_note:
      'MITRE ATT&CK is available under MITRE\'s terms; see docs/threat-classifications.md',
    records
  };
}

async function loadStix(sourceArg) {
  if (sourceArg) {
    return JSON.parse(await readFile(sourceArg, 'utf8'));
  }
  const res = await fetch(DEFAULT_STIX_URL);
  if (!res.ok) throw new Error(`Failed to download ATT&CK STIX: HTTP ${res.status}`);
  return res.json();
}

async function main() {
  const args = process.argv.slice(2);
  const srcIdx = args.indexOf('--source');
  const sourceArg = srcIdx >= 0 ? args[srcIdx + 1] : null;
  const outIdx = args.indexOf('--out');
  const outPath = outIdx >= 0 ? args[outIdx + 1] : DEFAULT_OUT;
  const stix = await loadStix(sourceArg);
  const version =
    stix?.objects?.find((o) => o.type === 'x-mitre-collection')?.x_mitre_version ||
    '19.2';
  const catalog = buildMitreAttackReference(stix, {
    version: `enterprise-attack-${version}`,
    source: 'MITRE ATT&CK Enterprise matrix (bundled snapshot for TalonHound classification and Threat Library mappings)'
  });
  const tactics = catalog.records.filter((r) => r.type === 'tactic').length;
  const techniques = catalog.records.filter((r) => r.type === 'technique').length;
  const subs = catalog.records.filter((r) => r.type === 'sub-technique').length;
  if (tactics < 10 || techniques < 100 || subs < 100) {
    throw new Error(`Catalog looks incomplete: tactics=${tactics} techniques=${techniques} sub-techniques=${subs}`);
  }
  await writeFile(outPath, `${JSON.stringify(catalog, null, 2)}\n`, 'utf8');
  console.log(`Wrote ${catalog.records.length} records (${tactics} tactics, ${techniques} techniques, ${subs} sub-techniques) to ${outPath}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main().catch((err) => {
    console.error(err.message || err);
    process.exit(1);
  });
}

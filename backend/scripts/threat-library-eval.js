#!/usr/bin/env node
/**
 * First-pass evaluation protocol (see docs/threat-library-first-pass-evaluation.md).
 *
 *   node scripts/threat-library-eval.js sample <population.json> --seed <s> --size <n> --out <manifest.json>
 *   node scripts/threat-library-eval.js packets <manifest.json> --out <dir>
 *   node scripts/threat-library-eval.js validate [<cases dir>]
 *   node scripts/threat-library-eval.js agreement <first.json> <second.json>
 *
 * The population is a list you write at import time, before any report is read:
 * [{ id, url, title, publisher, format, package_announced }]. Nothing here reads
 * extractor output, the database or IOC rows.
 */
import fs from 'node:fs';
import path from 'node:path';
import { contractFingerprint } from '../lib/threatLibrary/contractBundle.js';
import { buildLabelingPacket, drawStratifiedSample, labelAgreement, sealedSetReadiness } from '../lib/threatLibrary/benchmark/sealedProtocol.js';
import { SEALED_CASES_DIR, SEALED_MIN_REPORTS } from '../lib/threatLibrary/benchmark/scorecard.js';

const [command, ...rest] = process.argv.slice(2);
const flag = (name) => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 ? rest[i + 1] : null;
};
const readJson = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));

if (command === 'sample') {
  const manifest = drawStratifiedSample(readJson(rest[0]), {
    seed: flag('seed'),
    size: Number(flag('size')),
    contract_fingerprint: contractFingerprint()
  });
  fs.writeFileSync(flag('out'), JSON.stringify(manifest, null, 2));
  console.log(`${manifest.reports.length} of ${manifest.population} reports drawn across ${Object.keys(manifest.strata).length} strata; contract ${manifest.contract_fingerprint}`);
} else if (command === 'packets') {
  const manifest = readJson(rest[0]);
  const out = flag('out');
  fs.mkdirSync(out, { recursive: true });
  for (const entry of manifest.reports) {
    const packet = buildLabelingPacket(entry, manifest);
    fs.writeFileSync(path.join(out, `${packet.id}.json`), JSON.stringify(packet, null, 2));
    if (entry.second_labeler) fs.writeFileSync(path.join(out, `${packet.id}.second-labeler.json`), JSON.stringify(packet, null, 2));
  }
  console.log(`${manifest.reports.length} packets written to ${out}`);
} else if (command === 'validate') {
  const dir = rest[0] || SEALED_CASES_DIR;
  const cases = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => readJson(path.join(dir, f)));
  const r = sealedSetReadiness(cases, { min_reports: SEALED_MIN_REPORTS, contract_fingerprint: contractFingerprint() });
  for (const i of r.invalid) console.log(`INVALID ${i.id}\n  ${i.problems.join('\n  ')}`);
  console.log(r.ready ? 'First-pass evaluation can be scored.' : `Not ready: ${r.blockers.join('; ')}`);
  process.exitCode = r.invalid.length ? 1 : 0;
} else if (command === 'agreement') {
  const r = labelAgreement(readJson(rest[0]).ground_truth, readJson(rest[1]).ground_truth);
  console.log(JSON.stringify(r, null, 2));
} else {
  console.error('usage: threat-library-eval.js sample|packets|validate|agreement');
  process.exitCode = 2;
}

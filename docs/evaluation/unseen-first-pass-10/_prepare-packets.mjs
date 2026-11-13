/**
 * Build empty source-only packets for unseen-first-pass-10.
 * Does not import TalonHound extraction or invent GT labels.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(ROOT, '_source_html');
const OUT = path.join(ROOT, 'packets');
fs.mkdirSync(OUT, { recursive: true });

const FP = 'ee233e2fdf4e69bee40f1de64f56b091';
const DRAWN = '2026-11-13T00:00:00.000Z';

const REPORTS = [
  {
    id: 'msft-gsocket',
    publisher: 'Microsoft',
    title: 'The global socket: how threat actors are weaponizing GSocket for stealthy C2',
    url: 'https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/',
    traits: ['ioc_table', 'narrative', 'mixed_legit_abuse']
  },
  {
    id: 'huntress-sckit',
    publisher: 'Huntress',
    title: 'SCKit Worm Installs Rogue ScreenConnect Clients and Session Cookie Relays',
    url: 'https://www.huntress.com/blog/sckit-worm-rogue-screenconnect',
    traits: ['ioc_table', 'narrative', 'mixed_legit_abuse']
  },
  {
    id: 'rf-markirat',
    publisher: 'Recorded Future',
    title: 'Iran-Nexus TAG-182 Disseminates MarkiRAT Surveillance Tool',
    url: 'https://www.recordedfuture.com/research/nexus-tag182-disseminates-markirat',
    traits: ['ioc_table', 'narrative', 'phishing']
  },
  {
    id: 'trend-installfix',
    publisher: 'Trend Micro',
    title: 'InstallFix and Claude Code: How Fake Install Pages Lead to Real Compromise',
    url: 'https://www.trendmicro.com/en_us/research/26/e/installfix-and-claude-code.html',
    traits: ['ioc_table', 'narrative', 'mixed_legit_abuse']
  },
  {
    id: 'trend-kongtuke',
    publisher: 'Trend Micro',
    title: 'KongTuke ClickFix Abuse of Compromised WordPress Sites',
    url: 'https://www.trendmicro.com/en_us/research/26/c/kongtuke-clickfix-abuse-of-compromised-wordpress-sites.html',
    traits: ['narrative', 'compromised_sites', 'mixed_benign']
  },
  {
    id: 'trend-teampcp',
    publisher: 'Trend Micro',
    title: 'Analyzing TeamPCP Supply Chain Attacks',
    url: 'https://www.trendmicro.com/en_us/research/26/e/analyzing-teampcp-supply-chain-attacks.html',
    traits: ['narrative', 'linked_packages', 'supply_chain']
  },
  {
    id: 'unit42-falcon-c2',
    publisher: 'Unit 42',
    title: 'The XG Files: Falcon C2 Flying Under The (Browser) Radar',
    url: 'https://unit42.paloaltonetworks.com/falcon-c2-browser-compromise/',
    traits: ['ioc_table', 'narrative', 'browser_extension']
  },
  {
    id: 'groupib-ghost-stadium',
    publisher: 'Group-IB',
    title: 'The GHOST STADIUM Score: Billions At Stake At The Worlds Largest Football Tournament',
    url: 'https://www.group-ib.com/blog/ghost-stadium-football-fraud/',
    traits: ['ioc_table', 'narrative', 'fraud_domains']
  },
  {
    id: 'unit42-cairn',
    publisher: 'Unit 42',
    title: 'Attackers Use Autonomous AI to Target Semiconductor, Defense and Civil Society Sectors',
    url: 'https://unit42.paloaltonetworks.com/cairn-framework-ai-autonomous-attacks/',
    traits: ['ioc_table', 'narrative', 'sparse_iocs']
  },
  {
    id: 'google-tag-apt42',
    publisher: 'Google TAG',
    title: 'Iranian backed group steps up phishing campaigns against Israel, U.S.',
    url: 'https://blog.google/threat-analysis-group/iranian-backed-group-steps-up-phishing-campaigns-against-israel-us/',
    traits: ['ioc_list', 'narrative', 'phishing', 'abused_cloud']
  }
];

const manifest = {
  experiment: 'unseen-first-pass-10-2026-11-13',
  sealed_eligible: false,
  contract_fingerprint: FP,
  drawn_at: DRAWN,
  selection_rules: [
    'threat_library_check_report_urls exists=false',
    'not in first-measured-batch sealed 40',
    'not used as golden/fixture source URL in backend/lib/threatLibrary',
    'diverse publishers; prefer IOC tables / narrative / linked packs / mixed infra'
  ],
  reports: []
};

for (const r of REPORTS) {
  const htmlPath = path.join(SRC, `${r.id}.html`);
  if (!fs.existsSync(htmlPath)) throw new Error(`missing source html ${r.id}`);
  const buf = fs.readFileSync(htmlPath);
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  const packet = {
    id: `unseen-${r.id}`,
    evaluation_role: 'unseen_first_pass_experiment',
    sealed_eligible: false,
    talonhound_report_uuid: null,
    talonhound_report_id: null,
    title: r.title,
    publisher: r.publisher,
    format: 'html',
    sampling: {
      method: 'manual_unseen_screen_2026-11-13',
      seed: 'unseen-first-pass-10-2026-11-13',
      drawn_at: DRAWN,
      stratum: `${r.publisher}|html|${r.traits.join('+')}`,
      note: 'Genuinely never-imported at selection time; excluded sealed 40 and known fixtures.'
    },
    contract_fingerprint: FP,
    contract_fingerprint_note: 'Workspace freeze at packet prep; confirm against freeze-contract.json and production run stamps.',
    selection: {
      difficulty_proxy: 'mixed',
      structure_notes: r.traits.join(', '),
      diversity_axes: [`publisher:${r.publisher}`, ...r.traits.map((t) => `trait:${t}`)],
      library_check: { exists: false, checked_at: DRAWN }
    },
    source: {
      kind: 'private_source',
      url: r.url,
      reference: r.url,
      format: 'html',
      sha256,
      retained_local_path: `_source_html/${r.id}.html`,
      snapshot_verified_at: DRAWN,
      snapshot_stable: true,
      bytes: buf.length
    },
    annotation_instructions: {
      use_only: 'publisher URL or retained publisher HTML under _source_html/',
      methodology: 'Evidence-First (see worksheets/HOW-TO-COMPLETE.md and ../annotation-packet-guide.md)',
      do_not_open: [
        'TalonHound report UI / Indicators / Context Only',
        'approved IOC rows',
        'first-pass-captures/ until labeling of this packet is finished',
        'Qwen or Claude assessment lists',
        'sealed first-measured-batch packets'
      ],
      leave_unverified_empty_or_ambiguous: true
    },
    ground_truth: {
      provenance: {
        method: 'independent_human_review_of_publisher_source',
        verified_by: '',
        verified_at: '',
        coverage_note: '',
        second_labeler: null,
        disagreement_resolution: null
      },
      indicators: [],
      context_only: [],
      ambiguous: [],
      linked_packages: []
    }
  };
  const outPath = path.join(OUT, `unseen-${r.id}.json`);
  fs.writeFileSync(outPath, JSON.stringify(packet, null, 2) + '\n');
  manifest.reports.push({
    id: r.id,
    packet: `packets/unseen-${r.id}.json`,
    publisher: r.publisher,
    title: r.title,
    url: r.url,
    sha256,
    bytes: buf.length,
    traits: r.traits
  });
  console.log('packet', r.id, sha256.slice(0, 12), buf.length);
}

fs.writeFileSync(path.join(ROOT, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('manifest', manifest.reports.length);
